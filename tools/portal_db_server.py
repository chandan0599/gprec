#!/usr/bin/env python3
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import time
import uuid
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from cryptography.fernet import Fernet
from pypdf import PdfReader
from docx import Document as DocxDocument

ROOT = Path(__file__).resolve().parents[1]
# 0.0.0.0 (not 127.0.0.1) so this is reachable from other devices on the same LAN (e.g. a phone,
# to test QR scanning against a real camera) - still only bound to your own network interface, not
# exposed beyond it.
HOST = "0.0.0.0"
PORT = 8766
# tools/static_server.py is the actual dev origin this API is called from (VS Code Live Server was
# replaced earlier this project - see static_server.py's own docstring). Add the real deployed
# origin(s) here once this is hosted anywhere other than localhost.
# The LAN IP entry lets a phone on the same WiFi hit this API when testing features that need a
# real device (e.g. scanning a hostel-pass QR with an actual camera) - update it if your Mac's
# local IP changes (check with `ipconfig getifaddr en0`).
ALLOWED_ORIGINS = {"http://127.0.0.1:8080", "http://localhost:8080", "http://192.168.1.17:8080"}
PSQL = "/Applications/Postgres.app/Contents/Versions/18/bin/psql"
DB_NAME = os.environ.get("GPREC_DB_NAME", "lakkavaramsaichandan")
DB_SCHEMA = os.environ.get("GPREC_DB_SCHEMA", "gprec_erp")
DB_USER = os.environ.get("GPREC_DB_USER", "lakkavaramsaichandan")
DB_PASSWORD = os.environ.get("GPREC_DB_PASSWORD", "1230599")
DB_HOST = os.environ.get("GPREC_DB_HOST", "localhost")
DB_PORT = os.environ.get("GPREC_DB_PORT", "5432")

# reCAPTCHA on the public event registration/login forms (no GPREC login gate to fall back on
# there, unlike every other write path in this app). The secret key stays server-side-only via an
# env var, never committed - the site key is the public half and is safe to embed client-side.
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY", "")

# Encryption-at-rest for financial PII (bank account details) - a compromised DB dump or backup
# should not reveal plaintext account numbers/IFSC codes. Key is generated once and persisted
# outside the DB (a Postgres dump alone is then useless for decrypting this column); set
# GPREC_BANK_ENCRYPTION_KEY to pin a specific key instead (e.g. in production).
BANK_ENCRYPTION_KEY_PATH = ROOT / "tools" / ".bank_encryption.key"


def get_or_create_encryption_key():
    env_key = os.environ.get("GPREC_BANK_ENCRYPTION_KEY")
    if env_key:
        return env_key.encode("utf-8")
    if BANK_ENCRYPTION_KEY_PATH.exists():
        return BANK_ENCRYPTION_KEY_PATH.read_bytes().strip()
    key = Fernet.generate_key()
    BANK_ENCRYPTION_KEY_PATH.write_bytes(key)
    BANK_ENCRYPTION_KEY_PATH.chmod(0o600)
    return key


_bank_fernet = Fernet(get_or_create_encryption_key())


def encrypt_text(plaintext):
    return _bank_fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(token):
    return _bank_fernet.decrypt(token.encode("ascii")).decode("utf-8")


def mask_account_number(number):
    digits = "".join(str(number or "").split())
    if len(digits) <= 9:
        return digits
    return digits[:5] + ("X" * (len(digits) - 9)) + digits[-4:]


def build_masked_bank_details(details):
    masked = dict(details or {})
    if masked.get("accountNumber"):
        masked["accountNumber"] = mask_account_number(masked["accountNumber"])
    return masked


def run_psql(sql):
    env = {**os.environ, "PGPASSWORD": DB_PASSWORD}
    scoped_sql = f"SET search_path TO {DB_SCHEMA}, public; {sql}"
    result = subprocess.run(
        [PSQL, "-h", DB_HOST, "-p", DB_PORT, "-U", DB_USER, "-d", DB_NAME, "-q", "-t", "-A", "-c", scoped_sql],
        cwd=ROOT,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def run_json(sql, fallback):
    output = run_psql(sql)
    if not output:
        return fallback
    output = output.strip()
    if not output:
        return fallback
    # psql sometimes emits advisory messages or blank lines before JSON.
    # Keep only the first valid JSON object/array in the output.
    start = min(
        [pos for pos in (output.find('{'), output.find('[')) if pos >= 0] or [0]
    )
    output = output[start:]
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        # Fallback more leniently: strip any leading non-JSON prefix.
        for marker in ('{', '['):
            pos = output.find(marker)
            if pos > 0:
                try:
                    return json.loads(output[pos:])
                except json.JSONDecodeError:
                    continue
        # If parsing still fails, log the raw output and return fallback.
        print('portal_db_server: failed to parse JSON output from psql:', repr(output), file=sys.stderr)
        return fallback


# Deliberately narrow (name only, like /api/auth/has-admin-credentials elsewhere in this file) -
# the Challan form has no login (matching the real examcell.gprec.ac.in form it replaces), so this
# stays unauthenticated, but only ever returns the one field a receipt actually needs to show.
def lookup_student_name(roll_no):
    rows = run_json(
        f"SELECT COALESCE(json_agg(json_build_object('name', full_name)), '[]'::json) "
        f"FROM students WHERE roll_no = {quote(roll_no)};",
        [],
    )
    return rows[0]["name"] if rows else None


HEALTH_TABLES = ["students", "faculty", "non_teaching_staff", "notices", "user_credentials"]


def check_database_health():
    started = time.monotonic()
    try:
        counts_sql = "SELECT json_build_object(" + ", ".join(
            f"'{table}', (SELECT count(*) FROM {table})" for table in HEALTH_TABLES
        ) + ");"
        counts = run_json(counts_sql, {})
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {
            "ok": True,
            "database": DB_NAME,
            "schema": DB_SCHEMA,
            "user": DB_USER,
            "latencyMs": latency_ms,
            "tableCounts": counts,
            "checkedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z")
        }
    except Exception as exc:
        return {
            "ok": False,
            "database": DB_NAME,
            "schema": DB_SCHEMA,
            "user": DB_USER,
            "error": str(exc),
            "checkedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z")
        }


DB_STATS_SQL = r"""
SELECT json_build_object(
  'sessions', (SELECT json_build_object(
    'active', count(*) FILTER (WHERE state = 'active'),
    'idle', count(*) FILTER (WHERE state = 'idle'),
    'total', count(*)
  ) FROM pg_stat_activity WHERE datname = current_database()),
  'transactions', (SELECT json_build_object(
    'commit', xact_commit,
    'rollback', xact_rollback
  ) FROM pg_stat_database WHERE datname = current_database()),
  'blockIo', (SELECT json_build_object(
    'read', blks_read,
    'hit', blks_hit
  ) FROM pg_stat_database WHERE datname = current_database())
);
"""


def check_database_stats():
    # pg_stat_database's xact_commit/xact_rollback/blks_read/blks_hit are cumulative counters
    # since the server started, not point-in-time rates - the frontend samples this endpoint
    # repeatedly and computes its own deltas between polls to plot a rate over time.
    try:
        stats = run_json(DB_STATS_SQL, {})
        return {"ok": True, "sampledAt": time.time(), **stats}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "sampledAt": time.time()}


def get_finance_export():
    # Payments/fee_dues are deliberately never included in BOOTSTRAP_SQL (same isolation as
    # bank_details) since that's fetched on every page load - this is a dedicated, admin-triggered
    # export instead, joined with student name/department for a readable report.
    return run_json(
        "SELECT COALESCE(json_agg(json_build_object("
        "'studentId', p.student_roll_no, 'studentName', s.full_name, 'department', s.department_code, "
        "'feeType', COALESCE(fd.fee_type, p.details->>'feeType', 'Fee'), 'amount', p.amount, "
        "'paidOn', to_char(p.paid_on, 'DD Mon YYYY'), 'paymentMode', COALESCE(p.payment_mode, '-'), "
        "'status', p.status, 'transactionRef', COALESCE(p.transaction_ref, '-')"
        ") ORDER BY p.paid_on DESC), '[]'::json) "
        "FROM payments p "
        "JOIN students s ON s.roll_no = p.student_roll_no "
        "LEFT JOIN fee_dues fd ON fd.id = p.fee_due_id;",
        [],
    )


def check_data_retention():
    # Dry-run only: reports how many rows in each classified table are older than that table's
    # policy cutoff. Never deletes or modifies anything - purge/archival stays a manual, deliberate
    # action for an admin to take after reviewing this report, not something this endpoint does
    # automatically. table_name/date_column come from data_retention_table_policies (admin-entered
    # config, not end-user input), but are still checked against information_schema before being
    # interpolated into SQL, since they're used as bare identifiers rather than bound parameters.
    policies = run_json(
        "SELECT COALESCE(json_agg(json_build_object("
        "'tableName', t.table_name, 'dateColumn', t.date_column, "
        "'policyCode', t.policy_code, 'retentionMonths', p.retention_months"
        ")), '[]'::json) FROM data_retention_table_policies t "
        "JOIN data_retention_policies p ON p.policy_code = t.policy_code "
        "WHERE t.is_active AND p.retention_months IS NOT NULL;",
        [],
    )
    if not policies:
        return {"ok": True, "checkedAt": time.time(), "results": []}

    known_columns = run_json(
        f"SELECT COALESCE(json_agg(table_name || '.' || column_name), '[]'::json) "
        f"FROM information_schema.columns WHERE table_schema = '{DB_SCHEMA}';",
        [],
    )
    known_columns = set(known_columns or [])

    selects = []
    valid_entries = []
    for entry in policies:
        table_name = entry.get("tableName") or ""
        date_column = entry.get("dateColumn") or ""
        months = entry.get("retentionMonths")
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", table_name) or not re.fullmatch(r"[a-z_][a-z0-9_]*", date_column):
            continue
        if f"{table_name}.{date_column}" not in known_columns or not isinstance(months, int):
            continue
        valid_entries.append(entry)
        selects.append(
            f"SELECT '{table_name}' AS table_name, count(*) AS eligible_count "
            f"FROM {table_name} WHERE {date_column} < now() - interval '{months} months'"
        )

    if not selects:
        return {"ok": True, "checkedAt": time.time(), "results": []}

    counts_by_table = {
        row["table_name"]: row["eligible_count"]
        for row in run_json(
            "SELECT COALESCE(json_agg(json_build_object('table_name', table_name, 'eligible_count', eligible_count)), '[]'::json) FROM ("
            + " UNION ALL ".join(selects)
            + ") counts;",
            [],
        )
    }
    results = [
        {
            "tableName": entry["tableName"],
            "policyCode": entry["policyCode"],
            "retentionMonths": entry["retentionMonths"],
            "eligibleCount": counts_by_table.get(entry["tableName"], 0),
        }
        for entry in valid_entries
    ]
    return {"ok": True, "checkedAt": time.time(), "results": results}


MYSQL_CLI = "mysql"


def test_external_db_connection(config):
    # Distinct from check_database_health()/check_database_stats(), which only ever test the
    # connection this server itself was started with (DB_HOST/DB_USER/... above) - this tests
    # whatever host/port/database/username/password an admin just typed into the "Database
    # Connection" form, before they've saved/relied on it, since a browser can't open that raw
    # connection itself to check.
    db_type = config.get("type") or ""
    host = (config.get("host") or "").strip()
    database = (config.get("database") or "").strip()
    port = (config.get("port") or "").strip()
    username = (config.get("username") or "").strip()
    password = config.get("password") or ""
    if not host or not database:
        return {"ok": False, "error": "Host and Database Name are required."}

    started = time.monotonic()
    try:
        if db_type == "postgres":
            env = {**os.environ, "PGPASSWORD": password}
            subprocess.run(
                [PSQL, "-h", host, "-p", port or "5432", "-U", username, "-d", database, "-q", "-c", "SELECT 1;"],
                env=env, check=True, text=True, capture_output=True, timeout=8,
            )
        elif db_type == "mysql":
            subprocess.run(
                [MYSQL_CLI, "-h", host, "-P", port or "3306", "-u", username, f"-p{password}", database, "-e", "SELECT 1;"],
                check=True, text=True, capture_output=True, timeout=8,
            )
        else:
            return {"ok": False, "error": f"Unsupported database type: {db_type or '(none)'}"}
        return {"ok": True, "latencyMs": round((time.monotonic() - started) * 1000, 1)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Connection timed out after 8 seconds - check the host/port and that the database accepts remote connections."}
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or exc.stdout or str(exc)).strip()
        return {"ok": False, "error": message[:400] or "Connection failed."}
    except FileNotFoundError:
        tool = MYSQL_CLI if db_type == "mysql" else PSQL
        return {"ok": False, "error": f"The '{tool}' command-line tool isn't available on this server."}


BOOTSTRAP_SQL = r"""
WITH
student_rows AS (
  SELECT s.*, g.father_name, g.mother_name, g.guardian_mobile, g.guardian_email
  FROM students s
  LEFT JOIN guardians g ON g.student_roll_no = s.roll_no
),
hostel_rows AS (
  SELECT h.*, s.full_name, s.department_code, s.class_name, g.father_name, g.guardian_mobile
  FROM hostel_allocations h
  JOIN students s ON s.roll_no = h.student_roll_no
  LEFT JOIN guardians g ON g.student_roll_no = s.roll_no
),
complaint_rows AS (
  SELECT c.*, s.full_name, s.department_code, h.hostel_name, h.room_no
  FROM complaints c
  JOIN students s ON s.roll_no = c.student_roll_no
  LEFT JOIN hostel_allocations h ON h.student_roll_no = s.roll_no
),
exam_rows AS (
  SELECT department_code, json_agg(json_build_object(
    'id', id::text,
    'code', subject_code,
    'subject', subject_name,
    'date', exam_date::text,
    'time', exam_time,
    'rollFrom', roll_from,
    'rollTo', roll_to,
    'room', room,
    'startSeat', start_seat,
    'location', location
  ) ORDER BY exam_date, subject_code, roll_from) AS rows
  FROM exam_schedules
  WHERE term_label = 'current'
  GROUP BY department_code
),
past_exam_rows AS (
  SELECT term_label, json_agg(json_build_object(
    'code', subject_code,
    'subject', subject_name,
    'date', exam_date::text,
    'time', exam_time
  ) ORDER BY exam_date) AS rows
  FROM exam_schedules
  WHERE term_label <> 'current'
  GROUP BY term_label
),
fee_rows AS (
  SELECT student_roll_no, json_agg(json_build_object(
    'id', id::text,
    'application', lower(replace(fee_type, ' ', '-')),
    'feeType', fee_type,
    'detail', status,
    'totalFee', amount,
    'paidAmount', 0,
    'amount', amount,
    'dueDate', due_date::text
  ) ORDER BY due_date) AS rows
  FROM fee_dues
  WHERE status <> 'Paid'
  GROUP BY student_roll_no
),
placement_application_rows AS (
  SELECT student_roll_no, json_agg(drive_id::text) AS drive_ids
  FROM placement_applications
  GROUP BY student_roll_no
),
class_message_rows AS (
  SELECT json_agg(json_build_object(
    'id', id::text,
    'facultyEmail', faculty_email,
    'facultyName', faculty_name,
    'subjectCode', subject_code,
    'subject', subject,
    'section', section,
    'department', department_code,
    'title', title,
    'message', message,
    'createdAt', to_char(posted_at, 'YYYY-MM-DD"T"HH24:MI:SS'),
    'sentOn', to_char(posted_at, 'DD Mon, HH12:MI AM'),
    'postedAt', extract(epoch FROM posted_at) * 1000
  ) ORDER BY posted_at DESC) AS rows
  FROM class_messages
),
invigilation_duty_rows AS (
  SELECT json_agg(json_build_object(
    'id', id::text,
    'facultyEmail', faculty_email,
    'facultyName', faculty_name,
    'code', subject_code,
    'subject', subject,
    'date', exam_date::text,
    'time', exam_time,
    'room', room,
    'location', location
  ) ORDER BY exam_date) AS rows
  FROM invigilation_duties
),
leave_request_rows AS (
  SELECT json_agg(json_build_object(
    'id', id::text,
    'facultyEmail', faculty_email,
    'facultyName', faculty_name,
    'staffEmail', staff_email,
    'staffName', staff_name,
    'designation', designation,
    'leaveType', leave_type,
    'department', department_code,
    'reason', reason,
    'fromDate', from_date::text,
    'toDate', to_date::text,
    'status', status,
    'isHod', is_hod,
    'isNonTeaching', is_non_teaching,
    'requestedAt', extract(epoch FROM requested_at) * 1000
  ) ORDER BY requested_at DESC) AS rows
  FROM leave_requests
),
adhoc_class_request_rows AS (
  SELECT json_agg(json_build_object(
    'id', id::text,
    'facultyEmail', faculty_email,
    'facultyName', faculty_name,
    'department', department_code,
    'subject', subject,
    'subjectCode', subject_code,
    'reason', reason,
    'date', requested_date::text,
    'time', requested_time,
    'status', status,
    'isHod', is_hod,
    'requestedAt', extract(epoch FROM requested_at) * 1000
  ) ORDER BY requested_at DESC) AS rows
  FROM adhoc_class_requests
),
class_cancellation_rows AS (
  SELECT json_agg(json_build_object(
    'id', id::text,
    'facultyEmail', faculty_email,
    'subjectCode', subject_code,
    'subject', subject,
    'date', cancel_date::text,
    'reason', reason
  ) ORDER BY cancel_date DESC) AS rows
  FROM class_cancellations
),
student_project_rows AS (
  SELECT json_agg(data ORDER BY (data->>'submittedAt')::numeric DESC) AS rows FROM student_projects
),
student_research_rows AS (
  SELECT json_agg(data ORDER BY (data->>'submittedAt')::numeric DESC) AS rows FROM student_research
),
hostel_outing_request_rows AS (
  SELECT json_agg(data ORDER BY updated_at DESC) AS rows FROM hostel_outing_requests
),
hostel_visiting_request_rows AS (
  SELECT json_agg(data ORDER BY updated_at DESC) AS rows FROM hostel_visiting_requests
),
hostel_leave_request_rows AS (
  SELECT json_agg(data ORDER BY updated_at DESC) AS rows FROM hostel_leave_requests
),
campus_event_registration_rows AS (
  SELECT json_agg(data ORDER BY updated_at DESC) AS rows FROM campus_event_registrations
),
alumni_album_rows AS (
  SELECT json_agg(data ORDER BY updated_at DESC) AS rows FROM alumni_albums
),
alumni_memory_rows AS (
  SELECT json_agg(data ORDER BY updated_at DESC) AS rows FROM alumni_memories
),
alumni_event_rsvp_rows AS (
  SELECT json_agg(data) AS rows FROM alumni_event_rsvps
),
contact_message_rows AS (
  SELECT json_agg(data ORDER BY updated_at DESC) AS rows FROM contact_messages
),
calendar_reminder_rows AS (
  SELECT json_agg(data) AS rows FROM calendar_reminders
),
student_document_rows AS (
  SELECT student_roll_no, json_agg(json_build_object(
    'id', id::text,
    'docType', doc_type,
    'fileName', file_name,
    'fileUrl', file_url,
    'fileMime', file_mime,
    'uploadedAt', to_char(uploaded_at, 'DD Mon YYYY')
  ) ORDER BY uploaded_at DESC) AS rows
  FROM student_documents
  GROUP BY student_roll_no
),
course_material_rows AS (
  SELECT json_agg(json_build_object(
    'id', id::text,
    'subjectCode', subject_code,
    'title', title,
    'description', description,
    'fileName', file_name,
    'fileUrl', file_url,
    'fileMime', file_mime,
    'uploadedAt', to_char(uploaded_at, 'DD Mon YYYY')
  ) ORDER BY uploaded_at DESC) AS rows
  FROM course_materials
),
book_favorite_rows AS (
  SELECT identity, favorites FROM book_favorites
),
data_retention_policy_rows AS (
  SELECT json_agg(json_build_object(
    'policyCode', policy_code, 'behavior', behavior, 'description', description,
    'retentionMonths', retention_months, 'retentionBasis', retention_basis,
    'disposalAction', disposal_action, 'legalHoldAllowed', legal_hold_allowed
  ) ORDER BY policy_code) AS rows
  FROM data_retention_policies WHERE is_active
),
data_retention_table_policy_rows AS (
  SELECT json_agg(json_build_object(
    'tableName', table_name, 'policyCode', policy_code, 'ownerModule', owner_module,
    'dateColumn', date_column, 'containsPii', contains_pii, 'notes', notes
  ) ORDER BY owner_module, table_name) AS rows
  FROM data_retention_table_policies WHERE is_active
),
ai_request_log_rows AS (
  SELECT json_agg(entry) AS rows FROM (
    SELECT json_build_object(
      'provider', provider, 'model', model, 'status', status,
      'latencyMs', latency_ms, 'error', error, 'timestamp', extract(epoch FROM created_at) * 1000
    ) AS entry
    FROM ai_request_log ORDER BY created_at DESC LIMIT 20
  ) recent
),
ai_request_log_stats AS (
  SELECT
    COUNT(*) FILTER (WHERE status IN ('success', 'failure'))::int AS attempts,
    COUNT(*) FILTER (WHERE status = 'success')::int AS successes,
    COUNT(*) FILTER (WHERE status = 'failure')::int AS failures,
    COUNT(*) FILTER (WHERE status = 'rateLimited')::int AS rate_limited,
    COUNT(*) FILTER (WHERE status = 'blocked')::int AS blocked,
    COUNT(*) FILTER (WHERE status = 'offTopic')::int AS off_topic,
    MAX(created_at) AS last_used_at,
    (array_agg(provider ORDER BY created_at DESC))[1] AS last_provider,
    (array_agg(error ORDER BY created_at DESC))[1] AS last_error
  FROM ai_request_log
),
ai_usage_stats_row AS (
  SELECT * FROM ai_usage_stats
  UNION ALL
  SELECT true, 0, 0, 0, 0, 0, 0, NULL::timestamptz, NULL::text, NULL::text
  WHERE NOT EXISTS (SELECT 1 FROM ai_usage_stats WHERE id = true)
  LIMIT 1
),
activity_log_rows AS (
  SELECT json_agg(entry) AS rows FROM (
    SELECT json_build_object(
      'scope', scope, 'actor', actor, 'action', action, 'module', module, 'createdAt', extract(epoch FROM created_at) * 1000
    ) AS entry
    FROM activity_log ORDER BY created_at DESC LIMIT 100
  ) recent
),
funding_contribution_rows AS (
  SELECT json_agg(json_build_object(
    'id', id::text,
    'campaignId', campaign_id,
    'name', contributor_name,
    'email', contributor_email,
    'amount', amount,
    'paymentId', payment_id,
    'date', extract(epoch FROM contributed_at) * 1000
  ) ORDER BY contributed_at DESC) AS rows
  FROM funding_contributions
),
alumni_account_rows AS (
  -- password_hash/password_salt deliberately never selected here - same isolation as
  -- user_credentials, this is the one broadly-shared bootstrap response.
  SELECT json_agg(jsonb_build_object('email', email) || data ORDER BY created_at) AS rows FROM alumni_accounts
),
catalog_rows AS (
  SELECT json_object_agg(barcode, json_build_object('title', title, 'author', author)) AS catalog
  FROM library_books
),
library_rows AS (
  SELECT json_agg(json_build_object(
    'id', li.id::text,
    'barcode', li.barcode,
    'rollNumber', li.student_roll_no,
    'studentName', s.full_name,
    'bookTitle', b.title,
    'author', b.author,
    'issueDate', li.issued_on::text,
    'dueDate', li.due_on::text,
    'returnDate', li.returned_on::text,
    'status', li.status
  ) ORDER BY li.issued_on DESC) AS rows
  FROM library_issues li
  JOIN library_books b ON b.barcode = li.barcode
  JOIN students s ON s.roll_no = li.student_roll_no
),
faculty_rows AS (
  SELECT full_name, department_code, email, profile_photo_url, designation,
    qualifications, google_scholar, apaar_id, vidwan_profile, phone, primary_subject, subject_code
  FROM faculty
  WHERE status = 'Active'
)
SELECT json_build_object(
  'studentDirectory', COALESCE((SELECT json_agg(json_build_object(
    'studentId', roll_no,
    'name', full_name,
    'branch', department_code
  ) ORDER BY roll_no) FROM student_rows), '[]'::json),
  'studentProfiles', COALESCE((SELECT json_object_agg(roll_no, json_build_object(
    'name', full_name,
    'branch', department_code,
    'className', class_name,
    'semester', semester,
    'profilePhoto', profile_photo_url,
    'dob', to_char(date_of_birth, 'DD-MM-YYYY'),
    'mobile', mobile,
    'email', email,
    'gender', gender,
    'bloodGroup', blood_group,
    'address', address,
    'status', status,
    'hostelStatus', hostel_status,
    'program', 'B.Tech - ' || department_code,
    'admissionType', admission_type,
    'academicYear', academic_year,
    'admissionScheme', admission_scheme,
    'father', father_name,
    'mother', mother_name,
    'parentMobile', guardian_mobile,
    'parentEmail', guardian_email,
    'sscSchool', ssc_school,
    'sscBoardYear', ssc_board_year,
    'sscGpa', ssc_gpa,
    'interCollege', inter_college,
    'interBoardYear', inter_board_year,
    'interPercentage', inter_percentage
  )) FROM student_rows), '{}'::json),
  'hostelStudentData', COALESCE((SELECT json_object_agg(student_roll_no, json_build_object(
    'name', full_name,
    'branch', department_code,
    'className', class_name,
    'hostel', hostel_name,
    'block', block_name,
    'room', room_no,
    'bed', bed_no,
    'warden', CASE WHEN hostel_name ILIKE 'Girls%' THEN 'Girls Hostel Warden' ELSE 'Boys Hostel Warden' END,
    'parent', father_name,
    'parentMobile', guardian_mobile,
    'mess', mess_plan || ' | Present today',
    'outing', 'No active outing request',
    'complaints', 'Check complaint register',
    'status', status || ' hostler'
  )) FROM hostel_rows), '{}'::json),
  'admins', COALESCE((SELECT json_agg(json_build_object(
    'name', full_name,
    'email', email,
    'role', role,
    'department', COALESCE(department_code, 'All'),
    'canManageAdmins', can_manage_admins,
    'status', status,
    'photoUrl', photo_url,
    'studentRoll', student_roll
  ) ORDER BY email) FROM admins), '[]'::json),
  'facultyProfiles', COALESCE((SELECT json_agg(json_build_object(
    'name', full_name,
    'department', department_code,
    'email', email,
    'photoUrl', profile_photo_url,
    'designation', designation,
    'qualifications', qualifications,
    'googleScholar', google_scholar,
    'apaarId', apaar_id,
    'vidwanProfile', vidwan_profile,
    'phone', phone,
    'primarySubject', primary_subject,
    'subjectCode', subject_code
  ) ORDER BY full_name) FROM faculty_rows), '[]'::json),
  'nonTeachingStaff', COALESCE((SELECT json_agg(json_build_object(
    'name', full_name,
    'email', email,
    'designation', designation,
    'section', section,
    'photoUrl', profile_photo_url
  ) ORDER BY full_name) FROM non_teaching_staff WHERE status = 'Active'), '[]'::json),
  'curriculum', COALESCE((
    SELECT json_object_agg(department_code, subjects) FROM (
      SELECT department_code, json_agg(json_build_object(
        'code', subject_code, 'name', subject_name, 'semester', semester,
        'credits', credits, 'type', subject_type
      ) ORDER BY subject_code) AS subjects
      FROM curriculum GROUP BY department_code
    ) grouped_curriculum
  ), '{}'::json),
  'classTimetable', COALESCE((
    SELECT json_object_agg(department_code, slots) FROM (
      SELECT department_code, json_agg(json_build_object(
        'day', day_of_week, 'time', time_slot, 'code', subject_code,
        'subject', subject_name, 'facultyEmail', faculty_email, 'section', section
      ) ORDER BY day_of_week, time_slot) AS slots
      FROM class_timetable GROUP BY department_code
    ) grouped_timetable
  ), '{}'::json),
  'attendanceRecords', COALESCE((
    SELECT json_agg(json_build_object(
      'facultyEmail', r.faculty_email, 'subject', r.subject_code, 'section', r.section,
      'date', to_char(r.attendance_date, 'YYYY-MM-DD'),
      'entries', COALESCE((
        SELECT json_agg(json_build_object('studentId', e.student_roll_no, 'present', e.present))
        FROM attendance_entries e WHERE e.record_id = r.id
      ), '[]'::json)
    ) ORDER BY r.attendance_date DESC) FROM attendance_records r
  ), '[]'::json),
  'studentGrades', COALESCE((
    SELECT json_object_agg(student_roll_no, terms) FROM (
      SELECT student_roll_no, json_agg(json_build_object(
        'term', term, 'gpa', gpa, 'backlogs', backlogs,
        'updatedAt', extract(epoch FROM updated_at) * 1000
      ) ORDER BY term) AS terms
      FROM student_grades GROUP BY student_roll_no
    ) grouped_grades
  ), '{}'::json),
  'notices', COALESCE((SELECT json_agg(json_build_object(
    'id', id::text,
    'audience', audience,
    'title', title,
    'message', body,
    'department', department_code,
    'attachment', CASE WHEN attachment_url IS NOT NULL
      THEN json_build_object('name', attachment_name, 'dataUrl', attachment_url, 'mime', attachment_mime)
      ELSE NULL END,
    'createdAt', (extract(epoch FROM created_at) * 1000)::bigint
  ) ORDER BY created_at DESC) FROM notices WHERE status = 'Published'), '[]'::json),
  'busRoutes', COALESCE((SELECT json_agg(json_build_object(
    'id', id::text, 'routeName', route_name, 'stops', stops, 'pickupTime', pickup_time, 'dropTime', drop_time
  ) ORDER BY route_name) FROM bus_routes), '[]'::json),
  'buses', COALESCE((SELECT json_agg(json_build_object(
    'id', bu.id::text, 'busNumber', bu.bus_number, 'routeId', bu.route_id::text,
    'routeName', ro.route_name, 'stops', ro.stops, 'driverName', bu.driver_name, 'driverMobile', bu.driver_mobile,
    'pickupTime', ro.pickup_time, 'dropTime', ro.drop_time
  ) ORDER BY bu.bus_number) FROM buses bu JOIN bus_routes ro ON ro.id = bu.route_id), '[]'::json),
  'assignments', COALESCE((SELECT json_agg(json_build_object(
    'id', id::text,
    'department', department_code,
    'subjectCode', subject_code,
    'title', title,
    'description', description,
    'dueDate', to_char(due_at, 'YYYY-MM-DD"T"HH24:MI'),
    'createdAt', to_char(created_at, 'YYYY-MM-DD"T"HH24:MI'),
    'document', CASE WHEN document_url IS NOT NULL
      THEN json_build_object('name', document_name, 'dataUrl', document_url, 'mime', document_mime)
      ELSE NULL END
  ) ORDER BY created_at DESC) FROM assignments), '[]'::json),
  'assignmentSubmissions', COALESCE((SELECT json_agg(json_build_object(
    'id', s.id::text,
    'assignmentId', s.assignment_id::text,
    'studentId', s.student_roll_no,
    'studentName', st.full_name,
    'submittedAt', to_char(s.submitted_at, 'DD Mon, HH12:MI AM'),
    'comment', s.comments,
    'files', COALESCE((
      SELECT json_agg(json_build_object('name', f.file_name, 'dataUrl', f.file_url, 'mime', f.file_mime))
      FROM assignment_submission_files f WHERE f.submission_id = s.id
    ), '[]'::json)
  ) ORDER BY s.submitted_at DESC) FROM assignment_submissions s JOIN students st ON st.roll_no = s.student_roll_no), '[]'::json),
  'plagiarismChecks', COALESCE((SELECT json_agg(json_build_object(
    'type', submission_type,
    'referenceId', reference_id,
    'rollNo', student_roll_no,
    'percent', percent,
    'notes', notes,
    'checkedAt', to_char(checked_at, 'DD Mon, HH12:MI AM')
  )) FROM plagiarism_checks), '[]'::json),
  'pendingFees', COALESCE((SELECT json_object_agg(student_roll_no, rows) FROM fee_rows), '{}'::json)
)::jsonb || json_build_object(
  -- json_build_object() has a hard 100-argument (50 key/value pair) limit in Postgres - this
  -- bootstrap blob is right at that edge, so keys are split across two calls concatenated with
  -- ||. Add new top-level keys to whichever half has headroom, not by growing either past ~45.
  'complaints', COALESCE((SELECT json_agg(json_build_object(
    'id', id::text,
    'studentId', student_roll_no,
    'studentName', full_name,
    'category', category,
    'department', department_code,
    'hostel', COALESCE(hostel_name, '-'),
    'room', COALESCE(room_no, '-'),
    'subject', subject,
    'description', description,
    'status', status
  ) ORDER BY created_at DESC) FROM complaint_rows), '[]'::json),
  'examCellData', COALESCE((SELECT json_object_agg(department_code, rows) FROM exam_rows), '{}'::json),
  'placementDrives', COALESCE((SELECT json_agg(json_build_object(
    'id', id::text,
    'company', company,
    'role', role_title,
    'ctc', ctc,
    'date', drive_date::text,
    'minCgpa', min_cgpa,
    'maxBacklogs', max_backlogs,
    'branches', eligible_departments,
    'addedAt', extract(epoch from drive_date),
    'driveType', drive_type,
    'description', description,
    'sessionTime', session_time,
    'venue', venue,
    'mode', mode,
    'seatCap', seat_cap,
    'applyLink', apply_link,
    'registeredCount', (SELECT COUNT(*) FROM placement_applications pa WHERE pa.drive_id = placement_drives.id)
  ) ORDER BY drive_date) FROM placement_drives), '[]'::json),
  'libraryCatalog', COALESCE((SELECT catalog FROM catalog_rows), '{}'::json),
  'libraryRecords', COALESCE((SELECT rows FROM library_rows), '[]'::json),
  'pastExamSchedules', COALESCE((SELECT json_object_agg(term_label, rows) FROM past_exam_rows), '{}'::json),
  'siteContent', COALESCE((SELECT json_object_agg(content_key, content_value) FROM site_content), '{}'::json),
  'feeAmountOverrides', COALESCE((SELECT json_object_agg(application_type, amount) FROM fee_amount_overrides), '{}'::json),
  'sectionAssignments', COALESCE((SELECT json_object_agg(student_roll_no, section) FROM student_section_assignments), '{}'::json),
  'placementApplications', COALESCE((SELECT json_object_agg(student_roll_no, drive_ids) FROM placement_application_rows), '{}'::json),
  'classMessages', COALESCE((SELECT rows FROM class_message_rows), '[]'::json),
  'invigilationDuties', COALESCE((SELECT rows FROM invigilation_duty_rows), '[]'::json),
  'leaveRequests', COALESCE((SELECT rows FROM leave_request_rows), '[]'::json),
  'adhocClassRequests', COALESCE((SELECT rows FROM adhoc_class_request_rows), '[]'::json),
  'classCancellations', COALESCE((SELECT rows FROM class_cancellation_rows), '[]'::json),
  'studentProjects', COALESCE((SELECT rows FROM student_project_rows), '[]'::json),
  'studentResearch', COALESCE((SELECT rows FROM student_research_rows), '[]'::json),
  'outingRequests', COALESCE((SELECT rows FROM hostel_outing_request_rows), '[]'::json),
  'visitingRequests', COALESCE((SELECT rows FROM hostel_visiting_request_rows), '[]'::json),
  'campusEventRegistrations', COALESCE((SELECT rows FROM campus_event_registration_rows), '[]'::json),
  'hostelLeaveRequests', COALESCE((SELECT rows FROM hostel_leave_request_rows), '[]'::json),
  'courseMaterials', COALESCE((SELECT rows FROM course_material_rows), '[]'::json),
  'studentDocuments', COALESCE((SELECT json_object_agg(student_roll_no, rows) FROM student_document_rows), '{}'::json),
  'bookFavorites', COALESCE((SELECT json_object_agg(identity, favorites) FROM book_favorite_rows), '{}'::json),
  'dataRetentionPolicies', COALESCE((SELECT rows FROM data_retention_policy_rows), '[]'::json),
  'dataRetentionTablePolicies', COALESCE((SELECT rows FROM data_retention_table_policy_rows), '[]'::json),
  'aiUsageStats', (SELECT json_build_object(
    'attempts', GREATEST(ai_usage_stats.attempts, COALESCE(ai_request_log_stats.attempts, 0)),
    'successes', GREATEST(ai_usage_stats.successes, COALESCE(ai_request_log_stats.successes, 0)),
    'failures', GREATEST(ai_usage_stats.failures, COALESCE(ai_request_log_stats.failures, 0)),
    'rateLimited', GREATEST(ai_usage_stats.rate_limited, COALESCE(ai_request_log_stats.rate_limited, 0)),
    'blocked', GREATEST(ai_usage_stats.blocked, COALESCE(ai_request_log_stats.blocked, 0)),
    'offTopic', GREATEST(ai_usage_stats.off_topic, COALESCE(ai_request_log_stats.off_topic, 0)),
    'lastUsedAt', extract(epoch FROM COALESCE(ai_usage_stats.last_used_at, ai_request_log_stats.last_used_at)) * 1000,
    'lastProvider', COALESCE(ai_usage_stats.last_provider, ai_request_log_stats.last_provider),
    'lastError', COALESCE(NULLIF(ai_usage_stats.last_error, ''), NULLIF(ai_request_log_stats.last_error, ''))
  ) FROM ai_usage_stats_row ai_usage_stats CROSS JOIN ai_request_log_stats),
  'aiRequestLog', COALESCE((SELECT rows FROM ai_request_log_rows), '[]'::json),
  'activityLog', COALESCE((SELECT rows FROM activity_log_rows), '[]'::json),
  'fundingContributions', COALESCE((SELECT rows FROM funding_contribution_rows), '[]'::json),
  'alumniAccounts', COALESCE((SELECT rows FROM alumni_account_rows), '[]'::json),
  'alumniAlbums', COALESCE((SELECT rows FROM alumni_album_rows), '[]'::json),
  'alumniMemories', COALESCE((SELECT rows FROM alumni_memory_rows), '[]'::json),
  'alumniEventRsvps', COALESCE((SELECT rows FROM alumni_event_rsvp_rows), '[]'::json),
  'contactMessages', COALESCE((SELECT rows FROM contact_message_rows), '[]'::json),
  'calendarReminders', COALESCE((SELECT rows FROM calendar_reminder_rows), '[]'::json)
)::jsonb;
"""

# Served to /api/bootstrap when no valid session token is present. Deliberately omits every
# student-linked or otherwise sensitive field BOOTSTRAP_SQL carries (studentProfiles,
# studentGrades, attendanceRecords/Entries, assignmentSubmissions, complaints, hostel-request
# tables, pendingFees, examCellData, library borrowing records, admin roster, etc.) - only
# genuinely public/reference data an anonymous visitor to the public site already sees: curriculum,
# timetable, published notices, the faculty/staff directory (already-public fields per the
# existing schema comment), open placement drives, the library catalog, and site content. Each
# field expression below is copied verbatim from BOOTSTRAP_SQL's own definition, not
# re-derived, to avoid the two drifting apart.
PUBLIC_BOOTSTRAP_SQL = r"""
WITH
catalog_rows AS (
  SELECT json_object_agg(barcode, json_build_object('title', title, 'author', author)) AS catalog
  FROM library_books
),
faculty_rows AS (
  SELECT full_name, department_code, email, profile_photo_url, designation,
    qualifications, google_scholar, apaar_id, vidwan_profile, phone, primary_subject, subject_code
  FROM faculty
  WHERE status = 'Active'
)
SELECT json_build_object(
  'facultyProfiles', COALESCE((SELECT json_agg(json_build_object(
    'name', full_name,
    'department', department_code,
    'email', email,
    'photoUrl', profile_photo_url,
    'designation', designation,
    'qualifications', qualifications,
    'googleScholar', google_scholar,
    'apaarId', apaar_id,
    'vidwanProfile', vidwan_profile,
    'phone', phone,
    'primarySubject', primary_subject,
    'subjectCode', subject_code
  ) ORDER BY full_name) FROM faculty_rows), '[]'::json),
  'nonTeachingStaff', COALESCE((SELECT json_agg(json_build_object(
    'name', full_name,
    'email', email,
    'designation', designation,
    'section', section,
    'photoUrl', profile_photo_url
  ) ORDER BY full_name) FROM non_teaching_staff WHERE status = 'Active'), '[]'::json),
  'curriculum', COALESCE((
    SELECT json_object_agg(department_code, subjects) FROM (
      SELECT department_code, json_agg(json_build_object(
        'code', subject_code, 'name', subject_name, 'semester', semester,
        'credits', credits, 'type', subject_type
      ) ORDER BY subject_code) AS subjects
      FROM curriculum GROUP BY department_code
    ) grouped_curriculum
  ), '{}'::json),
  'classTimetable', COALESCE((
    SELECT json_object_agg(department_code, slots) FROM (
      SELECT department_code, json_agg(json_build_object(
        'day', day_of_week, 'time', time_slot, 'code', subject_code,
        'subject', subject_name, 'facultyEmail', faculty_email, 'section', section
      ) ORDER BY day_of_week, time_slot) AS slots
      FROM class_timetable GROUP BY department_code
    ) grouped_timetable
  ), '{}'::json),
  'notices', COALESCE((SELECT json_agg(json_build_object(
    'id', id::text,
    'audience', audience,
    'title', title,
    'message', body,
    'department', department_code,
    'attachment', CASE WHEN attachment_url IS NOT NULL
      THEN json_build_object('name', attachment_name, 'dataUrl', attachment_url, 'mime', attachment_mime)
      ELSE NULL END,
    'createdAt', (extract(epoch FROM created_at) * 1000)::bigint
  ) ORDER BY created_at DESC) FROM notices WHERE status = 'Published'), '[]'::json),
  'placementDrives', COALESCE((SELECT json_agg(json_build_object(
    'id', id::text,
    'company', company,
    'role', role_title,
    'ctc', ctc,
    'date', drive_date::text,
    'minCgpa', min_cgpa,
    'maxBacklogs', max_backlogs,
    'branches', eligible_departments,
    'addedAt', extract(epoch from drive_date),
    'driveType', drive_type,
    'description', description,
    'sessionTime', session_time,
    'venue', venue,
    'mode', mode,
    'seatCap', seat_cap,
    'applyLink', apply_link,
    'registeredCount', (SELECT COUNT(*) FROM placement_applications pa WHERE pa.drive_id = placement_drives.id)
  ) ORDER BY drive_date) FROM placement_drives), '[]'::json),
  'libraryCatalog', COALESCE((SELECT catalog FROM catalog_rows), '{}'::json),
  'siteContent', COALESCE((SELECT json_object_agg(content_key, content_value) FROM site_content), '{}'::json)
);
"""


def quote(value):
    if value is None:
        return "NULL"
    return "'" + str(value).replace("'", "''") + "'"


def numeric_or_null(value):
    # Unlike quote()'s "or 0" fallback used elsewhere for amounts, marks need real NULL semantics -
    # an unentered mark and a mark of 0 are different states for a partially-filled roster.
    if value in (None, ""):
        return "NULL"
    try:
        return str(float(value))
    except (TypeError, ValueError):
        return "NULL"


# Generic notification feed - ANY feature, current or future, that needs to tell a user
# "something happened" should call one of these two instead of inventing its own mechanism.
# Surfaced in the existing bell icon dropdown (see renderNotificationList in script.js).
def create_notification(recipient_type, recipient_id, title, message, link=None, source_module=None):
    run_psql(f"""
        INSERT INTO notifications (recipient_type, recipient_id, title, message, link, source_module)
        VALUES ({quote(recipient_type)}, {quote(recipient_id)}, {quote(title)}, {quote(message)}, {quote(link)}, {quote(source_module)});
    """)


def create_notifications_bulk(recipient_type, recipient_ids, title, message, link=None, source_module=None):
    recipient_ids = [rid for rid in dict.fromkeys(recipient_ids or []) if rid]
    if not recipient_ids:
        return
    values = ",".join(
        f"({quote(recipient_type)}, {quote(rid)}, {quote(title)}, {quote(message)}, {quote(link)}, {quote(source_module)})"
        for rid in recipient_ids
    )
    run_psql(f"""
        INSERT INTO notifications (recipient_type, recipient_id, title, message, link, source_module)
        VALUES {values};
    """)


def get_my_notifications(recipient_type, recipient_id):
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', id::text, 'title', title, 'message', message, 'link', link,
            'sourceModule', source_module, 'isRead', is_read,
            'createdAt', to_char(created_at, 'DD Mon, HH12:MI AM')
        ) ORDER BY created_at DESC), '[]'::json)
        FROM (
          SELECT * FROM notifications
          WHERE recipient_type = {quote(recipient_type)} AND recipient_id = {quote(recipient_id)}
          ORDER BY created_at DESC LIMIT 30
        ) recent;
    """, [])


def mark_notification_read(notification_id, recipient_type, recipient_id):
    run_psql(f"""
        UPDATE notifications SET is_read = true
        WHERE id = {quote(notification_id)}::uuid AND recipient_type = {quote(recipient_type)} AND recipient_id = {quote(recipient_id)};
    """)


def clear_notification(notification_id, recipient_type, recipient_id):
    run_psql(f"""
        DELETE FROM notifications
        WHERE id = {quote(notification_id)}::uuid AND recipient_type = {quote(recipient_type)} AND recipient_id = {quote(recipient_id)};
    """)


def clear_all_notifications(recipient_type, recipient_id):
    run_psql(f"""
        DELETE FROM notifications
        WHERE recipient_type = {quote(recipient_type)} AND recipient_id = {quote(recipient_id)};
    """)


# Bus/Vehicle pass validity on approval: students run through the end of the current academic
# year (matches the "2025-26" academic-year convention used for Internal Marks - the year starts
# in June, so it ends May 31 of the following calendar year); faculty (and non-student requesters)
# get a plain rolling 1 year from whenever they were approved, since they have no academic-year
# cycle to align to. Referenced inline in the same UPDATE as the status change, keyed off the
# row's own requester_type column, so it's one round trip rather than a separate lookup.
PASS_VALID_UNTIL_SQL = """
    CASE WHEN requester_type = 'student' THEN (
      CASE WHEN EXTRACT(MONTH FROM now()) >= 6 THEN make_date((EXTRACT(YEAR FROM now()) + 1)::int, 5, 31)
           ELSE make_date(EXTRACT(YEAR FROM now())::int, 5, 31) END
    ) ELSE (now() + INTERVAL '1 year')::date END
"""


PASSWORD_MAX_AGE_SECONDS = 90 * 24 * 60 * 60
PBKDF2_ITERATIONS = 200_000


def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, hash_hex):
    _, computed = hash_password(password, salt_hex)
    return hmac.compare_digest(computed, hash_hex)


def verify_recaptcha(token):
    # If no secret key is configured yet (RECAPTCHA_SECRET_KEY unset), fail open rather than
    # locking out every public registration/login - matches this app's existing "degrade gracefully
    # when an integration isn't configured" convention (e.g. resolvePayuPaymentLink's "gateway is
    # not linked yet" message) rather than a hard 500.
    if not RECAPTCHA_SECRET_KEY:
        return True
    if not token:
        return False
    try:
        request = Request(
            "https://www.google.com/recaptcha/api/siteverify",
            data=f"secret={RECAPTCHA_SECRET_KEY}&response={token}".encode("utf-8"),
            method="POST",
        )
        with urlopen(request, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))
        return bool(result.get("success"))
    except (URLError, HTTPError, TimeoutError, ValueError):
        return False


# Simple self-hosted CAPTCHA (a math question) used instead of reCAPTCHA on the public event
# forms - no external site key/account needed, works immediately. The question is generated
# server-side and the answer never sent to the client in the clear: the token is an HMAC of the
# answer plus an issue time, so verify_math_captcha can check a submitted answer is correct
# without the token itself revealing it, and expires after 10 minutes so a token can't be reused
# indefinitely against a stale question.
CAPTCHA_SECRET = secrets.token_hex(32)


def generate_math_captcha():
    a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
    answer = str(a + b)
    signature = hmac.new(CAPTCHA_SECRET.encode(), answer.encode(), hashlib.sha256).hexdigest()
    token = f"{signature}:{int(time.time())}"
    return f"What is {a} + {b}?", token


def verify_math_captcha(token, answer):
    if not token or answer is None:
        return False
    try:
        signature, issued_at = token.rsplit(":", 1)
    except ValueError:
        return False
    if time.time() - int(issued_at) > 600:
        return False
    expected = hmac.new(CAPTCHA_SECRET.encode(), str(answer).strip().encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def generate_password():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(10))


def normalize_mobile(value):
    return "".join((value or "").split())


def get_bank_details(key):
    # Deliberately not part of BOOTSTRAP_SQL (like user_credentials) - bank account numbers/IFSC
    # are financial PII and must never be handed out in the one big public bootstrap response.
    # Only reachable by whoever already knows the exact role-prefixed key (e.g.
    # "student-20X51A0501") for the single record they're asking about. The column itself also
    # stores Fernet-encrypted ciphertext, not plaintext JSON - decrypted only here, on the way out.
    encrypted = run_psql(f"SELECT details FROM bank_details WHERE detail_key = {quote(key)};")
    if not encrypted:
        return None
    return json.loads(decrypt_text(encrypted))


def get_payment_history(student_roll_no):
    # Same reasoning as get_bank_details - payment amounts/transaction refs are financial data,
    # scoped to one student's roll number instead of riding along in the public bootstrap.
    sql = f"""
        SELECT COALESCE((
            SELECT json_agg(COALESCE(details, '{{}}'::jsonb) || jsonb_build_object(
                'id', id::text, 'transactionRef', transaction_ref, 'paidOn', paid_on::text
            ) ORDER BY paid_on DESC)
            FROM payments WHERE student_roll_no = {quote(student_roll_no)}
        ), '[]'::json);
    """
    return run_json(sql, [])


ADMIN_CONFIG_PATH = ROOT / "admin-config.json"

# Plagiarism check only reads PDF/Word content - no OCR/image support in this environment.
PLAGIARISM_EXTRACTABLE_MIMES = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
}
PLAGIARISM_TEXT_CHAR_LIMIT = 12_000


def extract_text_from_upload(file_url, file_mime):
    # file_url is the same "/uploads/..." relative path the /upload endpoint (admin_config_server.py)
    # returns and this app stores as-is - resolve it back to a real path under ROOT (both servers
    # share the same repo root). Never raises - callers treat a None return as "not extractable".
    kind = PLAGIARISM_EXTRACTABLE_MIMES.get((file_mime or "").lower())
    if not kind:
        ext = Path(file_url or "").suffix.lower()
        kind = {".pdf": "pdf", ".docx": "docx"}.get(ext)
    if not kind:
        return None
    path = (ROOT / str(file_url or "").lstrip("/")).resolve()
    if ROOT.resolve() not in path.parents or not path.is_file():
        return None
    try:
        if kind == "pdf":
            reader = PdfReader(str(path))
            return "\n".join(page.extract_text() or "" for page in reader.pages).strip() or None
        if kind == "docx":
            document = DocxDocument(str(path))
            return "\n".join(paragraph.text for paragraph in document.paragraphs).strip() or None
    except Exception:
        return None
    return None


def read_admin_config():
    try:
        return json.loads(ADMIN_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


# --- GPRECian Bot knowledge base: real (embedding-based) semantic search -----------------------
# Uses a local Ollama embedding model (nomic-embed-text, 768 dims) rather than an external API -
# no extra API key/cost, and this app already runs everything else locally. Reads the Ollama base
# URL from the same aiSettings the chat model itself uses (falls back to the default local port if
# aiSettings isn't configured for ollama specifically - embeddings and chat can use different
# providers/hosts without any issue since this call is independent of fetchAiReply's provider).
EMBEDDING_MODEL = "nomic-embed-text"
EMBEDDING_DIMENSIONS = 768


def ollama_base_url():
    ai_settings = read_admin_config().get("aiSettings") or {}
    base_url = ai_settings.get("baseUrl") if ai_settings.get("provider") == "ollama" else None
    return (base_url or "http://localhost:11434").rstrip("/")


def get_embedding(text):
    body = json.dumps({"model": EMBEDDING_MODEL, "input": text[:4000]}).encode("utf-8")
    request = Request(f"{ollama_base_url()}/api/embed", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=20) as response:
        result = json.loads(response.read())
    embedding = (result.get("embeddings") or [None])[0]
    if not embedding or len(embedding) != EMBEDDING_DIMENSIONS:
        raise ValueError("Embedding model returned an unexpected shape - is nomic-embed-text pulled in Ollama?")
    return embedding


def vector_literal(embedding):
    return "[" + ",".join(repr(float(v)) for v in embedding) + "]"


def refresh_knowledge_base(chunks):
    # Upserts every chunk in this batch (re-embedding all of them - simplest correct approach for
    # a knowledge base of this size, no incremental diffing), then deletes any row whose id wasn't
    # in the batch, so content that was renamed/removed on the site doesn't linger as a stale,
    # unreachable chunk that could still surface in search results.
    kept_ids = []
    for chunk in chunks:
        chunk_id = str(chunk.get("id") or "").strip()
        text = str(chunk.get("text") or "").strip()
        if not chunk_id or not text:
            continue
        link = chunk.get("link") or {}
        embedding = get_embedding(text)
        run_psql(f"""
            INSERT INTO knowledge_base_chunks (id, chunk_text, link_url, link_label, link_download, embedding, updated_at)
            VALUES (
                {quote(chunk_id)}, {quote(text)}, {quote(link.get("url"))}, {quote(link.get("label"))},
                {"true" if link.get("download") else "false"}, {quote(vector_literal(embedding))}::vector, now()
            )
            ON CONFLICT (id) DO UPDATE SET
                chunk_text = EXCLUDED.chunk_text, link_url = EXCLUDED.link_url, link_label = EXCLUDED.link_label,
                link_download = EXCLUDED.link_download, embedding = EXCLUDED.embedding, updated_at = now();
        """)
        kept_ids.append(chunk_id)
    if kept_ids:
        kept_list = ",".join(quote(cid) for cid in kept_ids)
        run_psql(f"DELETE FROM knowledge_base_chunks WHERE id NOT IN ({kept_list});")
    else:
        run_psql("DELETE FROM knowledge_base_chunks;")
    return len(kept_ids)


def search_knowledge_base(question, top_n=4):
    embedding = get_embedding(question)
    vec = quote(vector_literal(embedding)) + "::vector"
    rows = run_json(f"""
        SELECT COALESCE(json_agg(row), '[]'::json) FROM (
          SELECT id, chunk_text AS text, link_url, link_label, link_download,
                 1 - (embedding <=> {vec}) AS score
          FROM knowledge_base_chunks
          ORDER BY embedding <=> {vec}
          LIMIT {int(top_n)}
        ) row;
    """, [])
    return rows


# --- GPRECian Bot feedback loop - the actual "learning" mechanism -------------------------------
# Nothing here retrains the LLM itself; this is a human-in-the-loop correction pipeline: a visitor
# flags a bad answer, an admin reviews it and writes the right one, and approving it embeds that
# correction into knowledge_base_chunks (the same table/pipeline as an ordinary refresh) so the
# same or a similarly-worded question is answered correctly next time via normal semantic search.
def submit_bot_feedback(question, bot_answer, reporter_type, reporter_id):
    run_psql(f"""
        INSERT INTO bot_feedback (question, bot_answer, reporter_type, reporter_id)
        VALUES ({quote(question)}, {quote(bot_answer)}, {quote(reporter_type)}, {quote(reporter_id)});
    """)


def list_bot_feedback(status=None):
    where = f"WHERE status = {quote(status)}" if status else ""
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', id::text, 'question', question, 'botAnswer', bot_answer, 'status', status,
            'correction', correction, 'reporterType', reporter_type,
            'createdAt', to_char(created_at, 'DD Mon, HH12:MI AM')
        ) ORDER BY created_at DESC), '[]'::json)
        FROM bot_feedback {where};
    """, [])


def resolve_bot_feedback(feedback_id, correction):
    correction = correction.strip()
    if not correction:
        return False
    run_psql(f"""
        UPDATE bot_feedback SET status = 'Approved', correction = {quote(correction)}, reviewed_at = now()
        WHERE id = {quote(feedback_id)}::uuid;
    """)
    embedding = get_embedding(correction)
    run_psql(f"""
        INSERT INTO knowledge_base_chunks (id, chunk_text, embedding, updated_at)
        VALUES ({quote(f"feedback-{feedback_id}")}, {quote(correction)}, {quote(vector_literal(embedding))}::vector, now())
        ON CONFLICT (id) DO UPDATE SET chunk_text = EXCLUDED.chunk_text, embedding = EXCLUDED.embedding, updated_at = now();
    """)
    return True


def dismiss_bot_feedback(feedback_id):
    run_psql(f"UPDATE bot_feedback SET status = 'Dismissed', reviewed_at = now() WHERE id = {quote(feedback_id)}::uuid;")


# --- Digital exam-cell application forms --------------------------------------------------------
EXAM_CELL_APPLICATION_TYPES = {"condonation", "certificate_request", "duplicate_certificate"}


def submit_exam_cell_application(application_type, student_roll_no, form_data):
    if application_type not in EXAM_CELL_APPLICATION_TYPES:
        return False
    run_psql(f"""
        INSERT INTO exam_cell_applications (application_type, student_roll_no, form_data)
        VALUES ({quote(application_type)}, {quote(student_roll_no)}, {quote(json.dumps(form_data))}::jsonb);
    """)
    return True


def get_my_exam_cell_applications(student_roll_no):
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', id::text, 'applicationType', application_type, 'formData', form_data,
            'status', status, 'adminNote', admin_note,
            'createdAt', to_char(created_at, 'DD Mon, HH12:MI AM')
        ) ORDER BY created_at DESC), '[]'::json)
        FROM exam_cell_applications WHERE student_roll_no = {quote(student_roll_no)};
    """, [])


def get_all_exam_cell_applications(status=None):
    where = f"WHERE a.status = {quote(status)}" if status else ""
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', id::text, 'applicationType', application_type, 'studentRollNo', student_roll_no,
            'studentName', s.full_name, 'formData', a.form_data, 'status', a.status,
            'adminNote', a.admin_note, 'createdAt', to_char(a.created_at, 'DD Mon, HH12:MI AM')
        ) ORDER BY a.created_at DESC), '[]'::json)
        FROM exam_cell_applications a
        JOIN students s ON s.roll_no = a.student_roll_no
        {where};
    """, [])


def update_exam_cell_application_status(application_id, status, admin_note):
    run_psql(f"""
        UPDATE exam_cell_applications
        SET status = {quote(status)}, admin_note = {quote(admin_note)}, reviewed_at = now()
        WHERE id = {quote(application_id)}::uuid;
    """)


def verify_google_id_token(id_token):
    # The alumni Google sign-in JWT was previously only ever decoded client-side (no signature
    # check) - anyone could POST a forged JWT-shaped payload and claim any alumni email. Google's
    # tokeninfo endpoint does full verification (signature, expiry, audience) for us, so no JWT
    # library / public-key rotation handling is needed here - one HTTPS GET, stdlib only.
    expected_client_id = (read_admin_config().get("googleClientId") or "").strip()
    if not expected_client_id or expected_client_id == "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com":
        return None
    try:
        with urlopen(f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}", timeout=6) as response:
            claims = json.loads(response.read().decode("utf-8"))
    except (URLError, HTTPError, TimeoutError, ValueError):
        return None
    if claims.get("aud") != expected_client_id:
        return None
    if claims.get("email_verified") not in ("true", True):
        return None
    email = (claims.get("email") or "").strip().lower()
    if not email:
        return None
    return {"email": email, "name": claims.get("name") or ""}


def send_msg91_sms(auth_key, template_id, template_variable, mobile, value):
    # MSG91's Flow API (transactional SMS via a DLT-approved template) - built to their commonly
    # documented v5 contract; verify against the current MSG91 dashboard/docs once real
    # credentials are in place, since third-party API surfaces can change. Returns
    # (sent: bool, error: str | None) - never raises, so a misconfigured/unreachable gateway falls
    # back to the caller's own fallback behavior instead of breaking the calling flow entirely.
    # Generic across use cases (OTP, grades/attendance notifications, ...) - the caller decides
    # which template and single variable value get sent.
    if not auth_key or not template_id:
        return False, "not-configured"

    digits = re.sub(r"\D", "", mobile)
    # MSG91 expects the number with country code, no leading zeros/plus - Indian mobiles are
    # stored as 10 digits in this app, so prefix 91 unless it's already there.
    msisdn = digits if len(digits) > 10 else f"91{digits}"

    body = json.dumps({
        "template_id": template_id,
        "short_url": "0",
        "realTimeResponse": "1",
        "recipients": [{"mobiles": msisdn, template_variable: value}]
    }).encode("utf-8")
    request = Request(
        "https://control.msg91.com/api/v5/flow/",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", "authkey": auth_key}
    )
    try:
        with urlopen(request, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (URLError, HTTPError, TimeoutError, ValueError) as exc:
        # Deliberately never includes the value itself (e.g. an OTP) in anything logged here.
        return False, f"gateway-error: {type(exc).__name__}"
    if str(result.get("type", "")).lower() == "error":
        return False, str(result.get("message") or "gateway-rejected")
    return True, None


def send_msg91_whatsapp(auth_key, integrated_number, template_name, body_variable, mobile, value):
    # Fallback channel when SMS isn't configured or the SMS send fails - MSG91's WhatsApp Business
    # API (same auth key, a separate DLT-exempt WhatsApp template on their dashboard). Built to
    # their commonly documented v5 contract; verify against the current MSG91 dashboard/docs once
    # real credentials are in place. Returns (sent: bool, error: str | None), never raises. Generic
    # across use cases, same as send_msg91_sms above.
    if not auth_key or not integrated_number or not template_name:
        return False, "not-configured"

    digits = re.sub(r"\D", "", mobile)
    msisdn = digits if len(digits) > 10 else f"91{digits}"

    body = json.dumps({
        "integrated_number": integrated_number,
        "content_type": "template",
        "payload": {
            "messaging_product": "whatsapp",
            "type": "template",
            "template": {
                "name": template_name,
                "language": {"code": "en", "policy": "deterministic"},
                "to_and_components": [{
                    "to": [msisdn],
                    "components": {body_variable: {"type": "text", "value": value}}
                }]
            }
        }
    }).encode("utf-8")
    request = Request(
        "https://control.msg91.com/api/v5/whatsapp/whatsapp-outbound-message/bulk/",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", "authkey": auth_key}
    )
    try:
        with urlopen(request, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (URLError, HTTPError, TimeoutError, ValueError) as exc:
        return False, f"gateway-error: {type(exc).__name__}"
    if str(result.get("status", "")).lower() == "error":
        return False, str(result.get("message") or "gateway-rejected")
    return True, None


def send_msg91_otp_sms(mobile, otp):
    settings = read_admin_config().get("smsSettings") or {}
    auth_key = (settings.get("authKey") or "").strip()
    template_id = (settings.get("templateId") or "").strip()
    template_variable = (settings.get("templateVariable") or "OTP").strip() or "OTP"
    return send_msg91_sms(auth_key, template_id, template_variable, mobile, otp)


def send_msg91_whatsapp_otp(mobile, otp):
    settings = read_admin_config().get("smsSettings") or {}
    auth_key = (settings.get("authKey") or "").strip()
    integrated_number = (settings.get("whatsappIntegratedNumber") or "").strip()
    template_name = (settings.get("whatsappTemplateName") or "").strip()
    body_variable = (settings.get("whatsappBodyVariable") or "body_1").strip() or "body_1"
    return send_msg91_whatsapp(auth_key, integrated_number, template_name, body_variable, mobile, otp)


def deliver_parent_otp(mobile, otp):
    # SMS first, WhatsApp as fallback if SMS isn't configured or fails - falls back further to
    # on-screen display (handled by the caller) if neither gateway is configured/reachable.
    sent, error = send_msg91_otp_sms(mobile, otp)
    if sent:
        return True, "sms", None
    sent, wa_error = send_msg91_whatsapp_otp(mobile, otp)
    if sent:
        return True, "whatsapp", None
    return False, None, wa_error or error


# kind is "grades" or "attendance" - each has its own DLT-approved SMS template and WhatsApp
# template (different wording/use-case than the OTP templates above), configured separately in
# the admin panel, but reuse the same MSG91 account (authKey/whatsappIntegratedNumber).
def deliver_parent_notification(mobile, kind, message):
    settings = read_admin_config().get("smsSettings") or {}
    auth_key = (settings.get("authKey") or "").strip()
    notif = settings.get("notifications") or {}
    template_id = (notif.get(f"{kind}TemplateId") or "").strip()
    template_variable = (notif.get(f"{kind}TemplateVariable") or "MESSAGE").strip() or "MESSAGE"
    sent, error = send_msg91_sms(auth_key, template_id, template_variable, mobile, message)
    if sent:
        return True, "sms", None

    integrated_number = (settings.get("whatsappIntegratedNumber") or "").strip()
    whatsapp_template_name = (notif.get(f"whatsapp{kind.capitalize()}TemplateName") or "").strip()
    body_variable = (settings.get("whatsappBodyVariable") or "body_1").strip() or "body_1"
    sent, wa_error = send_msg91_whatsapp(auth_key, integrated_number, whatsapp_template_name, body_variable, mobile, message)
    if sent:
        return True, "whatsapp", None
    return False, None, wa_error or error


def verify_vehicle_documents(license_number, vehicle_number):
    # Real government DL/RC lookups (India's Sarathi/VAHAN systems) have no public API for a
    # college app to call directly - this is a generic REST contract built for API Setu
    # (apisetu.gov.in), the Government of India's own API gateway, which exposes official DL/RC
    # verification from the Ministry of Road Transport at no per-call cost once GPREC is
    # registered as a consumer organization there. Admin fills in the base URL/paths/key API Setu
    # issues after that approval; verify the exact request/response shape against API Setu's docs
    # for the specific DL/RC verification API, since this was built to a generic best-guess
    # contract without real credentials to test against. Returns
    # (result: 'verified'|'failed'|'not-configured'|'error', notes: str | None) - never raises, and
    # the result is only ever a decision AID for the admin, never an auto-approval - the admin
    # always makes the final call. Never logs the license/vehicle numbers themselves.
    settings = read_admin_config().get("kycSettings") or {}
    auth_key = (settings.get("authKey") or "").strip()
    base_url = (settings.get("baseUrl") or "").strip().rstrip("/")
    if not auth_key or not base_url:
        return "not-configured", None

    def call(path, payload_key, value):
        if not path:
            return None, "no-path-configured"
        body = json.dumps({payload_key: value}).encode("utf-8")
        request = Request(
            f"{base_url}{path}",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {auth_key}"}
        )
        try:
            with urlopen(request, timeout=8) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (URLError, HTTPError, TimeoutError, ValueError) as exc:
            return None, f"gateway-error: {type(exc).__name__}"
        verified = bool(result.get("verified") or result.get("valid") or str(result.get("status", "")).lower() == "success")
        return verified, None if verified else (result.get("message") or "not-verified")

    dl_verified, dl_note = call((settings.get("dlVerifyPath") or "").strip(), "license_number", license_number)
    rc_verified, rc_note = call((settings.get("rcVerifyPath") or "").strip(), "vehicle_number", vehicle_number)

    if dl_verified is None or rc_verified is None:
        return "error", dl_note or rc_note
    if dl_verified and rc_verified:
        return "verified", "License and vehicle registration both verified"
    notes = "; ".join(filter(None, [
        None if dl_verified else f"License: {dl_note or 'not verified'}",
        None if rc_verified else f"RC: {rc_note or 'not verified'}"
    ]))
    return "failed", notes


def create_alumni_account(email, password, name, batch_year):
    salt_hex, hash_hex = hash_password(password)
    data = json.dumps({"name": name, "batchYear": batch_year, "viaGoogle": False})
    result = run_psql(f"""
        INSERT INTO alumni_accounts (email, password_hash, password_salt, data)
        VALUES ({quote(email)}, {quote(hash_hex)}, {quote(salt_hex)}, {quote(data)}::jsonb)
        ON CONFLICT (email) DO NOTHING
        RETURNING email;
    """)
    return bool(result.strip())


def verify_alumni_login(email, password):
    row = run_json(f"""
        SELECT COALESCE((SELECT json_build_object(
            'passwordHash', password_hash, 'passwordSalt', password_salt, 'data', data
        ) FROM alumni_accounts WHERE email = {quote(email)}), 'null'::json);
    """, None)
    if not row or not row.get("passwordHash") or not row.get("passwordSalt"):
        return None
    if not verify_password(password, row["passwordSalt"], row["passwordHash"]):
        return None
    return {"email": email, **(row.get("data") or {})}


def alumni_account_exists(email):
    return bool(run_psql(f"SELECT 1 FROM alumni_accounts WHERE email = {quote(email)};").strip())


def alumni_identity_matches(email, batch_year):
    # Previously alumni/reset-password only checked the account existed - anyone who knew an
    # alumnus's email could take over their account with no verification at all. batchYear isn't
    # a strong secret, but it's real data already on file from signup (not something newly
    # collected here) and is a meaningful bar over "just an email", consistent in spirit with the
    # recovery-mobile check admin/faculty/non-teaching password reset already uses.
    sql = (
        "SELECT COALESCE((SELECT true FROM alumni_accounts "
        f"WHERE email = {quote(email)} AND data->>'batchYear' = {quote(str(batch_year))}), false);"
    )
    return run_psql(sql).strip().lower() == "t"


def reset_alumni_password(email, new_password):
    salt_hex, hash_hex = hash_password(new_password)
    run_psql(f"""
        UPDATE alumni_accounts SET password_hash = {quote(hash_hex)}, password_salt = {quote(salt_hex)}, updated_at = now()
        WHERE email = {quote(email)};
    """)


def upsert_alumni_google_profile(email, name, batch_year):
    # Merges into existing `data` (rather than overwriting it) so a repeat Google sign-in doesn't
    # clobber profile fields (bio, posts, memories, etc.) set since the account was created.
    # password_hash/salt stay NULL until/unless this alumnus also sets a real password - a
    # Google-only account simply can't use the email+password sign-in form.
    data = json.dumps({"name": name, "batchYear": batch_year, "viaGoogle": True})
    run_psql(f"""
        INSERT INTO alumni_accounts (email, data) VALUES ({quote(email)}, {quote(data)}::jsonb)
        ON CONFLICT (email) DO UPDATE SET data = alumni_accounts.data || EXCLUDED.data, updated_at = now();
    """)
    row = run_json(f"SELECT COALESCE((SELECT data FROM alumni_accounts WHERE email = {quote(email)}), '{{}}'::jsonb);", {})
    return {"email": email, **(row or {})}


def save_alumni_profiles(accounts):
    # Every profile-edit call site reads the full alumni directory, mutates or appends one
    # account's non-secret fields, and saves the full array back - this treats each entry as an
    # update to that email's `data` column only. Never touches password_hash/salt, and never
    # inserts a brand-new row (account creation only happens through create_alumni_account /
    # upsert_alumni_google_profile, which are the only paths allowed to set a password).
    statements = []
    for account in accounts:
        email = (account.get("email") or "").strip().lower()
        if not email:
            continue
        data = {k: v for k, v in account.items() if k not in ("email", "password")}
        statements.append(
            f"UPDATE alumni_accounts SET data = {quote(json.dumps(data))}::jsonb, updated_at = now() WHERE email = {quote(email)};"
        )
    if statements:
        run_psql("\n".join(statements))


def get_credential_row(email, role_type=None):
    role_clause = f" AND role_type = {quote(role_type)}" if role_type else ""
    sql = (
        "SELECT COALESCE((SELECT json_build_object("
        "'roleType', role_type, 'fullName', full_name, 'passwordHash', password_hash, "
        "'passwordSalt', password_salt, 'mustChangePassword', must_change_password, "
        "'passwordSetAt', extract(epoch from password_set_at)) "
        f"FROM user_credentials WHERE email = {quote(email)}{role_clause}), 'null'::json);"
    )
    return run_json(sql, None)


def set_credential_row(email, role_type, full_name, recovery_mobile, password):
    salt_hex, hash_hex = hash_password(password)
    sql = f"""
    INSERT INTO user_credentials (email, role_type, full_name, recovery_mobile, password_hash, password_salt, must_change_password, password_set_at, failed_attempts, updated_at)
    VALUES ({quote(email)}, {quote(role_type)}, {quote(full_name)}, {quote(normalize_mobile(recovery_mobile))}, {quote(hash_hex)}, {quote(salt_hex)}, true, now(), 0, now())
    ON CONFLICT (email) DO UPDATE SET
      role_type = EXCLUDED.role_type,
      full_name = EXCLUDED.full_name,
      recovery_mobile = EXCLUDED.recovery_mobile,
      password_hash = EXCLUDED.password_hash,
      password_salt = EXCLUDED.password_salt,
      must_change_password = true,
      password_set_at = now(),
      failed_attempts = 0,
      updated_at = now();
    """
    run_psql(sql)


def update_password(email, new_password, role_type=None):
    salt_hex, hash_hex = hash_password(new_password)
    role_clause = f" AND role_type = {quote(role_type)}" if role_type else ""
    sql = (
        f"UPDATE user_credentials SET password_hash = {quote(hash_hex)}, password_salt = {quote(salt_hex)}, "
        "must_change_password = false, password_set_at = now(), failed_attempts = 0, updated_at = now() "
        f"WHERE email = {quote(email)}{role_clause};"
    )
    run_psql(sql)


def record_failed_attempt(email):
    run_psql(f"UPDATE user_credentials SET failed_attempts = failed_attempts + 1, updated_at = now() WHERE email = {quote(email)};")


def reset_failed_attempts(email):
    run_psql(f"UPDATE user_credentials SET failed_attempts = 0, updated_at = now() WHERE email = {quote(email)};")


def identity_matches(email, recovery_mobile):
    sql = (
        "SELECT COALESCE((SELECT true FROM user_credentials "
        f"WHERE email = {quote(email)} AND recovery_mobile = {quote(normalize_mobile(recovery_mobile))}), false);"
    )
    return run_psql(sql).strip().lower() == "t"


CREDENTIALS_LIST_SQL = """
SELECT COALESCE((SELECT json_agg(json_build_object(
  'email', email,
  'roleType', role_type,
  'fullName', full_name,
  'mustChangePassword', must_change_password,
  'passwordSetAt', password_set_at::text
) ORDER BY full_name) FROM user_credentials), '[]'::json);
"""


def any_admin_credentials_exist():
    return bool(run_psql("SELECT 1 FROM user_credentials WHERE role_type = 'admin' LIMIT 1;").strip())


# --- Session tokens (all six login roles) ---------------------------------------------------
# Sliding-expiry - idle timeout resets on every authenticated request (see authenticate()), so
# anyone who opens the app at least once within the idle window stays logged in indefinitely in
# practice ("always logged in"). The absolute cap is the one thing that never extends no matter
# how active the session is - a stolen/leaked token, or a browser left open on a shared device and
# forgotten about, still eventually stops working on its own rather than staying valid forever.
SESSION_TIERS = {
    "admin": ("60 days", "365 days"),
    "faculty": ("60 days", "365 days"),
    "non_teaching": ("60 days", "365 days"),
    "student": ("60 days", "365 days"),
    "parent": ("60 days", "365 days"),
    "alumni": ("60 days", "365 days"),
    # Shorter-lived than every real GPREC identity above - these accounts only exist for the
    # duration of a public event registration and get deleted once that event ends (see
    # cleanup_completed_public_events), so there's no reason for the session itself to outlive that.
    "event_visitor": ("14 days", "30 days"),
}


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(identity_type, identity_id, role_label=None):
    idle, cap = SESSION_TIERS[identity_type]
    token = secrets.token_urlsafe(32)
    run_psql(f"""
        INSERT INTO sessions (token_hash, identity_type, identity_id, role_label, expires_at)
        VALUES ({quote(hash_token(token))}, {quote(identity_type)}, {quote(identity_id)}, {quote(role_label)},
                now() + INTERVAL '{idle}');
    """)
    return token


def authenticate(handler):
    # Validates the Authorization: Bearer <token> header (if present) against the sessions table,
    # refreshing the sliding idle timeout as a side effect of the same query - one psql round trip,
    # not two. Returns the identity dict on success, None on missing/invalid/expired/revoked token.
    auth_header = handler.headers.get("Authorization") or ""
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):].strip()
    if not token:
        return None
    token_hash = hash_token(token)
    case_parts = []
    for identity_type, (idle, cap) in SESSION_TIERS.items():
        case_parts.append(
            f"WHEN identity_type = {quote(identity_type)} THEN "
            f"CASE WHEN now() > issued_at + INTERVAL '{cap}' THEN expires_at "
            f"WHEN now() > expires_at - INTERVAL '30 minutes' THEN now() + INTERVAL '{idle}' "
            "ELSE expires_at END"
        )
    case_sql = "CASE " + " ".join(case_parts) + " END"
    sql = f"""
        UPDATE sessions SET last_seen_at = now(), expires_at = {case_sql}
        WHERE token_hash = {quote(token_hash)} AND revoked_at IS NULL AND expires_at > now()
        RETURNING json_build_object('identityType', identity_type, 'identityId', identity_id, 'roleLabel', role_label);
    """
    return run_json(sql, None)


def revoke_session(token):
    run_psql(f"UPDATE sessions SET revoked_at = now() WHERE token_hash = {quote(hash_token(token))};")


def revoke_all_sessions(identity_type, identity_id):
    run_psql(
        f"UPDATE sessions SET revoked_at = now() WHERE identity_type = {quote(identity_type)} "
        f"AND identity_id = {quote(identity_id)} AND revoked_at IS NULL;"
    )


def get_admin_row(email):
    return run_json(
        "SELECT COALESCE((SELECT json_build_object("
        "'role', role, 'departmentCode', department_code, 'canManageAdmins', can_manage_admins, 'status', status"
        f") FROM admins WHERE email = {quote(email)}), 'null'::json);",
        None,
    )


# --- Login-attempt throttling (shared by every login/recovery flow) -------------------------
LOCKOUT_THRESHOLD = 8
LOCKOUT_WINDOW = "20 minutes"


def check_throttle(throttle_key):
    row = run_json(
        f"SELECT COALESCE((SELECT json_build_object('lockedUntil', locked_until, 'isLocked', locked_until > now()) "
        f"FROM login_throttle WHERE throttle_key = {quote(throttle_key)}), 'null'::json);",
        None,
    )
    return bool(row and row.get("isLocked"))


def record_throttle_failure(throttle_key):
    run_psql(f"""
        INSERT INTO login_throttle (throttle_key, failed_attempts, updated_at)
        VALUES ({quote(throttle_key)}, 1, now())
        ON CONFLICT (throttle_key) DO UPDATE SET
          failed_attempts = login_throttle.failed_attempts + 1,
          locked_until = CASE WHEN login_throttle.failed_attempts + 1 >= {LOCKOUT_THRESHOLD}
                               THEN now() + INTERVAL '{LOCKOUT_WINDOW}' ELSE login_throttle.locked_until END,
          updated_at = now();
    """)


def clear_throttle(throttle_key):
    run_psql(f"DELETE FROM login_throttle WHERE throttle_key = {quote(throttle_key)};")


def require_auth(handler, allowed_types=None):
    identity = authenticate(handler)
    if not identity or (allowed_types and identity["identityType"] not in allowed_types):
        handler.send_json(401, {"ok": False, "error": "unauthorized"})
        return None
    return identity


# Bank-detail keys are prefixed per role (see bankKey/scholarshipBankKey in script.js) but
# non_teaching's prefix uses a hyphen ("non-teaching-<email>") while the identity_type value uses
# an underscore - this maps between the two rather than changing either existing convention.
IDENTITY_TYPE_TO_KEY_PREFIX = {
    "student": "student",
    "faculty": "faculty",
    "non_teaching": "non-teaching",
}


def owns_key(identity, key):
    prefix = IDENTITY_TYPE_TO_KEY_PREFIX.get(identity["identityType"])
    return bool(prefix) and key == f"{prefix}-{identity['identityId']}"


def replace_complaints(records):
    values = []
    for item in records:
        values.append(
            "("
            + ", ".join(
                [
                    quote(item.get("studentId")),
                    quote(item.get("category") or "General"),
                    quote(item.get("subject") or "Request"),
                    quote(item.get("description") or ""),
                    quote(item.get("status") or "Pending"),
                ]
            )
            + ")"
        )
    sql = "BEGIN; TRUNCATE complaints RESTART IDENTITY;"
    if values:
        sql += """
        INSERT INTO complaints (student_roll_no, category, subject, description, status)
        VALUES """ + ",".join(values) + ";"
    sql += " COMMIT;"
    run_psql(sql)


# Placement/Internship/Mock Interview/Aptitude Test/Job Recommendation all share this one table
# (drive_type discriminator - see the field-reuse comment on the placement_drives CREATE TABLE in
# schema.sql). create/remove are targeted single-row operations, not a full-array replace - the
# previous replace_placement_drives() did "TRUNCATE placement_drives ... CASCADE" on every single
# add/remove, which silently wiped ALL placement_applications (and would now also wipe
# interview_schedules) every time, since TRUNCATE CASCADE empties the whole child table regardless
# of which row changed. This matches the notices/assignments create+remove-by-id idiom instead.
DRIVE_TYPES_WITH_ELIGIBILITY = ("Placement", "Internship")


def create_placement_drive(payload):
    drive_type = payload.get("driveType") or "Placement"
    if drive_type in DRIVE_TYPES_WITH_ELIGIBILITY:
        min_cgpa = float(payload.get("minCgpa") or 0)
        max_backlogs = int(payload.get("maxBacklogs") or 0)
        branches = payload.get("branches") or []
    else:
        # Mock Interview/Aptitude Test/Job Recommendation are open to everyone - force "no
        # restriction" sentinels server-side rather than trusting whatever the client sent for
        # these fields (min_cgpa/max_backlogs/eligible_departments stay NOT NULL in the schema).
        min_cgpa = 0
        max_backlogs = 99
        branches = []
    array_value = "ARRAY[" + ",".join(quote(branch) for branch in branches) + "]::text[]"
    seat_cap = payload.get("seatCap")
    seat_cap_sql = str(int(seat_cap)) if seat_cap not in (None, "") else "NULL"
    run_psql(f"""
        INSERT INTO placement_drives (
            company, role_title, ctc, drive_date, min_cgpa, max_backlogs, eligible_departments,
            drive_type, description, session_time, venue, mode, seat_cap, apply_link
        ) VALUES (
            {quote(payload.get("company"))}, {quote(payload.get("role"))}, {quote(payload.get("ctc"))},
            {quote(payload.get("date"))}, {min_cgpa}, {max_backlogs}, {array_value},
            {quote(drive_type)}, {quote(payload.get("description") or "")}, {quote(payload.get("sessionTime"))},
            {quote(payload.get("venue"))}, {quote(payload.get("mode"))}, {seat_cap_sql},
            {quote(payload.get("applyLink"))}
        );
    """)


def remove_placement_drive(drive_id):
    run_psql(f"DELETE FROM placement_drives WHERE id = {quote(drive_id)}::uuid;")


def replace_exam_schedules(payload):
    values = []
    for department, rows in (payload or {}).items():
        for item in rows:
            values.append(
                "("
                + ", ".join(
                    [
                        quote(department),
                        quote(item.get("code")),
                        quote(item.get("subject")),
                        quote(item.get("date")),
                        quote(item.get("time")),
                        quote(item.get("rollFrom")),
                        quote(item.get("rollTo")),
                        quote(item.get("room")),
                        str(int(item.get("startSeat") or 1)),
                        quote(item.get("location")),
                    ]
                )
                + ")"
            )
    sql = "BEGIN; TRUNCATE exam_schedules RESTART IDENTITY;"
    if values:
        sql += """
        INSERT INTO exam_schedules (department_code, subject_code, subject_name, exam_date, exam_time, roll_from, roll_to, room, start_seat, location)
        VALUES """ + ",".join(values) + ";"
    sql += " COMMIT;"
    run_psql(sql)


def replace_pending_fees(payload):
    values = []
    for student_roll_no, fees in (payload or {}).items():
        for item in fees:
            values.append(
                "("
                + ", ".join(
                    [
                        quote(student_roll_no),
                        quote(item.get("feeType") or "Pending Fee"),
                        str(float(item.get("amount") or 0)),
                        quote(item.get("dueDate")),
                        quote(item.get("detail") or "Pending"),
                    ]
                )
                + ")"
            )
    sql = "BEGIN; TRUNCATE fee_dues RESTART IDENTITY CASCADE;"
    if values:
        sql += """
        INSERT INTO fee_dues (student_roll_no, fee_type, amount, due_date, status)
        VALUES """ + ",".join(values) + ";"
    sql += " COMMIT;"
    run_psql(sql)


def upsert_curriculum(department_code, subjects):
    # Upsert by (department_code, subject_code) instead of truncate-and-replace, so re-uploading
    # a CSV to fix/add a few subjects updates just those rows and leaves the rest of the
    # department's curriculum untouched, rather than silently deleting anything left out of it.
    values = []
    for item in subjects:
        code = (item.get("code") or "").strip()
        name = (item.get("name") or "").strip()
        if not code or not name:
            continue
        values.append(
            "(" + ", ".join([
                quote(department_code), quote(code), quote(name),
                quote(item.get("semester") or "-"), quote(item.get("credits") or "-"),
                quote(item.get("type") or "Theory"),
            ]) + ")"
        )
    if not values:
        return
    sql = """
        INSERT INTO curriculum (department_code, subject_code, subject_name, semester, credits, subject_type)
        VALUES """ + ",".join(values) + """
        ON CONFLICT (department_code, subject_code) DO UPDATE SET
            subject_name = EXCLUDED.subject_name, semester = EXCLUDED.semester,
            credits = EXCLUDED.credits, subject_type = EXCLUDED.subject_type, updated_at = now();
    """
    run_psql(sql)


def upsert_class_timetable(department_code, slots):
    # Same upsert-by-natural-key reasoning as upsert_curriculum, keyed on the actual timetable
    # slot (day + time + section) so re-uploading updates just the slots included in this file.
    values = []
    for item in slots:
        day = (item.get("day") or "").strip()
        time_slot = (item.get("time") or "").strip()
        code = (item.get("code") or "").strip()
        if not day or not time_slot or not code:
            continue
        values.append(
            "(" + ", ".join([
                quote(department_code), quote(item.get("section") or ""), quote(day), quote(time_slot),
                quote(code), quote(item.get("subject") or code), quote(item.get("facultyEmail") or None),
            ]) + ")"
        )
    if not values:
        return
    sql = """
        INSERT INTO class_timetable (department_code, section, day_of_week, time_slot, subject_code, subject_name, faculty_email)
        VALUES """ + ",".join(values) + """
        ON CONFLICT (department_code, section, day_of_week, time_slot) DO UPDATE SET
            subject_code = EXCLUDED.subject_code, subject_name = EXCLUDED.subject_name,
            faculty_email = EXCLUDED.faculty_email, updated_at = now();
    """
    run_psql(sql)


def upsert_student_grades(rows):
    # Upsert by (roll no, term) - same reasoning as upsert_curriculum: re-uploading a CSV to fix
    # or add a term updates just that row, leaving every other term on file untouched.
    values = []
    for item in rows:
        roll_no = (item.get("rollNo") or "").strip()
        term = (item.get("term") or "").strip()
        gpa = (item.get("gpa") or "").strip()
        if not roll_no or not term or not gpa:
            continue
        values.append(
            "(" + ", ".join([quote(roll_no), quote(term), quote(gpa), quote(item.get("backlogs") or "NIL")]) + ")"
        )
    if not values:
        return
    sql = """
        INSERT INTO student_grades (student_roll_no, term, gpa, backlogs)
        VALUES """ + ",".join(values) + """
        ON CONFLICT (student_roll_no, term) DO UPDATE SET
            gpa = EXCLUDED.gpa, backlogs = EXCLUDED.backlogs, updated_at = now();
    """
    run_psql(sql)


def save_attendance_record(faculty_email, subject_code, section, attendance_date, entries):
    # One class session's roster - the whole entries list is the source of truth for that
    # session, so this deletes and re-inserts entries for the (upserted) record rather than
    # trying to diff them, unlike curriculum/timetable's per-row upsert.
    #
    # Deliberately three separate top-level statements, not one WITH-clause combining the upsert,
    # delete, and insert as CTEs: Postgres does not guarantee a data-modifying CTE runs before a
    # sibling one unless there's a real data dependency between them, and the delete-then-insert
    # here has none (both just need the record's id) - tested directly against Postgres and the
    # delete silently didn't happen before the insert, so a re-save hit a duplicate-key error
    # instead of replacing the roster. Plain sequential statements in one psql call don't have
    # that ambiguity - each one fully completes before the next runs.
    record_key = f"""
        faculty_email = {quote(faculty_email)} AND subject_code = {quote(subject_code)}
        AND section = {quote(section)} AND attendance_date = {quote(attendance_date)}
    """
    sql = f"""
        INSERT INTO attendance_records (faculty_email, subject_code, section, attendance_date)
        VALUES ({quote(faculty_email)}, {quote(subject_code)}, {quote(section)}, {quote(attendance_date)})
        ON CONFLICT (faculty_email, subject_code, section, attendance_date) DO NOTHING;
        DELETE FROM attendance_entries WHERE record_id = (SELECT id FROM attendance_records WHERE {record_key});
    """
    entry_values = []
    for entry in entries:
        student_roll_no = (entry.get("studentId") or "").strip()
        if not student_roll_no:
            continue
        entry_values.append(f"({quote(student_roll_no)}, {'true' if entry.get('present') else 'false'})")
    if entry_values:
        sql += f"""
        INSERT INTO attendance_entries (record_id, student_roll_no, present)
        SELECT (SELECT id FROM attendance_records WHERE {record_key}), v.student_roll_no, v.present
        FROM (VALUES {",".join(entry_values)}) AS v(student_roll_no, present);
        """
    run_psql(sql)


def upsert_internal_marks(department_code, subject_code, section, academic_year, faculty_email, rows):
    # Upsert by (student, subject, section, year) - re-saving the roster (e.g. after fixing one
    # student's mark) updates just the touched rows via ON CONFLICT, same shape as
    # upsert_student_grades.
    values = []
    for item in rows:
        roll_no = (item.get("rollNo") or "").strip()
        if not roll_no:
            continue
        values.append(
            "(" + ", ".join([
                quote(roll_no), quote(department_code), quote(subject_code), quote(section),
                quote(academic_year), quote(faculty_email),
                numeric_or_null(item.get("mid1")), numeric_or_null(item.get("mid2")),
                numeric_or_null(item.get("assignment")), numeric_or_null(item.get("labMarks")),
            ]) + ")"
        )
    if not values:
        return
    sql = """
        INSERT INTO internal_marks (
            student_roll_no, department_code, subject_code, section, academic_year, faculty_email,
            mid1, mid2, assignment, lab_marks
        )
        VALUES """ + ",".join(values) + """
        ON CONFLICT (student_roll_no, subject_code, section, academic_year) DO UPDATE SET
            mid1 = EXCLUDED.mid1, mid2 = EXCLUDED.mid2, assignment = EXCLUDED.assignment,
            lab_marks = EXCLUDED.lab_marks, faculty_email = EXCLUDED.faculty_email, updated_at = now();
    """
    run_psql(sql)


def get_internal_marks_for_subject(subject_code, section, academic_year):
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'rollNo', student_roll_no, 'mid1', mid1, 'mid2', mid2,
            'assignment', assignment, 'labMarks', lab_marks
        )), '[]'::json)
        FROM internal_marks
        WHERE subject_code = {quote(subject_code)} AND section = {quote(section)}
          AND academic_year = {quote(academic_year)};
    """, [])


def get_internal_marks_for_student(student_roll_no):
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'subjectCode', m.subject_code,
            'subjectName', COALESCE(c.subject_name, m.subject_code),
            'mid1', m.mid1, 'mid2', m.mid2, 'assignment', m.assignment, 'labMarks', m.lab_marks,
            'academicYear', m.academic_year
        ) ORDER BY m.academic_year DESC, m.subject_code), '[]'::json)
        FROM internal_marks m
        LEFT JOIN curriculum c ON c.subject_code = m.subject_code AND c.department_code = m.department_code
        WHERE m.student_roll_no = {quote(student_roll_no)};
    """, [])


LEAVE_BALANCE_QUOTAS = {"Casual Leave": 12, "Sick Leave": 12, "Earned Leave": 15}


def get_leave_balance(identity_type, identity_id):
    email_column = "staff_email" if identity_type == "non_teaching" else "faculty_email"
    row = run_json(f"""
        SELECT json_build_object(
            'Casual Leave', COALESCE(SUM(CASE WHEN leave_type = 'Casual Leave' THEN (to_date - from_date + 1) ELSE 0 END), 0),
            'Sick Leave', COALESCE(SUM(CASE WHEN leave_type = 'Sick Leave' THEN (to_date - from_date + 1) ELSE 0 END), 0),
            'Earned Leave', COALESCE(SUM(CASE WHEN leave_type = 'Earned Leave' THEN (to_date - from_date + 1) ELSE 0 END), 0)
        )
        FROM leave_requests
        WHERE {email_column} = {quote(identity_id)} AND status = 'Approved'
          AND EXTRACT(YEAR FROM from_date) = EXTRACT(YEAR FROM now());
    """, {})
    used = row or {}
    return {
        key.lower().split(" ")[0]: {
            "quota": quota,
            "used": int(used.get(key) or 0),
            "remaining": max(0, quota - int(used.get(key) or 0)),
        }
        for key, quota in LEAVE_BALANCE_QUOTAS.items()
    }


def get_attendance_shortage_report(department_code):
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'rollNo', roster.student_roll_no, 'name', st.full_name, 'className', st.class_name,
            'held', roster.held, 'present', roster.present, 'percent', roster.percent
        ) ORDER BY roster.percent, roster.student_roll_no), '[]'::json)
        FROM (
          SELECT e.student_roll_no,
            COUNT(*) AS held,
            SUM(CASE WHEN e.present THEN 1 ELSE 0 END) AS present,
            ROUND(100.0 * SUM(CASE WHEN e.present THEN 1 ELSE 0 END) / COUNT(*), 1) AS percent
          FROM attendance_entries e
          JOIN attendance_records r ON r.id = e.record_id
          JOIN students s ON s.roll_no = e.student_roll_no
          WHERE s.department_code = {quote(department_code)}
          GROUP BY e.student_roll_no
        ) roster
        JOIN students st ON st.roll_no = roster.student_roll_no
        WHERE roster.percent < 75;
    """, [])


def get_attendance_section_report(department_code, from_date, to_date, section=""):
    # One row per student per class session (not aggregated like the shortage report above).
    # from_date/to_date are both optional and inclusive, same "either edge blank = no limit on
    # that side" rule as the Hostel Gate Activity date-range export. section is also optional -
    # blank/omitted means every section in the department (still shown per-row, so the report
    # stays "section-wise" either way).
    date_clause = ""
    if from_date:
        date_clause += f" AND r.attendance_date >= {quote(from_date)}::date"
    if to_date:
        date_clause += f" AND r.attendance_date <= {quote(to_date)}::date"
    section_clause = f" AND r.section = {quote(section)}" if section else ""
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'date', to_char(r.attendance_date, 'YYYY-MM-DD'), 'subject', r.subject_code, 'section', r.section,
            'rollNo', s.roll_no, 'name', s.full_name, 'present', e.present
        ) ORDER BY r.attendance_date, r.section, s.roll_no), '[]'::json)
        FROM attendance_entries e
        JOIN attendance_records r ON r.id = e.record_id
        JOIN students s ON s.roll_no = e.student_roll_no
        WHERE s.department_code = {quote(department_code)}{date_clause}{section_clause};
    """, [])


def save_assignment_submission(assignment_id, student_roll_no, comment, files):
    # Same reasoning as save_attendance_record: a submission's file list is replaced wholesale
    # (delete-then-insert) rather than diffed, and the three statements are sequential top-level
    # statements - not a WITH-clause - for the same CTE-ordering reason documented there.
    submission_key = f"""
        assignment_id = {quote(assignment_id)}::uuid AND student_roll_no = {quote(student_roll_no)}
    """
    sql = f"""
        INSERT INTO assignment_submissions (assignment_id, student_roll_no, comments, submitted_at, status)
        VALUES ({quote(assignment_id)}::uuid, {quote(student_roll_no)}, {quote(comment)}, now(), 'Submitted')
        ON CONFLICT (assignment_id, student_roll_no) DO UPDATE SET
            comments = EXCLUDED.comments, submitted_at = now(), status = 'Submitted';
        DELETE FROM assignment_submission_files WHERE submission_id = (SELECT id FROM assignment_submissions WHERE {submission_key});
    """
    file_values = []
    for file in files or []:
        name = (file.get("name") or "").strip()
        data_url = file.get("dataUrl") or ""
        if not name or not data_url:
            continue
        file_values.append(f"({quote(name)}, {quote(data_url)}, {quote(file.get('mime'))})")
    if file_values:
        sql += f"""
        INSERT INTO assignment_submission_files (submission_id, file_name, file_url, file_mime)
        SELECT (SELECT id FROM assignment_submissions WHERE {submission_key}), v.file_name, v.file_url, v.file_mime
        FROM (VALUES {",".join(file_values)}) AS v(file_name, file_url, file_mime);
        """
    run_psql(sql)


def create_online_course(faculty_email, title, description, lessons, sections):
    # Course id is generated here (not left to gen_random_uuid()'s DEFAULT) so it can be reused
    # across the course insert and the lesson inserts in the same run_psql call, same reasoning
    # as save_attendance_record's record_key - one round trip, no RETURNING-then-second-query.
    faculty_row = run_json(f"""
        SELECT json_build_object('name', full_name, 'department', department_code)
        FROM faculty WHERE email = {quote(faculty_email)};
    """, None)
    if not faculty_row:
        return None
    course_id = str(uuid.uuid4())
    sections_array = "ARRAY[" + ",".join(quote(s) for s in sections) + "]::text[]"
    sql = f"""
        INSERT INTO online_courses (id, faculty_email, faculty_name, department_code, sections, title, description)
        VALUES ({quote(course_id)}::uuid, {quote(faculty_email)}, {quote(faculty_row["name"])},
          {quote(faculty_row.get("department"))}, {sections_array}, {quote(title)}, {quote(description)});
    """
    lesson_values = []
    for index, lesson in enumerate(lessons or []):
        lesson_title = (lesson.get("title") or "").strip()
        resource_url = (lesson.get("resourceUrl") or "").strip()
        if not lesson_title or not resource_url:
            continue
        lesson_values.append(
            "(" + ", ".join([
                f"{quote(course_id)}::uuid", str(index), quote(lesson_title), quote(resource_url)
            ]) + ")"
        )
    if lesson_values:
        sql += f"""
        INSERT INTO online_course_lessons (course_id, position, title, resource_url)
        VALUES {",".join(lesson_values)};
        """
    run_psql(sql)
    section_students = run_json(
        "SELECT COALESCE(json_agg(roll_no), '[]'::json) FROM students WHERE class_name = ANY("
        + sections_array + ");",
        [],
    )
    create_notifications_bulk(
        "student", section_students,
        f"New course: {title}", f"{faculty_row['name']} just published a new course - {description}",
        link="#online-courses", source_module="Online Courses",
    )
    return course_id


def enroll_in_course(course_id, student_roll_no):
    run_psql(f"""
        INSERT INTO online_course_enrollments (course_id, student_roll_no)
        VALUES ({quote(course_id)}::uuid, {quote(student_roll_no)})
        ON CONFLICT (course_id, student_roll_no) DO NOTHING;
    """)


def get_all_online_courses():
    return run_json("""
        SELECT COALESCE(json_agg(json_build_object(
            'id', c.id::text, 'title', c.title, 'description', c.description,
            'facultyName', c.faculty_name, 'facultyEmail', c.faculty_email,
            'departmentCode', c.department_code, 'sections', to_json(c.sections), 'createdAt', to_char(c.created_at, 'DD Mon YYYY'),
            'lessons', COALESCE((
              SELECT json_agg(json_build_object(
                'id', l.id::text, 'position', l.position, 'title', l.title,
                'resourceUrl', l.resource_url
              ) ORDER BY l.position) FROM online_course_lessons l WHERE l.course_id = c.id
            ), '[]'::json)
        ) ORDER BY c.created_at DESC), '[]'::json)
        FROM online_courses c;
    """, [])


def get_courses_for_student(student_roll_no):
    # A course is visible to a student only if their own section (students.class_name) is one of
    # the course's target sections - or the course has no sections set at all (courses created
    # before section-scoping existed, kept visible to everyone rather than orphaned).
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', c.id::text, 'title', c.title, 'description', c.description,
            'facultyName', c.faculty_name, 'facultyEmail', c.faculty_email,
            'departmentCode', c.department_code, 'sections', to_json(c.sections), 'createdAt', to_char(c.created_at, 'DD Mon YYYY'),
            'lessons', COALESCE((
              SELECT json_agg(json_build_object(
                'id', l.id::text, 'position', l.position, 'title', l.title,
                'resourceUrl', l.resource_url
              ) ORDER BY l.position) FROM online_course_lessons l WHERE l.course_id = c.id
            ), '[]'::json)
        ) ORDER BY c.created_at DESC), '[]'::json)
        FROM online_courses c
        WHERE c.sections IS NULL OR (
          SELECT class_name FROM students WHERE roll_no = {quote(student_roll_no)}
        ) = ANY(c.sections);
    """, [])


def get_class_sections():
    return run_json(
        "SELECT COALESCE(json_agg(DISTINCT class_name ORDER BY class_name), '[]'::json) FROM students;", []
    )


# Scoped variant of get_class_sections() for the department dashboard's Section-wise Attendance
# Report filter - a department admin should only ever see their own department's sections in that
# dropdown, not every section site-wide.
def get_department_sections(department_code):
    return run_json(
        f"SELECT COALESCE(json_agg(DISTINCT class_name ORDER BY class_name), '[]'::json) FROM students WHERE department_code = {quote(department_code)};",
        [],
    )


def create_webinar(admin_email, title, description, live_link, scheduled_at):
    admin_row = run_json(f"""
        SELECT json_build_object('name', full_name, 'role', role, 'department', department_code)
        FROM admins WHERE email = {quote(admin_email)};
    """, None)
    if not admin_row:
        return False
    # A "<X> Department Admin" role scopes the webinar to their own department; a College Admin
    # (or any other role) leaves department_code NULL, meaning visible to everyone.
    department_code = admin_row.get("department") if (admin_row.get("role") or "").endswith("Department Admin") else None
    run_psql(f"""
        INSERT INTO webinars (created_by_email, created_by_name, department_code, title, description, live_link, scheduled_at)
        VALUES ({quote(admin_email)}, {quote(admin_row["name"])}, {quote(department_code)}, {quote(title)}, {quote(description)}, {quote(live_link)}, {quote(scheduled_at)}::timestamptz);
    """)
    department_filter = f"WHERE department_code = {quote(department_code)}" if department_code else ""
    recipient_students = run_json(f"SELECT COALESCE(json_agg(roll_no), '[]'::json) FROM students {department_filter};", [])
    recipient_faculty = run_json(f"SELECT COALESCE(json_agg(email), '[]'::json) FROM faculty {department_filter};", [])
    create_notifications_bulk(
        "student", recipient_students, f"New webinar: {title}", description,
        link="#webinars", source_module="Webinars",
    )
    create_notifications_bulk(
        "faculty", recipient_faculty, f"New webinar: {title}", description,
        link="#webinars", source_module="Webinars",
    )
    return True


def cleanup_expired_webinars():
    # Lazy cleanup (no background scheduler in this app) - runs on every read, which is the only
    # way webinars are ever accessed, so expired ones disappear the next time anyone looks.
    run_psql("DELETE FROM webinars WHERE scheduled_at < now() - INTERVAL '24 hours';")


# A viewer only counts toward "watching now" if they've pinged within this window - the client
# pings every 20s while the modal is open, so 45s comfortably survives one missed ping without
# still counting someone who closed the tab a while ago.
WATCHING_WINDOW = "45 seconds"


WATCHING_VIEWERS_SQL = f"""(
      SELECT COALESCE(json_agg(row_to_json(vw)), '[]'::json) FROM (
        (
          SELECT s.full_name AS name, s.profile_photo_url AS "photoUrl", 'student' AS type
          FROM webinar_viewers v JOIN students s ON s.roll_no = v.viewer_id
          WHERE v.webinar_id = w.id AND v.viewer_type = 'student' AND v.last_seen_at > now() - INTERVAL '{WATCHING_WINDOW}'
          ORDER BY v.last_seen_at DESC LIMIT 6
        ) UNION ALL (
          SELECT f.full_name AS name, f.profile_photo_url AS "photoUrl", 'faculty' AS type
          FROM webinar_viewers v JOIN faculty f ON f.email = v.viewer_id
          WHERE v.webinar_id = w.id AND v.viewer_type = 'faculty' AND v.last_seen_at > now() - INTERVAL '{WATCHING_WINDOW}'
          ORDER BY v.last_seen_at DESC LIMIT 6
        )
      ) vw
    )"""


def get_all_webinars():
    cleanup_expired_webinars()
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', id::text, 'title', title, 'description', description, 'liveLink', live_link,
            'createdByName', created_by_name, 'createdByEmail', created_by_email, 'departmentCode', department_code,
            'scheduledAt', to_char(scheduled_at, 'DD Mon YYYY, HH12:MI AM'),
            'scheduledAtRaw', extract(epoch FROM scheduled_at) * 1000,
            'watchingCount', (
              SELECT COUNT(*) FROM webinar_viewers v
              WHERE v.webinar_id = webinars.id AND v.last_seen_at > now() - INTERVAL '{WATCHING_WINDOW}'
            ),
            'watchingViewers', {WATCHING_VIEWERS_SQL.replace("w.id", "webinars.id")}
        ) ORDER BY scheduled_at DESC), '[]'::json)
        FROM webinars;
    """, [])


def get_webinars_for_viewer(identity_type, identity_id):
    cleanup_expired_webinars()
    department_table = "students" if identity_type == "student" else "faculty"
    id_column = "roll_no" if identity_type == "student" else "email"
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', w.id::text, 'title', w.title, 'description', w.description, 'liveLink', w.live_link,
            'createdByName', w.created_by_name, 'createdByEmail', w.created_by_email, 'departmentCode', w.department_code,
            'scheduledAt', to_char(w.scheduled_at, 'DD Mon YYYY, HH12:MI AM'),
            'scheduledAtRaw', extract(epoch FROM w.scheduled_at) * 1000,
            'watchingCount', (
              SELECT COUNT(*) FROM webinar_viewers v
              WHERE v.webinar_id = w.id AND v.last_seen_at > now() - INTERVAL '{WATCHING_WINDOW}'
            ),
            'watchingViewers', {WATCHING_VIEWERS_SQL}
        ) ORDER BY w.scheduled_at DESC), '[]'::json)
        FROM webinars w
        WHERE w.department_code IS NULL OR w.department_code = (
          SELECT department_code FROM {department_table} WHERE {id_column} = {quote(identity_id)}
        );
    """, [])


def record_webinar_view(webinar_id, viewer_type, viewer_id):
    run_psql(f"""
        INSERT INTO webinar_viewers (webinar_id, viewer_type, viewer_id)
        VALUES ({quote(webinar_id)}::uuid, {quote(viewer_type)}, {quote(viewer_id)})
        ON CONFLICT (webinar_id, viewer_type, viewer_id) DO UPDATE SET last_seen_at = now();
    """)


# Online Classes - same live-link/scheduled-time/watching-count shape as webinars, but
# faculty-created and scoped to section(s) (like online_courses) instead of admin-created and
# scoped to department.
def cleanup_expired_online_classes():
    run_psql("DELETE FROM online_classes WHERE scheduled_at < now() - INTERVAL '24 hours';")


CLASS_WATCHING_VIEWERS_SQL = f"""(
      SELECT COALESCE(json_agg(row_to_json(vw)), '[]'::json) FROM (
        (
          SELECT s.full_name AS name, s.profile_photo_url AS "photoUrl", 'student' AS type
          FROM online_class_viewers v JOIN students s ON s.roll_no = v.viewer_id
          WHERE v.class_id = c.id AND v.viewer_type = 'student' AND v.last_seen_at > now() - INTERVAL '{WATCHING_WINDOW}'
          ORDER BY v.last_seen_at DESC LIMIT 6
        ) UNION ALL (
          SELECT f.full_name AS name, f.profile_photo_url AS "photoUrl", 'faculty' AS type
          FROM online_class_viewers v JOIN faculty f ON f.email = v.viewer_id
          WHERE v.class_id = c.id AND v.viewer_type = 'faculty' AND v.last_seen_at > now() - INTERVAL '{WATCHING_WINDOW}'
          ORDER BY v.last_seen_at DESC LIMIT 6
        )
      ) vw
    )"""


def create_online_class(faculty_email, title, description, live_link, scheduled_at, sections):
    faculty_row = run_json(f"""
        SELECT json_build_object('name', full_name) FROM faculty WHERE email = {quote(faculty_email)};
    """, None)
    if not faculty_row:
        return False
    sections_array = "ARRAY[" + ",".join(quote(s) for s in sections) + "]::text[]"
    run_psql(f"""
        INSERT INTO online_classes (faculty_email, faculty_name, sections, title, description, live_link, scheduled_at)
        VALUES ({quote(faculty_email)}, {quote(faculty_row["name"])}, {sections_array}, {quote(title)}, {quote(description)}, {quote(live_link)}, {quote(scheduled_at)}::timestamptz);
    """)
    section_students = run_json(
        "SELECT COALESCE(json_agg(roll_no), '[]'::json) FROM students WHERE class_name = ANY(" + sections_array + ");",
        [],
    )
    create_notifications_bulk(
        "student", section_students, f"New online class: {title}", f"{faculty_row['name']} scheduled a new online class - {description}",
        link="#online-classes", source_module="Online Classes",
    )
    return True


def get_online_classes_for_student(student_roll_no):
    cleanup_expired_online_classes()
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', c.id::text, 'title', c.title, 'description', c.description, 'liveLink', c.live_link,
            'facultyName', c.faculty_name, 'facultyEmail', c.faculty_email, 'sections', to_json(c.sections),
            'scheduledAt', to_char(c.scheduled_at, 'DD Mon YYYY, HH12:MI AM'),
            'scheduledAtRaw', extract(epoch FROM c.scheduled_at) * 1000,
            'watchingCount', (
              SELECT COUNT(*) FROM online_class_viewers v
              WHERE v.class_id = c.id AND v.last_seen_at > now() - INTERVAL '{WATCHING_WINDOW}'
            ),
            'watchingViewers', {CLASS_WATCHING_VIEWERS_SQL}
        ) ORDER BY c.scheduled_at DESC), '[]'::json)
        FROM online_classes c
        WHERE (
          SELECT class_name FROM students WHERE roll_no = {quote(student_roll_no)}
        ) = ANY(c.sections);
    """, [])


def get_my_online_classes(faculty_email):
    cleanup_expired_online_classes()
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'id', c.id::text, 'title', c.title, 'description', c.description, 'liveLink', c.live_link,
            'facultyName', c.faculty_name, 'facultyEmail', c.faculty_email, 'sections', to_json(c.sections),
            'scheduledAt', to_char(c.scheduled_at, 'DD Mon YYYY, HH12:MI AM'),
            'scheduledAtRaw', extract(epoch FROM c.scheduled_at) * 1000,
            'watchingCount', (
              SELECT COUNT(*) FROM online_class_viewers v
              WHERE v.class_id = c.id AND v.last_seen_at > now() - INTERVAL '{WATCHING_WINDOW}'
            ),
            'watchingViewers', {CLASS_WATCHING_VIEWERS_SQL}
        ) ORDER BY c.scheduled_at DESC), '[]'::json)
        FROM online_classes c
        WHERE c.faculty_email = {quote(faculty_email)};
    """, [])


def remove_online_class(class_id, faculty_email):
    owner = run_psql(f"""
        SELECT 1 FROM online_classes WHERE id = {quote(class_id)}::uuid AND faculty_email = {quote(faculty_email)};
    """).strip()
    if not owner:
        return False
    run_psql(f"DELETE FROM online_classes WHERE id = {quote(class_id)}::uuid;")
    return True


def record_class_view(class_id, viewer_type, viewer_id):
    run_psql(f"""
        INSERT INTO online_class_viewers (class_id, viewer_type, viewer_id)
        VALUES ({quote(class_id)}::uuid, {quote(viewer_type)}, {quote(viewer_id)})
        ON CONFLICT (class_id, viewer_type, viewer_id) DO UPDATE SET last_seen_at = now();
    """)


def remove_webinar(webinar_id):
    run_psql(f"DELETE FROM webinars WHERE id = {quote(webinar_id)}::uuid;")


def get_my_course_enrollments(student_roll_no):
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'enrollmentId', e.id::text, 'courseId', e.course_id::text,
            'title', c.title, 'description', c.description, 'facultyName', c.faculty_name,
            'status', e.status, 'enrolledAt', to_char(e.enrolled_at, 'DD Mon YYYY'),
            'completedAt', to_char(e.completed_at, 'DD Mon YYYY'),
            'totalLessons', (SELECT COUNT(*) FROM online_course_lessons WHERE course_id = c.id),
            'completedLessonIds', COALESCE((
              SELECT json_agg(lesson_id::text) FROM online_course_lesson_progress WHERE enrollment_id = e.id
            ), '[]'::json)
        ) ORDER BY e.enrolled_at DESC), '[]'::json)
        FROM online_course_enrollments e
        JOIN online_courses c ON c.id = e.course_id
        WHERE e.student_roll_no = {quote(student_roll_no)};
    """, [])


def complete_course_lesson(course_id, lesson_id, student_roll_no):
    enrollment_id = run_psql(f"""
        SELECT id FROM online_course_enrollments
        WHERE course_id = {quote(course_id)}::uuid AND student_roll_no = {quote(student_roll_no)};
    """).strip()
    if not enrollment_id:
        return False
    run_psql(f"""
        INSERT INTO online_course_lesson_progress (enrollment_id, lesson_id)
        VALUES ({quote(enrollment_id)}::uuid, {quote(lesson_id)}::uuid)
        ON CONFLICT (enrollment_id, lesson_id) DO NOTHING;
        UPDATE online_course_enrollments SET
          status = CASE WHEN (
            SELECT COUNT(*) FROM online_course_lesson_progress WHERE enrollment_id = {quote(enrollment_id)}::uuid
          ) >= (
            SELECT COUNT(*) FROM online_course_lessons WHERE course_id = {quote(course_id)}::uuid
          ) THEN 'Completed' ELSE 'In Progress' END,
          completed_at = CASE WHEN (
            SELECT COUNT(*) FROM online_course_lesson_progress WHERE enrollment_id = {quote(enrollment_id)}::uuid
          ) >= (
            SELECT COUNT(*) FROM online_course_lessons WHERE course_id = {quote(course_id)}::uuid
          ) THEN now() ELSE completed_at END
        WHERE id = {quote(enrollment_id)}::uuid;
    """)
    return True


def uncomplete_course_lesson(course_id, lesson_id, student_roll_no):
    enrollment_id = run_psql(f"""
        SELECT id FROM online_course_enrollments
        WHERE course_id = {quote(course_id)}::uuid AND student_roll_no = {quote(student_roll_no)};
    """).strip()
    if not enrollment_id:
        return False
    run_psql(f"""
        DELETE FROM online_course_lesson_progress
        WHERE enrollment_id = {quote(enrollment_id)}::uuid AND lesson_id = {quote(lesson_id)}::uuid;
        UPDATE online_course_enrollments SET
          status = CASE WHEN (
            SELECT COUNT(*) FROM online_course_lesson_progress WHERE enrollment_id = {quote(enrollment_id)}::uuid
          ) = 0 THEN 'Registered' ELSE 'In Progress' END,
          completed_at = NULL
        WHERE id = {quote(enrollment_id)}::uuid;
    """)
    return True


def get_faculty_course_stats(faculty_email):
    return run_json(f"""
        SELECT COALESCE(json_agg(json_build_object(
            'courseId', c.id::text, 'title', c.title, 'description', c.description, 'sections', to_json(c.sections),
            'registered', COALESCE(stats.registered, 0),
            'inProgress', COALESCE(stats.in_progress, 0),
            'completed', COALESCE(stats.completed, 0),
            'lessons', COALESCE((
              SELECT json_agg(json_build_object(
                'id', l.id::text, 'position', l.position, 'title', l.title, 'resourceUrl', l.resource_url
              ) ORDER BY l.position) FROM online_course_lessons l WHERE l.course_id = c.id
            ), '[]'::json),
            'registeredStudents', COALESCE((
              SELECT json_agg(json_build_object('rollNo', s.roll_no, 'name', s.full_name, 'className', s.class_name) ORDER BY s.class_name, s.full_name)
              FROM online_course_enrollments e JOIN students s ON s.roll_no = e.student_roll_no
              WHERE e.course_id = c.id AND e.status = 'Registered'
            ), '[]'::json),
            'inProgressStudents', COALESCE((
              SELECT json_agg(json_build_object('rollNo', s.roll_no, 'name', s.full_name, 'className', s.class_name) ORDER BY s.class_name, s.full_name)
              FROM online_course_enrollments e JOIN students s ON s.roll_no = e.student_roll_no
              WHERE e.course_id = c.id AND e.status = 'In Progress'
            ), '[]'::json),
            'completedStudents', COALESCE((
              SELECT json_agg(json_build_object('rollNo', s.roll_no, 'name', s.full_name, 'className', s.class_name) ORDER BY s.class_name, s.full_name)
              FROM online_course_enrollments e JOIN students s ON s.roll_no = e.student_roll_no
              WHERE e.course_id = c.id AND e.status = 'Completed'
            ), '[]'::json),
            'notRegisteredStudents', COALESCE((
              SELECT json_agg(json_build_object('rollNo', s.roll_no, 'name', s.full_name, 'className', s.class_name) ORDER BY s.class_name, s.full_name)
              FROM students s
              WHERE (c.sections IS NULL OR s.class_name = ANY(c.sections))
                AND NOT EXISTS (
                  SELECT 1 FROM online_course_enrollments e WHERE e.course_id = c.id AND e.student_roll_no = s.roll_no
                )
            ), '[]'::json)
        ) ORDER BY c.created_at DESC), '[]'::json)
        FROM online_courses c
        LEFT JOIN (
          SELECT course_id,
            SUM(CASE WHEN status = 'Registered' THEN 1 ELSE 0 END) AS registered,
            SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) AS in_progress,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed
          FROM online_course_enrollments GROUP BY course_id
        ) stats ON stats.course_id = c.id
        WHERE c.faculty_email = {quote(faculty_email)};
    """, [])


def add_course_lesson(course_id, faculty_email, title, resource_url):
    owner = run_psql(f"""
        SELECT 1 FROM online_courses WHERE id = {quote(course_id)}::uuid AND faculty_email = {quote(faculty_email)};
    """).strip()
    if not owner:
        return False
    run_psql(f"""
        INSERT INTO online_course_lessons (course_id, position, title, resource_url)
        VALUES (
          {quote(course_id)}::uuid,
          COALESCE((SELECT MAX(position) + 1 FROM online_course_lessons WHERE course_id = {quote(course_id)}::uuid), 0),
          {quote(title)}, {quote(resource_url)}
        );
    """)
    return True


def remove_course_lesson(lesson_id, faculty_email):
    owner = run_psql(f"""
        SELECT 1 FROM online_course_lessons l
        JOIN online_courses c ON c.id = l.course_id
        WHERE l.id = {quote(lesson_id)}::uuid AND c.faculty_email = {quote(faculty_email)};
    """).strip()
    if not owner:
        return False
    run_psql(f"DELETE FROM online_course_lessons WHERE id = {quote(lesson_id)}::uuid;")
    return True


def update_course_lesson(lesson_id, faculty_email, title, resource_url):
    owner = run_psql(f"""
        SELECT 1 FROM online_course_lessons l
        JOIN online_courses c ON c.id = l.course_id
        WHERE l.id = {quote(lesson_id)}::uuid AND c.faculty_email = {quote(faculty_email)};
    """).strip()
    if not owner:
        return False
    run_psql(f"""
        UPDATE online_course_lessons SET title = {quote(title)}, resource_url = {quote(resource_url)}
        WHERE id = {quote(lesson_id)}::uuid;
    """)
    return True


def upsert_site_content(key, value_json_text):
    run_psql(f"""
        INSERT INTO site_content (content_key, content_value) VALUES ({quote(key)}, {quote(value_json_text)}::jsonb)
        ON CONFLICT (content_key) DO UPDATE SET content_value = EXCLUDED.content_value, updated_at = now();
    """)


def create_admin(admin):
    run_psql(f"""
        INSERT INTO admins (full_name, email, role, department_code, can_manage_admins, status, photo_url, student_roll)
        VALUES ({quote(admin.get('name'))}, {quote(admin.get('email'))}, {quote(admin.get('role'))},
                {quote(admin.get('department'))}, {'true' if admin.get('canManageAdmins') else 'false'}, 'Active',
                {quote(admin.get('photoUrl'))}, {quote(admin.get('studentRoll'))})
        ON CONFLICT (email) DO UPDATE SET
            full_name = EXCLUDED.full_name, role = EXCLUDED.role, department_code = EXCLUDED.department_code,
            can_manage_admins = EXCLUDED.can_manage_admins, status = 'Active',
            photo_url = COALESCE(EXCLUDED.photo_url, admins.photo_url),
            student_roll = COALESCE(EXCLUDED.student_roll, admins.student_roll);
    """)


def remove_admin(email):
    run_psql(f"DELETE FROM admins WHERE email = {quote(email)};")


def apply_to_placement_drive(student_roll_no, drive_id):
    # Also used for Mock Interview/Aptitude Test registrations (same table/shape, driveType just
    # differs) - seat_cap is NULL for Placement/Internship/Job Recommendation, which makes the
    # capacity guard below a no-op for them (seat_cap IS NULL always satisfies the WHERE EXISTS).
    rows = run_json(
        f"""
        WITH cap AS (
          SELECT seat_cap, (SELECT COUNT(*) FROM placement_applications WHERE drive_id = {quote(drive_id)}::uuid) AS taken
          FROM placement_drives WHERE id = {quote(drive_id)}::uuid
        )
        INSERT INTO placement_applications (drive_id, student_roll_no)
        SELECT {quote(drive_id)}::uuid, {quote(student_roll_no)}
        WHERE EXISTS (SELECT 1 FROM cap WHERE seat_cap IS NULL OR taken < seat_cap)
        ON CONFLICT (drive_id, student_roll_no) DO NOTHING
        RETURNING json_build_array(id::text)::json AS row;
        """,
        [],
    )
    return bool(rows)


def record_payment(student_roll_no, amount, payment_mode, transaction_ref, details_json_text):
    run_psql(f"""
        INSERT INTO payments (student_roll_no, amount, payment_mode, transaction_ref, details)
        VALUES ({quote(student_roll_no)}, {quote(amount)}, {quote(payment_mode)}, {quote(transaction_ref)}, {quote(details_json_text)}::jsonb);
    """)


def upsert_bank_details(key, details_json_text):
    # Two copies: `details` is Fernet-encrypted ciphertext of the full record (only ever decrypted
    # by get_bank_details, which nothing in the current UI calls - the account number is never
    # editable in place, only re-enterable). `masked_details` is a plaintext preview (account
    # number masked to first-5/last-4) safe to include in the public bootstrap so the dashboard can
    # show "account ending 4821" without decrypting anything on every page load.
    details = json.loads(details_json_text)
    encrypted = encrypt_text(details_json_text)
    masked = json.dumps(build_masked_bank_details(details))
    run_psql(f"""
        INSERT INTO bank_details (detail_key, details, masked_details)
        VALUES ({quote(key)}, {quote(encrypted)}, {quote(masked)}::jsonb)
        ON CONFLICT (detail_key) DO UPDATE SET
            details = EXCLUDED.details, masked_details = EXCLUDED.masked_details, updated_at = now();
    """)


def upsert_fee_amount_override(application_type, amount):
    run_psql(f"""
        INSERT INTO fee_amount_overrides (application_type, amount) VALUES ({quote(application_type)}, {quote(amount)})
        ON CONFLICT (application_type) DO UPDATE SET amount = EXCLUDED.amount, updated_at = now();
    """)


def upsert_section_assignment(student_roll_no, department_code, section):
    run_psql(f"""
        INSERT INTO student_section_assignments (student_roll_no, department_code, section)
        VALUES ({quote(student_roll_no)}, {quote(department_code)}, {quote(section)})
        ON CONFLICT (student_roll_no) DO UPDATE SET
            department_code = EXCLUDED.department_code, section = EXCLUDED.section, updated_at = now();
    """)


def create_class_message(payload):
    run_psql(f"""
        INSERT INTO class_messages (faculty_email, faculty_name, subject_code, subject, section, department_code, title, message)
        VALUES ({quote(payload.get('facultyEmail'))}, {quote(payload.get('facultyName'))}, {quote(payload.get('subjectCode'))},
                {quote(payload.get('subject'))}, {quote(payload.get('section'))}, {quote(payload.get('department'))},
                {quote(payload.get('title'))}, {quote(payload.get('message'))});
    """)


def create_invigilation_duty(payload):
    run_psql(f"""
        INSERT INTO invigilation_duties (faculty_email, faculty_name, subject_code, subject, exam_date, exam_time, room, location)
        VALUES ({quote(payload.get('facultyEmail'))}, {quote(payload.get('facultyName'))}, {quote(payload.get('code'))},
                {quote(payload.get('subject'))}, {quote(payload.get('date'))}::date, {quote(payload.get('time'))},
                {quote(payload.get('room'))}, {quote(payload.get('location'))});
    """)


def create_leave_request(payload):
    run_psql(f"""
        INSERT INTO leave_requests (
            faculty_email, faculty_name, staff_email, staff_name, designation, leave_type,
            department_code, reason, from_date, to_date, is_hod, is_non_teaching
        )
        VALUES (
            {quote(payload.get('facultyEmail'))}, {quote(payload.get('facultyName'))},
            {quote(payload.get('staffEmail'))}, {quote(payload.get('staffName'))},
            {quote(payload.get('designation'))}, {quote(payload.get('leaveType'))},
            {quote(payload.get('department'))}, {quote(payload.get('reason'))},
            {quote(payload.get('fromDate'))}::date, {quote(payload.get('toDate'))}::date,
            {'true' if payload.get('isHod') else 'false'}, {'true' if payload.get('isNonTeaching') else 'false'}
        );
    """)


def decide_leave_request(request_id, status, decided_by):
    run_psql(f"""
        UPDATE leave_requests SET status = {quote(status)}, decided_by = {quote(decided_by)}, decided_at = now()
        WHERE id = {quote(request_id)}::uuid;
    """)


def create_adhoc_class_request(payload):
    status = "Approved" if payload.get("isHod") else "Pending"
    run_psql(f"""
        INSERT INTO adhoc_class_requests (faculty_email, faculty_name, department_code, subject, subject_code, reason, requested_date, requested_time, is_hod, status)
        VALUES ({quote(payload.get('facultyEmail'))}, {quote(payload.get('facultyName'))}, {quote(payload.get('department'))},
                {quote(payload.get('subject'))}, {quote(payload.get('subjectCode'))}, {quote(payload.get('reason'))}, {quote(payload.get('date'))}::date,
                {quote(payload.get('time'))}, {'true' if payload.get('isHod') else 'false'}, {quote(status)});
    """)


def decide_adhoc_class_request(request_id, status):
    run_psql(f"UPDATE adhoc_class_requests SET status = {quote(status)} WHERE id = {quote(request_id)}::uuid;")


def create_class_cancellation(payload):
    run_psql(f"""
        INSERT INTO class_cancellations (faculty_email, subject_code, subject, cancel_date, reason)
        VALUES ({quote(payload.get('facultyEmail'))}, {quote(payload.get('subjectCode'))}, {quote(payload.get('subject'))},
                {quote(payload.get('date'))}::date, {quote(payload.get('reason'))});
    """)


# Projects/research are rich nested documents (team members, per-milestone submission status,
# staged files) that the frontend already manages as one JS object per record, read-all/mutate-
# one/save-all (including removal-by-filter) across ~30 call sites. Storing the whole record as
# JSONB keyed by its client-generated id, and treating each save as the full replacement set
# (delete whatever's no longer present, upsert the rest), preserves all of that existing logic
# unchanged instead of normalizing team/milestone data into new tables in this pass.
def replace_student_submissions(table, records):
    ids = [record.get("id") for record in records if record.get("id")]
    id_list = ", ".join(quote(item_id) for item_id in ids) or "''"
    sql = f"DELETE FROM {table} WHERE id NOT IN ({id_list});\n"
    values = ",".join(f"({quote(record.get('id'))}, {quote(json.dumps(record))}::jsonb)" for record in records if record.get("id"))
    if values:
        sql += f"""
        INSERT INTO {table} (id, data) VALUES {values}
        ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now();
        """
    run_psql(sql)


# Gate scanning for the three hostel pass types re-uses these same JSONB-blob tables rather than
# adding dedicated ones - the QR printed on a pass just encodes {passType, passId, gateToken}, and
# gateToken/gateLog live as extra keys inside the existing `data` blob (the student side already
# treats that blob as a free-form object, e.g. request.studentId/request.status, so adding fields
# here needs no migration). gateToken is a random opaque string set once when the pass PDF is first
# generated - never the request's own id - so a printed pass reveals nothing an outsider could use
# to look up or guess any other pass.
HOSTEL_PASS_TABLES = {
    "outing": "hostel_outing_requests",
    "leave": "hostel_leave_requests",
    "visit": "hostel_visiting_requests",
}


def hostel_gate_lookup(pass_type, pass_id, token):
    table = HOSTEL_PASS_TABLES.get(pass_type)
    if not table:
        return None
    rows = run_json(
        f"SELECT COALESCE(json_agg(data), '[]'::json) FROM {table} "
        f"WHERE id = {quote(pass_id)} AND data->>'gateToken' = {quote(token)} AND data->>'status' = 'Approved';",
        [],
    )
    return rows[0] if rows else None


def hostel_gate_log_append(pass_type, pass_id, token, direction, scanned_by):
    table = HOSTEL_PASS_TABLES.get(pass_type)
    if not table:
        return None
    rows = run_json(
        f"""
        UPDATE {table} SET
          data = jsonb_set(
            data, '{{gateLog}}',
            COALESCE(data->'gateLog', '[]'::jsonb) || jsonb_build_array(
              jsonb_build_object('direction', {quote(direction)}, 'scannedBy', {quote(scanned_by)}, 'scannedAt', to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS'))
            )
          ),
          updated_at = now()
        WHERE id = {quote(pass_id)} AND data->>'gateToken' = {quote(token)} AND data->>'status' = 'Approved'
          -- Every pass is one round trip (Exit+Entry, or Entry+Exit for a Visit Pass), not a
          -- repeatable in/out toggle - once both directions are already on file, reject further
          -- scans server-side too (the gate-scan page itself already stops offering the buttons,
          -- this is the same rule enforced against a stale page or a direct API call).
          AND NOT (
            EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(data->'gateLog', '[]'::jsonb)) e WHERE e->>'direction' = 'Exit')
            AND EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(data->'gateLog', '[]'::jsonb)) e WHERE e->>'direction' = 'Entry')
          )
        RETURNING json_build_array(data)::json AS row;
        """,
        [],
    )
    return rows[0] if rows else None


# Campus Event registrations get a single-record upsert rather than replace_student_submissions'
# delete-then-reinsert-by-id shape - a student only ever has one registration record for
# themselves (id = "{eventId}:{rollNo}"), never a personal list they manage/prune, so there's no
# "delete anything the client didn't send" semantics to reuse, and reusing that shape here would
# risk a lost-update race (a stale full-array snapshot from one student's page silently deleting
# another student's just-inserted row).
def upsert_campus_event_registration(record):
    # Enforces an optional per-event registration cap (event.capacity, set by admin/faculty head)
    # server-side - this is the authoritative check; the UI also pre-checks client-side using the
    # cached registration count for immediate feedback, but that snapshot can race between two
    # students registering close together, so the real limit has to be enforced here. Only blocks
    # a genuinely NEW registration - re-saving your own existing one (e.g. regenerating a ticket)
    # must never get rejected by a cap that only counts new signups, so an existing row for this
    # exact id is always allowed through regardless of how full the event is.
    reg_id = record.get("id")
    event_id = record.get("eventId")
    events = run_json("SELECT content_value FROM site_content WHERE content_key = 'campusEvents';", [])
    event = next((e for e in events if e.get("id") == event_id), None) if isinstance(events, list) else None
    capacity = (event or {}).get("capacity")
    if capacity:
        already_registered = run_json(f"SELECT COUNT(*)::int FROM campus_event_registrations WHERE id = {quote(reg_id)};", 0)
        if not already_registered:
            current_count = run_json(f"SELECT COUNT(*)::int FROM campus_event_registrations WHERE data->>'eventId' = {quote(event_id)};", 0)
            if current_count >= int(capacity):
                return False
    run_psql(f"""
        INSERT INTO campus_event_registrations (id, data) VALUES ({quote(reg_id)}, {quote(json.dumps(record))}::jsonb)
        ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now();
    """)
    return True


# Self-service account for an outside-college visitor - same email+password hash/salt shape as
# create_alumni_account, own table (event_visitor_accounts) since these aren't alumni. Upserts
# rather than rejecting a repeat email so someone registering for a second public event with the
# same address just re-confirms their existing password rather than erroring.
def create_event_visitor_account(email, password, name, phone, college):
    salt_hex, hash_hex = hash_password(password)
    run_psql(f"""
        INSERT INTO event_visitor_accounts (email, password_hash, password_salt, name, phone, college)
        VALUES ({quote(email)}, {quote(hash_hex)}, {quote(salt_hex)}, {quote(name)}, {quote(phone)}, {quote(college)})
        ON CONFLICT (email) DO UPDATE SET
            password_hash = EXCLUDED.password_hash, password_salt = EXCLUDED.password_salt,
            name = EXCLUDED.name, phone = EXCLUDED.phone, college = EXCLUDED.college, updated_at = now();
    """)


def verify_event_visitor_login(email, password):
    row = run_json(f"""
        SELECT COALESCE((SELECT json_build_object('passwordHash', password_hash, 'passwordSalt', password_salt, 'name', name)
        FROM event_visitor_accounts WHERE email = {quote(email)}), 'null'::json);
    """, None)
    if not row or not row.get("passwordHash"):
        return None
    if not verify_password(password, row["passwordSalt"], row["passwordHash"]):
        return None
    return {"email": email, "name": row.get("name")}


# Forgot-password for a visitor account - no email/OTP delivery infra exists in this app to prove
# inbox ownership, so this checks the phone number they gave at registration instead (the same
# "something they already gave us, not a newly collected secret" shape as alumni_identity_matches'
# batchYear check) rather than accepting a bare email with no verification at all.
def event_visitor_identity_matches(email, phone):
    return run_psql(
        f"SELECT COALESCE((SELECT true FROM event_visitor_accounts WHERE email = {quote(email)} AND phone = {quote(phone)}), false);"
    ).strip().lower() == "t"


def reset_event_visitor_password(email, new_password):
    salt_hex, hash_hex = hash_password(new_password)
    run_psql(f"""
        UPDATE event_visitor_accounts SET password_hash = {quote(hash_hex)}, password_salt = {quote(salt_hex)}, updated_at = now()
        WHERE email = {quote(email)};
    """)


# Shared by both a brand-new public registration (register_for_public_event, which also creates
# the visitor's account) and an already-signed-in visitor registering for a second/third event
# (register_existing_visitor_for_event, which reuses their existing account's details) - the event
# validation, fee/payment check, and record shape are identical either way. Reuses
# upsert_campus_event_registration as-is, so the same capacity cap and single-record-upsert safety
# already covers external registrants too - the id just uses "ext:{email}" instead of a roll
# number, since external registrants don't have one.
def _build_and_insert_public_registration(event_id, name, email, phone, college, payment_type, payment_reference):
    cleanup_completed_public_events()
    events = run_json("SELECT content_value FROM site_content WHERE content_key = 'campusEvents';", [])
    event = next((e for e in events if e.get("id") == event_id), None) if isinstance(events, list) else None
    if not event or not event.get("isPublic"):
        return None, "This event is not open for public registration."
    fee = float(event.get("fee") or 0)
    # Payment itself isn't verified server-side (matches this app's existing PayU pattern for
    # students - see openPayuCheckoutAndRecord in script.js, a hosted-checkout-link + trust-the-
    # payer flow with no webhook yet), but a paid event still requires the client to have gone
    # through that checkout-open step and gotten a reference back before the registration counts.
    if fee > 0 and not payment_reference:
        return None, "Payment is required for this event."
    reg_id = f"{event_id}:ext:{email}"
    already_registered = run_json(f"SELECT COUNT(*)::int FROM campus_event_registrations WHERE id = {quote(reg_id)};", 0)
    if already_registered:
        return None, "Already registered for this event."
    record = {
        "id": reg_id,
        "eventId": event_id,
        "eventName": event.get("title"),
        "participantName": name,
        "rollNumber": None,
        "email": email,
        "phone": (phone or "").strip(),
        "college": (college or "").strip(),
        "isExternal": True,
        "fee": fee,
        "paymentType": payment_type or ("Online Payment" if fee > 0 else "Free"),
        "paymentReference": payment_reference or "-",
        "paymentStatus": "Paid" if fee > 0 else "Registered",
        "registeredAt": datetime.datetime.utcnow().isoformat() + "Z",
        # Generated here, not via ensureEventGateToken's usual client-side read-back-from-bootstrap
        # path - an anonymous public registrant has no session, and campusEventRegistrations
        # (everyone's names/emails/phones) is deliberately not exposed in the public bootstrap, so
        # the client has no way to read this back after the fact. Returning it directly in the
        # response is the only path available.
        "gateToken": secrets.token_hex(16),
    }
    if not upsert_campus_event_registration(record):
        return None, "Registration limit reached for this event."
    return record, None


# Public/external event registration - no GPREC login at all up front, for outside-college
# visitors, but registering creates a real account (email+password, self-chosen) so they can log
# back in later rather than only ever having the one downloaded ticket image. Only events an admin
# explicitly marked event.isPublic=true accept this (server-checked here, never client-trusted).
def register_for_public_event(event_id, name, email, phone, college, password, payment_type=None, payment_reference=None):
    name = (name or "").strip()
    email = (email or "").strip().lower()
    if not name or not email or "@" not in email:
        return None, "A valid name and email are required."
    if not password or len(password) < 6:
        return None, "Choose a password of at least 6 characters."
    record, error = _build_and_insert_public_registration(event_id, name, email, phone, college, payment_type, payment_reference)
    if not record:
        return None, error
    create_event_visitor_account(email, password, name, phone, college)
    return record, None


# An already-signed-in visitor (registered for a previous event) registering for another public
# event - reuses their existing account's name/phone/college instead of asking for them (and a new
# password) again. Identity comes from the session (require_auth), never a client-supplied email.
def register_existing_visitor_for_event(identity_email, event_id, payment_type=None, payment_reference=None):
    account = run_json(
        f"SELECT COALESCE((SELECT json_build_object('name', name, 'phone', phone, 'college', college) "
        f"FROM event_visitor_accounts WHERE email = {quote(identity_email)}), 'null'::json);",
        None,
    )
    if not account:
        return None, "Account not found."
    return _build_and_insert_public_registration(
        event_id, account.get("name"), identity_email, account.get("phone"), account.get("college"),
        payment_type, payment_reference,
    )


def delete_event_visitor_account(identity_email):
    email = (identity_email or "").strip().lower()
    if not email:
        return
    run_psql(f"DELETE FROM campus_event_registrations WHERE lower(data->>'email') = {quote(email)} AND data->>'isExternal' = 'true';")
    run_psql(f"DELETE FROM event_visitor_accounts WHERE lower(email) = {quote(email)};")
    revoke_all_sessions("event_visitor", email)


# Deletes an event's registrations and, for each external registrant, their visitor account too -
# but only once they have no OTHER remaining registration elsewhere (one email can register for
# several public events; deleting the account the moment any single one of those ends would lock
# them out of a still-open registration). Called both when an admin explicitly removes an event
# and opportunistically from cleanup_completed_public_events for events whose date has passed.
def remove_campus_event_registrations(event_id):
    emails = run_json(
        f"SELECT COALESCE(json_agg(DISTINCT data->>'email'), '[]'::json) FROM campus_event_registrations "
        f"WHERE data->>'eventId' = {quote(event_id)} AND data->>'isExternal' = 'true';",
        [],
    )
    run_psql(f"DELETE FROM campus_event_registrations WHERE data->>'eventId' = {quote(event_id)};")
    for email in emails or []:
        if not email:
            continue
        still_registered = run_psql(f"SELECT 1 FROM campus_event_registrations WHERE data->>'email' = {quote(email)} LIMIT 1;").strip()
        if not still_registered:
            run_psql(f"DELETE FROM event_visitor_accounts WHERE email = {quote(email)};")


def cleanup_completed_public_events():
    events = run_json("SELECT content_value FROM site_content WHERE content_key = 'campusEvents';", [])
    if not isinstance(events, list):
        return
    today = datetime.date.today().isoformat()
    expired_ids = [e.get("id") for e in events if e.get("isPublic") and e.get("date") and e.get("date") < today]
    if not expired_ids:
        return
    remaining = [e for e in events if e.get("id") not in expired_ids]
    upsert_site_content("campusEvents", json.dumps(remaining))
    for event_id in expired_ids:
        remove_campus_event_registrations(event_id)


# Event pass gate scanning - same gateToken/checkIn-inside-the-JSONB-blob technique as the hostel
# gate passes above, simplified to a single check-in (no Exit/Entry round trip - a ticket is used
# once, then it's used). Both 'Paid' and 'Registered' payment statuses are valid (free events never
# reach 'Paid'), unlike the hostel passes' single 'Approved' status check.
def campus_event_gate_lookup(event_id, reg_id, token):
    rows = run_json(
        f"SELECT COALESCE(json_agg(data), '[]'::json) FROM campus_event_registrations "
        f"WHERE id = {quote(reg_id)} AND data->>'eventId' = {quote(event_id)} AND data->>'gateToken' = {quote(token)} "
        f"AND data->>'paymentStatus' IN ('Paid', 'Registered');",
        [],
    )
    return rows[0] if rows else None


def campus_event_gate_log_append(event_id, reg_id, token, scanned_by):
    rows = run_json(
        f"""
        UPDATE campus_event_registrations SET
          data = jsonb_set(
            data, '{{checkIn}}',
            jsonb_build_object('scannedBy', {quote(scanned_by)}, 'scannedAt', to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS'))
          ),
          updated_at = now()
        WHERE id = {quote(reg_id)} AND data->>'eventId' = {quote(event_id)} AND data->>'gateToken' = {quote(token)}
          AND data->>'paymentStatus' IN ('Paid', 'Registered')
          AND data->'checkIn' IS NULL
        RETURNING json_build_array(data)::json AS row;
        """,
        [],
    )
    return rows[0] if rows else None


# Campus Events themselves (title/date/venue/fee/description) live under the generic
# site_content key "campusEvents" - normally admin-only via /api/site-content. A faculty member
# assigned as an event's "Faculty Head" (event.facultyHeadEmail) needs to manage that one event's
# own details too, not just view its registrants, so this is a purpose-built endpoint with its own
# permission check rather than reusing the generic admin-only one: allowed if the caller is an
# admin, OR a faculty identity whose email matches the event's CURRENT facultyHeadEmail. Only an
# admin may reassign facultyHeadEmail itself - the current head can't hand off/lock out admin
# control by changing who else is allowed to manage the event.
def campus_event_manual_checkin(event_id, roll_number, email, scanned_by):
    # QR-fallback lookup for student volunteers: internal attendees can be checked in by roll
    # number, and outside-college/event-visitor attendees by email.
    roll_number = (roll_number or "").strip().upper()
    email = (email or "").strip().lower()
    if not roll_number and not email:
        return None
    identity_clause = (
        f"data->>'rollNumber' = {quote(roll_number)}"
        if roll_number
        else f"lower(data->>'email') = {quote(email)}"
    )
    rows = run_json(
        f"""
        UPDATE campus_event_registrations SET
          data = jsonb_set(data, '{{checkIn}}', jsonb_build_object('scannedBy', {quote(scanned_by)}, 'scannedAt', to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS'), 'manual', true)),
          updated_at = now()
        WHERE data->>'eventId' = {quote(event_id)} AND ({identity_clause})
          AND data->>'paymentStatus' IN ('Paid', 'Registered') AND data->'checkIn' IS NULL
        RETURNING json_build_array(data)::json AS row;
        """,
        [],
    )
    return rows[0] if rows else None


def reset_campus_event_checkins(event_id=None):
    event_filter = f"AND data->>'eventId' = {quote(event_id)}" if event_id else ""
    run_psql(f"""
        UPDATE campus_event_registrations
        SET data = data - 'checkIn', updated_at = now()
        WHERE data ? 'checkIn' {event_filter};
    """)


def update_campus_event_as_head(identity, event_id, fields):
    rows = run_json("SELECT content_value FROM site_content WHERE content_key = 'campusEvents';", [])
    events = rows if isinstance(rows, list) else []
    index = next((i for i, item in enumerate(events) if item.get("id") == event_id), None)
    if index is None:
        return None
    event = events[index]
    is_admin = identity["identityType"] == "admin"
    is_head = identity["identityType"] == "faculty" and (event.get("facultyHeadEmail") or "").lower() == (identity["identityId"] or "").lower()
    if not (is_admin or is_head):
        return None
    editable_fields = ["title", "date", "venue", "fee", "description", "capacity"] + (["facultyHeadEmail", "isPublic"] if is_admin else [])
    for key in editable_fields:
        if key in fields:
            event[key] = fields[key]
    events[index] = event
    upsert_site_content("campusEvents", json.dumps(events))
    return event


# College Fest activities (a separate feature from the public-facing Campus Events above - no
# registration/fees/gate scanning, just an activity - published by admin or by an approved faculty
# coordinator - that gets staffed with student volunteers by roll number). Same "purpose-built
# endpoint, own permission check" shape as update_campus_event_as_head: an admin, or the faculty
# identity matching the activity's CURRENT facultyCoordinatorEmail, may update it - only an admin
# may reassign the coordinator itself (handing that off would otherwise let a coordinator lock
# admin out of their own activity).
def update_fest_activity(identity, activity_id, fields):
    rows = run_json("SELECT content_value FROM site_content WHERE content_key = 'festActivities';", [])
    activities = rows if isinstance(rows, list) else []
    index = next((i for i, item in enumerate(activities) if item.get("id") == activity_id), None)
    if index is None:
        return None
    activity = activities[index]
    is_admin = identity["identityType"] == "admin"
    is_coordinator = identity["identityType"] == "faculty" and (activity.get("facultyCoordinatorEmail") or "").lower() == (identity["identityId"] or "").lower()
    if not (is_admin or is_coordinator):
        return None
    editable_fields = ["volunteers", "title", "date", "time", "venue", "description"] + (["facultyCoordinatorEmail"] if is_admin else [])
    for key in editable_fields:
        if key in fields:
            activity[key] = fields[key]
    if "volunteers" in fields:
        activity["volunteers"] = sorted({str(roll).strip().upper() for roll in (fields["volunteers"] or []) if str(roll).strip()})
    activities[index] = activity
    upsert_site_content("festActivities", json.dumps(activities))
    return activity


# Admin can publish a fest activity for any coordinator directly (via the generic admin-only
# /api/site-content, same as Campus Events). A faculty member creating their OWN activity goes
# through this instead, gated on the festCoordinators allowlist (site_content key
# "festCoordinators", an array of emails admin maintains) - otherwise any faculty login could
# publish fest activities for themselves with no admin involvement at all.
def create_fest_activity(identity, fields):
    if identity["identityType"] != "faculty":
        return None
    coordinators_rows = run_json("SELECT content_value FROM site_content WHERE content_key = 'festCoordinators';", [])
    coordinators = coordinators_rows if isinstance(coordinators_rows, list) else []
    approved = {str(email).strip().lower() for email in coordinators}
    if (identity["identityId"] or "").lower() not in approved:
        return None
    rows = run_json("SELECT content_value FROM site_content WHERE content_key = 'festActivities';", [])
    activities = rows if isinstance(rows, list) else []
    activity = {
        "id": f"fest-activity-{secrets.token_hex(6)}",
        "title": fields.get("title", ""),
        "date": fields.get("date", ""),
        "time": fields.get("time", ""),
        "venue": fields.get("venue", ""),
        "description": fields.get("description", ""),
        "facultyCoordinatorEmail": identity["identityId"],
        "volunteers": []
    }
    activities.append(activity)
    upsert_site_content("festActivities", json.dumps(activities))
    return activity


def create_student_document(payload):
    run_psql(f"""
        INSERT INTO student_documents (student_roll_no, doc_type, file_name, file_url, file_mime)
        VALUES ({quote(payload.get('studentId'))}, {quote(payload.get('docType'))},
                {quote(payload.get('fileName'))}, {quote(payload.get('fileUrl'))}, {quote(payload.get('fileMime'))});
    """)


def create_course_material(payload):
    run_psql(f"""
        INSERT INTO course_materials (subject_code, title, description, file_name, file_url, file_mime)
        VALUES ({quote(payload.get('subjectCode'))}, {quote(payload.get('title'))}, {quote(payload.get('description'))},
                {quote(payload.get('fileName'))}, {quote(payload.get('fileUrl'))}, {quote(payload.get('fileMime'))});
    """)


def set_book_favorites(identity, favorites):
    run_psql(f"""
        INSERT INTO book_favorites (identity, favorites) VALUES ({quote(identity)}, {quote(json.dumps(favorites))}::jsonb)
        ON CONFLICT (identity) DO UPDATE SET favorites = EXCLUDED.favorites, updated_at = now();
    """)


def record_ai_usage(partial):
    # Prefer server-side increments so counters stay accurate across browsers/tabs. Absolute SET
    # keys are still accepted for backwards compatibility with older clients.
    run_psql("INSERT INTO ai_usage_stats (id) VALUES (true) ON CONFLICT (id) DO NOTHING;")
    absolute_map = [
        ("attempts", "attempts"), ("successes", "successes"), ("failures", "failures"),
        ("rate_limited", "rateLimited"), ("blocked", "blocked"), ("off_topic", "offTopic")
    ]
    delta_map = [
        ("attempts", "attemptsDelta"), ("successes", "successesDelta"), ("failures", "failuresDelta"),
        ("rate_limited", "rateLimitedDelta"), ("blocked", "blockedDelta"), ("off_topic", "offTopicDelta")
    ]
    clauses = [f"{col} = {quote(partial.get(key))}" for col, key in absolute_map if partial.get(key) is not None]
    clauses += [f"{col} = {col} + {int(partial.get(key) or 0)}" for col, key in delta_map if partial.get(key) is not None]
    for col, key in [("last_provider", "lastProvider"), ("last_error", "lastError")]:
        if partial.get(key) is not None:
            clauses.append(f"{col} = {quote(partial.get(key))}")
    if clauses:
        run_psql(f"UPDATE ai_usage_stats SET {', '.join(clauses)}, last_used_at = now() WHERE id = true;")


def record_ai_request_log(entry):
    run_psql(f"""
        INSERT INTO ai_request_log (provider, model, status, latency_ms, error)
        VALUES ({quote(entry.get('provider'))}, {quote(entry.get('model'))}, {quote(entry.get('status'))},
                {quote(entry.get('latencyMs'))}, {quote(entry.get('error'))});
        DELETE FROM ai_request_log WHERE id NOT IN (SELECT id FROM ai_request_log ORDER BY created_at DESC LIMIT 20);
    """)


def reset_ai_usage():
    run_psql("""
        INSERT INTO ai_usage_stats (id) VALUES (true) ON CONFLICT (id) DO NOTHING;
        UPDATE ai_usage_stats SET attempts = 0, successes = 0, failures = 0, rate_limited = 0,
          blocked = 0, off_topic = 0, last_used_at = NULL, last_provider = NULL, last_error = NULL
        WHERE id = true;
        DELETE FROM ai_request_log;
    """)


def record_activity(scope, actor, action, module):
    run_psql(f"""
        INSERT INTO activity_log (scope, actor, action, module) VALUES ({quote(scope)}, {quote(actor)}, {quote(action)}, {quote(module)});
    """)


def create_funding_contribution(payload):
    run_psql(f"""
        INSERT INTO funding_contributions (campaign_id, contributor_name, contributor_email, amount, payment_id)
        VALUES ({quote(payload.get('campaignId'))}, {quote(payload.get('name'))}, {quote(payload.get('email'))},
                {quote(payload.get('amount'))}, {quote(payload.get('paymentId'))});
    """)


def upsert_faculty_row(payload):
    run_psql(f"""
        INSERT INTO faculty (full_name, email, department_code, designation, qualifications, google_scholar, apaar_id, vidwan_profile, phone, primary_subject, subject_code, status)
        VALUES ({quote(payload.get('name'))}, {quote(payload.get('email'))}, {quote(payload.get('department'))},
                {quote(payload.get('designation'))}, {quote(payload.get('qualifications'))}, {quote(payload.get('googleScholar'))},
                {quote(payload.get('apaarId'))}, {quote(payload.get('vidwanProfile'))}, {quote(payload.get('phone'))},
                {quote(payload.get('primarySubject'))}, {quote(payload.get('subjectCode'))}, 'Active')
        ON CONFLICT (email) DO UPDATE SET
            full_name = EXCLUDED.full_name, department_code = EXCLUDED.department_code,
            designation = EXCLUDED.designation, qualifications = EXCLUDED.qualifications,
            google_scholar = EXCLUDED.google_scholar, apaar_id = EXCLUDED.apaar_id,
            vidwan_profile = EXCLUDED.vidwan_profile, phone = EXCLUDED.phone,
            primary_subject = EXCLUDED.primary_subject, subject_code = EXCLUDED.subject_code, status = 'Active';
    """)


def remove_faculty_row(email):
    run_psql(f"UPDATE faculty SET status = 'Removed' WHERE email = {quote(email)};")


def replace_library_records(records):
    values = []
    for item in records:
        barcode = item.get("barcode") or item.get("bookId") or item.get("bookTitle")
        if not barcode:
            continue
        run_psql(
            "INSERT INTO library_books (barcode, title, author) VALUES "
            f"({quote(barcode)}, {quote(item.get('bookTitle') or barcode)}, {quote(item.get('author') or '-')}) "
            "ON CONFLICT (barcode) DO UPDATE SET title = EXCLUDED.title, author = EXCLUDED.author;"
        )
        values.append(
            "("
            + ", ".join(
                [
                    quote(barcode),
                    quote(item.get("rollNumber")),
                    quote(item.get("issueDate")),
                    quote(item.get("dueDate")),
                    quote(item.get("returnDate")),
                    quote(item.get("status") or "Issued"),
                ]
            )
            + ")"
        )
    sql = "BEGIN; TRUNCATE library_issues RESTART IDENTITY;"
    if values:
        sql += """
        INSERT INTO library_issues (barcode, student_roll_no, issued_on, due_on, returned_on, status)
        VALUES """ + ",".join(values) + ";"
    sql += " COMMIT;"
    run_psql(sql)


class PortalHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        # A wildcard origin paired with bearer-token auth is the one combination CORS treats as
        # unsafe - only echo back an allowed origin instead. Add real deployed origin(s) here once
        # this is hosted somewhere other than the local dev server.
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        if not self.path.startswith("/api/") and re.search(r"\.(?:html|css|js|json)$", urlparse(self.path).path):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode("utf-8") or "null")

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        try:
            if path == "/api/captcha/math":
                question, token = generate_math_captcha()
                self.send_json(200, {"ok": True, "question": question, "token": token})
                return
            if path == "/api/bank-details":
                identity = require_auth(self)
                if not identity:
                    return
                key = (query.get("key") or [""])[0]
                if not key:
                    self.send_json(400, {"ok": False, "error": "key is required"})
                    return
                if identity["identityType"] not in ("admin", "non_teaching") and not owns_key(identity, key):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                self.send_json(200, {"details": get_bank_details(key)})
                return
            if path == "/api/payment-history":
                identity = require_auth(self)
                if not identity:
                    return
                student_id = (query.get("studentId") or [""])[0]
                if not student_id:
                    self.send_json(400, {"ok": False, "error": "studentId is required"})
                    return
                if identity["identityType"] in ("student", "parent") and identity["identityId"] != student_id:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                self.send_json(200, {"history": get_payment_history(student_id)})
                return
            if path == "/api/internal-marks/mine":
                identity = require_auth(self, allowed_types=["student"])
                if not identity:
                    return
                self.send_json(200, {"marks": get_internal_marks_for_student(identity["identityId"])})
                return
            if path == "/api/internal-marks/by-subject":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                subject_code = (query.get("subjectCode") or [""])[0]
                section = (query.get("section") or [""])[0]
                academic_year = (query.get("academicYear") or [""])[0]
                if not subject_code or not section or not academic_year:
                    self.send_json(400, {"ok": False, "error": "subjectCode, section and academicYear are required"})
                    return
                self.send_json(200, {"marks": get_internal_marks_for_subject(subject_code, section, academic_year)})
                return
            if path == "/api/leave-balance":
                identity = require_auth(self, allowed_types=["faculty", "non_teaching"])
                if not identity:
                    return
                self.send_json(200, get_leave_balance(identity["identityType"], identity["identityId"]))
                return
            if path == "/api/attendance-shortage-report":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                department_code = (query.get("departmentCode") or [""])[0]
                if not department_code:
                    self.send_json(400, {"ok": False, "error": "departmentCode is required"})
                    return
                self.send_json(200, {"rows": get_attendance_shortage_report(department_code)})
                return
            if path == "/api/attendance-section-report":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                department_code = (query.get("departmentCode") or [""])[0]
                if not department_code:
                    self.send_json(400, {"ok": False, "error": "departmentCode is required"})
                    return
                from_date = (query.get("fromDate") or [""])[0]
                to_date = (query.get("toDate") or [""])[0]
                section = (query.get("section") or [""])[0]
                self.send_json(200, {"rows": get_attendance_section_report(department_code, from_date, to_date, section)})
                return
            if path == "/api/department-sections":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                department_code = (query.get("departmentCode") or [""])[0]
                if not department_code:
                    self.send_json(400, {"ok": False, "error": "departmentCode is required"})
                    return
                self.send_json(200, {"sections": get_department_sections(department_code)})
                return
            if path == "/api/students/lookup-name":
                roll_no = (query.get("rollNo") or [""])[0].strip()
                self.send_json(200, {"name": lookup_student_name(roll_no) if roll_no else None})
                return
            if path == "/api/health":
                self.send_json(200, check_database_health())
                return
            if path == "/api/db-stats":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                self.send_json(200, check_database_stats())
                return
            if path == "/api/data-retention/check":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                self.send_json(200, check_data_retention())
                return
            if path == "/api/finance/export":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                self.send_json(200, {"payments": get_finance_export()})
                return
            if path == "/api/bootstrap":
                identity = authenticate(self)
                self.send_json(200, run_json(BOOTSTRAP_SQL, {}) if identity else run_json(PUBLIC_BOOTSTRAP_SQL, {}))
                return
            if path == "/api/catalog":
                self.send_json(200, run_json("SELECT COALESCE(json_object_agg(barcode, json_build_object('title', title, 'author', author)), '{}'::json) FROM library_books;", {}))
                return
            if path == "/api/issued-books":
                if not require_auth(self):
                    return
                self.send_json(200, run_json(BOOTSTRAP_SQL, {}).get("libraryRecords", []))
                return
            if path == "/api/auth/has-admin-credentials":
                # Public and deliberately narrow (just a boolean) - admin-login.html's
                # "First-Time Setup" card needs to know whether to show itself before anyone has
                # ever logged in, but the full email/status listing that /api/auth/credentials
                # returns is real staff-roster data and stays admin-only below.
                self.send_json(200, {"hasAdmin": any_admin_credentials_exist()})
                return
            if path == "/api/auth/credentials":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                self.send_json(200, run_json(CREDENTIALS_LIST_SQL, []))
                return
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})
            return
        super().do_GET()

    def do_PUT(self):
        self.do_POST()

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            payload = self.read_json()
            if path == "/api/complaints":
                if not require_auth(self):
                    return
                replace_complaints(payload or [])
                self.send_json(200, run_json(BOOTSTRAP_SQL, {}).get("complaints", []))
                return
            if path == "/api/placement-drives/create":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                create_placement_drive(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/placement-drives/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                remove_placement_drive((payload or {}).get("id") or "")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/exam-schedules":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                replace_exam_schedules(payload or {})
                self.send_json(200, run_json(BOOTSTRAP_SQL, {}).get("examCellData", {}))
                return
            if path == "/api/pending-fees":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                replace_pending_fees(payload or {})
                self.send_json(200, run_json(BOOTSTRAP_SQL, {}).get("pendingFees", {}))
                return
            if path == "/api/issued-books":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                replace_library_records(payload or [])
                self.send_json(200, run_json(BOOTSTRAP_SQL, {}).get("libraryRecords", []))
                return
            if path == "/api/auth/set-password":
                # Genesis exception: admin-login.html's "First-Time Setup" card (see
                # adminFirstSetupCard in script.js) calls this before anyone has ever logged in,
                # to create the very first admin's credentials - there's no admin session to
                # require yet in that one case. Only allowed through unauthenticated when zero
                # admin credentials exist anywhere; the moment one does, every call here (setting
                # up faculty/non-teaching/further admins) requires a real admin session again.
                if any_admin_credentials_exist() and not require_auth(self, allowed_types=["admin"]):
                    return
                email = (payload.get("email") or "").strip().lower()
                role_type = payload.get("roleType") or ""
                full_name = payload.get("fullName") or email
                recovery_mobile = payload.get("recoveryMobile") or ""
                if not email or not role_type or not recovery_mobile:
                    self.send_json(400, {"ok": False, "error": "email, roleType and recoveryMobile are required"})
                    return
                generated_password = generate_password()
                set_credential_row(email, role_type, full_name, recovery_mobile, generated_password)
                self.send_json(200, {"ok": True, "email": email, "generatedPassword": generated_password})
                return
            if path == "/api/auth/login":
                email = (payload.get("email") or "").strip().lower()
                password = payload.get("password") or ""
                role_type = payload.get("roleType") or ""
                throttle_key = f"login:{email}"
                if check_throttle(throttle_key):
                    self.send_json(200, {"ok": False, "reason": "locked"})
                    return
                row = get_credential_row(email, role_type)
                if not row:
                    self.send_json(200, {"ok": False, "reason": "no-credentials"})
                    return
                if not verify_password(password, row["passwordSalt"], row["passwordHash"]):
                    record_failed_attempt(email)
                    record_throttle_failure(throttle_key)
                    self.send_json(200, {"ok": False, "reason": "bad-password"})
                    return
                clear_throttle(throttle_key)
                reset_failed_attempts(email)
                expired = (time.time() - row["passwordSetAt"]) > PASSWORD_MAX_AGE_SECONDS
                must_change = bool(row["mustChangePassword"]) or expired
                response = {"ok": True, "mustChange": must_change}
                if not must_change:
                    # Token issuance is deliberately skipped when a forced reset is pending, so the
                    # change-password step can't be bypassed by just reusing this response's token.
                    role_label = None
                    if role_type == "admin":
                        admin_row = get_admin_row(email)
                        role_label = admin_row.get("role") if admin_row else None
                    response["token"] = create_session(role_type, email, role_label)
                self.send_json(200, response)
                return
            if path == "/api/auth/change-password":
                email = (payload.get("email") or "").strip().lower()
                role_type = payload.get("roleType") or ""
                old_password = payload.get("oldPassword") or ""
                new_password = payload.get("newPassword") or ""
                if not new_password or len(new_password) < 8:
                    self.send_json(400, {"ok": False, "error": "New password must be at least 8 characters."})
                    return
                row = get_credential_row(email, role_type) if role_type else get_credential_row(email)
                if not row or not verify_password(old_password, row["passwordSalt"], row["passwordHash"]):
                    self.send_json(200, {"ok": False, "reason": "bad-password"})
                    return
                update_password(email, new_password, role_type or None)
                effective_role_type = role_type or row.get("roleType")
                revoke_all_sessions(effective_role_type, email)
                role_label = None
                if effective_role_type == "admin":
                    admin_row = get_admin_row(email)
                    role_label = admin_row.get("role") if admin_row else None
                token = create_session(effective_role_type, email, role_label)
                self.send_json(200, {"ok": True, "token": token})
                return
            if path == "/api/auth/logout":
                auth_header = self.headers.get("Authorization") or ""
                if auth_header.startswith("Bearer "):
                    revoke_session(auth_header[len("Bearer "):].strip())
                self.send_json(200, {"ok": True})
                return
            if path == "/api/auth/verify-identity":
                email = (payload.get("email") or "").strip().lower()
                recovery_mobile = payload.get("recoveryMobile") or ""
                throttle_key = f"reset:{email}"
                if check_throttle(throttle_key):
                    self.send_json(200, {"ok": False, "reason": "locked"})
                    return
                matched = identity_matches(email, recovery_mobile)
                if not matched:
                    record_throttle_failure(throttle_key)
                else:
                    clear_throttle(throttle_key)
                self.send_json(200, {"ok": matched})
                return
            if path == "/api/auth/reset-password":
                email = (payload.get("email") or "").strip().lower()
                recovery_mobile = payload.get("recoveryMobile") or ""
                new_password = payload.get("newPassword") or ""
                throttle_key = f"reset:{email}"
                if check_throttle(throttle_key):
                    self.send_json(200, {"ok": False, "reason": "locked"})
                    return
                if not new_password or len(new_password) < 8:
                    self.send_json(400, {"ok": False, "error": "New password must be at least 8 characters."})
                    return
                if not identity_matches(email, recovery_mobile):
                    record_throttle_failure(throttle_key)
                    self.send_json(200, {"ok": False, "reason": "identity-mismatch"})
                    return
                clear_throttle(throttle_key)
                update_password(email, new_password)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/auth/student-login":
                # Previously student login never touched the backend at all - roll+DOB was
                # compared purely client-side against data already sitting in the browser
                # (getGprecDbBootstrap().studentProfiles), which isn't really verification. This
                # is the first real server-side check for this role.
                roll_no = (payload.get("rollNo") or "").strip().upper()
                dob_digits = re.sub(r"\D", "", payload.get("dob") or "")
                throttle_key = f"student:{roll_no}"
                if check_throttle(throttle_key):
                    self.send_json(200, {"ok": False, "reason": "locked"})
                    return
                if not roll_no or len(dob_digits) != 8:
                    self.send_json(400, {"ok": False, "error": "rollNo and an 8-digit dob are required"})
                    return
                matched = run_psql(
                    f"SELECT 1 FROM students WHERE roll_no = {quote(roll_no)} AND status = 'Active' "
                    f"AND date_of_birth = to_date({quote(dob_digits)}, 'DDMMYYYY');"
                ).strip()
                if not matched:
                    record_throttle_failure(throttle_key)
                    self.send_json(200, {"ok": False, "reason": "no-match"})
                    return
                clear_throttle(throttle_key)
                token = create_session("student", roll_no)
                self.send_json(200, {"ok": True, "rollNo": roll_no, "token": token})
                return
            if path == "/api/auth/parent-otp/request":
                mobile = normalize_mobile(payload.get("mobile") or "")
                client_ip = self.client_address[0]
                # Rate-limited independently by mobile AND by IP, so neither "many mobiles from one
                # IP" nor "one mobile retried behind many IPs" escapes throttling on its own.
                mobile_throttle_key = f"parent-otp:{mobile}"
                ip_throttle_key = f"parent-otp-ip:{client_ip}"
                if check_throttle(mobile_throttle_key) or check_throttle(ip_throttle_key):
                    self.send_json(200, {"ok": False, "reason": "locked"})
                    return
                if not mobile:
                    self.send_json(400, {"ok": False, "error": "mobile is required"})
                    return
                recent = run_json(
                    "SELECT COALESCE((SELECT json_build_object("
                    "'count', count(*), 'lastCreatedAt', extract(epoch FROM max(created_at))"
                    f") FROM otp_challenges WHERE mobile = {quote(mobile)} AND created_at > now() - INTERVAL '15 minutes'), "
                    "json_build_object('count', 0, 'lastCreatedAt', null));",
                    {"count": 0, "lastCreatedAt": None},
                )
                if recent["lastCreatedAt"] and (time.time() - recent["lastCreatedAt"]) < 45:
                    self.send_json(200, {"ok": False, "reason": "cooldown"})
                    return
                if recent["count"] >= 3:
                    self.send_json(200, {"ok": False, "reason": "too-many-resends"})
                    return
                roll_no = run_psql(
                    f"SELECT student_roll_no FROM guardians WHERE guardian_mobile = {quote(mobile)} LIMIT 1;"
                ).strip()
                if not roll_no:
                    record_throttle_failure(mobile_throttle_key)
                    record_throttle_failure(ip_throttle_key)
                    # Deliberately the same shape as the success response below (no "reason" that
                    # distinguishes "mobile not registered" from anything else) - the one exception
                    # this local app can't avoid is that a match includes an "otp" field and this
                    # doesn't, since there's no SMS gateway to deliver it out-of-band instead. A
                    # real deployment with SMS delivery would make this response identical too.
                    self.send_json(200, {"ok": True})
                    return
                otp = f"{secrets.randbelow(1_000_000):06d}"
                run_psql(f"""
                    INSERT INTO otp_challenges (mobile, student_roll_no, otp_hash, expires_at)
                    VALUES ({quote(mobile)}, {quote(roll_no)}, {quote(hash_token(otp))}, now() + INTERVAL '5 minutes');
                """)
                # Never logged: the default request logger only records the method/path/status
                # line, never the JSON body this OTP travels in.
                sent, _channel, _error = deliver_parent_otp(mobile, otp)
                if sent:
                    # Real delivery (SMS, or WhatsApp fallback) - the response now matches the "no
                    # such mobile" branch above exactly (no otp field either way), closing the one
                    # enumeration gap that was unavoidable while every OTP had to be shown on-screen.
                    self.send_json(200, {"ok": True})
                    return
                # Neither gateway configured/reachable - fall back to the original on-screen
                # display so parent login still works either way.
                self.send_json(200, {"ok": True, "otp": otp})
                return
            if path == "/api/auth/parent-otp/verify":
                mobile = normalize_mobile(payload.get("mobile") or "")
                otp = (payload.get("otp") or "").strip()
                client_ip = self.client_address[0]
                mobile_throttle_key = f"parent-otp-verify:{mobile}"
                ip_throttle_key = f"parent-otp-verify-ip:{client_ip}"
                if check_throttle(mobile_throttle_key) or check_throttle(ip_throttle_key):
                    self.send_json(200, {"ok": False, "reason": "locked"})
                    return
                row = run_json(
                    "SELECT COALESCE((SELECT json_build_object('id', id::text, 'studentRollNo', student_roll_no, 'otpHash', otp_hash, 'attempts', attempts) "
                    f"FROM otp_challenges WHERE mobile = {quote(mobile)} AND consumed_at IS NULL AND expires_at > now() "
                    "ORDER BY created_at DESC LIMIT 1), 'null'::json);",
                    None,
                )
                if not row or row["attempts"] >= 5 or not hmac.compare_digest(hash_token(otp), row["otpHash"]):
                    if row:
                        run_psql(f"UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = {quote(row['id'])}::uuid;")
                    record_throttle_failure(mobile_throttle_key)
                    record_throttle_failure(ip_throttle_key)
                    self.send_json(200, {"ok": False, "reason": "bad-otp"})
                    return
                clear_throttle(mobile_throttle_key)
                clear_throttle(ip_throttle_key)
                # Invalidate immediately on success - one OTP is usable exactly once, even if
                # somehow replayed before its 5-minute expiry.
                run_psql(f"UPDATE otp_challenges SET consumed_at = now() WHERE id = {quote(row['id'])}::uuid;")
                token = create_session("parent", row["studentRollNo"])
                self.send_json(200, {"ok": True, "studentId": row["studentRollNo"], "token": token})
                return
            if path == "/api/students/photo":
                identity = require_auth(self)
                if not identity:
                    return
                roll_no = payload.get("rollNo") or ""
                if identity["identityType"] == "student" and identity["identityId"] != roll_no:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                if not roll_no:
                    self.send_json(400, {"ok": False, "error": "rollNo is required"})
                    return
                # None -> quote() emits SQL NULL, which is exactly "delete this student's photo".
                photo_path = payload.get("photoPath") or None
                run_psql(f"UPDATE students SET profile_photo_url = {quote(photo_path)} WHERE roll_no = {quote(roll_no)};")
                self.send_json(200, {"ok": True, "rollNo": roll_no, "photoPath": photo_path})
                return
            if path == "/api/faculty/photo":
                identity = require_auth(self)
                if not identity:
                    return
                email = (payload.get("email") or "").strip().lower()
                if identity["identityType"] == "faculty" and identity["identityId"] != email:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                if not email:
                    self.send_json(400, {"ok": False, "error": "email is required"})
                    return
                photo_path = payload.get("photoPath") or None
                run_psql(f"UPDATE faculty SET profile_photo_url = {quote(photo_path)} WHERE email = {quote(email)};")
                self.send_json(200, {"ok": True, "email": email, "photoPath": photo_path})
                return
            if path == "/api/faculty/profile-links":
                identity = require_auth(self)
                if not identity:
                    return
                email = (payload.get("email") or "").strip().lower()
                if identity["identityType"] == "faculty" and identity["identityId"] != email:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                if not email:
                    self.send_json(400, {"ok": False, "error": "email is required"})
                    return
                qualifications = payload.get("qualifications") or None
                google_scholar = payload.get("googleScholar") or None
                vidwan_profile = payload.get("vidwanProfile") or None
                run_psql(f"""
                    UPDATE faculty SET
                        qualifications = {quote(qualifications)},
                        google_scholar = {quote(google_scholar)},
                        vidwan_profile = {quote(vidwan_profile)}
                    WHERE email = {quote(email)};
                """)
                self.send_json(200, {"ok": True, "email": email})
                return
            if path == "/api/test-db-connection":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                self.send_json(200, test_external_db_connection(payload or {}))
                return
            if path == "/api/sms/test":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                mobile = normalize_mobile((payload or {}).get("mobile") or "")
                if not mobile:
                    self.send_json(400, {"ok": False, "error": "mobile is required"})
                    return
                test_otp = f"{secrets.randbelow(1_000_000):06d}"
                sent, channel, error = deliver_parent_otp(mobile, test_otp)
                self.send_json(200, {"ok": sent, "channel": channel, "error": error})
                return
            if path == "/api/notify/parent":
                # Manual "Notify Parent" action from the Grades/Attendance screens - staff sees the
                # data on screen already and triggers this explicitly per student, it's never
                # sent automatically on every data change.
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                roll_no = (payload.get("rollNo") or "").strip().upper()
                kind = (payload.get("kind") or "").strip()
                message = (payload.get("message") or "").strip()
                if kind not in ("grades", "attendance"):
                    self.send_json(400, {"ok": False, "error": "kind must be grades or attendance"})
                    return
                if not roll_no or not message:
                    self.send_json(400, {"ok": False, "error": "rollNo and message are required"})
                    return
                mobile = run_psql(
                    f"SELECT guardian_mobile FROM guardians WHERE student_roll_no = {quote(roll_no)} LIMIT 1;"
                ).strip()
                if not mobile:
                    self.send_json(200, {"ok": False, "reason": "no-guardian-mobile"})
                    return
                sent, channel, error = deliver_parent_notification(mobile, kind, message)
                self.send_json(200, {"ok": sent, "channel": channel, "error": error})
                return
            if path == "/api/plagiarism/extract-text":
                # Pulls text out of an assignment submission's uploaded PDF/Word file(s) so the
                # browser can hand it to the configured AI provider (same fetchAiReply() call the
                # rest of the app already uses) for a manual, faculty-triggered originality check.
                # Project/Research submissions don't need this - their title/description text is
                # already in the bootstrap the browser has.
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                submission_id = (payload.get("submissionId") or "").strip()
                if not submission_id:
                    self.send_json(400, {"ok": False, "error": "submissionId is required"})
                    return
                files = run_json(
                    "SELECT COALESCE(json_agg(json_build_object('fileUrl', file_url, 'fileMime', file_mime)), '[]'::json) "
                    f"FROM assignment_submission_files WHERE submission_id = {quote(submission_id)};",
                    [],
                )
                texts = [extract_text_from_upload(f["fileUrl"], f["fileMime"]) for f in files]
                combined = "\n\n".join(t for t in texts if t)
                if not combined:
                    self.send_json(200, {"ok": False, "reason": "no-extractable-text"})
                    return
                self.send_json(200, {"ok": True, "text": combined[:PLAGIARISM_TEXT_CHAR_LIMIT]})
                return
            if path == "/api/plagiarism/result":
                identity = require_auth(self, allowed_types=["admin", "faculty"])
                if not identity:
                    return
                submission_type = (payload.get("type") or "").strip()
                reference_id = (payload.get("referenceId") or "").strip()
                roll_no = (payload.get("rollNo") or "").strip().upper()
                percent = payload.get("percent")
                notes = (payload.get("notes") or "").strip()
                if submission_type not in ("assignment", "project", "research"):
                    self.send_json(400, {"ok": False, "error": "type must be assignment, project, or research"})
                    return
                if not reference_id or not roll_no or not isinstance(percent, (int, float)):
                    self.send_json(400, {"ok": False, "error": "referenceId, rollNo, and a numeric percent are required"})
                    return
                percent = max(0, min(100, int(percent)))
                run_psql(f"""
                    INSERT INTO plagiarism_checks (submission_type, reference_id, student_roll_no, percent, notes, checked_by)
                    VALUES ({quote(submission_type)}, {quote(reference_id)}, {quote(roll_no)}, {percent}, {quote(notes)}, {quote(identity["identityId"])})
                    ON CONFLICT (submission_type, reference_id) DO UPDATE SET
                      percent = EXCLUDED.percent, notes = EXCLUDED.notes, checked_by = EXCLUDED.checked_by, checked_at = now();
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/curriculum":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                department_code = (payload or {}).get("departmentCode") or ""
                subjects = (payload or {}).get("subjects") or []
                if not department_code or not subjects:
                    self.send_json(400, {"ok": False, "error": "departmentCode and subjects are required"})
                    return
                upsert_curriculum(department_code, subjects)
                self.send_json(200, {"ok": True, "departmentCode": department_code, "count": len(subjects)})
                return
            if path == "/api/timetable":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                department_code = (payload or {}).get("departmentCode") or ""
                slots = (payload or {}).get("slots") or []
                if not department_code or not slots:
                    self.send_json(400, {"ok": False, "error": "departmentCode and slots are required"})
                    return
                upsert_class_timetable(department_code, slots)
                self.send_json(200, {"ok": True, "departmentCode": department_code, "count": len(slots)})
                return
            if path == "/api/grades":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                rows = (payload or {}).get("rows") or []
                if not rows:
                    self.send_json(400, {"ok": False, "error": "rows is required"})
                    return
                upsert_student_grades(rows)
                self.send_json(200, {"ok": True, "count": len(rows)})
                return
            if path == "/api/notices":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                title = (payload or {}).get("title") or ""
                message = (payload or {}).get("message") or ""
                audience = (payload or {}).get("audience") or "All"
                published_by = (payload or {}).get("publishedBy") or "admin@gprec.ac.in"
                department = (payload or {}).get("department") or None
                attachment = (payload or {}).get("attachment") or None
                if not title or not message:
                    self.send_json(400, {"ok": False, "error": "title and message are required"})
                    return
                run_psql(f"""
                    INSERT INTO notices (title, body, audience, published_by, department_code, attachment_name, attachment_url, attachment_mime)
                    VALUES (
                        {quote(title)}, {quote(message)}, {quote(audience)}, {quote(published_by)}, {quote(department)},
                        {quote(attachment.get('name') if attachment else None)},
                        {quote(attachment.get('dataUrl') if attachment else None)},
                        {quote(attachment.get('mime') if attachment else None)}
                    );
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/notices/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                notice_id = (payload or {}).get("id") or ""
                if not notice_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM notices WHERE id = {quote(notice_id)};")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bus-routes":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                route_name = (payload.get("routeName") or "").strip()
                stops = (payload.get("stops") or "").strip()
                pickup_time = (payload.get("pickupTime") or "").strip()
                drop_time = (payload.get("dropTime") or "").strip()
                if not route_name or not stops:
                    self.send_json(400, {"ok": False, "error": "routeName and stops are required"})
                    return
                run_psql(f"""
                    INSERT INTO bus_routes (route_name, stops, pickup_time, drop_time)
                    VALUES ({quote(route_name)}, {quote(stops)}, {quote(pickup_time or None)}, {quote(drop_time or None)});
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bus-routes/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                route_id = (payload.get("id") or "").strip()
                if not route_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM bus_routes WHERE id = {quote(route_id)};")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/buses":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                bus_number = (payload.get("busNumber") or "").strip()
                route_id = (payload.get("routeId") or "").strip()
                driver_name = (payload.get("driverName") or "").strip()
                driver_mobile = normalize_mobile(payload.get("driverMobile") or "")
                if not bus_number or not route_id or not driver_name:
                    self.send_json(400, {"ok": False, "error": "busNumber, routeId, and driverName are required"})
                    return
                run_psql(f"""
                    INSERT INTO buses (bus_number, route_id, driver_name, driver_mobile)
                    VALUES ({quote(bus_number)}, {quote(route_id)}, {quote(driver_name)}, {quote(driver_mobile or None)});
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/buses/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                bus_id = (payload.get("id") or "").strip()
                if not bus_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM buses WHERE id = {quote(bus_id)};")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bus-requests":
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                bus_id = (payload.get("busId") or "").strip()
                requester_name = (payload.get("requesterName") or "").strip()
                pickup_point = (payload.get("pickupPoint") or "").strip()
                drop_point = (payload.get("dropPoint") or "").strip()
                if not bus_id or not requester_name or not pickup_point or not drop_point:
                    self.send_json(400, {"ok": False, "error": "busId, requesterName, pickupPoint and dropPoint are required"})
                    return
                run_psql(f"""
                    INSERT INTO bus_route_requests (bus_id, requester_type, requester_id, requester_name, pickup_point, drop_point)
                    VALUES ({quote(bus_id)}, {quote(identity["identityType"])}, {quote(identity["identityId"])}, {quote(requester_name)},
                      {quote(pickup_point)}, {quote(drop_point)});
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bus-requests/mine":
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                row = run_json(f"""
                    SELECT COALESCE((SELECT json_build_object(
                        'id', r.id::text, 'status', r.status, 'decisionNote', r.decision_note,
                        'requestedAt', to_char(r.requested_at, 'DD Mon, HH12:MI AM'),
                        'busNumber', b.bus_number, 'routeName', ro.route_name, 'driverName', b.driver_name,
                        'driverMobile', b.driver_mobile,
                        'pickupPoint', r.pickup_point, 'dropPoint', r.drop_point,
                        'pickupTime', ro.pickup_time, 'dropTime', ro.drop_time,
                        'feePaid', (r.fee_paid_at IS NOT NULL),
                        'validUntil', to_char(r.valid_until, 'DD Mon YYYY')
                    ) FROM bus_route_requests r
                      JOIN buses b ON b.id = r.bus_id
                      JOIN bus_routes ro ON ro.id = b.route_id
                      WHERE r.requester_type = {quote(identity["identityType"])} AND r.requester_id = {quote(identity["identityId"])}
                      ORDER BY r.requested_at DESC LIMIT 1), 'null'::json);
                """, None)
                self.send_json(200, {"ok": True, "request": row})
                return
            if path == "/api/bus-requests/mark-paid":
                # Called right after a successful Transportation Fee payment (see the payment
                # success handler in script.js) - marks the caller's own latest bus request as
                # paid, which /api/bus-requests/decide then requires before a student's request
                # can be Approved. Faculty never call this (no fee for faculty), but the endpoint
                # doesn't need to special-case that - it just marks the caller's own latest row.
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                run_psql(f"""
                    UPDATE bus_route_requests SET fee_paid_at = now()
                    WHERE id = (
                      SELECT id FROM bus_route_requests
                      WHERE requester_type = {quote(identity["identityType"])} AND requester_id = {quote(identity["identityId"])}
                      ORDER BY requested_at DESC LIMIT 1
                    );
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bus-requests/request-cancellation":
                # Self-service surrender of an already-Approved pass - for students this is also
                # how they switch routes/buses (cancel the current one, then submit a fresh
                # request for a different bus from the Available Buses list). This doesn't cancel
                # it outright - it flags it for admin to confirm (matches the rest of this app's
                # convention of admin having the final say on request state changes), via the
                # "Cancelled" status /api/bus-requests/decide now also accepts.
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                run_psql(f"""
                    UPDATE bus_route_requests SET status = 'Cancellation Requested'
                    WHERE id = (
                      SELECT id FROM bus_route_requests
                      WHERE requester_type = {quote(identity["identityType"])} AND requester_id = {quote(identity["identityId"])}
                        AND status = 'Approved'
                      ORDER BY requested_at DESC LIMIT 1
                    );
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bus-requests/all":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                rows = run_json("""
                    SELECT COALESCE(json_agg(json_build_object(
                        'id', r.id::text, 'status', r.status, 'decisionNote', r.decision_note,
                        'requesterType', r.requester_type, 'requesterId', r.requester_id, 'requesterName', r.requester_name,
                        'requestedAt', to_char(r.requested_at, 'DD Mon, HH12:MI AM'),
                        'busNumber', b.bus_number, 'routeName', ro.route_name, 'driverName', b.driver_name,
                        'pickupPoint', r.pickup_point, 'dropPoint', r.drop_point,
                        'feePaid', (r.fee_paid_at IS NOT NULL)
                    ) ORDER BY r.requested_at DESC), '[]'::json)
                    FROM bus_route_requests r
                    JOIN buses b ON b.id = r.bus_id
                    JOIN bus_routes ro ON ro.id = b.route_id;
                """, [])
                self.send_json(200, {"ok": True, "requests": rows})
                return
            if path == "/api/bus-requests/decide":
                identity = require_auth(self, allowed_types=["admin"])
                if not identity:
                    return
                request_id = (payload.get("id") or "").strip()
                status = (payload.get("status") or "").strip()
                decision_note = (payload.get("decisionNote") or "").strip()
                if not request_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                if status not in ("Approved", "Rejected", "Cancelled"):
                    self.send_json(400, {"ok": False, "error": "status must be Approved, Rejected, or Cancelled"})
                    return
                if status == "Approved":
                    # Students must pay the Transportation Fee before their bus request can be
                    # approved - faculty have no fee, so this only applies to student requesters.
                    unpaid = run_psql(f"""
                        SELECT 1 FROM bus_route_requests
                        WHERE id = {quote(request_id)} AND requester_type = 'student' AND fee_paid_at IS NULL;
                    """).strip()
                    if unpaid:
                        self.send_json(400, {"ok": False, "error": "This student has not paid the Transportation Fee yet"})
                        return
                valid_until_clause = PASS_VALID_UNTIL_SQL if status == "Approved" else "NULL"
                run_psql(f"""
                    UPDATE bus_route_requests SET status = {quote(status)}, decision_note = {quote(decision_note or None)},
                      decided_by = {quote(identity["identityId"])}, decided_at = now(), valid_until = {valid_until_clause}
                    WHERE id = {quote(request_id)};
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bus-requests/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                request_id = (payload.get("id") or "").strip()
                if not request_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM bus_route_requests WHERE id = {quote(request_id)};")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/vehicle-passes":
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                requester_name = (payload.get("requesterName") or "").strip()
                vehicle_type = (payload.get("vehicleType") or "").strip()
                vehicle_number = (payload.get("vehicleNumber") or "").strip()
                license_number = (payload.get("licenseNumber") or "").strip()
                license_doc_url = (payload.get("licenseDocUrl") or "").strip()
                rc_doc_url = (payload.get("rcDocUrl") or "").strip()
                if not requester_name or not vehicle_type or not vehicle_number or not license_number:
                    self.send_json(400, {"ok": False, "error": "requesterName, vehicleType, vehicleNumber, and licenseNumber are required"})
                    return
                if not license_doc_url or not rc_doc_url:
                    self.send_json(400, {"ok": False, "error": "License and RC document photos are mandatory"})
                    return
                verification_result, verification_notes = verify_vehicle_documents(license_number, vehicle_number)
                run_psql(f"""
                    INSERT INTO vehicle_passes (
                        requester_type, requester_id, requester_name, vehicle_type, vehicle_number, license_number,
                        license_doc_url, rc_doc_url, verification_result, verification_notes
                    ) VALUES (
                        {quote(identity["identityType"])}, {quote(identity["identityId"])}, {quote(requester_name)},
                        {quote(vehicle_type)}, {quote(vehicle_number)}, {quote(license_number)},
                        {quote(license_doc_url or None)}, {quote(rc_doc_url or None)},
                        {quote(verification_result)}, {quote(verification_notes)}
                    );
                """)
                self.send_json(200, {"ok": True, "verificationResult": verification_result, "verificationNotes": verification_notes})
                return
            if path == "/api/vehicle-passes/mine":
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                row = run_json(f"""
                    SELECT COALESCE((SELECT json_build_object(
                        'id', id::text, 'status', status, 'decisionNote', decision_note,
                        'vehicleType', vehicle_type, 'vehicleNumber', vehicle_number, 'licenseNumber', license_number,
                        'verificationResult', verification_result, 'verificationNotes', verification_notes,
                        'requestedAt', to_char(requested_at, 'DD Mon, HH12:MI AM'),
                        'validUntil', to_char(valid_until, 'DD Mon YYYY')
                    ) FROM vehicle_passes
                      WHERE requester_type = {quote(identity["identityType"])} AND requester_id = {quote(identity["identityId"])}
                      ORDER BY requested_at DESC LIMIT 1), 'null'::json);
                """, None)
                self.send_json(200, {"ok": True, "pass": row})
                return
            if path == "/api/vehicle-passes/all":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                rows = run_json("""
                    SELECT COALESCE(json_agg(json_build_object(
                        'id', id::text, 'status', status, 'decisionNote', decision_note,
                        'requesterType', requester_type, 'requesterId', requester_id, 'requesterName', requester_name,
                        'vehicleType', vehicle_type, 'vehicleNumber', vehicle_number, 'licenseNumber', license_number,
                        'licenseDocUrl', license_doc_url, 'rcDocUrl', rc_doc_url,
                        'verificationResult', verification_result, 'verificationNotes', verification_notes,
                        'requestedAt', to_char(requested_at, 'DD Mon, HH12:MI AM')
                    ) ORDER BY requested_at DESC), '[]'::json)
                    FROM vehicle_passes;
                """, [])
                self.send_json(200, {"ok": True, "passes": rows})
                return
            if path == "/api/vehicle-passes/decide":
                identity = require_auth(self, allowed_types=["admin"])
                if not identity:
                    return
                pass_id = (payload.get("id") or "").strip()
                status = (payload.get("status") or "").strip()
                decision_note = (payload.get("decisionNote") or "").strip()
                if not pass_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                if status not in ("Approved", "Rejected"):
                    self.send_json(400, {"ok": False, "error": "status must be Approved or Rejected"})
                    return
                valid_until_clause = PASS_VALID_UNTIL_SQL if status == "Approved" else "NULL"
                run_psql(f"""
                    UPDATE vehicle_passes SET status = {quote(status)}, decision_note = {quote(decision_note or None)},
                      decided_by = {quote(identity["identityId"])}, decided_at = now(), valid_until = {valid_until_clause}
                    WHERE id = {quote(pass_id)};
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/vehicle-passes/verify":
                # Re-runs the KYC check on demand (the "Verify" button in the admin Vehicle Passes
                # table) - separate from the automatic check at submission time so the admin can
                # retry after fixing kycSettings, or re-check if the applicant's documents changed.
                if not require_auth(self, allowed_types=["admin"]):
                    return
                pass_id = (payload.get("id") or "").strip()
                if not pass_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                row = run_json(f"""
                    SELECT json_build_object('licenseNumber', license_number, 'vehicleNumber', vehicle_number)
                    FROM vehicle_passes WHERE id = {quote(pass_id)};
                """, None)
                if not row:
                    self.send_json(404, {"ok": False, "error": "Vehicle pass not found"})
                    return
                verification_result, verification_notes = verify_vehicle_documents(row["licenseNumber"], row["vehicleNumber"])
                run_psql(f"""
                    UPDATE vehicle_passes SET verification_result = {quote(verification_result)}, verification_notes = {quote(verification_notes)}
                    WHERE id = {quote(pass_id)};
                """)
                self.send_json(200, {"ok": True, "verificationResult": verification_result, "verificationNotes": verification_notes})
                return
            if path == "/api/vehicle-passes/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                pass_id = (payload.get("id") or "").strip()
                if not pass_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM vehicle_passes WHERE id = {quote(pass_id)};")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/kyc/test":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                test_license = (payload.get("licenseNumber") or "").strip() or "TEST0000000000"
                test_vehicle = (payload.get("vehicleNumber") or "").strip() or "TEST0000"
                result, notes = verify_vehicle_documents(test_license, test_vehicle)
                self.send_json(200, {"ok": True, "result": result, "notes": notes})
                return
            if path == "/api/attendance":
                identity = require_auth(self, allowed_types=["admin", "faculty"])
                if not identity:
                    return
                faculty_email = (payload or {}).get("facultyEmail") or ""
                if identity["identityType"] == "faculty" and identity["identityId"] != faculty_email:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                subject_code = (payload or {}).get("subject") or ""
                section = (payload or {}).get("section") or ""
                attendance_date = (payload or {}).get("date") or ""
                entries = (payload or {}).get("entries") or []
                if not faculty_email or not subject_code or not section or not attendance_date:
                    self.send_json(400, {"ok": False, "error": "facultyEmail, subject, section and date are required"})
                    return
                save_attendance_record(faculty_email, subject_code, section, attendance_date, entries)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/internal-marks":
                identity = require_auth(self, allowed_types=["admin", "faculty"])
                if not identity:
                    return
                department_code = (payload or {}).get("department") or ""
                subject_code = (payload or {}).get("subjectCode") or ""
                section = (payload or {}).get("section") or ""
                academic_year = (payload or {}).get("academicYear") or ""
                rows = (payload or {}).get("rows") or []
                if not department_code or not subject_code or not section or not academic_year:
                    self.send_json(400, {"ok": False, "error": "department, subjectCode, section and academicYear are required"})
                    return
                if identity["identityType"] == "faculty":
                    # Ownership check: a faculty member can only enter marks for the subject the
                    # faculty table actually has them assigned to, not any subject code they claim
                    # in the payload - this is the reason a real table + server-side check is used
                    # here instead of the JSONB-blob-replace-all pattern used elsewhere in this file.
                    real_subject_code = run_psql(f"SELECT subject_code FROM faculty WHERE email = {quote(identity['identityId'])};").strip()
                    if not real_subject_code or real_subject_code != subject_code:
                        self.send_json(403, {"ok": False, "error": "forbidden"})
                        return
                    faculty_email = identity["identityId"]
                else:
                    faculty_email = (payload or {}).get("facultyEmail") or ""
                upsert_internal_marks(department_code, subject_code, section, academic_year, faculty_email, rows)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/assignments":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                department_code = (payload or {}).get("department") or ""
                subject_code = (payload or {}).get("subjectCode") or ""
                title = (payload or {}).get("title") or ""
                description = (payload or {}).get("description") or ""
                due_at = (payload or {}).get("dueDate") or ""
                created_by = (payload or {}).get("createdBy") or ""
                document = (payload or {}).get("document") or None
                if not department_code or not subject_code or not title or not due_at:
                    self.send_json(400, {"ok": False, "error": "department, subjectCode, title and dueDate are required"})
                    return
                run_psql(f"""
                    INSERT INTO assignments (department_code, subject_code, title, description, due_at, created_by, document_name, document_url, document_mime)
                    VALUES (
                        {quote(department_code)}, {quote(subject_code)}, {quote(title)}, {quote(description)}, {quote(due_at)}::timestamptz, {quote(created_by)},
                        {quote(document.get('name') if document else None)},
                        {quote(document.get('dataUrl') if document else None)},
                        {quote(document.get('mime') if document else None)}
                    );
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/assignments/remove":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                assignment_id = (payload or {}).get("id") or ""
                if not assignment_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM assignments WHERE id = {quote(assignment_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/assignment-submissions":
                identity = require_auth(self)
                if not identity:
                    return
                assignment_id = (payload or {}).get("assignmentId") or ""
                student_roll_no = (payload or {}).get("studentId") or ""
                if identity["identityType"] == "student" and identity["identityId"] != student_roll_no:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                comment = (payload or {}).get("comment") or ""
                files = (payload or {}).get("files") or []
                if not assignment_id or not student_roll_no:
                    self.send_json(400, {"ok": False, "error": "assignmentId and studentId are required"})
                    return
                save_assignment_submission(assignment_id, student_roll_no, comment, files)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/site-content":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                key = (payload or {}).get("key") or ""
                value = (payload or {}).get("value")
                if not key or value is None:
                    self.send_json(400, {"ok": False, "error": "key and value are required"})
                    return
                upsert_site_content(key, json.dumps(value))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/admins":
                identity = require_auth(self, allowed_types=["admin"])
                if not identity:
                    return
                caller = get_admin_row(identity["identityId"])
                if not caller or not caller.get("canManageAdmins"):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                admin = payload or {}
                if not admin.get("email") or not admin.get("name"):
                    self.send_json(400, {"ok": False, "error": "name and email are required"})
                    return
                create_admin(admin)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/admins/remove":
                identity = require_auth(self, allowed_types=["admin"])
                if not identity:
                    return
                caller = get_admin_row(identity["identityId"])
                if not caller or not caller.get("canManageAdmins"):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                email = (payload or {}).get("email") or ""
                if not email:
                    self.send_json(400, {"ok": False, "error": "email is required"})
                    return
                remove_admin(email)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/placement-applications":
                identity = require_auth(self)
                if not identity:
                    return
                student_roll_no = (payload or {}).get("studentId") or ""
                if identity["identityType"] == "student" and identity["identityId"] != student_roll_no:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                drive_id = (payload or {}).get("driveId") or ""
                if not student_roll_no or not drive_id:
                    self.send_json(400, {"ok": False, "error": "studentId and driveId are required"})
                    return
                applied = apply_to_placement_drive(student_roll_no, drive_id)
                if not applied:
                    self.send_json(200, {"ok": False, "error": "Registration unavailable - session may be full or you're already registered."})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/placement-drive-applicants":
                # Placement-admin-only (loose "any admin" check, matching the rest of this file's
                # admin-family endpoints rather than a stricter role_label check nothing else here
                # does either) - powers the CSV export on placement-dashboard.html. driveId is
                # optional: omitted means "every application, across every drive" (Export All).
                if not require_auth(self, allowed_types=["admin"]):
                    return
                drive_id = (payload or {}).get("driveId") or ""
                where_clause = f"WHERE pa.drive_id = {quote(drive_id)}::uuid" if drive_id else ""
                rows = run_json(
                    f"""
                    SELECT COALESCE(json_agg(json_build_object(
                        'driveId', pd.id::text, 'company', pd.company, 'role', pd.role_title, 'rollNo', s.roll_no,
                        'studentName', s.full_name, 'department', s.department_code, 'driveType', pd.drive_type,
                        'appliedAt', pa.applied_at::text, 'status', pa.status
                    ) ORDER BY pd.company, pa.applied_at), '[]'::json)
                    FROM placement_applications pa
                    JOIN students s ON s.roll_no = pa.student_roll_no
                    JOIN placement_drives pd ON pd.id = pa.drive_id
                    {where_clause};
                    """,
                    [],
                )
                self.send_json(200, {"ok": True, "applicants": rows})
                return
            if path == "/api/placement-applications/update-status":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                drive_id = (payload or {}).get("driveId") or ""
                roll_no = (payload or {}).get("rollNo") or ""
                status = (payload or {}).get("status") or ""
                if status not in ("Applied", "Selected", "Rejected"):
                    self.send_json(400, {"ok": False, "error": "status must be Applied, Selected, or Rejected"})
                    return
                if not drive_id or not roll_no:
                    self.send_json(400, {"ok": False, "error": "driveId and rollNo are required"})
                    return
                run_psql(f"""
                    UPDATE placement_applications SET status = {quote(status)}
                    WHERE drive_id = {quote(drive_id)}::uuid AND student_roll_no = {quote(roll_no)};
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/placement-stats":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                # Broken out per drive_type ('Placement' vs 'Internship') - same underlying tables,
                # just scoped by joining through placement_drives.drive_type, so Overview can show
                # each one's own counts rather than one number blending both together.
                stats = run_json("""
                    SELECT json_build_object(
                        'placement', json_build_object(
                            'totalDrives', (SELECT COUNT(*) FROM placement_drives WHERE drive_type = 'Placement'),
                            'totalApplications', (SELECT COUNT(*) FROM placement_applications pa JOIN placement_drives pd ON pd.id = pa.drive_id WHERE pd.drive_type = 'Placement'),
                            'totalApplicants', (SELECT COUNT(DISTINCT pa.student_roll_no) FROM placement_applications pa JOIN placement_drives pd ON pd.id = pa.drive_id WHERE pd.drive_type = 'Placement'),
                            'totalPlaced', (SELECT COUNT(DISTINCT pa.student_roll_no) FROM placement_applications pa JOIN placement_drives pd ON pd.id = pa.drive_id WHERE pd.drive_type = 'Placement' AND pa.status = 'Selected')
                        ),
                        'internship', json_build_object(
                            'totalDrives', (SELECT COUNT(*) FROM placement_drives WHERE drive_type = 'Internship'),
                            'totalApplications', (SELECT COUNT(*) FROM placement_applications pa JOIN placement_drives pd ON pd.id = pa.drive_id WHERE pd.drive_type = 'Internship'),
                            'totalApplicants', (SELECT COUNT(DISTINCT pa.student_roll_no) FROM placement_applications pa JOIN placement_drives pd ON pd.id = pa.drive_id WHERE pd.drive_type = 'Internship'),
                            'totalPlaced', (SELECT COUNT(DISTINCT pa.student_roll_no) FROM placement_applications pa JOIN placement_drives pd ON pd.id = pa.drive_id WHERE pd.drive_type = 'Internship' AND pa.status = 'Selected')
                        )
                    );
                """, {})
                self.send_json(200, {"ok": True, "stats": stats})
                return
            if path == "/api/interview-schedules":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                drive_id = (payload or {}).get("driveId") or ""
                roll_no = (payload or {}).get("rollNo") or ""
                round_name = (payload or {}).get("roundName") or ""
                slot_date = (payload or {}).get("date") or ""
                slot_time = (payload or {}).get("time") or ""
                if not drive_id or not roll_no or not round_name or not slot_date or not slot_time:
                    self.send_json(400, {"ok": False, "error": "driveId, rollNo, roundName, date, and time are required"})
                    return
                rows = run_json(
                    f"""
                    INSERT INTO interview_schedules (drive_id, student_roll_no, round_name, slot_date, slot_time, venue, notes)
                    SELECT {quote(drive_id)}::uuid, {quote(roll_no)}, {quote(round_name)}, {quote(slot_date)}::date,
                        {quote(slot_time)}, {quote((payload or {}).get("venue"))}, {quote((payload or {}).get("notes"))}
                    WHERE EXISTS (
                        SELECT 1 FROM placement_applications WHERE drive_id = {quote(drive_id)}::uuid AND student_roll_no = {quote(roll_no)}
                    )
                    RETURNING json_build_array(id::text)::json AS row;
                    """,
                    [],
                )
                if not rows:
                    self.send_json(400, {"ok": False, "error": "That student has not applied to this drive."})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/interview-schedules/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                run_psql(f"DELETE FROM interview_schedules WHERE id = {quote((payload or {}).get('id') or '')}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/interview-schedules/for-drive":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                drive_id = (payload or {}).get("driveId") or ""
                rows = run_json(
                    f"""
                    SELECT COALESCE(json_agg(json_build_object(
                        'id', ischeds.id::text, 'rollNo', s.roll_no, 'studentName', s.full_name,
                        'roundName', ischeds.round_name, 'date', ischeds.slot_date::text, 'time', ischeds.slot_time,
                        'venue', ischeds.venue, 'notes', ischeds.notes
                    ) ORDER BY ischeds.slot_date, ischeds.slot_time), '[]'::json)
                    FROM interview_schedules ischeds
                    JOIN students s ON s.roll_no = ischeds.student_roll_no
                    WHERE ischeds.drive_id = {quote(drive_id)}::uuid;
                    """,
                    [],
                )
                self.send_json(200, {"ok": True, "slots": rows})
                return
            if path == "/api/interview-schedules/mine":
                identity = require_auth(self, allowed_types=["student"])
                if not identity:
                    return
                roll_no = (payload or {}).get("studentId") or ""
                if identity["identityId"] != roll_no:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                rows = run_json(
                    f"""
                    SELECT COALESCE(json_agg(json_build_object(
                        'id', ischeds.id::text, 'company', pd.company, 'role', pd.role_title, 'driveType', pd.drive_type,
                        'roundName', ischeds.round_name, 'date', ischeds.slot_date::text, 'time', ischeds.slot_time,
                        'venue', ischeds.venue, 'notes', ischeds.notes
                    ) ORDER BY ischeds.slot_date, ischeds.slot_time), '[]'::json)
                    FROM interview_schedules ischeds
                    JOIN placement_drives pd ON pd.id = ischeds.drive_id
                    WHERE ischeds.student_roll_no = {quote(roll_no)};
                    """,
                    [],
                )
                self.send_json(200, {"ok": True, "slots": rows})
                return
            if path == "/api/payments":
                identity = require_auth(self)
                if not identity:
                    return
                student_roll_no = (payload or {}).get("studentId") or ""
                if identity["identityType"] == "student" and identity["identityId"] != student_roll_no:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                amount = (payload or {}).get("amount")
                if not student_roll_no or amount is None:
                    self.send_json(400, {"ok": False, "error": "studentId and amount are required"})
                    return
                details = {k: v for k, v in (payload or {}).items() if k not in ("studentId",)}
                record_payment(
                    student_roll_no, amount, (payload or {}).get("mode"),
                    (payload or {}).get("transactionRef"), json.dumps(details)
                )
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bank-details":
                identity = require_auth(self)
                if not identity:
                    return
                key = (payload or {}).get("key") or ""
                if identity["identityType"] not in ("admin", "non_teaching") and not owns_key(identity, key):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                details = (payload or {}).get("details")
                if not key or details is None:
                    self.send_json(400, {"ok": False, "error": "key and details are required"})
                    return
                upsert_bank_details(key, json.dumps(details))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/fee-amount-overrides":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                application_type = (payload or {}).get("applicationType") or ""
                amount = (payload or {}).get("amount")
                if not application_type or amount is None:
                    self.send_json(400, {"ok": False, "error": "applicationType and amount are required"})
                    return
                upsert_fee_amount_override(application_type, amount)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/section-assignments":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                student_roll_no = (payload or {}).get("studentId") or ""
                section = (payload or {}).get("section") or ""
                if not student_roll_no or not section:
                    self.send_json(400, {"ok": False, "error": "studentId and section are required"})
                    return
                upsert_section_assignment(student_roll_no, (payload or {}).get("department"), section)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/section-assignments/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                student_roll_no = (payload or {}).get("studentId") or ""
                if not student_roll_no:
                    self.send_json(400, {"ok": False, "error": "studentId is required"})
                    return
                run_psql(f"DELETE FROM student_section_assignments WHERE student_roll_no = {quote(student_roll_no)};")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/class-messages":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                create_class_message(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/class-messages/remove":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                message_id = (payload or {}).get("id") or ""
                if not message_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM class_messages WHERE id = {quote(message_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/invigilation-duties":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                create_invigilation_duty(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/invigilation-duties/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                duty_id = (payload or {}).get("id") or ""
                if not duty_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM invigilation_duties WHERE id = {quote(duty_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/leave-requests":
                if not require_auth(self, allowed_types=["admin", "faculty", "non_teaching"]):
                    return
                create_leave_request(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/leave-requests/decide":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                decide_leave_request((payload or {}).get("id"), (payload or {}).get("status"), (payload or {}).get("decidedBy"))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/leave-requests/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                request_id = (payload or {}).get("id") or ""
                if not request_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM leave_requests WHERE id = {quote(request_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/adhoc-class-requests":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                create_adhoc_class_request(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/adhoc-class-requests/decide":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                decide_adhoc_class_request((payload or {}).get("id"), (payload or {}).get("status"))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/adhoc-class-requests/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                request_id = (payload or {}).get("id") or ""
                if not request_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM adhoc_class_requests WHERE id = {quote(request_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/class-cancellations":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                create_class_cancellation(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/class-cancellations/remove":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                cancellation_id = (payload or {}).get("id") or ""
                if not cancellation_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM class_cancellations WHERE id = {quote(cancellation_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/student-projects":
                if not require_auth(self):
                    return
                replace_student_submissions("student_projects", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/student-research":
                if not require_auth(self):
                    return
                replace_student_submissions("student_research", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/hostel-outing-requests":
                if not require_auth(self):
                    return
                replace_student_submissions("hostel_outing_requests", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/hostel-visiting-requests":
                if not require_auth(self):
                    return
                replace_student_submissions("hostel_visiting_requests", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/hostel-leave-requests":
                if not require_auth(self):
                    return
                replace_student_submissions("hostel_leave_requests", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/hostel-allocations/assign":
                # Warden/admin-only, matches allowed_types=["admin"] already used for the
                # hostel/gate-* endpoints below. hostel_allocations has student_roll_no UNIQUE, so
                # this upserts - assigning a student who's already allocated moves them to the new
                # room/bed instead of erroring or creating a duplicate row.
                if not require_auth(self, allowed_types=["admin"]):
                    return
                data = payload or {}
                roll_no = (data.get("rollNo") or "").strip()
                if not roll_no:
                    self.send_json(400, {"ok": False, "error": "rollNo is required"})
                    return
                run_psql(f"""
                    INSERT INTO hostel_allocations (student_roll_no, hostel_name, block_name, room_no, bed_no, mess_plan, status)
                    VALUES ({quote(roll_no)}, {quote(data.get('hostelName') or '')}, {quote(data.get('blockName') or '')},
                            {quote(data.get('roomNo') or '')}, {quote(data.get('bedNo') or '')}, {quote(data.get('messPlan') or '')},
                            {quote(data.get('status') or 'Active')})
                    ON CONFLICT (student_roll_no) DO UPDATE SET
                        hostel_name = EXCLUDED.hostel_name, block_name = EXCLUDED.block_name,
                        room_no = EXCLUDED.room_no, bed_no = EXCLUDED.bed_no,
                        mess_plan = EXCLUDED.mess_plan, status = EXCLUDED.status;
                """)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/hostel-allocations/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                roll_no = (payload or {}).get("rollNo") or ""
                run_psql(f"DELETE FROM hostel_allocations WHERE student_roll_no = {quote(roll_no)};")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/hostel/gate-lookup":
                # Hostel-warden-only, matches the loose "any admin sub-role" convention already
                # used for the hostel-*-requests endpoints above rather than a stricter role_label
                # check this codebase doesn't do anywhere else yet.
                if not require_auth(self, allowed_types=["admin"]):
                    return
                record = hostel_gate_lookup(
                    (payload or {}).get("passType"), (payload or {}).get("passId"), (payload or {}).get("token")
                )
                if not record:
                    self.send_json(404, {"ok": False, "error": "Pass not found, already inactive, or the QR code doesn't match."})
                    return
                self.send_json(200, {"ok": True, "pass": record})
                return
            if path == "/api/hostel/gate-log":
                identity = require_auth(self, allowed_types=["admin"])
                if not identity:
                    return
                direction = (payload or {}).get("direction")
                if direction not in ("Exit", "Entry"):
                    self.send_json(400, {"ok": False, "error": "direction must be Exit or Entry"})
                    return
                record = hostel_gate_log_append(
                    (payload or {}).get("passType"), (payload or {}).get("passId"), (payload or {}).get("token"),
                    direction, identity["identityId"],
                )
                if not record:
                    self.send_json(404, {"ok": False, "error": "Pass not found, already inactive, or the QR code doesn't match."})
                    return
                self.send_json(200, {"ok": True, "pass": record})
                return
            if path == "/api/campus-event-registrations":
                # No allowed_types restriction, matching the hostel-outing/leave/visit convention -
                # any authenticated identity (a student registering for themselves) can write here.
                if not require_auth(self):
                    return
                record = payload or {}
                if not record.get("id"):
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                if not upsert_campus_event_registration(record):
                    self.send_json(409, {"ok": False, "error": "Registration limit reached for this event."})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/campus-event-registrations/public":
                # Deliberately no require_auth() call - this is for visitors with no GPREC login
                # at all (outside-college attendees). register_for_public_event() does its own
                # server-side checks (event.isPublic, payment-required-if-fee) rather than trusting
                # the client.
                data = payload or {}
                if not verify_math_captcha(data.get("captchaToken"), data.get("captchaAnswer")):
                    self.send_json(400, {"ok": False, "error": "Incorrect CAPTCHA answer. Please try again."})
                    return
                record, error = register_for_public_event(
                    data.get("eventId"), data.get("name"), data.get("email"), data.get("phone"), data.get("college"),
                    data.get("password"), data.get("paymentType"), data.get("paymentReference"),
                )
                if not record:
                    self.send_json(409, {"ok": False, "error": error or "Could not complete registration."})
                    return
                token = create_session("event_visitor", record["email"], record["participantName"])
                self.send_json(200, {"ok": True, "registration": record, "token": token})
                return
            if path == "/api/campus-event-registrations/existing":
                # For a visitor who already has an account (registered for a previous event) -
                # identity comes from their session, not a client-supplied email/password, so no
                # CAPTCHA needed here (the bearer token already proves who they are).
                identity = require_auth(self, allowed_types=["event_visitor"])
                if not identity:
                    return
                data = payload or {}
                record, error = register_existing_visitor_for_event(
                    identity["identityId"], data.get("eventId"), data.get("paymentType"), data.get("paymentReference"),
                )
                if not record:
                    self.send_json(409, {"ok": False, "error": error or "Could not complete registration."})
                    return
                self.send_json(200, {"ok": True, "registration": record})
                return
            if path == "/api/event-visitor/signup":
                # Creating an account is now a standalone step (event-visitor-dashboard.html's
                # "Create an account" view), separate from registering for any specific event -
                # register_for_public_event still creates the account inline too, for a visitor who
                # goes straight to an event link without an account yet, so this isn't the only path
                # to a visitor account, just the direct one.
                data = payload or {}
                if not verify_math_captcha(data.get("captchaToken"), data.get("captchaAnswer")):
                    self.send_json(400, {"ok": False, "error": "Incorrect CAPTCHA answer. Please try again."})
                    return
                name = (data.get("name") or "").strip()
                email = (data.get("email") or "").strip().lower()
                password = data.get("password") or ""
                if not name or not email or "@" not in email:
                    self.send_json(400, {"ok": False, "error": "A valid name and email are required."})
                    return
                if not password or len(password) < 6:
                    self.send_json(400, {"ok": False, "error": "Choose a password of at least 6 characters."})
                    return
                # "Create Account" is also the reset/start-over path for event visitors. If the
                # email already exists, replace that visitor account and clear prior public-event
                # registrations so the visitor can begin again from the account creation step.
                delete_event_visitor_account(email)
                create_event_visitor_account(email, password, name, (data.get("phone") or "").strip(), (data.get("college") or "").strip())
                token = create_session("event_visitor", email, name)
                self.send_json(200, {"ok": True, "token": token, "name": name})
                return
            if path == "/api/event-visitor/login":
                data = payload or {}
                if not verify_math_captcha(data.get("captchaToken"), data.get("captchaAnswer")):
                    self.send_json(400, {"ok": False, "error": "Incorrect CAPTCHA answer. Please try again."})
                    return
                account = verify_event_visitor_login((data.get("email") or "").strip().lower(), data.get("password") or "")
                if not account:
                    # 200 + ok:false, not 401 - matches /api/auth/login's convention (see
                    # "bad-password" there). gprecDbRequest treats ANY 401 response, from any
                    # endpoint, as "your session expired" and force-redirects to student-login.html
                    # - that's for an invalid/expired session TOKEN, not a rejected login attempt,
                    # and this call carries no session token at all yet.
                    self.send_json(200, {"ok": False, "error": "Incorrect email or password."})
                    return
                token = create_session("event_visitor", account["email"], account.get("name"))
                self.send_json(200, {"ok": True, "token": token, "name": account.get("name")})
                return
            if path == "/api/event-visitor/forgot-password":
                data = payload or {}
                if not verify_math_captcha(data.get("captchaToken"), data.get("captchaAnswer")):
                    self.send_json(400, {"ok": False, "error": "Incorrect CAPTCHA answer. Please try again."})
                    return
                email = (data.get("email") or "").strip().lower()
                phone = (data.get("phone") or "").strip()
                new_password = data.get("newPassword") or ""
                if len(new_password) < 6:
                    self.send_json(400, {"ok": False, "error": "Choose a new password of at least 6 characters."})
                    return
                if not event_visitor_identity_matches(email, phone):
                    # 200 + ok:false, not 401 - see the identical note in /api/event-visitor/login.
                    self.send_json(200, {"ok": False, "error": "Email and phone number don't match our records."})
                    return
                reset_event_visitor_password(email, new_password)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/event-visitor/delete-account":
                identity = require_auth(self, allowed_types=["event_visitor"])
                if not identity:
                    return
                delete_event_visitor_account(identity["identityId"])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/campus-events/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                event_id = (payload or {}).get("eventId")
                if not event_id:
                    self.send_json(400, {"ok": False, "error": "eventId is required"})
                    return
                events = run_json("SELECT content_value FROM site_content WHERE content_key = 'campusEvents';", [])
                remaining = [e for e in events if e.get("id") != event_id] if isinstance(events, list) else []
                upsert_site_content("campusEvents", json.dumps(remaining))
                remove_campus_event_registrations(event_id)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/event-visitor/my-registrations":
                identity = require_auth(self, allowed_types=["event_visitor"])
                if not identity:
                    return
                rows = run_json(
                    f"SELECT COALESCE(json_agg(data ORDER BY updated_at DESC), '[]'::json) FROM campus_event_registrations "
                    f"WHERE data->>'email' = {quote(identity['identityId'])};",
                    [],
                )
                self.send_json(200, {"ok": True, "registrations": rows, "name": identity.get("roleLabel")})
                return
            if path == "/api/campus-event/gate-lookup":
                if not require_auth(self, allowed_types=["admin", "student"]):
                    return
                record = campus_event_gate_lookup((payload or {}).get("eventId"), (payload or {}).get("regId"), (payload or {}).get("token"))
                if not record:
                    self.send_json(404, {"ok": False, "error": "Ticket not found, unpaid, or the QR code doesn't match."})
                    return
                self.send_json(200, {"ok": True, "registration": record})
                return
            if path == "/api/campus-event/gate-log":
                identity = require_auth(self, allowed_types=["admin", "student"])
                if not identity:
                    return
                record = campus_event_gate_log_append(
                    (payload or {}).get("eventId"), (payload or {}).get("regId"), (payload or {}).get("token"), identity["identityId"],
                )
                if not record:
                    self.send_json(404, {"ok": False, "error": "Ticket not found, unpaid, already checked in, or the QR code doesn't match."})
                    return
                self.send_json(200, {"ok": True, "registration": record})
                return
            if path == "/api/campus-event/manual-checkin":
                identity = require_auth(self, allowed_types=["admin", "student"])
                if not identity:
                    return
                record = campus_event_manual_checkin(
                    (payload or {}).get("eventId"), (payload or {}).get("rollNumber"), (payload or {}).get("email"), identity["identityId"],
                )
                if not record:
                    self.send_json(404, {"ok": False, "error": "No matching registration, unpaid, or already checked in."})
                    return
                self.send_json(200, {"ok": True, "registration": record})
                return
            if path == "/api/campus-event/reset-checkins":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                reset_campus_event_checkins((payload or {}).get("eventId"))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/campus-events/update":
                # require_auth(self) not allowed_types=["admin"] - a faculty Event Head needs to
                # reach this too; the actual authorization (admin, or the matching facultyHeadEmail)
                # happens inside update_campus_event_as_head.
                identity = require_auth(self)
                if not identity:
                    return
                data = payload or {}
                event_id = data.get("eventId")
                if not event_id:
                    self.send_json(400, {"ok": False, "error": "eventId is required"})
                    return
                fields = {key: data[key] for key in ("title", "date", "venue", "fee", "description", "facultyHeadEmail") if key in data}
                event = update_campus_event_as_head(identity, event_id, fields)
                if not event:
                    self.send_json(403, {"ok": False, "error": "Event not found, or you're not authorized to manage it."})
                    return
                self.send_json(200, {"ok": True, "event": event})
                return
            if path == "/api/fest-activities/update":
                # require_auth(self) not allowed_types=["admin"] - a faculty coordinator needs to
                # reach this too; the actual authorization (admin, or the matching
                # facultyCoordinatorEmail) happens inside update_fest_activity.
                identity = require_auth(self)
                if not identity:
                    return
                data = payload or {}
                activity_id = data.get("activityId")
                if not activity_id:
                    self.send_json(400, {"ok": False, "error": "activityId is required"})
                    return
                fields = {key: data[key] for key in ("title", "date", "time", "venue", "description", "facultyCoordinatorEmail", "volunteers") if key in data}
                activity = update_fest_activity(identity, activity_id, fields)
                if not activity:
                    self.send_json(403, {"ok": False, "error": "Fest activity not found, or you're not authorized to manage it."})
                    return
                self.send_json(200, {"ok": True, "activity": activity})
                return
            if path == "/api/fest-activities/create":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                data = payload or {}
                fields = {key: data[key] for key in ("title", "date", "time", "venue", "description") if key in data}
                activity = create_fest_activity(identity, fields)
                if not activity:
                    self.send_json(403, {"ok": False, "error": "You're not an approved fest coordinator yet. Ask admin to add you first."})
                    return
                self.send_json(200, {"ok": True, "activity": activity})
                return
            if path == "/api/alumni-albums":
                if not require_auth(self):
                    return
                replace_student_submissions("alumni_albums", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/alumni-memories":
                if not require_auth(self):
                    return
                replace_student_submissions("alumni_memories", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/alumni-event-rsvps":
                if not require_auth(self):
                    return
                replace_student_submissions("alumni_event_rsvps", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/contact-messages":
                # Deliberately left open, unlike its siblings above - this is the public Contact Us
                # form's submit path (anonymous visitors, no login at all) sharing one bulk-replace
                # endpoint with the admin inbox's "remove a message" action. Splitting those into
                # separate add-only/admin-only endpoints so this can be gated too is real follow-up
                # work, not attempted here - noted as a residual gap, not silently left implicit.
                replace_student_submissions("contact_messages", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/calendar-reminders":
                if not require_auth(self):
                    return
                replace_student_submissions("calendar_reminders", payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/student-documents":
                identity = require_auth(self)
                if not identity:
                    return
                doc = payload or {}
                if identity["identityType"] == "student" and identity["identityId"] != doc.get("studentId"):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                if not doc.get("studentId") or not doc.get("docType") or not doc.get("fileUrl"):
                    self.send_json(400, {"ok": False, "error": "studentId, docType and fileUrl are required"})
                    return
                create_student_document(doc)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/student-documents/remove":
                if not require_auth(self):
                    return
                doc_id = (payload or {}).get("id") or ""
                if not doc_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM student_documents WHERE id = {quote(doc_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/course-materials":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                create_course_material(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/course-materials/remove":
                if not require_auth(self, allowed_types=["admin", "faculty"]):
                    return
                material_id = (payload or {}).get("id") or ""
                if not material_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                run_psql(f"DELETE FROM course_materials WHERE id = {quote(material_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/notifications/mine":
                identity = require_auth(self)
                if not identity:
                    return
                notifications = get_my_notifications(identity["identityType"], identity["identityId"])
                self.send_json(200, {"ok": True, "notifications": notifications})
                return
            if path == "/api/notifications/mark-read":
                identity = require_auth(self)
                if not identity:
                    return
                notification_id = (payload.get("id") or "").strip()
                if not notification_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                mark_notification_read(notification_id, identity["identityType"], identity["identityId"])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/notifications/clear":
                identity = require_auth(self)
                if not identity:
                    return
                notification_id = (payload.get("id") or "").strip()
                if notification_id:
                    clear_notification(notification_id, identity["identityType"], identity["identityId"])
                else:
                    clear_all_notifications(identity["identityType"], identity["identityId"])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/knowledge-base/refresh":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                chunks = payload.get("chunks") or []
                try:
                    count = refresh_knowledge_base(chunks)
                except (URLError, HTTPError, ValueError) as error:
                    self.send_json(502, {"ok": False, "error": f"Embedding model unavailable: {error}"})
                    return
                self.send_json(200, {"ok": True, "count": count})
                return
            if path == "/api/knowledge-base/search":
                # Deliberately unauthenticated, like /api/contact-messages - the public marketing
                # site's chatbot (index.html) calls this from anonymous, logged-out visitors, not
                # just the dashboards' bots.
                question = (payload.get("question") or "").strip()
                top_n = payload.get("topN") or 4
                if not question:
                    self.send_json(400, {"ok": False, "error": "question is required"})
                    return
                try:
                    chunks = search_knowledge_base(question, top_n)
                except (URLError, HTTPError, ValueError) as error:
                    self.send_json(502, {"ok": False, "error": f"Embedding model unavailable: {error}"})
                    return
                self.send_json(200, {"ok": True, "chunks": chunks})
                return
            if path == "/api/bot-feedback":
                # Unauthenticated like the search endpoint above - anonymous public-site visitors
                # can flag a bad answer too, not just logged-in dashboard users. reporterType/
                # reporterId are best-effort (whoever's session is present, or "public").
                question = (payload.get("question") or "").strip()
                bot_answer = (payload.get("botAnswer") or "").strip()
                if not question or not bot_answer:
                    self.send_json(400, {"ok": False, "error": "question and botAnswer are required"})
                    return
                identity = authenticate(self)
                submit_bot_feedback(
                    question, bot_answer,
                    identity["identityType"] if identity else "public",
                    identity["identityId"] if identity else None,
                )
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bot-feedback/list":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                status = (payload.get("status") or "").strip() or None
                self.send_json(200, {"ok": True, "items": list_bot_feedback(status)})
                return
            if path == "/api/bot-feedback/resolve":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                feedback_id = (payload.get("id") or "").strip()
                correction = (payload.get("correction") or "").strip()
                if not feedback_id or not correction:
                    self.send_json(400, {"ok": False, "error": "id and correction are required"})
                    return
                try:
                    resolve_bot_feedback(feedback_id, correction)
                except (URLError, HTTPError, ValueError) as error:
                    self.send_json(502, {"ok": False, "error": f"Embedding model unavailable: {error}"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/bot-feedback/dismiss":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                feedback_id = (payload.get("id") or "").strip()
                if not feedback_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                dismiss_bot_feedback(feedback_id)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/exam-cell-applications":
                identity = require_auth(self, allowed_types=["student"])
                if not identity:
                    return
                application_type = (payload.get("applicationType") or "").strip()
                form_data = payload.get("formData") or {}
                if application_type not in EXAM_CELL_APPLICATION_TYPES:
                    self.send_json(400, {"ok": False, "error": "Unknown application type"})
                    return
                submit_exam_cell_application(application_type, identity["identityId"], form_data)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/exam-cell-applications/mine":
                identity = require_auth(self, allowed_types=["student"])
                if not identity:
                    return
                self.send_json(200, {"ok": True, "items": get_my_exam_cell_applications(identity["identityId"])})
                return
            if path == "/api/exam-cell-applications/all":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                status = (payload.get("status") or "").strip() or None
                self.send_json(200, {"ok": True, "items": get_all_exam_cell_applications(status)})
                return
            if path == "/api/exam-cell-applications/status":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                application_id = (payload.get("id") or "").strip()
                status = (payload.get("status") or "").strip()
                admin_note = (payload.get("adminNote") or "").strip() or None
                if not application_id or status not in ("Approved", "Rejected"):
                    self.send_json(400, {"ok": False, "error": "id and a valid status (Approved/Rejected) are required"})
                    return
                update_exam_cell_application_status(application_id, status, admin_note)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/courses":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                title = (payload.get("title") or "").strip()
                description = (payload.get("description") or "").strip()
                lessons = payload.get("lessons") or []
                sections = [s.strip() for s in (payload.get("sections") or []) if s.strip()]
                if not title or not description or not lessons or not sections:
                    self.send_json(400, {"ok": False, "error": "title, description, at least one section, and at least one lesson are required"})
                    return
                course_id = create_online_course(identity["identityId"], title, description, lessons, sections)
                if not course_id:
                    self.send_json(400, {"ok": False, "error": "Could not resolve your faculty record"})
                    return
                self.send_json(200, {"ok": True, "id": course_id})
                return
            if path == "/api/courses/sections":
                if not require_auth(self, allowed_types=["faculty"]):
                    return
                self.send_json(200, {"ok": True, "sections": get_class_sections()})
                return
            if path == "/api/webinars":
                identity = require_auth(self, allowed_types=["admin"])
                if not identity:
                    return
                title = (payload.get("title") or "").strip()
                description = (payload.get("description") or "").strip()
                live_link = (payload.get("liveLink") or "").strip()
                scheduled_at = (payload.get("scheduledAt") or "").strip()
                if not title or not description or not live_link or not scheduled_at:
                    self.send_json(400, {"ok": False, "error": "title, description, live link and scheduled time are required"})
                    return
                if not create_webinar(identity["identityId"], title, description, live_link, scheduled_at):
                    self.send_json(400, {"ok": False, "error": "Could not resolve your admin record"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/webinars/all":
                identity = require_auth(self, allowed_types=["student", "faculty", "admin"])
                if not identity:
                    return
                webinars = (
                    get_all_webinars()
                    if identity["identityType"] == "admin"
                    else get_webinars_for_viewer(identity["identityType"], identity["identityId"])
                )
                self.send_json(200, {"ok": True, "webinars": webinars})
                return
            if path == "/api/webinars/remove":
                identity = require_auth(self, allowed_types=["admin"])
                if not identity:
                    return
                webinar_id = (payload.get("id") or "").strip()
                if not webinar_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                remove_webinar(webinar_id)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/webinars/view-ping":
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                webinar_id = (payload.get("webinarId") or "").strip()
                if not webinar_id:
                    self.send_json(400, {"ok": False, "error": "webinarId is required"})
                    return
                record_webinar_view(webinar_id, identity["identityType"], identity["identityId"])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/online-classes":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                title = (payload.get("title") or "").strip()
                description = (payload.get("description") or "").strip()
                live_link = (payload.get("liveLink") or "").strip()
                scheduled_at = (payload.get("scheduledAt") or "").strip()
                sections = [s.strip() for s in (payload.get("sections") or []) if s.strip()]
                if not title or not description or not live_link or not scheduled_at or not sections:
                    self.send_json(400, {"ok": False, "error": "title, description, live link, scheduled time and at least one section are required"})
                    return
                live_link_lower = live_link.lower()
                if "zoom.us" not in live_link_lower and "teams.microsoft.com" not in live_link_lower and "teams.live.com" not in live_link_lower:
                    self.send_json(400, {"ok": False, "error": "Live link must be a Zoom or Microsoft Teams meeting link"})
                    return
                if not create_online_class(identity["identityId"], title, description, live_link, scheduled_at, sections):
                    self.send_json(400, {"ok": False, "error": "Could not resolve your faculty record"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/online-classes/all":
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                classes = (
                    get_my_online_classes(identity["identityId"])
                    if identity["identityType"] == "faculty"
                    else get_online_classes_for_student(identity["identityId"])
                )
                self.send_json(200, {"ok": True, "classes": classes})
                return
            if path == "/api/online-classes/remove":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                class_id = (payload.get("id") or "").strip()
                if not class_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                if not remove_online_class(class_id, identity["identityId"]):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/online-classes/view-ping":
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                class_id = (payload.get("classId") or "").strip()
                if not class_id:
                    self.send_json(400, {"ok": False, "error": "classId is required"})
                    return
                record_class_view(class_id, identity["identityType"], identity["identityId"])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/courses/all":
                identity = require_auth(self, allowed_types=["student", "faculty"])
                if not identity:
                    return
                courses = (
                    get_courses_for_student(identity["identityId"])
                    if identity["identityType"] == "student"
                    else get_all_online_courses()
                )
                self.send_json(200, {"ok": True, "courses": courses})
                return
            if path == "/api/courses/remove":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                course_id = (payload.get("id") or "").strip()
                if not course_id:
                    self.send_json(400, {"ok": False, "error": "id is required"})
                    return
                owner = run_psql(f"""
                    SELECT 1 FROM online_courses WHERE id = {quote(course_id)}::uuid AND faculty_email = {quote(identity["identityId"])};
                """).strip()
                if not owner:
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                run_psql(f"DELETE FROM online_courses WHERE id = {quote(course_id)}::uuid;")
                self.send_json(200, {"ok": True})
                return
            if path == "/api/course-enrollments":
                identity = require_auth(self, allowed_types=["student"])
                if not identity:
                    return
                course_id = (payload.get("courseId") or "").strip()
                if not course_id:
                    self.send_json(400, {"ok": False, "error": "courseId is required"})
                    return
                enroll_in_course(course_id, identity["identityId"])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/course-enrollments/mine":
                identity = require_auth(self, allowed_types=["student"])
                if not identity:
                    return
                self.send_json(200, {"ok": True, "enrollments": get_my_course_enrollments(identity["identityId"])})
                return
            if path == "/api/course-lessons/complete":
                identity = require_auth(self, allowed_types=["student"])
                if not identity:
                    return
                course_id = (payload.get("courseId") or "").strip()
                lesson_id = (payload.get("lessonId") or "").strip()
                if not course_id or not lesson_id:
                    self.send_json(400, {"ok": False, "error": "courseId and lessonId are required"})
                    return
                if not complete_course_lesson(course_id, lesson_id, identity["identityId"]):
                    self.send_json(400, {"ok": False, "error": "You are not enrolled in this course"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/course-lessons/uncomplete":
                identity = require_auth(self, allowed_types=["student"])
                if not identity:
                    return
                course_id = (payload.get("courseId") or "").strip()
                lesson_id = (payload.get("lessonId") or "").strip()
                if not course_id or not lesson_id:
                    self.send_json(400, {"ok": False, "error": "courseId and lessonId are required"})
                    return
                if not uncomplete_course_lesson(course_id, lesson_id, identity["identityId"]):
                    self.send_json(400, {"ok": False, "error": "You are not enrolled in this course"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/courses/mine/stats":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                self.send_json(200, {"ok": True, "courses": get_faculty_course_stats(identity["identityId"])})
                return
            if path == "/api/courses/lessons/add":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                course_id = (payload.get("courseId") or "").strip()
                title = (payload.get("title") or "").strip()
                resource_url = (payload.get("resourceUrl") or "").strip()
                if not course_id or not title or not resource_url:
                    self.send_json(400, {"ok": False, "error": "courseId, title and resourceUrl are required"})
                    return
                if not add_course_lesson(course_id, identity["identityId"], title, resource_url):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/courses/lessons/remove":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                lesson_id = (payload.get("lessonId") or "").strip()
                if not lesson_id:
                    self.send_json(400, {"ok": False, "error": "lessonId is required"})
                    return
                if not remove_course_lesson(lesson_id, identity["identityId"]):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/courses/lessons/update":
                identity = require_auth(self, allowed_types=["faculty"])
                if not identity:
                    return
                lesson_id = (payload.get("lessonId") or "").strip()
                title = (payload.get("title") or "").strip()
                resource_url = (payload.get("resourceUrl") or "").strip()
                if not lesson_id or not title or not resource_url:
                    self.send_json(400, {"ok": False, "error": "lessonId, title and resourceUrl are required"})
                    return
                if not update_course_lesson(lesson_id, identity["identityId"], title, resource_url):
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                self.send_json(200, {"ok": True})
                return
            if path == "/api/book-favorites":
                auth_identity = require_auth(self)
                if not auth_identity:
                    return
                identity = (payload or {}).get("identity") or ""
                # bookFavorites identity strings are "student:<roll>"/"faculty:<email>" (colon,
                # not the hyphen bank-details/owns_key uses) - checked inline rather than adding a
                # second helper for one caller.
                if auth_identity["identityType"] in ("student", "faculty") and identity != f"{auth_identity['identityType']}:{auth_identity['identityId']}":
                    self.send_json(403, {"ok": False, "error": "forbidden"})
                    return
                favorites = (payload or {}).get("favorites")
                if not identity or favorites is None:
                    self.send_json(400, {"ok": False, "error": "identity and favorites are required"})
                    return
                set_book_favorites(identity, favorites)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/ai-usage":
                record_ai_usage(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/ai-usage/reset":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                reset_ai_usage()
                self.send_json(200, {"ok": True})
                return
            if path == "/api/ai-request-log":
                record_ai_request_log(payload or {})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/activity-log":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                record_activity(
                    (payload or {}).get("scope"), (payload or {}).get("actor"),
                    (payload or {}).get("action"), (payload or {}).get("module")
                )
                self.send_json(200, {"ok": True})
                return
            if path == "/api/alumni/signup":
                email = ((payload or {}).get("email") or "").strip().lower()
                password = (payload or {}).get("password") or ""
                if not email or not password:
                    self.send_json(400, {"ok": False, "error": "email and password are required"})
                    return
                created = create_alumni_account(email, password, (payload or {}).get("name"), (payload or {}).get("batchYear"))
                if not created:
                    self.send_json(200, {"ok": False, "reason": "email-exists"})
                    return
                token = create_session("alumni", email)
                self.send_json(200, {"ok": True, "account": {"email": email, "name": (payload or {}).get("name"), "batchYear": (payload or {}).get("batchYear")}, "token": token})
                return
            if path == "/api/alumni/login":
                email = ((payload or {}).get("email") or "").strip().lower()
                password = (payload or {}).get("password") or ""
                throttle_key = f"alumni-login:{email}"
                if check_throttle(throttle_key):
                    self.send_json(200, {"ok": False, "reason": "locked"})
                    return
                account = verify_alumni_login(email, password) if email and password else None
                if not account:
                    record_throttle_failure(throttle_key)
                    self.send_json(200, {"ok": False, "reason": "bad-credentials"})
                    return
                clear_throttle(throttle_key)
                token = create_session("alumni", email)
                self.send_json(200, {"ok": True, "account": account, "token": token})
                return
            if path == "/api/alumni/reset-password":
                email = ((payload or {}).get("email") or "").strip().lower()
                batch_year = (payload or {}).get("batchYear") or ""
                new_password = (payload or {}).get("newPassword") or ""
                throttle_key = f"alumni-reset:{email}"
                if check_throttle(throttle_key):
                    self.send_json(200, {"ok": False, "reason": "locked"})
                    return
                if not email or not new_password or not batch_year:
                    self.send_json(400, {"ok": False, "error": "email, batchYear and newPassword are required"})
                    return
                if not alumni_account_exists(email):
                    self.send_json(200, {"ok": False, "reason": "no-account"})
                    return
                if not alumni_identity_matches(email, batch_year):
                    record_throttle_failure(throttle_key)
                    self.send_json(200, {"ok": False, "reason": "identity-mismatch"})
                    return
                clear_throttle(throttle_key)
                reset_alumni_password(email, new_password)
                revoke_all_sessions("alumni", email)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/alumni/google-complete":
                id_token = (payload or {}).get("idToken") or ""
                if not id_token:
                    self.send_json(400, {"ok": False, "error": "idToken is required"})
                    return
                verified = verify_google_id_token(id_token)
                if not verified:
                    self.send_json(200, {"ok": False, "reason": "invalid-token"})
                    return
                account = upsert_alumni_google_profile(
                    verified["email"], (payload or {}).get("name") or verified["name"], (payload or {}).get("batchYear")
                )
                token = create_session("alumni", verified["email"])
                self.send_json(200, {"ok": True, "account": account, "token": token})
                return
            if path == "/api/alumni/profiles":
                if not require_auth(self, allowed_types=["alumni", "admin"]):
                    return
                save_alumni_profiles(payload or [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/funding-contributions":
                if not require_auth(self, allowed_types=["alumni", "admin"]):
                    return
                contribution = payload or {}
                if not contribution.get("campaignId") or contribution.get("amount") is None:
                    self.send_json(400, {"ok": False, "error": "campaignId and amount are required"})
                    return
                create_funding_contribution(contribution)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/faculty":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                faculty = payload or {}
                if not faculty.get("email") or not faculty.get("name"):
                    self.send_json(400, {"ok": False, "error": "name and email are required"})
                    return
                upsert_faculty_row(faculty)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/faculty/remove":
                if not require_auth(self, allowed_types=["admin"]):
                    return
                email = (payload or {}).get("email") or ""
                if not email:
                    self.send_json(400, {"ok": False, "error": "email is required"})
                    return
                remove_faculty_row(email)
                self.send_json(200, {"ok": True})
                return
            self.send_json(404, {"error": "Not found"})
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), PortalHandler)
    print(f"GPREC portal running at http://{HOST}:{PORT}")
    print(f"Database: postgresql://{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME} schema={DB_SCHEMA}")
    server.serve_forever()
