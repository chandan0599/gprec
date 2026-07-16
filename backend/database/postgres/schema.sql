BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE SCHEMA IF NOT EXISTS gprec_erp;
SET search_path TO gprec_erp, public;

DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN
    SELECT c.relname, c.relkind
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'v', 'm', 'S')
      AND c.relname NOT LIKE 'pg_%'
  LOOP
    IF r.relkind = 'r' THEN
      EXECUTE format('ALTER TABLE IF EXISTS public.%I SET SCHEMA gprec_erp', r.relname);
    ELSIF r.relkind = 'v' THEN
      EXECUTE format('ALTER VIEW IF EXISTS public.%I SET SCHEMA gprec_erp', r.relname);
    ELSIF r.relkind = 'm' THEN
      EXECUTE format('ALTER MATERIALIZED VIEW IF EXISTS public.%I SET SCHEMA gprec_erp', r.relname);
    ELSE
      EXECUTE format('ALTER SEQUENCE IF EXISTS public.%I SET SCHEMA gprec_erp', r.relname);
    END IF;
  END LOOP;
END $$;

CREATE TABLE IF NOT EXISTS departments (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  short_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS students (
  roll_no TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  department_code TEXT NOT NULL REFERENCES departments(code),
  class_name TEXT NOT NULL,
  semester TEXT NOT NULL,
  date_of_birth DATE,
  gender TEXT,
  blood_group TEXT,
  mobile TEXT,
  email TEXT UNIQUE,
  address TEXT,
  admission_type TEXT,
  academic_year TEXT NOT NULL,
  hostel_status TEXT NOT NULL DEFAULT 'Day scholar',
  status TEXT NOT NULL DEFAULT 'Active',
  profile_photo_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE IF EXISTS students ADD COLUMN IF NOT EXISTS profile_photo_url TEXT;
-- Regulation/curriculum-version identifier (e.g. "R20"). Nullable and admin-set - never
-- fabricated client-side; the UI shows "-" until an admin actually enters one.
ALTER TABLE IF EXISTS students ADD COLUMN IF NOT EXISTS admission_scheme TEXT;
ALTER TABLE IF EXISTS faculty ADD COLUMN IF NOT EXISTS profile_photo_url TEXT;

-- Educational history shown on the student dashboard's profile card, previously only ever
-- present on the one hardcoded fallback student and never on a real database row.
ALTER TABLE IF EXISTS students ADD COLUMN IF NOT EXISTS ssc_school TEXT;
ALTER TABLE IF EXISTS students ADD COLUMN IF NOT EXISTS ssc_board_year TEXT;
ALTER TABLE IF EXISTS students ADD COLUMN IF NOT EXISTS ssc_gpa TEXT;
ALTER TABLE IF EXISTS students ADD COLUMN IF NOT EXISTS inter_college TEXT;
ALTER TABLE IF EXISTS students ADD COLUMN IF NOT EXISTS inter_board_year TEXT;
ALTER TABLE IF EXISTS students ADD COLUMN IF NOT EXISTS inter_percentage TEXT;

-- Academic profile fields shown on the faculty profile row (student dashboard's Faculty/HOD
-- cards, and the faculty's own dashboard), same gap as above - only ever on hardcoded entries.
ALTER TABLE IF EXISTS faculty ADD COLUMN IF NOT EXISTS qualifications TEXT;
ALTER TABLE IF EXISTS faculty ADD COLUMN IF NOT EXISTS google_scholar TEXT;
ALTER TABLE IF EXISTS faculty ADD COLUMN IF NOT EXISTS apaar_id TEXT;
ALTER TABLE IF EXISTS faculty ADD COLUMN IF NOT EXISTS vidwan_profile TEXT;

-- Directory contact number - faculty phone is public/office-directory info (unlike student
-- personal data), shown alongside name/email/department in the faculty directory and the
-- GPRECian chat bot's directory lookups.
ALTER TABLE IF EXISTS faculty ADD COLUMN IF NOT EXISTS phone TEXT;

-- Primary subject taught, so "who teaches DBMS" style directory lookups (chat bot and elsewhere)
-- have something real to match against - previously only ever set on hardcoded fallback entries.
ALTER TABLE IF EXISTS faculty ADD COLUMN IF NOT EXISTS primary_subject TEXT;

-- Short course code (e.g. "DBMS", "OS", "PS") for the subject above - lets a directory lookup
-- match the exact abbreviation someone typed directly, instead of always needing an AI call to
-- expand it to the full subject name first (which a small/local model doesn't always get right).
ALTER TABLE IF EXISTS faculty ADD COLUMN IF NOT EXISTS subject_code TEXT;

CREATE TABLE IF NOT EXISTS guardians (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  father_name TEXT,
  mother_name TEXT,
  guardian_mobile TEXT,
  guardian_email TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS faculty (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  department_code TEXT REFERENCES departments(code),
  designation TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Active',
  profile_photo_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Non-teaching staff (office, accounts, library, lab, maintenance) previously had no database
-- table at all - the entire directory used for their login and display was hardcoded in script.js.
CREATE TABLE IF NOT EXISTS non_teaching_staff (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  designation TEXT NOT NULL,
  section TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Active',
  profile_photo_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  department_code TEXT,
  can_manage_admins BOOLEAN NOT NULL DEFAULT false,
  status TEXT NOT NULL DEFAULT 'Active',
  photo_url TEXT,
  student_roll TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Login credentials for admin / faculty / non-teaching staff. Kept as a thin, separate table
-- (rather than columns on admins/faculty) so the bootstrap query never has to touch it and can
-- never accidentally expose a hash - it is only ever read/written by the /api/auth/* endpoints.
CREATE TABLE IF NOT EXISTS user_credentials (
  email TEXT PRIMARY KEY,
  role_type TEXT NOT NULL,
  full_name TEXT NOT NULL,
  recovery_mobile TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  must_change_password BOOLEAN NOT NULL DEFAULT true,
  password_set_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Session tokens for all six login roles (student/parent logins previously never touched the
-- backend at all - see student-login/parent-otp endpoints - so this is the first real
-- server-side session concept anywhere in the app, not an extension of an existing one).
-- Only the SHA-256 hash of the token is stored, matching the password_hash/bank_details posture
-- elsewhere in this file - the raw token is returned to the client exactly once, at login.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  identity_type TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  role_label TEXT,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sessions_identity ON sessions(identity_type, identity_id);

-- Generic login-attempt lockout, keyed by a caller-chosen string ('student:<rollNo>',
-- 'parent-otp:<mobile>', 'reset:<email>', etc.) so every login/recovery flow can share one table
-- instead of each needing its own attempt-counter column.
CREATE TABLE IF NOT EXISTS login_throttle (
  throttle_key TEXT PRIMARY KEY,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Server-generated parent-login OTPs. Still shown on-screen to the parent (no SMS gateway exists,
-- an accepted constraint of this local app - see parent-otp/request), but now verified against a
-- real stored hash server-side instead of a pure client-side string compare.
CREATE TABLE IF NOT EXISTS otp_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  mobile TEXT NOT NULL,
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  otp_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_otp_challenges_mobile ON otp_challenges(mobile, created_at);

CREATE TABLE IF NOT EXISTS notices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  audience TEXT NOT NULL DEFAULT 'All',
  published_by TEXT NOT NULL,
  published_on DATE NOT NULL DEFAULT CURRENT_DATE,
  status TEXT NOT NULL DEFAULT 'Published',
  attachment_name TEXT,
  attachment_url TEXT,
  attachment_mime TEXT,
  department_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fee_dues (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  fee_type TEXT NOT NULL,
  amount NUMERIC(10,2) NOT NULL CHECK (amount >= 0),
  due_date DATE NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  fee_due_id UUID REFERENCES fee_dues(id) ON DELETE SET NULL,
  transaction_ref TEXT UNIQUE,
  amount NUMERIC(10,2) NOT NULL CHECK (amount >= 0),
  paid_on TIMESTAMPTZ NOT NULL DEFAULT now(),
  payment_mode TEXT,
  status TEXT NOT NULL DEFAULT 'Success',
  -- Free-form receipt shape (feeType/detail/receiptLines/tempId fields etc.) - the payment flow
  -- has no real gateway integration and the receipt layout is ad-hoc per fee type, so this avoids
  -- a brittle one-column-per-field mapping. Core queryable fields still live in real columns above.
  details JSONB
);
ALTER TABLE IF EXISTS payments ALTER COLUMN transaction_ref DROP NOT NULL;
ALTER TABLE IF EXISTS payments ADD COLUMN IF NOT EXISTS details JSONB;
ALTER TABLE IF EXISTS payments ALTER COLUMN payment_mode DROP NOT NULL;

CREATE TABLE IF NOT EXISTS exam_schedules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  department_code TEXT NOT NULL REFERENCES departments(code),
  subject_code TEXT NOT NULL,
  subject_name TEXT NOT NULL,
  exam_date DATE NOT NULL,
  exam_time TEXT NOT NULL,
  roll_from TEXT NOT NULL,
  roll_to TEXT NOT NULL,
  room TEXT NOT NULL,
  start_seat INTEGER NOT NULL,
  location TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- 'current' = live exam-cell schedule; any other value is a past semester's schedule kept for
  -- students'/parents' historical reference (e.g. "V Semester").
  term_label TEXT NOT NULL DEFAULT 'current'
);
ALTER TABLE IF EXISTS exam_schedules ADD COLUMN IF NOT EXISTS term_label TEXT NOT NULL DEFAULT 'current';
CREATE INDEX IF NOT EXISTS idx_exam_schedules_term ON exam_schedules(term_label);

CREATE TABLE IF NOT EXISTS hostel_allocations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_roll_no TEXT NOT NULL UNIQUE REFERENCES students(roll_no) ON DELETE CASCADE,
  hostel_name TEXT NOT NULL,
  block_name TEXT NOT NULL,
  room_no TEXT NOT NULL,
  bed_no TEXT NOT NULL,
  mess_plan TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Active'
);

-- Outing/visiting/hostel-leave requests are rich per-type documents (mobile numbers, room/hostel,
-- visitor relationship, etc.) that the frontend manages as one JS object per record, read-all/
-- mutate-one/save-all - same JSONB-blob-keyed-by-client-id pattern as student_projects/
-- student_research (see replace_student_submissions in portal_db_server.py). Replaces an earlier
-- hostel_requests table that was never actually wired up to anything.
CREATE TABLE IF NOT EXISTS hostel_outing_requests (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS hostel_visiting_requests (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS hostel_leave_requests (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Campus Event registrations: one row per student per event (id = "{eventId}:{rollNo}"). Unlike
-- the hostel_*_requests tables above, a student never manages a personal list here - they submit
-- exactly one record for themselves once - so this is written via a single-row upsert
-- (upsert_campus_event_registration in portal_db_server.py), not the delete-then-reinsert-by-id
-- replace_student_submissions() pattern, which would have a real lost-update race for this table
-- (two students registering close together could have the second POST's stale snapshot silently
-- delete the first student's just-inserted row). gateToken/checkIn live as extra keys inside the
-- data blob, same technique as hostel gate passes (see campus_event_gate_lookup).
CREATE TABLE IF NOT EXISTS campus_event_registrations (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Alumni Photo & Video Albums feed (albums group "memory" posts with like/comment/share) and
-- event RSVPs - same JSONB-blob-per-record pattern as student_projects. RSVPs have no natural id
-- of their own (keyed by eventId+email in the UI), so the client synthesizes "eventId:email" as
-- the id before saving (see saveEventRsvps in script.js).
CREATE TABLE IF NOT EXISTS alumni_albums (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS alumni_memories (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS alumni_event_rsvps (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Contact Us form inbox - previously only visible in whichever admin browser happened to load
-- it, not shared across admins.
CREATE TABLE IF NOT EXISTS contact_messages (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dashboard calendar reminders - includes both "personal" (owner-scoped) and "shared" (e.g.
-- college holidays) entries in the same list; "shared" ones must be visible to every viewer, so
-- this can't be per-browser localStorage.
CREATE TABLE IF NOT EXISTS calendar_reminders (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS complaints (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  category TEXT NOT NULL,
  subject TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS library_books (
  barcode TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  author TEXT NOT NULL,
  department_code TEXT REFERENCES departments(code),
  status TEXT NOT NULL DEFAULT 'Available'
);

CREATE TABLE IF NOT EXISTS library_issues (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  barcode TEXT NOT NULL REFERENCES library_books(barcode),
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  issued_on DATE NOT NULL,
  due_on DATE NOT NULL,
  returned_on DATE,
  status TEXT NOT NULL DEFAULT 'Issued'
);

CREATE TABLE IF NOT EXISTS placement_drives (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company TEXT NOT NULL,
  role_title TEXT NOT NULL,
  ctc TEXT NOT NULL,
  drive_date DATE NOT NULL,
  min_cgpa NUMERIC(3,2) NOT NULL,
  max_backlogs INTEGER NOT NULL DEFAULT 0,
  eligible_departments TEXT[] NOT NULL,
  status TEXT NOT NULL DEFAULT 'Open',
  -- 'Placement', 'Internship', 'Mock Interview', 'Aptitude Test', or 'Job Recommendation' - one
  -- table/form/applications flow for all five (posted, optionally applied/registered to, and
  -- tracked the same way), tagged so the UI can show/report on them separately. Several columns
  -- are repurposed per type rather than adding a column per type - see the per-type field-reuse
  -- table in the feature's plan doc. ctc stays free-text for both Placement/Internship ("6 LPA" or
  -- "15k/month") and doubles as an optional package field for Job Recommendation.
  drive_type TEXT NOT NULL DEFAULT 'Placement',
  -- Below: unused by Placement/Internship. Mock Interview/Aptitude Test use description/
  -- session_time/venue/mode/seat_cap; Job Recommendation uses description (as an eligibility
  -- blurb) and apply_link. min_cgpa/max_backlogs/eligible_departments stay NOT NULL for schema
  -- simplicity and get server-forced sentinel values (0 / 99 / '{}') for these three types instead
  -- of being made nullable - see apply_to_placement_drive()/create_placement_drive() in
  -- portal_db_server.py.
  description TEXT NOT NULL DEFAULT '',
  session_time TEXT,
  venue TEXT,
  mode TEXT,
  seat_cap INTEGER,
  apply_link TEXT
);

CREATE TABLE IF NOT EXISTS assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  department_code TEXT NOT NULL REFERENCES departments(code),
  subject_code TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  due_at TIMESTAMPTZ NOT NULL,
  created_by TEXT NOT NULL,
  document_name TEXT,
  document_url TEXT,
  document_mime TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assignment_submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assignment_id UUID NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  comments TEXT,
  status TEXT NOT NULL DEFAULT 'Submitted',
  UNIQUE (assignment_id, student_roll_no)
);

-- Multiple documents/photos per submission (the form allows attaching several files at once).
CREATE TABLE IF NOT EXISTS assignment_submission_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_id UUID NOT NULL REFERENCES assignment_submissions(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,
  file_url TEXT NOT NULL,
  file_mime TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS assignment_submission_files ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Department admin's CSV uploads (Curriculum, Timetable) - previously localStorage-only, so an
-- upload on one browser never showed up for students on any other device. Upserted by natural
-- key (subject code / day+time+section) so re-uploading a CSV updates matching rows in place
-- instead of wiping and replacing the whole department's list every time.
CREATE TABLE IF NOT EXISTS curriculum (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  department_code TEXT NOT NULL,
  subject_code TEXT NOT NULL,
  subject_name TEXT NOT NULL,
  semester TEXT NOT NULL DEFAULT '-',
  credits TEXT NOT NULL DEFAULT '-',
  subject_type TEXT NOT NULL DEFAULT 'Theory',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (department_code, subject_code)
);

CREATE TABLE IF NOT EXISTS class_timetable (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  department_code TEXT NOT NULL,
  section TEXT NOT NULL DEFAULT '',
  day_of_week TEXT NOT NULL,
  time_slot TEXT NOT NULL,
  subject_code TEXT NOT NULL,
  subject_name TEXT NOT NULL,
  faculty_email TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (department_code, section, day_of_week, time_slot)
);

-- Faculty attendance marking (Attendance Marking panel), previously localStorage-only. One row
-- per class session (faculty+subject+section+date), with a per-student present/absent entry -
-- upserted so re-saving a correction to yesterday's attendance updates in place.
CREATE TABLE IF NOT EXISTS attendance_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_email TEXT NOT NULL,
  subject_code TEXT NOT NULL,
  section TEXT NOT NULL,
  attendance_date DATE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (faculty_email, subject_code, section, attendance_date)
);

CREATE TABLE IF NOT EXISTS attendance_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  record_id UUID NOT NULL REFERENCES attendance_records(id) ON DELETE CASCADE,
  student_roll_no TEXT NOT NULL,
  present BOOLEAN NOT NULL,
  UNIQUE (record_id, student_roll_no)
);

CREATE INDEX IF NOT EXISTS idx_attendance_entries_record ON attendance_entries(record_id);
CREATE INDEX IF NOT EXISTS idx_attendance_entries_student ON attendance_entries(student_roll_no);

-- Semester GPA/backlog history (Grades panel) - previously a single hardcoded 4-row list shown
-- identically to every student regardless of who was logged in. Upserted by (roll no, term).
CREATE TABLE IF NOT EXISTS student_grades (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  term TEXT NOT NULL,
  gpa TEXT NOT NULL,
  backlogs TEXT NOT NULL DEFAULT 'NIL',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (student_roll_no, term)
);

CREATE INDEX IF NOT EXISTS idx_student_grades_roll ON student_grades(student_roll_no);
CREATE INDEX IF NOT EXISTS idx_assignment_submission_files_submission ON assignment_submission_files(submission_id);

-- Internal/CIA marks - Mid-1 + Mid-2 (averaged) + Assignment, out of 30, entered by the faculty
-- who teaches subject_code. Raw components are stored, not the computed total, so the total
-- formula can be corrected later without a migration. lab_marks is populated only when the
-- theory subject has an associated lab subject (see findAssociatedLabSubject() in script.js).
CREATE TABLE IF NOT EXISTS internal_marks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  department_code TEXT NOT NULL,
  subject_code TEXT NOT NULL,
  section TEXT NOT NULL,
  academic_year TEXT NOT NULL,
  faculty_email TEXT NOT NULL,
  mid1 NUMERIC,
  mid2 NUMERIC,
  assignment NUMERIC,
  lab_marks NUMERIC,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (student_roll_no, subject_code, section, academic_year)
);
CREATE INDEX IF NOT EXISTS idx_internal_marks_subject ON internal_marks(subject_code, section, academic_year);
CREATE INDEX IF NOT EXISTS idx_internal_marks_faculty ON internal_marks(faculty_email);

-- Generic admin-managed public site content (hero slides, galleries, placement logos,
-- affiliations, social links, admissions/fees/scholarships/about text, alumni funding/events,
-- career listings, student voices, R&D section rows). One key-value table instead of ~27 bespoke
-- tables for what is uniformly "an admin edits a JSON blob that every visitor sees."
CREATE TABLE IF NOT EXISTS site_content (
  content_key TEXT PRIMARY KEY,
  content_value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS placement_applications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  drive_id UUID NOT NULL REFERENCES placement_drives(id) ON DELETE CASCADE,
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'Applied',
  UNIQUE (drive_id, student_roll_no)
);

-- Per-student interview round slots for a Placement/Internship drive (Technical Round, HR Round,
-- etc.) - a student can have several, one per round, so this is a real table rather than a JSONB
-- column bolted onto placement_applications. A slot can only be created for a student who already
-- has a placement_applications row for that drive (enforced server-side, not by a DB constraint,
-- since it's a cross-table business rule rather than a referential one).
CREATE TABLE IF NOT EXISTS interview_schedules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  drive_id UUID NOT NULL REFERENCES placement_drives(id) ON DELETE CASCADE,
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  round_name TEXT NOT NULL,
  slot_date DATE NOT NULL,
  slot_time TEXT NOT NULL,
  venue TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_interview_schedules_student ON interview_schedules(student_roll_no);
CREATE INDEX IF NOT EXISTS idx_interview_schedules_drive ON interview_schedules(drive_id);

-- Generic key -> bank-detail-blob store. Key is role-prefixed on the client (e.g.
-- "student-20X51A0501", "faculty-k.ramesh@gprec.ac.in") since the same refund/salary bank
-- details form is reused across student/faculty/non-teaching dashboards.
-- `details` is Fernet-encrypted ciphertext (TEXT, not JSONB) - account numbers/IFSC are financial
-- PII, encrypted at rest so a raw DB dump/backup doesn't expose them in plaintext. Encrypted and
-- decrypted only in portal_db_server.py (get_bank_details/upsert_bank_details); this table is also
-- never part of BOOTSTRAP_SQL, same isolation as user_credentials - only reachable one key at a
-- time via GET /api/bank-details?key=...
CREATE TABLE IF NOT EXISTS bank_details (
  detail_key TEXT PRIMARY KEY,
  details TEXT NOT NULL,
  -- Plaintext preview with accountNumber masked (first 5 / last 4 digits visible, rest 'X') - safe
  -- to read without decrypting, for any future admin-facing "accounts on file" listing.
  masked_details JSONB,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS bank_details ALTER COLUMN details TYPE TEXT USING details::text;
ALTER TABLE IF EXISTS bank_details ADD COLUMN IF NOT EXISTS masked_details JSONB;

CREATE TABLE IF NOT EXISTS fee_amount_overrides (
  application_type TEXT PRIMARY KEY,
  amount NUMERIC(10,2) NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS student_section_assignments (
  student_roll_no TEXT PRIMARY KEY REFERENCES students(roll_no) ON DELETE CASCADE,
  -- Nullable: "section" already carries the full class label (e.g. "CSE III-A"), department is
  -- only ever set as a convenience, never required.
  department_code TEXT,
  section TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS student_section_assignments ALTER COLUMN department_code DROP NOT NULL;

CREATE TABLE IF NOT EXISTS class_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_email TEXT NOT NULL,
  faculty_name TEXT,
  subject_code TEXT NOT NULL,
  subject TEXT,
  section TEXT,
  department_code TEXT,
  title TEXT,
  message TEXT NOT NULL,
  posted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS class_messages ADD COLUMN IF NOT EXISTS faculty_name TEXT;
ALTER TABLE IF EXISTS class_messages ADD COLUMN IF NOT EXISTS subject TEXT;
ALTER TABLE IF EXISTS class_messages ADD COLUMN IF NOT EXISTS title TEXT;

CREATE TABLE IF NOT EXISTS invigilation_duties (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_email TEXT NOT NULL,
  faculty_name TEXT NOT NULL,
  subject_code TEXT,
  subject TEXT,
  exam_date DATE NOT NULL,
  exam_time TEXT,
  room TEXT,
  location TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Faculty and non-teaching staff leave share this one table: faculty_email/faculty_name are set
-- for the faculty path, staff_email/staff_name for the non-teaching path (is_non_teaching flags
-- which), matching the single "Leave Requests" approval panel the admin dashboard shows for both.
CREATE TABLE IF NOT EXISTS leave_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_email TEXT,
  faculty_name TEXT,
  staff_email TEXT,
  staff_name TEXT,
  designation TEXT,
  leave_type TEXT,
  department_code TEXT,
  reason TEXT NOT NULL,
  from_date DATE NOT NULL,
  to_date DATE NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  is_hod BOOLEAN NOT NULL DEFAULT false,
  is_non_teaching BOOLEAN NOT NULL DEFAULT false,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_by TEXT,
  decided_at TIMESTAMPTZ
);
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS staff_email TEXT;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS staff_name TEXT;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS designation TEXT;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS leave_type TEXT;
ALTER TABLE IF EXISTS leave_requests ADD COLUMN IF NOT EXISTS is_non_teaching BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE IF EXISTS leave_requests ALTER COLUMN faculty_email DROP NOT NULL;
ALTER TABLE IF EXISTS leave_requests ALTER COLUMN faculty_name DROP NOT NULL;

-- Transportation: college bus service (day scholars only, all faculty) + personal vehicle pass.
-- Real tables with server-decided status (not the JSONB-blob-replace-all pattern used by hostel
-- outing/leave requests) since a paid fee and a downloadable pass hang off the approval here -
-- the blob pattern has no server-side ownership check, which would let a requester self-approve.
CREATE TABLE IF NOT EXISTS bus_routes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  route_name TEXT NOT NULL,
  stops TEXT NOT NULL,
  pickup_time TEXT,
  drop_time TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS bus_routes ADD COLUMN IF NOT EXISTS pickup_time TEXT;
ALTER TABLE IF EXISTS bus_routes ADD COLUMN IF NOT EXISTS drop_time TEXT;

CREATE TABLE IF NOT EXISTS buses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bus_number TEXT NOT NULL,
  route_id UUID NOT NULL REFERENCES bus_routes(id) ON DELETE CASCADE,
  driver_name TEXT NOT NULL,
  driver_mobile TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_buses_route ON buses(route_id);

-- No UNIQUE constraint on requester - a rejected request must be resubmittable, and
-- ON CONFLICT DO NOTHING (as used by placement_applications) would make that a silent no-op.
-- "My current status" is always the latest row per requester by requested_at.
CREATE TABLE IF NOT EXISTS bus_route_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bus_id UUID NOT NULL REFERENCES buses(id) ON DELETE CASCADE,
  requester_type TEXT NOT NULL,
  requester_id TEXT NOT NULL,
  requester_name TEXT NOT NULL,
  pickup_point TEXT,
  drop_point TEXT,
  status TEXT NOT NULL DEFAULT 'Pending',
  decision_note TEXT,
  fee_paid_at TIMESTAMPTZ,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_by TEXT,
  decided_at TIMESTAMPTZ,
  valid_until DATE
);
ALTER TABLE IF EXISTS bus_route_requests ADD COLUMN IF NOT EXISTS pickup_point TEXT;
ALTER TABLE IF EXISTS bus_route_requests ADD COLUMN IF NOT EXISTS drop_point TEXT;
ALTER TABLE IF EXISTS bus_route_requests ADD COLUMN IF NOT EXISTS fee_paid_at TIMESTAMPTZ;
ALTER TABLE IF EXISTS bus_route_requests ADD COLUMN IF NOT EXISTS valid_until DATE;
CREATE INDEX IF NOT EXISTS idx_bus_route_requests_requester ON bus_route_requests(requester_type, requester_id);

CREATE TABLE IF NOT EXISTS vehicle_passes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_type TEXT NOT NULL,
  requester_id TEXT NOT NULL,
  requester_name TEXT NOT NULL,
  vehicle_type TEXT NOT NULL,
  vehicle_number TEXT NOT NULL,
  license_number TEXT NOT NULL,
  license_doc_url TEXT,
  rc_doc_url TEXT,
  status TEXT NOT NULL DEFAULT 'Pending',
  verification_result TEXT,
  verification_notes TEXT,
  decision_note TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_by TEXT,
  decided_at TIMESTAMPTZ,
  valid_until DATE
);
CREATE INDEX IF NOT EXISTS idx_vehicle_passes_requester ON vehicle_passes(requester_type, requester_id);

CREATE TABLE IF NOT EXISTS adhoc_class_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_email TEXT NOT NULL,
  faculty_name TEXT NOT NULL,
  department_code TEXT,
  subject TEXT,
  subject_code TEXT,
  reason TEXT NOT NULL,
  requested_date DATE NOT NULL,
  requested_time TEXT,
  status TEXT NOT NULL DEFAULT 'Pending',
  is_hod BOOLEAN NOT NULL DEFAULT false,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS adhoc_class_requests ADD COLUMN IF NOT EXISTS subject_code TEXT;

CREATE TABLE IF NOT EXISTS class_cancellations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_email TEXT NOT NULL,
  subject_code TEXT,
  subject TEXT,
  cancel_date DATE NOT NULL,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Projects/research are rich nested documents (team members, per-milestone submission status,
-- staged files) that the frontend manages as one JS object per record, read-all/mutate-one/
-- save-all across many call sites. Stored as JSONB keyed by the client-generated id rather than
-- normalized into columns, so that existing logic didn't need a relational redesign to move off
-- localStorage - see replace_student_submissions in portal_db_server.py.
CREATE TABLE IF NOT EXISTS student_projects (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS student_research (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- AI-estimated originality check, manually triggered by faculty/admin from the Assignment
-- Submissions / Project / Research review screens (never automatic). One row per submission,
-- re-checking overwrites the previous result. Assignment percentages are only ever shown to
-- faculty/admin in the frontend; project/research percentages are shown to the student too -
-- that visibility split is enforced client-side by submission_type, same as the rest of this
-- app's per-role bootstrap filtering.
CREATE TABLE IF NOT EXISTS plagiarism_checks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_type TEXT NOT NULL, -- 'assignment' | 'project' | 'research'
  reference_id TEXT NOT NULL,
  student_roll_no TEXT NOT NULL,
  percent INTEGER NOT NULL,
  notes TEXT,
  checked_by TEXT NOT NULL,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (submission_type, reference_id)
);
CREATE INDEX IF NOT EXISTS idx_plagiarism_checks_student ON plagiarism_checks(student_roll_no);

CREATE TABLE IF NOT EXISTS course_materials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_code TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  file_name TEXT,
  file_url TEXT,
  file_mime TEXT,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Online Courses: faculty-designed self-contained courses (title + description + ordered
-- lessons), open enrollment for any student (not scoped to the faculty's own class/section).
-- Enrollment status is derived from lesson_progress rows, not set manually - Registered ->
-- In Progress (first lesson done) -> Completed (every lesson done), computed server-side on each
-- lesson-complete write in the /api/course-lessons/complete handler.
CREATE TABLE IF NOT EXISTS online_courses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_email TEXT NOT NULL,
  faculty_name TEXT NOT NULL,
  department_code TEXT,
  -- Each entry matches students.class_name (e.g. "CSE III A") - a course is visible to students
  -- in any of these sections. NULL means visible to everyone (kept for backward compatibility
  -- with courses created before section-scoping existed).
  sections TEXT[],
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_online_courses_faculty ON online_courses(faculty_email);

CREATE TABLE IF NOT EXISTS online_course_lessons (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id UUID NOT NULL REFERENCES online_courses(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  title TEXT NOT NULL,
  resource_url TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_online_course_lessons_course ON online_course_lessons(course_id, position);

CREATE TABLE IF NOT EXISTS online_course_enrollments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id UUID NOT NULL REFERENCES online_courses(id) ON DELETE CASCADE,
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'Registered',
  enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  UNIQUE (course_id, student_roll_no)
);
CREATE INDEX IF NOT EXISTS idx_online_course_enrollments_student ON online_course_enrollments(student_roll_no);
CREATE INDEX IF NOT EXISTS idx_online_course_enrollments_course ON online_course_enrollments(course_id);

CREATE TABLE IF NOT EXISTS online_course_lesson_progress (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  enrollment_id UUID NOT NULL REFERENCES online_course_enrollments(id) ON DELETE CASCADE,
  lesson_id UUID NOT NULL REFERENCES online_course_lessons(id) ON DELETE CASCADE,
  completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (enrollment_id, lesson_id)
);

-- Admin/department-admin posted webinars. department_code is set automatically from the
-- creating admin's own admins.department_code when their role ends in "Department Admin" -
-- scoping the webinar to just that department; a College Admin's webinar leaves it NULL,
-- meaning visible to everyone.
CREATE TABLE IF NOT EXISTS webinars (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_by_email TEXT NOT NULL,
  created_by_name TEXT NOT NULL,
  department_code TEXT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  live_link TEXT NOT NULL,
  scheduled_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webinars_scheduled ON webinars(scheduled_at);

-- Presence tracking for the "N watching now" count - the client pings this on open and every ~20s
-- while the resource viewer modal stays open on a webinar; a viewer only counts as "watching" if
-- last_seen_at is recent (checked at read time, see get_webinar_watch_counts).
CREATE TABLE IF NOT EXISTS webinar_viewers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webinar_id UUID NOT NULL REFERENCES webinars(id) ON DELETE CASCADE,
  viewer_type TEXT NOT NULL,
  viewer_id TEXT NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (webinar_id, viewer_type, viewer_id)
);
CREATE INDEX IF NOT EXISTS idx_webinar_viewers_webinar ON webinar_viewers(webinar_id);

-- Generic, reusable notification feed - any feature (present or future) that needs to tell a
-- user "something happened" calls create_notification()/create_notifications_bulk() in
-- portal_db_server.py rather than inventing its own ad hoc mechanism. Surfaced in the existing
-- bell icon dropdown on every dashboard (see renderNotificationList in script.js), merged
-- alongside that widget's older per-page "pending approvals" lists.
CREATE TABLE IF NOT EXISTS notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  recipient_type TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  link TEXT,
  source_module TEXT,
  is_read BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON notifications(recipient_type, recipient_id, is_read);

-- Faculty-scheduled live online classes, scoped to one or more sections (like online_courses)
-- rather than webinars' department-wide scoping. Same live-link/scheduled-time/watching-count
-- shape as webinars, just a different creator and audience.
CREATE TABLE IF NOT EXISTS online_classes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  faculty_email TEXT NOT NULL,
  faculty_name TEXT NOT NULL,
  sections TEXT[] NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  live_link TEXT NOT NULL,
  scheduled_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_online_classes_faculty ON online_classes(faculty_email);
CREATE INDEX IF NOT EXISTS idx_online_classes_scheduled ON online_classes(scheduled_at);

CREATE TABLE IF NOT EXISTS online_class_viewers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES online_classes(id) ON DELETE CASCADE,
  viewer_type TEXT NOT NULL,
  viewer_id TEXT NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (class_id, viewer_type, viewer_id)
);
CREATE INDEX IF NOT EXISTS idx_online_class_viewers_class ON online_class_viewers(class_id);

-- Student-uploaded records (SSC/inter/admission/ID proof) - previously a dead "View documents"
-- placeholder link with no upload/view mechanism at all.
CREATE TABLE IF NOT EXISTS student_documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  doc_type TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_url TEXT NOT NULL,
  file_mime TEXT,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_student_documents_student ON student_documents(student_roll_no);

-- Self-serve alumni signup/login. password_hash/salt are set only by the dedicated
-- /api/alumni/signup, /api/alumni/login, /api/alumni/reset-password endpoints (same
-- pbkdf2 pattern as user_credentials); every other alumni feature (profile edits, posts,
-- comments, memories) reads/writes only the `profile` JSONB blob via /api/alumni/profile
-- and never touches the password columns.
-- password_hash/salt nullable: a Google-only signup has no password until the alumnus sets one.
-- `data` holds everything else (name, batchYear, viaGoogle, nested edit-profile fields, posts,
-- memories) as one JSONB blob per the same read-all/mutate-one/save-all pattern as
-- student_projects - see save_alumni_profiles in portal_db_server.py. password_hash/salt are
-- only ever touched by create_alumni_account/verify_alumni_login/reset_alumni_password/
-- upsert_alumni_google_profile, and never included in BOOTSTRAP_SQL (same isolation as
-- user_credentials).
CREATE TABLE IF NOT EXISTS alumni_accounts (
  email TEXT PRIMARY KEY,
  password_hash TEXT,
  password_salt TEXT,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS alumni_accounts ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE IF EXISTS alumni_accounts ALTER COLUMN password_salt DROP NOT NULL;
ALTER TABLE IF EXISTS alumni_accounts DROP COLUMN IF EXISTS name;

-- Self-service accounts for outside-college visitors registering for a public campus event (see
-- register_for_public_event) - same email+password self-signup shape as alumni_accounts, kept as
-- its own table rather than reusing that one since these aren't alumni and don't need alumni-only
-- fields (batchYear etc). Deliberately short-lived: cleanup_completed_public_events deletes a
-- visitor's account once every public event they registered for has ended or been removed - the
-- account only ever existed to let them revisit a still-open registration/ticket.
CREATE TABLE IF NOT EXISTS event_visitor_accounts (
  email TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  name TEXT NOT NULL,
  phone TEXT,
  college TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS alumni_accounts DROP COLUMN IF EXISTS batch_year;
ALTER TABLE IF EXISTS alumni_accounts DROP COLUMN IF EXISTS profile;
ALTER TABLE IF EXISTS alumni_accounts ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Favorited books are full Open Library search-result objects (workKey, title, author, cover
-- etc.), not rows from the local library_books catalog - one JSONB array per user identity
-- (roll number, staff email, etc.) rather than a row-per-barcode join table.
CREATE TABLE IF NOT EXISTS book_favorites (
  identity TEXT PRIMARY KEY,
  favorites JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Singleton row (id is always `true`) - a running counter of the local AI provider's usage,
-- surfaced in the Admin Dashboard's AI Provider Configuration card. Not analytics sent
-- anywhere, just a shared counter so it survives across admins/browsers now.
CREATE TABLE IF NOT EXISTS ai_usage_stats (
  id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
  attempts INTEGER NOT NULL DEFAULT 0,
  successes INTEGER NOT NULL DEFAULT 0,
  failures INTEGER NOT NULL DEFAULT 0,
  rate_limited INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  off_topic INTEGER NOT NULL DEFAULT 0,
  last_used_at TIMESTAMPTZ,
  last_provider TEXT,
  last_error TEXT
);
INSERT INTO ai_usage_stats (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

-- Per-attempt AI request log, most recent 20 kept (trimmed on insert - see record_ai_request_log
-- in portal_db_server.py) so it doesn't grow unbounded.
CREATE TABLE IF NOT EXISTS ai_request_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT,
  model TEXT,
  -- One of "success" | "failure" | "offTopic" | "rateLimited" | "blocked" - more than a boolean
  -- can express, since the admin panel distinguishes all five outcomes.
  status TEXT,
  latency_ms INTEGER,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS ai_request_log ADD COLUMN IF NOT EXISTS status TEXT;
ALTER TABLE IF EXISTS ai_request_log DROP COLUMN IF EXISTS success;

-- Generic admin-action audit trail. `scope` distinguishes which dashboard/panel the action
-- happened in (e.g. 'admin', 'exam_cell') so different "Recent Activity" panels can each filter
-- to their own scope from the same table.
CREATE TABLE IF NOT EXISTS activity_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope TEXT NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  module TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS activity_log ADD COLUMN IF NOT EXISTS module TEXT;

-- Retention policy metadata for every functional table. These tables do not delete data by
-- themselves; they define the retention standard that scheduled archival/purge jobs should
-- follow based on record behavior (academic evidence, operational data, audit history, etc.).
CREATE TABLE IF NOT EXISTS data_retention_policies (
  policy_code TEXT PRIMARY KEY,
  behavior TEXT NOT NULL,
  description TEXT NOT NULL,
  retention_months INTEGER CHECK (retention_months IS NULL OR retention_months >= 0),
  retention_basis TEXT NOT NULL DEFAULT 'created_at',
  disposal_action TEXT NOT NULL,
  legal_hold_allowed BOOLEAN NOT NULL DEFAULT true,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS data_retention_table_policies (
  schema_name TEXT NOT NULL DEFAULT 'gprec_erp',
  table_name TEXT NOT NULL,
  policy_code TEXT NOT NULL REFERENCES data_retention_policies(policy_code),
  owner_module TEXT NOT NULL,
  date_column TEXT NOT NULL DEFAULT 'created_at',
  contains_pii BOOLEAN NOT NULL DEFAULT false,
  notes TEXT,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (schema_name, table_name)
);

CREATE TABLE IF NOT EXISTS funding_contributions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id TEXT NOT NULL,
  contributor_name TEXT,
  contributor_email TEXT,
  amount NUMERIC(10,2) NOT NULL,
  payment_id TEXT,
  contributed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_funding_contributions_campaign ON funding_contributions(campaign_id);

CREATE INDEX IF NOT EXISTS idx_placement_applications_student ON placement_applications(student_roll_no);
CREATE INDEX IF NOT EXISTS idx_class_messages_subject ON class_messages(subject_code, section);
CREATE INDEX IF NOT EXISTS idx_leave_requests_department ON leave_requests(department_code);
CREATE INDEX IF NOT EXISTS idx_adhoc_class_requests_department ON adhoc_class_requests(department_code);
CREATE INDEX IF NOT EXISTS idx_student_projects_student ON student_projects(((data->>'studentId')));
CREATE INDEX IF NOT EXISTS idx_student_research_student ON student_research(((data->>'studentId')));
CREATE INDEX IF NOT EXISTS idx_course_materials_subject ON course_materials(subject_code);
CREATE INDEX IF NOT EXISTS idx_ai_request_log_created ON ai_request_log(created_at);
CREATE INDEX IF NOT EXISTS idx_activity_log_scope ON activity_log(scope, created_at);
CREATE INDEX IF NOT EXISTS idx_retention_table_policies_policy ON data_retention_table_policies(policy_code);
CREATE INDEX IF NOT EXISTS idx_retention_table_policies_module ON data_retention_table_policies(owner_module);

CREATE INDEX IF NOT EXISTS idx_students_department ON students(department_code);
CREATE INDEX IF NOT EXISTS idx_fee_dues_student ON fee_dues(student_roll_no);
CREATE INDEX IF NOT EXISTS idx_exam_schedules_department ON exam_schedules(department_code, exam_date);
CREATE INDEX IF NOT EXISTS idx_hostel_outing_requests_student ON hostel_outing_requests(((data->>'studentId')));
CREATE INDEX IF NOT EXISTS idx_hostel_visiting_requests_student ON hostel_visiting_requests(((data->>'studentId')));
CREATE INDEX IF NOT EXISTS idx_hostel_leave_requests_student ON hostel_leave_requests(((data->>'studentId')));
CREATE INDEX IF NOT EXISTS idx_complaints_status ON complaints(status);

-- GPRECian Bot's knowledge base: real semantic (embedding-based) retrieval to replace the old
-- keyword-overlap match, so the bot's grounding context is found by meaning, not exact word
-- matches. One row per content "chunk" (FAQ answer, notice, admissions/fee/scholarship text,
-- department blurb) - script.js's buildGprecianKnowledgeBase() is still the single source of
-- truth for WHAT chunks exist (it already pulls from the DB, admin-config, and hardcoded FAQ
-- copy correctly); this table just adds a real embedding per chunk so retrieval can be semantic.
-- Refreshed wholesale via POST /api/knowledge-base/refresh (upserts every current chunk, then
-- deletes any row whose id wasn't in that batch, so deleted/renamed source content doesn't
-- linger here as a stale, unreachable chunk).
CREATE TABLE IF NOT EXISTS knowledge_base_chunks (
  id TEXT PRIMARY KEY,
  chunk_text TEXT NOT NULL,
  link_url TEXT,
  link_label TEXT,
  link_download BOOLEAN NOT NULL DEFAULT false,
  embedding vector(768),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_knowledge_base_chunks_embedding
  ON knowledge_base_chunks USING hnsw (embedding vector_cosine_ops);

-- GPRECian Bot's real feedback loop - the actual "learning" mechanism, since neither the LLM's
-- weights nor anything else here retrains itself. A visitor flags a bad answer -> an admin reviews
-- it and writes the correct answer -> approving it embeds that correction straight into
-- knowledge_base_chunks (id = 'feedback-<row id>'), so the same or a similarly-worded question
-- gets the right answer next time via ordinary semantic search. Cumulative improvement from real
-- usage, driven by an admin decision at each step - not automatic/unsupervised.
CREATE TABLE IF NOT EXISTS bot_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  question TEXT NOT NULL,
  bot_answer TEXT NOT NULL,
  reporter_type TEXT,
  reporter_id TEXT,
  status TEXT NOT NULL DEFAULT 'Pending',
  correction TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_bot_feedback_status ON bot_feedback(status, created_at);

-- Digital exam-cell application forms - only for the three real GPREC forms that are pure data
-- collection with no physical/legal requirement that would make a digital submission meaningless
-- (Condonation of Attendance, PC/CMM/TC/Study Certificate request, Duplicate Certificate request).
-- The Notary Affidavit (needs an actual notary stamp/signature) and the SKU Convocation Application
-- (mailed with original certificates to an external university) stay download-only for that reason -
-- see the Download Applications table on the Exam Cell page and student dashboard. One flexible
-- table for all three types (application_type + form_data JSONB) rather than three near-identical
-- tables, since the only real difference between them is which fields the form collects.
CREATE TABLE IF NOT EXISTS exam_cell_applications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  application_type TEXT NOT NULL,
  student_roll_no TEXT NOT NULL REFERENCES students(roll_no) ON DELETE CASCADE,
  form_data JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  admin_note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_exam_cell_applications_student ON exam_cell_applications(student_roll_no, created_at);
CREATE INDEX IF NOT EXISTS idx_exam_cell_applications_type ON exam_cell_applications(application_type, status);

COMMIT;
