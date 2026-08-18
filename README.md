# GPREC College Portal

Static website and role-based dashboard portal for G Pulla Reddy Engineering College
(gprec.ac.in) - the public site plus a full ERP-style admin/student/faculty portal, all built
as plain HTML/CSS/JS with an optional Python + PostgreSQL backend.

A copy of this Read Me, plus an Admin Console module reference, is also available inside the
app itself: log in as College Admin and open **Read Me** at the bottom of the sidebar.

For deploying this for real (not just running it locally), see [PRODUCTION.md](PRODUCTION.md).

## Structure

### Frontend

| File / folder | What it's used for |
| --- | --- |
| `index.html` | Public homepage. |
| `pages/` | Public pages (About, Admissions, Careers, Contact, Fee Structure, ...) and the six role login pages (`admin-login`, `student-login`, `faculty-login`, `parent-login`, `alumni-login`, `non-teaching-login`). |
| `dashboards/` | Role-based dashboards: admin, student, faculty, parent, alumni, department, placement, exam cell, hostel, non-teaching, plus event-management/volunteer/visitor dashboards. |
| `file_templates/` | Printable HTML templates (ID cards, passes, hall tickets, fee challan, pay slip, Form 16, event posters, certificates) - the design source `script.js`'s poster/pass/card builders mirror, not files loaded directly at runtime. |
| `script.js` | Single shared JS file driving every page - nav, dashboards, auth, forms, and every dashboard's client-side logic. |
| `styles.css` | Single shared stylesheet for every page. |
| `qrcode-generator.js` | Vendored third-party library for generating QR codes (ID cards, passes, event check-in). |
| `vendor/html2canvas.min.js` | Vendored third-party library for client-side PDF/image rendering - the fallback path when `pdf_render_server.py` isn't running. |
| `gprec-logo-enhanced.png` | Site logo. |
| `admin-config.json` | Local, gitignored runtime config (main admin contact, integration keys, DB connection, SMS/KYC settings, admin directory) written by the admin dashboard via `admin_config_server.py`. Doesn't need to exist ahead of time - the first Save from any Integrations panel creates it. Never commit it, it holds live credentials. |
| `uploads/` | User-uploaded files (profile pictures, assignments, notices, media, site photos, etc.), written by the admin config server. |

### Backend (`backend/tools/`)

| File | What it's used for |
| --- | --- |
| `portal_db_server.py` | The Postgres-backed API (port 8766) - authentication, bootstrap data, and every read/write operation the dashboards call. |
| `admin_config_server.py` | Handles `admin-config.json` writes and file uploads (port 8765). Binds to `127.0.0.1` only - see the file's own comment for why. |
| `pdf_render_server.py` | Optional Playwright-based HTML-to-PDF/PNG rendering (port 8767) for pay slips, hall tickets, passes, etc. - pixel-perfect vs. the `html2canvas` fallback. |
| `static_server.py` | Dev-only static file server (port 8080) - a Live Server replacement that doesn't auto-refresh on `admin-config.json`/`uploads/` writes. Not used in production (nginx serves those files directly instead). |
| `send_fee_reminders_cron.py` | Thin CLI wrapper that calls the same function the admin dashboard's "Send Fee Reminders Now" button uses, for unattended OS-level cron scheduling. |
| `send_attendance_alerts_cron.py` | Same pattern as above, for the "Send Attendance Alerts" button (students below 75% attendance). |
| `start_servers.sh` | Starts `portal_db_server.py`, `static_server.py`, and `pdf_render_server.py` for local dev (safe to re-run - kills previous instances first). |
| `stop_servers.sh` | Stops whatever `start_servers.sh` started. |

### Database (`backend/database/postgres/`)

| File | What it's used for |
| --- | --- |
| `schema.sql` | Creates the `gprec_erp` schema and all 86 tables. Load this for a real deployment. |
| `seed.sql` | Fake demo data (sample students, admins, etc.) for local dev only - never load this in production. |
| `README.md` | Setup instructions specific to the database. |

## Running locally

The site works opened directly via `file://`, but for full functionality (uploads, the admin
config API, and the PostgreSQL-backed portal data) run the local servers:

```bash
./backend/tools/start_servers.sh
```

This starts three servers (safe to re-run - it kills previous instances first):

- `static_server.py` - serves the static site at `http://127.0.0.1:8080`
- `portal_db_server.py` - Postgres-backed API at `http://127.0.0.1:8766` (`/api/bootstrap`, etc.)
- `pdf_render_server.py` - optional Playwright-based HTML-to-PDF rendering at
  `http://127.0.0.1:8767` (falls back to an in-browser `html2canvas` render if not running)

Stop them with `./backend/tools/stop_servers.sh`.

The `admin_config_server.py` tool (port 8765) handles admin-config and upload writes; see that
file for details.

For database setup, see [backend/database/postgres/README.md](backend/database/postgres/README.md).

Once the servers are running, open `http://127.0.0.1:8080/index.html`.

## Roles & login

| Role | Login page | Dashboard |
| --- | --- | --- |
| College Admin | `pages/admin-login.html` | `dashboards/admin-dashboard.html` |
| Department Admin (per department) | `pages/admin-login.html` | `dashboards/department-dashboard.html` |
| Hostel Warden (Boys/Girls) | `pages/admin-login.html` | `dashboards/hostel-dashboard.html` |
| Exam Cell Officer | `pages/admin-login.html` | `dashboards/exam-cell-dashboard.html` |
| Placement Cell Officer | `pages/admin-login.html` | `dashboards/placement-dashboard.html` |
| Student | `pages/student-login.html` | `dashboards/student-dashboard.html` |
| Faculty | `pages/faculty-login.html` | `dashboards/faculty-dashboard.html` |
| Parent | `pages/parent-login.html` | `dashboards/parent-dashboard.html` |
| Alumni | `pages/alumni-login.html` | `dashboards/alumni-dashboard.html` |
| Non-Teaching Staff | `pages/non-teaching-login.html` | `dashboards/non-teaching-dashboard.html` |

The specific admin role (College Admin vs. a department/hostel/exam/placement admin) is chosen
on the Admin Login form and must match the role configured for that admin's email under
Admin Console > Users & Access.

## First-time admin setup

No admin can log in until an admin password exists, and passwords can normally only be set
from Users & Access inside the dashboard - which itself requires being logged in. To break that
bootstrap loop, `pages/admin-login.html` shows a one-time **First-Time Setup** card whenever
*zero* admins anywhere have a password yet.

1. The email must already be a registered admin (seeded via `backend/database/postgres/seed.sql`,
   e.g. `admin@gprec.ac.in` as College Admin, or added later via `admin-config.json`). The login
   page can only set a password for an admin that already exists - it can't create one.
2. Open `pages/admin-login.html`. If no admin has a password yet, the **First-Time Setup** card
   appears below the normal login form automatically.
3. Enter that admin email and a recovery mobile number, then click **Generate Initial Password**.
   This is the only time `POST /api/auth/set-password` is allowed without an admin session -
   once any admin has a password, the same endpoint requires one.
4. Save the generated password shown on screen - it's shown once and never again.
5. Log in normally on the main Admin Login form (role, email, password, captcha). Since it's a
   freshly generated password, you'll be forced to change it immediately after this first login.
6. The First-Time Setup card is now gone for good. Every further admin is added by an
   already-logged-in admin under Users & Access, not this bootstrap path.

This requires the backend running (`./backend/tools/start_servers.sh`), since it goes through
`/api/auth/*` on `portal_db_server.py`. If a password already exists and you've just forgotten
it, use **Forgot password?** on the login form instead.

## Admin Console modules

| Module | What it's for |
| --- | --- |
| Overview | Portal-wide counts, system health, a directory of every dashboard/integration, and an Analytics & Trends panel (placements, attendance, fee collection, exam pass rates). |
| Calendar | Academic dates and reminders shown on the student and faculty dashboards. |
| Campus Events | Fest and activity listings shown on the public Campus Life page. |
| Contact Messages | Submissions from the public Contact Us form. |
| Data Integrations | Google, PayU, AI (chatbot config plus a Bot Performance panel), Map SDK usage stats, library, database, and SMS/KYC connection settings. |
| Feature Ideas | Describe a feature in plain English and get a draft approach and starter code for a developer to review. |
| Fee Management | Student fee structures, dues, payment tracking, and one-click SMS/WhatsApp fee-due reminders. |
| Grievances | Every complaint filed portal-wide (academic, hostel, general) in one queue, with status tracking and resolution notes. |
| HOD Leave Requests | Leave approvals routed to department HODs. |
| Media | Photos and media used across the public site and dashboards. |
| Non-Teaching Staff Leave | Leave approvals for non-teaching staff. |
| Notices | Notices published to students, faculty, and other dashboards, with optional SMS/WhatsApp broadcast. |
| Poster Design | Event poster builder for campus events. |
| Register for Event | Faculty/Admin self-registration as a campus/fest event attendee, alongside the public/student flow. |
| Reports & Audit | Academic/financial report exports, the admin audit trail, and the data retention policy reference. |
| Site Maintenance | Take the public site or individual dashboards offline, with an optional advance-warning banner. |
| Transportation | Bus routes and transportation records. |
| Users & Access | Admin directory - who has access, at what role, in which department. |
| Web Page Content | Editable content blocks on the public website. |
| Webinars | Webinar listings shown on the public site. |

## Data & security

Every dashboard requires a real session, issued at login, matched against the role it was
issued for. Session tokens and role identity are kept in the browser's local storage and
cleared on logout. Uploaded files are written under `uploads/`, and portal records live in
PostgreSQL under the `gprec_erp` schema when the backend is connected.
