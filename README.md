# GPREC College Portal

Static website and role-based dashboard portal for G Pulla Reddy Engineering College
(gprec.ac.in) - the public site plus a full ERP-style admin/student/faculty portal, all built
as plain HTML/CSS/JS with an optional Python + PostgreSQL backend.

A copy of this Read Me, plus an Admin Console module reference, is also available inside the
app itself: log in as College Admin and open **Read Me** at the bottom of the sidebar.

For deploying this for real (not just running it locally), see [PRODUCTION.md](PRODUCTION.md).

## Structure

| Path | What it is |
| --- | --- |
| `index.html` | Public homepage. |
| `pages/` | Public pages (About, Admissions, Careers, Contact, Fee Structure, ...) and the six role login pages (`admin-login`, `student-login`, `faculty-login`, `parent-login`, `alumni-login`, `non-teaching-login`). |
| `dashboards/` | Role-based dashboards: admin, student, faculty, parent, alumni, department, placement, exam cell, hostel, non-teaching, plus event-management/volunteer/visitor dashboards. |
| `file_templates/` | Printable HTML templates (ID cards, passes, hall tickets, fee challan, pay slip, Form 16, event posters, certificates). |
| `backend/tools/` | Local Python servers (see below). |
| `backend/database/postgres/` | `schema.sql` / `seed.sql` for the `gprec_erp` schema, and its own [README](backend/database/postgres/README.md). |
| `uploads/` | User-uploaded files (profile pictures, assignments, notices, media, site photos, etc.), written by the admin config server. |
| `admin-config.json` | Local, git-tracked runtime config (main admin contact, integration keys, SMS/KYC settings, admin directory) written by the admin dashboard. |
| `script.js` | Single shared JS file driving every page (nav, dashboards, auth, forms). |
| `styles.css` | Single shared stylesheet. |
| `qrcode-generator.js`, `html2canvas.min.js` | Vendored third-party libraries used for QR codes and client-side PDF/image rendering. |

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
| Overview | Portal-wide counts, system health, and a directory of every dashboard and integration. |
| Calendar | Academic dates and reminders shown on the student and faculty dashboards. |
| Campus Events | Fest and activity listings shown on the public Campus Life page. |
| Contact Messages | Submissions from the public Contact Us form. |
| Data Integrations | Google, PayU, AI, library, database, and SMS/KYC connection settings. |
| Feature Ideas | Describe a feature in plain English and get a draft approach and starter code for a developer to review. |
| Fee Management | Student fee structures, dues, and payment tracking. |
| HOD Leave Requests | Leave approvals routed to department HODs. |
| Media | Photos and media used across the public site and dashboards. |
| Non-Teaching Staff Leave | Leave approvals for non-teaching staff. |
| Notices | Notices published to students, faculty, and other dashboards. |
| Poster Design | Event poster builder for campus events. |
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
