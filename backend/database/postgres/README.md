# GPREC Postgres Setup

These scripts create the production-ready tables for the portal modules used by the website and seed them with 10 student records plus related academic, hostel, fee, exam, library, placement, and admin data.

All portal tables live in the `gprec_erp` schema.

Run them against your local PostgreSQL database:

```bash
createdb -U lakkavaramsaichandan lakkavaramsaichandan
psql -U lakkavaramsaichandan -d lakkavaramsaichandan -f backend/database/postgres/schema.sql
psql -U lakkavaramsaichandan -d lakkavaramsaichandan -f backend/database/postgres/seed.sql
```

The browser site cannot connect directly to PostgreSQL. Use the Admin Dashboard > Integrations > Database Connection panel to record your PostgreSQL JDBC details, then connect the website to a backend API that reads these tables.

For this project, run the included local backend/static server:

```bash
python3 backend/tools/portal_db_server.py
```

Then open `http://127.0.0.1:8766`. The site will read core portal records from PostgreSQL schema `gprec_erp` through `/api/bootstrap` and write supported updates back through `/api/complaints`, `/api/pending-fees`, `/api/placement-drives`, `/api/exam-schedules`, and `/api/issued-books`.
