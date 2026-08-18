# GPREC Postgres Setup

These scripts create the production-ready tables for the portal modules used by the website and seed them with 10 student records plus related academic, hostel, fee, exam, library, placement, and admin data.

All portal tables live in the `gprec_erp` schema.

Run them against your local PostgreSQL database:

```bash
createdb -U gprec_dev gprec_dev
psql -U gprec_dev -d gprec_dev -f backend/database/postgres/schema.sql
psql -U gprec_dev -d gprec_dev -f backend/database/postgres/seed.sql
```

(Use whatever role/database name you actually created - these are just the defaults `portal_db_server.py` falls back to if nothing else is configured.)

The browser site cannot connect directly to PostgreSQL - it talks to `portal_db_server.py`, which does. Run it:

```bash
python3 backend/tools/portal_db_server.py
```

It reads its connection details entirely from `admin-config.json`'s `databaseApiConfig` (host, port, username, password, database, schema) - the same file the Admin Dashboard's Integrations > Database Connection panel saves to, so filling that form in from the browser is enough. There's no environment-variable override for these fields. Copy `admin-config.example.json` to `admin-config.json` first if you don't have one yet; it's gitignored, so it's safe to put real credentials in it - see [PRODUCTION.md](../../../PRODUCTION.md).

Then open `http://127.0.0.1:8766`. The site will read core portal records from PostgreSQL schema `gprec_erp` through `/api/bootstrap` and write supported updates back through `/api/complaints`, `/api/pending-fees`, `/api/placement-drives`, `/api/exam-schedules`, and `/api/issued-books`.
