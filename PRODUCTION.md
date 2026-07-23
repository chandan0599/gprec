# Production Deployment

End-to-end steps to run this app for real, not just on a dev machine. See
[README.md](README.md) for the local-dev quickstart and app overview first - this document
only covers what's different in production.

## Architecture assumption

This guide assumes **one server** hosting everything: the static frontend, PostgreSQL, and all
four backend tools. That's the natural fit for a college portal this size and requires no code
changes beyond what's in this doc. (A multi-server/CDN setup is possible but needs more work -
see "Multi-server note" at the end.)

Four backend processes, each a separate port:

| Process | Port | What it does |
| --- | --- | --- |
| `portal_db_server.py` | 8766 | Postgres-backed API (`/api/*`) - portal data, auth, uploads metadata |
| `admin_config_server.py` | 8765 | `/admin-config` and `/upload` - writes to `admin-config.json` and `uploads/`. Binds to `127.0.0.1` only, on purpose (see the file) |
| `pdf_render_server.py` | 8767 | Native Chromium PDF/PNG rendering (optional - the app falls back to client-side `html2canvas` if this isn't reachable) |
| `static_server.py` | 8080 | Dev-only file server. **Don't run this in production** - let nginx serve the static files directly instead (faster, and one less Python process) |

## 1. Server prep

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip postgresql nginx certbot python3-certbot-nginx git
```

## 2. Get the code

```bash
git clone https://github.com/chandan0599/gprec.git /var/www/gprec
cd /var/www/gprec
```

## 3. Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
playwright install --with-deps chromium   # only needed for pdf_render_server.py
```

## 4. Database

Create the database and load the schema - **not** `seed.sql`, which is fake demo data (10 sample
students, made-up admins, etc.) meant for local dev only:

```bash
sudo -u postgres createuser gprec_prod --pwprompt
sudo -u postgres createdb -O gprec_prod gprec_prod
psql -U gprec_prod -d gprec_prod -f backend/database/postgres/schema.sql
```

## 5. Environment variables

Set these wherever you run the services (e.g. an `/etc/gprec.env` file loaded by systemd - see
below). None of them should be hardcoded in source or committed to git.

| Variable | Purpose |
| --- | --- |
| `GPREC_DB_NAME`, `GPREC_DB_USER`, `GPREC_DB_PASSWORD`, `GPREC_DB_HOST`, `GPREC_DB_PORT` | PostgreSQL connection (defaults in `portal_db_server.py` are dev-only placeholders - override every one of them) |
| `GPREC_DB_SCHEMA` | Defaults to `gprec_erp`, only override if you changed `schema.sql` |
| `GPREC_PSQL_PATH` | Only needed if `psql` isn't on `PATH` |
| `GPREC_ALLOWED_ORIGINS` | Comma-separated list adding your real `https://yourdomain.com` origin (CORS) |
| `GPREC_BANK_ENCRYPTION_KEY` | Pin a specific Fernet key for bank-detail encryption-at-rest, instead of the auto-generated `backend/tools/.bank_encryption.key` file (still fine to use, just make sure it's backed up and never committed) |
| `RECAPTCHA_SECRET_KEY` | For the public event registration/login forms |

**Before going live**, also rotate what's currently in `admin-config.json` (it's git-tracked and
was written assuming local-only use): the PostgreSQL password/`databaseApiConfig` block, and any
provider keys under `smsSettings`/`kycSettings`/`aiSettings` you plan to actually use. If this
repo's history has ever been pushed anywhere with real production secrets in it, rotate those
credentials at the source (DB, SMS/KYC provider, payment gateway) - editing the file afterward
doesn't remove them from git history.

## 6. Run the backend services

`portal_db_server.py` and `admin_config_server.py` are plain `http.server` processes (not WSGI
apps), so they just need a process supervisor. `pdf_render_server.py` is a real Flask app, so run
it under `gunicorn` instead of `python3 pdf_render_server.py` (that's the dev-only Flask server).

Example systemd units (`/etc/systemd/system/gprec-*.service`):

```ini
# /etc/systemd/system/gprec-db-api.service
[Unit]
Description=GPREC portal DB API
After=network.target postgresql.service

[Service]
User=www-data
WorkingDirectory=/var/www/gprec
EnvironmentFile=/etc/gprec.env
ExecStart=/var/www/gprec/venv/bin/python3 backend/tools/portal_db_server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/gprec-admin-config.service
[Unit]
Description=GPREC admin-config/upload server
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/gprec
EnvironmentFile=/etc/gprec.env
ExecStart=/var/www/gprec/venv/bin/python3 backend/tools/admin_config_server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/gprec-pdf-render.service
[Unit]
Description=GPREC PDF/PNG render server
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/gprec
EnvironmentFile=/etc/gprec.env
ExecStart=/var/www/gprec/venv/bin/gunicorn -w 2 -b 0.0.0.0:8767 --chdir backend/tools pdf_render_server:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gprec-db-api gprec-admin-config gprec-pdf-render
```

Do **not** create a unit for `static_server.py` - nginx serves those files directly (next step).

## 7. Nginx: static files, TLS, and proxying the backend ports

The frontend talks to the backend over `https://yourdomain.com:PORT`, matching whatever protocol
the page itself was loaded with (see `gprecApiBaseUrl()` and `GPREC_UPLOAD_ENDPOINT` in
`script.js`) - it does not assume a same-origin `/api` path. So each backend port needs its own
TLS-terminating nginx block on the same domain, in addition to the main site on 443.

```nginx
# Main site - static files
server {
    listen 443 ssl;
    server_name yourdomain.com;

    root /var/www/gprec;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
}

# Portal DB API
server {
    listen 8766 ssl;
    server_name yourdomain.com;
    location / { proxy_pass http://127.0.0.1:8766; }
    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
}

# Admin-config / uploads
server {
    listen 8765 ssl;
    server_name yourdomain.com;
    client_max_body_size 25m;   # uploads
    location / { proxy_pass http://127.0.0.1:8765; }
    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
}

# PDF/PNG render
server {
    listen 8767 ssl;
    server_name yourdomain.com;
    location / { proxy_pass http://127.0.0.1:8767; }
    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
}
```

Get the certificate first (`certbot --nginx -d yourdomain.com`), then reload nginx.

Alternative, simpler than four TLS ports: set `databaseApiConfig.baseUrl` under Admin Console >
Data Integrations to `https://yourdomain.com/api`, and instead add `location /api/`,
`location /admin-config`, `location /upload`, `location /render-pdf`, `location /render-png`
blocks inside the **main** `server { listen 443; ... }` block, each `proxy_pass`-ing to its
service's `127.0.0.1:PORT`. That gets you one certificate and one port (443) for everything -
`gprecApiBaseUrl()` already honors `databaseApiConfig.baseUrl` when it's set; the
upload/admin-config/render endpoints don't have an equivalent override field yet, so that path
means adjusting `GPREC_UPLOAD_ENDPOINT`, `GPREC_CONFIG_SAVE_ENDPOINT`, and the two `render-*`
fetch URLs in `script.js` to relative paths (`/upload`, `/admin-config`, `/render-pdf`,
`/render-png`) instead of the `hostname:PORT` pattern they use today.

## 8. First admin login

With a fresh `schema.sql` (no `seed.sql`), no admin exists yet. Add the first admin's email
directly to the `admins` table (or `admin-config.json`'s `admins` array), then follow
**First-Time Admin Setup** in [README.md](README.md) / the in-app Read Me panel to generate its
initial password.

## 9. Smoke test

- Load `https://yourdomain.com` - check the browser console for mixed-content or CORS errors.
- Log in as the first admin, open **Read Me** in the sidebar, confirm it renders.
- Upload a photo somewhere (e.g. Media) and confirm it lands in `uploads/` on the server.
- Generate a pay slip/pass PDF and confirm it comes from `pdf_render_server.py` (pixel-perfect)
  rather than the `html2canvas` fallback (slightly lower fidelity) - if it's falling back, check
  `gprec-pdf-render`'s systemd status and the port-8767 nginx block.

## Multi-server note

If the frontend and backend ever need to live on different hosts (not just different ports on
one host), everything above still works as long as each backend keeps its own TLS-terminated,
publicly reachable port and the frontend's origin is added to `GPREC_ALLOWED_ORIGINS` - the
`hostname:PORT` pattern doesn't care whether "hostname" is the same physical machine, only that
it resolves and that port is reachable from the browser.
