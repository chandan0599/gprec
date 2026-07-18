#!/usr/bin/env bash
# Starts the local servers this app needs:
#   - portal_db_server.py  (port 8766) - the Postgres-backed API
#   - static_server.py     (port 8080) - serves the static site (no auto-reload)
#   - pdf_render_server.py (port 8767) - Playwright-backed native HTML->PDF rendering (pay slip,
#     etc.) - script.js falls back to an in-browser html2canvas render if this isn't running, so
#     it's optional but gives pixel-perfect output when available.
# Safe to re-run: kills any previous instances first.

cd "$(dirname "$0")/.." || exit 1

pkill -f "portal_db_server.py" 2>/dev/null
pkill -f "static_server.py" 2>/dev/null
pkill -f "pdf_render_server.py" 2>/dev/null
sleep 0.5

nohup python3 tools/portal_db_server.py > /tmp/portal_db_server.log 2>&1 &
echo "portal_db_server.py started (pid $!) - http://127.0.0.1:8766"

nohup python3 tools/static_server.py > /tmp/static_server.log 2>&1 &
echo "static_server.py started (pid $!) - http://127.0.0.1:8080"

nohup python3 tools/pdf_render_server.py > /tmp/pdf_render_server.log 2>&1 &
echo "pdf_render_server.py started (pid $!) - http://127.0.0.1:8767"

sleep 1
if curl -s -o /dev/null -w "" --max-time 3 http://127.0.0.1:8766/api/bootstrap; then
  echo "API server is responding."
else
  echo "WARNING: API server did not respond - check /tmp/portal_db_server.log"
fi
