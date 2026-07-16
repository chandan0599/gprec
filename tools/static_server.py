#!/usr/bin/env python3
"""Plain static file server for this project, meant to replace VS Code Live Server.

Unlike Live Server, this never auto-refreshes the browser - it just serves files. That matters
here because portal_db_server.py and admin_config_server.py write into this same project folder
(admin-config.json, uploads/) as part of normal saves; Live Server watches every file in the
project and reloads the page whenever any of them change, including those writes, which made
saving in the admin dashboard look like the page was randomly refreshing itself.

Usage: python3 tools/static_server.py
Then open http://127.0.0.1:8080/index.html (or any dashboards/logins/pages page under that origin).
"""
from pathlib import Path

from flask import Flask, send_from_directory

ROOT = Path(__file__).resolve().parents[1]
# 0.0.0.0 (not 127.0.0.1) so this is reachable from other devices on the same LAN (e.g. a phone,
# to test QR scanning against a real camera) - still only bound to your own network interface, not
# exposed beyond it.
HOST = "0.0.0.0"
PORT = 8080

app = Flask(__name__, static_folder=None)


@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve(path):
    response = send_from_directory(ROOT, path)
    # Without this, browsers can cache CSS/JS/HTML for hours and a real code change looks like it
    # "didn't apply" until a hard refresh - confusing during active development.
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    print(f"Serving {ROOT} at http://{HOST}:{PORT}/ (no auto-reload)")
    app.run(host=HOST, port=PORT, debug=False)
