#!/usr/bin/env python3
import base64
import binascii
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import time

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "admin-config.json"
UPLOAD_ROOT = ROOT / "uploads"
# Loopback-only on purpose: /upload and /admin-config accept writes with no auth check beyond
# origin, so this is deliberately unreachable from outside this machine. In production, put a
# reverse proxy (same server) in front and let it terminate TLS/handle the public origin - do not
# change this to 0.0.0.0 without adding real authentication first.
HOST = "127.0.0.1"
PORT = 8765
# Set GPREC_ALLOWED_ORIGINS (comma-separated) to add the real deployed origin(s) instead of
# editing this default - see portal_db_server.py's ALLOWED_ORIGINS for the same pattern.
ALLOWED_ORIGINS = {"http://127.0.0.1:8080", "http://localhost:8080"} | {
    origin.strip() for origin in os.environ.get("GPREC_ALLOWED_ORIGINS", "").split(",") if origin.strip()
}
INTEGRATION_KEYS = {
    "googleClientId",
    "googleCalendarApiKey",
    "payuPaymentLink",
    "aiSettings",
    "mapSdkSettings",
    "libraryApiConfig",
    "databaseApiConfig",
    "smsSettings",
    "kycSettings",
}
DATA_URL_RE = re.compile(r"^data:([^;,]+)?;base64,(.*)$", re.DOTALL)


def safe_path_part(value, fallback="file"):
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip()).strip(".-")
    return cleaned[:80] or fallback


def safe_section_path(section):
    parts = [safe_path_part(part, "") for part in str(section or "general").split("/")]
    parts = [part for part in parts if part]
    return Path(*parts) if parts else Path("general")


def decode_data_url(data_url):
    match = DATA_URL_RE.match(str(data_url or ""))
    if not match:
        raise ValueError("Expected a base64 data URL")
    mime = match.group(1) or "application/octet-stream"
    try:
        return mime, base64.b64decode(match.group(2), validate=True)
    except binascii.Error as exc:
        raise ValueError("Invalid base64 upload data") from exc


class AdminConfigHandler(BaseHTTPRequestHandler):
    def _cors_headers(self):
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, status, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_POST(self):
        if self.path == "/admin-config":
            self.save_admin_config()
            return
        if self.path == "/upload":
            self.save_upload()
            return
        self._send_json(404, {"error": "Not found"})

    def save_admin_config(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            incoming = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            current = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            for key in INTEGRATION_KEYS:
                if key in incoming:
                    current[key] = incoming[key]
            CONFIG_PATH.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
            self._send_json(200, current)
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def save_upload(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            incoming = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            section_path = safe_section_path(incoming.get("section"))
            destination_dir = (UPLOAD_ROOT / section_path).resolve()
            if UPLOAD_ROOT.resolve() not in destination_dir.parents and destination_dir != UPLOAD_ROOT.resolve():
                raise ValueError("Invalid upload section")
            destination_dir.mkdir(parents=True, exist_ok=True)

            mime, content = decode_data_url(incoming.get("dataUrl"))
            original_name = safe_path_part(incoming.get("filename"), "upload")
            timestamp = str(int(time() * 1000))
            destination = destination_dir / f"{timestamp}-{original_name}"
            destination.write_bytes(content)

            relative_path = destination.relative_to(ROOT).as_posix()
            self._send_json(
                200,
                {
                    "name": original_name,
                    "path": relative_path,
                    "url": f"/{relative_path}",
                    "mime": mime,
                    "size": len(content),
                },
            )
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def log_message(self, fmt, *args):
        print(f"[admin-config] {self.address_string()} - {fmt % args}")


if __name__ == "__main__":
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), AdminConfigHandler)
    print(f"Admin helper running at http://{HOST}:{PORT}")
    print(f"Config endpoint: http://{HOST}:{PORT}/admin-config")
    print(f"Upload endpoint: http://{HOST}:{PORT}/upload")
    print(f"Writing {CONFIG_PATH}")
    print(f"Storing uploads in {UPLOAD_ROOT}")
    server.serve_forever()
