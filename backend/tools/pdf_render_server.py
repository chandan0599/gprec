#!/usr/bin/env python3
"""Renders document HTML (pay slip, tickets/passes, and any future document built the same way)
to a real PDF or PNG using Playwright's native Chromium rendering pipeline.

Earlier versions re-implemented the mockup's CSS by hand (canvas drawing, then html2canvas
rasterizing a hidden DOM clone), and both drifted from the real CSS over time. These routes
instead send the client's exact HTML/CSS to a real browser, so there's nothing left to drift.

Usage: python3 tools/pdf_render_server.py
The client (script.js) POSTs {html, css, width} to /render-pdf (A4-style documents: pay slip,
Form 16, hall ticket, fee challan) or /render-png (ticket-stub passes: event/bus/vehicle/hostel)
and gets back bytes sized exactly to the rendered content. If this server isn't running, script.js
falls back to the html2canvas path so the download button still works either way.
"""
import re
from html import escape as html_escape
from pathlib import Path

from flask import Flask, request, Response
from playwright.sync_api import sync_playwright

HOST = "0.0.0.0"
PORT = 8767
# Same allowed-origins convention as portal_db_server.py.
ALLOWED_ORIGINS = {"http://127.0.0.1:8080", "http://localhost:8080", "http://192.168.1.17:8080"}

app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/render-pdf", methods=["OPTIONS"])
def render_pdf_preflight():
    return ("", 204)


@app.route("/render-pdf", methods=["POST"])
def render_pdf():
    data = request.get_json(force=True)
    html = data["html"]
    css = data.get("css", "")
    width = int(data.get("width", 793))
    root_selector = data.get("rootSelector", ".ps-sheet")
    # Without a <title>, Chromium's PDF export leaves the document's Title metadata blank - shows
    # up as an empty/ugly name in PDF viewer tabs, Preview.app's title bar, Finder's Get Info, etc.
    title = html_escape(data.get("title") or "GPREC Document")
    # Restricted to #rgb/#rrggbb so this value can't break out of the inline style attribute.
    # Falls back to white; a mismatched background would show as a visible strip around sheets
    # narrower/shorter than the rendered page.
    background_match = re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", data.get("background") or "")
    background = background_match.group(0) if background_match else "#fff"

    # Playwright's sync API binds to the thread that started it, so a cached global browser broke
    # once Flask's dev server handled a request on a different thread ("cannot switch to a
    # different thread"). Launching fresh per request avoids that; the ~1s cost is fine since this
    # endpoint isn't hot (one PDF per user click).
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1200})
        try:
            # networkidle (not a fixed sleep) so a slow Google Fonts fetch can't produce a PDF
            # with the wrong fallback font silently baked in.
            page.set_content(
                f"<!doctype html><html><head><title>{title}</title><style>{css}</style></head>"
                f"<body style='margin:0;background:{background}'>{html}</body></html>",
                wait_until="networkidle",
            )
            box = page.eval_on_selector(
                root_selector,
                "el => ({ w: Math.ceil(el.getBoundingClientRect().width), h: Math.ceil(el.getBoundingClientRect().height) })",
            )
            # print_background's layout pass renders a few px taller than the screen-mode height
            # just measured, so without this slack the overflow silently spills onto a second page
            # instead of erroring. The extra space is invisible - just more background color.
            pdf_bytes = page.pdf(
                width=f"{box['w']}px",
                height=f"{box['h'] + 24}px",
                print_background=True,
                margin={"top": "0px", "bottom": "0px", "left": "0px", "right": "0px"},
            )
        finally:
            browser.close()

    return Response(pdf_bytes, mimetype="application/pdf")


@app.route("/render-png", methods=["OPTIONS"])
def render_png_preflight():
    return ("", 204)


@app.route("/render-png", methods=["POST"])
def render_png():
    data = request.get_json(force=True)
    html = data["html"]
    css = data.get("css", "")
    width = int(data.get("width", 420))
    scale = float(data.get("scale", 2.4))
    root_selector = data.get("rootSelector", ".ts-card")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        # deviceScaleFactor gives a crisp high-DPI raster (matching this app's existing 2-2.4x
        # canvas SCALE convention) without needing a second upscale pass.
        page = browser.new_page(viewport={"width": width, "height": 1200}, device_scale_factor=scale)
        try:
            page.set_content(
                f"<!doctype html><html><head><style>{css}</style></head>"
                f"<body style='margin:0'>{html}</body></html>",
                wait_until="networkidle",
            )
            # element.screenshot() clips to exactly that element's own box (including its
            # rounded corners/shadow, since Chromium screenshots the actual painted pixels) -
            # no manual width/height math needed the way page.pdf() required.
            png_bytes = page.locator(root_selector).screenshot(type="png", omit_background=True)
        finally:
            browser.close()

    return Response(png_bytes, mimetype="image/png")


if __name__ == "__main__":
    print(f"Render server at http://{HOST}:{PORT}/render-pdf and /render-png")
    app.run(host=HOST, port=PORT, debug=False)
