#!/usr/bin/env python3
"""Renders document HTML (pay slip, tickets/passes, and any future document built the same way)
to a real PDF or PNG using Playwright's native Chromium rendering pipeline.

Why this exists: this app used to build these documents two ways, both re-implementations of the
mockup's CSS - hand-drawn <canvas> fillText/fillRect calls, then html2canvas rasterizing a hidden
DOM clone. Both are approximations (html2canvas in particular re-implements text layout/painting
in JS instead of using the browser's real engine) and both drifted from the actual CSS in ways
that only showed up on side-by-side pixel comparison. These routes send the exact HTML/CSS the
client already builds and let a real browser render it - there's no re-implementation step left
to drift.

Usage: python3 tools/pdf_render_server.py
The client (script.js) POSTs {html, css, width} to /render-pdf (A4-style documents: pay slip,
Form 16, hall ticket, fee challan) or /render-png (ticket-stub passes: event/bus/vehicle/hostel -
these download as a plain image, not a PDF) and gets back bytes sized exactly to the rendered
content. If this server isn't running, script.js falls back to the html2canvas path so the
download button still works either way.
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
    # Backs the "extra space is invisible" claim below - without a matching body background, that
    # slack is transparent-over-white, not the document's own color, and shows as a visible pale
    # strip under any sheet narrower/shorter than the page (e.g. the Payment Receipt's 440px card).
    # Restricted to #rgb/#rrggbb so this can't break out of the inline style attribute.
    background_match = re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", data.get("background") or "")
    background = background_match.group(0) if background_match else "#fff"

    # Playwright's sync API binds its dispatcher to the thread that started it - a cached global
    # browser broke the moment Flask's dev server handled a second request on a different thread
    # ("cannot switch to a different thread"). Launching fresh per request costs ~1s but can't hit
    # that failure mode; this endpoint isn't hot enough (one PDF per user click) for it to matter.
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
            # print_background rendering resolves a few px taller than the screen-mode height
            # getBoundingClientRect() just measured (Chromium's print layout pass isn't pixel-
            # identical to its screen layout pass) - without slack here that overflow silently
            # spills the last section (e.g. a footer strip) onto a second page instead of erroring.
            # The extra space is invisible: it's just more of the document's own background color.
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
