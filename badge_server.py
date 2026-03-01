#!/usr/bin/env python3
# Copyright (c) 2026 Tanmay Dikey <enceladus441@gmail.com>
# SPDX-License-Identifier: MIT
"""
AgentArmor Badge Server
=======================
Serves dynamic SVG security badges for GitHub READMEs.

Usage:
  python badge_server.py                  # default port 8765
  python badge_server.py --port 9000

Endpoints:
  GET /badge?status=approved              → green  "secured | approved"
  GET /badge?status=warned                → yellow "secured | warned"
  GET /badge?status=blocked               → red    "secured | blocked"
  GET /badge?repo=myapp&attested=142      → "attested | 142 files"
  GET /badge?lines=4200&attested=142      → "142/4200 lines attested"
  GET /health                             → {"status":"ok"}

Embed in your README.md:
  ![AgentArmor](http://localhost:8765/badge?status=approved)
"""

import json
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# ──────────────────────────────────────────────────────────────────────────────
# Colour palette
# ──────────────────────────────────────────────────────────────────────────────
COLOURS = {
    "approved": "#4caf50",   # green
    "warned":   "#ff9800",   # orange
    "blocked":  "#f44336",   # red
    "blue":     "#2196f3",
    "grey":     "#555555",
    "label_bg": "#555555",
}


def _svg_badge(label: str, message: str, colour: str) -> str:
    """Generate a flat Shields.io-style SVG badge."""
    font = "DejaVu Sans,Verdana,Geneva,sans-serif"
    lw = len(label) * 6 + 10      # approximate text width for label
    mw = len(message) * 6 + 10    # approximate text width for message
    total = lw + mw

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="{COLOURS['grey']}"/>
    <rect x="{lw}" width="{mw}" height="20" fill="{colour}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" font-family="{font}" font-size="11">
    <text x="5" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="5" y="14">{label}</text>
    <text x="{lw + 5}" y="15" fill="#010101" fill-opacity=".3">{message}</text>
    <text x="{lw + 5}" y="14">{message}</text>
  </g>
</svg>"""


# ──────────────────────────────────────────────────────────────────────────────
# Request handler
# ──────────────────────────────────────────────────────────────────────────────
class BadgeHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — zero dependencies beyond stdlib."""

    def log_message(self, fmt, *args):  # suppress noisy access log
        pass

    def _send(self, body: str, content_type: str = "image/svg+xml", status: int = 200):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-cache, max-age=0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs     = parse_qs(parsed.query)

        def _q(key: str, default: str = "") -> str:
            return qs.get(key, [default])[0].lower()

        # ── /health ──────────────────────────────────────────────────────────
        if parsed.path == "/health":
            self._send(
                json.dumps({"status": "ok", "service": "kvlr-badge-server"}),
                content_type="application/json",
            )
            return

        # ── /badge ───────────────────────────────────────────────────────────
        if parsed.path != "/badge":
            self._send("Not Found", content_type="text/plain", status=404)
            return

        # Mode 1: ?status=approved|warned|blocked
        status_val = _q("status")
        if status_val in ("approved", "warned", "blocked"):
            label   = "AgentArmor"
            message = status_val.upper()
            colour  = COLOURS[status_val]
            self._send(_svg_badge(label, message, colour))
            return

        # Mode 2: ?repo=myapp&attested=142
        repo      = qs.get("repo",     [""])[0]
        attested  = qs.get("attested", [""])[0]
        lines     = qs.get("lines",    [""])[0]

        if attested and lines:
            label   = "attested"
            message = f"{attested}/{lines} lines"
            colour  = COLOURS["blue"]
            self._send(_svg_badge(label, message, colour))
            return

        if attested:
            label   = repo or "attested"
            message = f"{attested} files"
            colour  = COLOURS["blue"]
            self._send(_svg_badge(label, message, colour))
            return

        # Mode 3: default generic badge
        self._send(_svg_badge("AgentArmor", "secured", COLOURS["approved"]))


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="AgentArmor Badge Server")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), BadgeHandler)
    print(f"🛡️  AgentArmor Badge Server listening on http://{args.host}:{args.port}")
    print(f"    Endpoints:")
    print(f"      /badge?status=approved")
    print(f"      /badge?status=warned")
    print(f"      /badge?status=blocked")
    print(f"      /badge?repo=myapp&attested=142")
    print(f"      /badge?lines=4200&attested=142")
    print(f"      /health")
    print(f"\n    Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBadge server stopped.")


if __name__ == "__main__":
    main()
