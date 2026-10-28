#!/usr/bin/env python3
"""Minimal dependency-free HTTP application for authorized local reconnaissance."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

HOST = "127.0.0.1"
PORT = 8765


class LabHandler(BaseHTTPRequestHandler):
    server_version = "OffensiveLab/1.0"

    def do_GET(self):
        if self.path == "/":
            payload = b"<!doctype html><html><head><title>Offensive Lab Demo</title></head><body><h1>Authorized training lab</h1><p>127.0.0.1 only.</p></body></html>"
            self._respond(200, "text/html; charset=utf-8", payload)
        elif self.path == "/health":
            self._respond(200, "application/json", b'{"status":"ok"}')
        elif self.path == "/debug":
            # Intentional training marker; no actual credentials or secrets.
            payload = json.dumps({"LAB_DEBUG_ONLY": True, "message": "training demo"}).encode()
            self._respond(200, "application/json", payload)
        else:
            self._respond(404, "text/plain", b"Not Found")

    def _respond(self, status, mime, payload):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    print(f"Demo server listening at http://{HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), LabHandler).serve_forever()
