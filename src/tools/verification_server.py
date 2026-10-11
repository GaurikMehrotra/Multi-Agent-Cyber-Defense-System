"""Authenticated verification gateway inside lab-only container; no Docker socket."""

import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from src.agents.budgets import Budget
from src.config import Budgets
from src.db.audit import Audit
from src.tools.nmap_profiles import ScanArgs, scan


class Handler(BaseHTTPRequestHandler):
    last_scan = 0.0

    def setup(self):
        super().setup()
        self.connection.settimeout(25)

    def log_message(self, fmt, *args):
        pass  # Do not log headers or credentials.

    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        expected = os.environ["VERIFY_API_KEY"]
        if not expected or not hmac.compare_digest(self.headers.get("X-API-Key", ""), expected):
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/verify" or not 0 < length <= 1024:
                raise ValueError("bounded request required")
            args = ScanArgs.model_validate_json(self.rfile.read(length))
            if time.monotonic() - Handler.last_scan < 10:
                self.send_error(429)
                return
            Handler.last_scan = time.monotonic()
            result = scan(
                args,
                Budget(Budgets(tools=1, scans=1, llm=0, seconds=25)),
                Audit(),
                "verification-gateway",
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        except Exception as exc:
            Audit().write("verification-gateway", "scan_rejected", {"error": type(exc).__name__})
            self.send_error(422, "verification rejected")


if __name__ == "__main__":
    if not os.environ.get("VERIFY_API_KEY"):
        raise SystemExit("VERIFY_API_KEY required")
    server = HTTPServer(("0.0.0.0", 8090), Handler)  # nosec B104
    server.serve_forever()
