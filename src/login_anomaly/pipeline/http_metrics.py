"""Tiny /metrics + /healthz HTTP server for pipeline processes."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def start_metrics_server(port: int, *, label: str = "pipeline") -> None:
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    except ImportError:
        print(f"{label}: prometheus_client missing; /metrics disabled", flush=True)
        return

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path not in {"/metrics", "/healthz"}:
                self.send_response(404)
                self.end_headers()
                return
            if self.path == "/healthz":
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            payload = generate_latest()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    server = HTTPServer(("0.0.0.0", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"{label}: metrics on :{port}/metrics", flush=True)
