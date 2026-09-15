"""
A tiny WAF, served by the console itself, so the tool has something real to audit.

The hosted console cannot point at a third-party site -- that would make it an open
request forwarder -- and a demo that only ever reports "allowed" proves nothing. So
the console serves its own target: a small defense that blocks non-browser clients
the way a real CDN does, including the vendor markers the classifier attributes.

This is the same shape as the WAF in `pythonlib/tests/test_audit.py`, and
deliberately so: the hosted demo and the test suite exercise the classifier against
the same behaviour.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple

#: Marker in a blocked response body, matched by the Cloudflare signature.
_BLOCK_BODY = b"<html><title>Attention Required! | Cloudflare</title></html>"
_ALLOW_BODY = b"<html><body><h1>Demo WAF</h1><p>welcome</p></body></html>"


class DemoWafHandler(BaseHTTPRequestHandler):
    """Blocks anything that does not look like a browser."""

    protocol_version = "HTTP/1.1"
    hits = 0
    _lock = threading.Lock()

    def _send(self, status: int, body: bytes, headers: Optional[dict] = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        with type(self)._lock:
            type(self).hits += 1
        agent = (self.headers.get("User-Agent") or "").strip().lower()

        # The defense under test: a client that does not claim to be a browser is
        # refused outright. This is exactly what L0 ("naive HTTP") sends.
        if not agent or "python" in agent or "urllib" in agent or "curl" in agent:
            self._send(403, _BLOCK_BODY, {"Server": "cloudflare"})
            return

        self._send(200, _ALLOW_BODY)

    def log_message(self, *args) -> None:
        """Silence the default stderr chatter; the console reports its own results."""


class DemoWaf:
    """A running demo WAF on an ephemeral loopback port."""

    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), DemoWafHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/"

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def hits(self) -> int:
        return DemoWafHandler.hits

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def start_demo_waf() -> Tuple[DemoWaf, str]:
    """Start the demo WAF and return it with its base URL."""
    waf = DemoWaf()
    return waf, waf.url
