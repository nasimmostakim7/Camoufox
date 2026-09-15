"""
The console's HTTP surface: start an audit, stream its progress, export the report.

Deliberately a small, explicit router over `http.server` rather than a web
framework. The console has to run from a bare Python with nothing installed -- that
is what makes it hostable and what makes the CI build a single file -- so pulling in
a framework would defeat the point. The routes are few enough that an explicit table
is clearer than a decorator registry.

Browsing is refused, and so is the request body. This server exists to run audits
against its own demo target; it does not proxy, fetch, or render anything a caller
names, and the one place a URL enters (the audit target) is checked against the
allow-list before use.
"""

from __future__ import annotations

import json
import mimetypes
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .runs import AuditService, TargetNotAllowed

UI_DIR = Path(__file__).resolve().parent / "ui"
MAX_BODY_BYTES = 64 * 1024


def read_ui_asset(name: str) -> Optional[bytes]:
    """
    Read a UI file, whether the app is running from a directory or a zipapp.

    The released artifact is a single `.pyz`, where `__file__` points *inside* the
    archive and no ordinary filesystem read works -- `Path('...pyz/console/ui/x')`
    is not a real path. So the archive itself is consulted when the directory form
    is not found. Returns None for anything outside the UI directory, which is what
    keeps a traversing name from being honoured in either form.
    """
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    direct = UI_DIR / name
    try:
        if direct.is_file():
            return direct.read_bytes()
    except OSError:
        pass

    archive = Path(sys.executable if getattr(sys, "frozen", False) else "")
    # A zipapp sets __file__ to `<archive>/<package>/<module>.py`; walk up to the
    # `.pyz` and read the member from it.
    here = Path(__file__)
    for parent in here.parents:
        if parent.suffix == ".pyz" and parent.is_file():
            member = f"{here.parent.relative_to(parent).as_posix()}/ui/{name}"
            try:
                with zipfile.ZipFile(parent) as zf:
                    return zf.read(member)
            except (KeyError, OSError):
                return None
    return None


def _json_bytes(payload: Any, status: int = 200) -> Tuple[int, bytes, str]:
    return status, json.dumps(payload, default=str).encode("utf-8"), "application/json"


class ConsoleHandler(BaseHTTPRequestHandler):
    """Routes the console's API and serves its single-page UI."""

    protocol_version = "HTTP/1.1"
    service: AuditService  # set on the subclass by make_server

    # -- plumbing ----------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # The UI is served from this same origin and needs no external asset.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid JSON body: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("request body must be a JSON object")
        return parsed

    def log_message(self, *args) -> None:
        """Quiet: the console reports through its own endpoints."""

    # -- routes ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/":
            return self._serve_ui("index.html")
        # Any bare filename is served from the UI directory. read_ui_asset accepts
        # only a plain name -- no separators, no leading dot -- so a traversal
        # attempt cannot escape it, in either the directory or the zipapp form.
        if path.count("/") == 1 and path != "/api":
            name = path.lstrip("/")
            if read_ui_asset(name) is not None:
                return self._serve_ui(name)
        if path == "/api/levels":
            return self._send(*_json_bytes({"levels": self.service.levels()}))
        if path == "/api/health":
            return self._send(
                *_json_bytes(
                    {
                        "ok": True,
                        "demo_target": self.service.demo_target,
                        "allowed_hosts": self.service.allowed_hosts,
                    }
                )
            )
        if path.startswith("/api/audits/"):
            return self._audit_route(path, query)
        return self._send(*_json_bytes({"error": "not found"}, 404))

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/audits":
            return self._start_audit()
        if path.endswith("/cancel"):
            parts = path.split("/")
            # /api/audits/<id>/cancel
            if len(parts) == 5:
                return self._cancel_audit(parts[3])
        return self._send(*_json_bytes({"error": "not found"}, 404))

    # -- handlers ----------------------------------------------------------

    def _serve_ui(self, name: str) -> None:
        body = read_ui_asset(name)
        if body is None:
            return self._send(*_json_bytes({"error": "not found"}, 404))
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype == "application/javascript":
            ctype += "; charset=utf-8"
        self._send(200, body, ctype)

    def _start_audit(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            return self._send(*_json_bytes({"error": str(exc)}, 400))

        target_url = str(body.get("target_url") or "").strip() or self.service.demo_target
        if not target_url:
            return self._send(
                *_json_bytes(
                    {"error": "target_url is required (this console has no demo target)"},
                    400,
                )
            )
        try:
            session = self.service.start_audit(
                target_url=target_url,
                visitor_count=body.get("visitor_count", 12),
                duration_hours=body.get("duration_hours", 0.02),
                max_level=body.get("max_level", 2),
                seed=body.get("seed"),
            )
        except TargetNotAllowed as exc:
            return self._send(*_json_bytes({"error": str(exc)}, 403))
        except (TypeError, ValueError) as exc:
            return self._send(*_json_bytes({"error": f"bad parameters: {exc}"}, 400))
        return self._send(*_json_bytes(session.snapshot(), 202))

    def _audit_route(self, path: str, query: Dict[str, list]) -> None:
        parts = path.split("/")
        # /api/audits/<id>[/events|/report]
        if len(parts) < 4 or not parts[3]:
            return self._send(*_json_bytes({"error": "not found"}, 404))
        session = self.service.get(parts[3])
        if session is None:
            return self._send(*_json_bytes({"error": "no such audit"}, 404))

        if len(parts) == 4:
            return self._send(*_json_bytes(session.snapshot()))

        tail = parts[4]
        if tail == "events":
            try:
                since = int((query.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            return self._send(
                *_json_bytes(
                    {
                        "session": session.snapshot(),
                        "events": session.events_since(since),
                    }
                )
            )
        if tail == "report":
            fmt = (query.get("format") or ["json"])[0]
            if fmt == "html":
                body = session.export_html()
                if body is None:
                    return self._send(*_json_bytes({"error": "audit not finished"}, 409))
                return self._send(200, body.encode("utf-8"), "text/html; charset=utf-8")
            body = session.export(fmt)
            if body is None:
                return self._send(*_json_bytes({"error": "audit not finished"}, 409))
            ctype = "text/plain; charset=utf-8" if fmt == "text" else "application/json"
            return self._send(200, body.encode("utf-8"), ctype)
        return self._send(*_json_bytes({"error": "not found"}, 404))

    def _cancel_audit(self, session_id: str) -> None:
        session = self.service.get(session_id)
        if session is None:
            return self._send(*_json_bytes({"error": "no such audit"}, 404))
        cancelled = session.cancel()
        return self._send(*_json_bytes({"cancelled": cancelled, **session.snapshot()}))


def make_server(
    host: str, port: int, service: AuditService
) -> ThreadingHTTPServer:
    """A server bound to `host:port`, wired to `service`."""
    handler = type("BoundConsoleHandler", (ConsoleHandler,), {"service": service})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve(host: str, port: int, service: AuditService) -> None:
    server = make_server(host, port, service)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
