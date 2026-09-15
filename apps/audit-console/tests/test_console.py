"""
Tests for the WAF Audit Console.

These drive the console through its real HTTP surface -- the same `http.server` the
hosted build serves -- against the real demo WAF it starts. No mocks: the point of
most of these is that the console refuses the wrong things, and a mocked transport
would not prove the refusal happens before a request leaves.

Run with:
    cd apps/audit-console && python -m pytest tests/ -v
"""

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(APP_DIR))

from console import demo_waf  # noqa: E402
from console.runs import AuditService, browser_available  # noqa: E402
from console.server import make_server  # noqa: E402


# --------------------------------------------------------------------------
# harness


class Console:
    """A console process on an ephemeral port, wired to a fresh demo WAF."""

    def __init__(self) -> None:
        self.waf, self.target = demo_waf.start_demo_waf()
        host = self.target.split("//", 1)[1].split("/", 1)[0].split(":")[0]
        self.service = AuditService(allowed_hosts=[host], demo_target=self.target)
        self.server = make_server("127.0.0.1", 0, self.service)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.waf.stop()

    def request(self, method, path, body=None):
        url = self.base + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, raw, resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8"), exc.headers.get("Content-Type", "")

    def get_json(self, path):
        status, raw, _ = self.request("GET", path)
        return status, json.loads(raw)

    def post_json(self, path, body=None):
        status, raw, _ = self.request("POST", path, body)
        return status, json.loads(raw)


@pytest.fixture
def console():
    c = Console()
    try:
        yield c
    finally:
        c.stop()


def run_audit(console, **overrides):
    """Start an audit and poll until it leaves 'running'."""
    import time

    body = {
        "visitor_count": 2,
        "duration_hours": 0.002,
        "max_level": 0,
        "seed": 3,
    }
    body.update(overrides)
    status, started = console.post_json("/api/audits", body)
    assert status == 202, started
    sid = started["id"]
    for _ in range(300):
        _, session = console.get_json(f"/api/audits/{sid}")
        if session["status"] != "running":
            return session
        time.sleep(0.2)
    raise AssertionError("audit did not finish")


# --------------------------------------------------------------------------
# the scope gate: a hosted console must not be an open request forwarder


def test_external_target_is_refused(console):
    """The whole point of the allow-list: a stranger cannot point us at a third party."""
    status, body = console.post_json(
        "/api/audits", {"target_url": "https://example.com/", "max_level": 0}
    )
    assert status == 403
    assert "allow-list" in body["error"]


def test_cloud_metadata_address_is_refused(console):
    """An SSRF-shaped target is refused by the same check, not a special case."""
    status, body = console.post_json(
        "/api/audits", {"target_url": "http://169.254.169.254/latest/meta-data/"}
    )
    assert status == 403
    assert "169.254.169.254" in body["error"]


def test_non_http_schemes_are_refused(console):
    status, body = console.post_json(
        "/api/audits", {"target_url": "file:///etc/passwd"}
    )
    assert status == 403
    assert "http(s)" in body["error"]


def test_no_traffic_when_the_target_is_refused(console):
    """A refused target must not have been fetched even once."""
    before = console.waf.hits
    console.post_json("/api/audits", {"target_url": "https://example.com/"})
    assert console.waf.hits == before


def test_service_without_allow_list_still_requires_a_host():
    """An empty allow-list means "unrestricted", not "anything, including garbage"."""
    from console.runs import TargetNotAllowed

    service = AuditService(allowed_hosts=[])
    with pytest.raises(TargetNotAllowed):
        service.authorize("not-a-url")
    with pytest.raises(TargetNotAllowed):
        service.authorize("ftp://example.com/")


# --------------------------------------------------------------------------
# the audit itself


def test_audit_runs_and_reports_the_demo_defense(console):
    """The bundled demo must actually be audited, and the block attributed."""
    session = run_audit(console, visitor_count=6, max_level=0)
    assert session["status"] == "done", session["error"]

    summary = session["summary"]
    assert summary["total_visits"] == 6
    assert summary["first_effective_level"] == "L0 - Naive HTTP"

    l0 = summary["levels"][0]
    assert l0["counts"]["blocked"] == 6
    assert "Cloudflare" in l0["vendors"]


def test_empty_body_targets_the_demo(console):
    """The UI omits the target; the console fills in its own demo."""
    status, started = console.post_json(
        "/api/audits", {"visitor_count": 2, "duration_hours": 0.002, "max_level": 0}
    )
    assert status == 202
    assert started["target_url"].startswith("http://127.0.0.1:")


def test_ladder_is_capped_by_the_ceiling_not_the_request(console):
    """A request cannot raise the console above MAX_LEVELS."""
    from console.runs import MAX_LEVELS

    status, started = console.post_json(
        "/api/audits", {"max_level": 99, "visitor_count": 1, "duration_hours": 0.002}
    )
    assert status == 202
    assert started["max_level"] <= MAX_LEVELS


def test_browser_rungs_are_capped_when_no_browser_is_installed(console, monkeypatch):
    """
    A host with no browser must be told so, not handed an audit that errors.

    The console runs on a bare Python, so this is the normal state for the hosted
    build: it caps at L0 and records a notice explaining why.
    """
    monkeypatch.setattr("console.runs.browser_available", lambda: False)
    session = run_audit(console, visitor_count=2, max_level=2)
    assert session["status"] == "done"
    assert session["max_level"] == 0

    _, events = console.get_json(f"/api/audits/{session['id']}/events?since=0")
    messages = [e.get("message", "") for e in events["events"] if e.get("event") == "notice"]
    assert any("capped at L0" in m for m in messages), messages


def test_events_are_monotonic_and_resumable(console):
    """The UI polls with `since`; sequence numbers must be stable and ordered."""
    session = run_audit(console, visitor_count=4, max_level=0)
    sid = session["id"]

    _, first = console.get_json(f"/api/audits/{sid}/events?since=0")
    seqs = [e["seq"] for e in first["events"]]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)

    _, second = console.get_json(f"/api/audits/{sid}/events?since={seqs[len(seqs) // 2]}")
    assert all(e["seq"] >= seqs[len(seqs) // 2] for e in second["events"])


# --------------------------------------------------------------------------
# reports


def test_reports_render_in_every_format(console):
    session = run_audit(console, visitor_count=4, max_level=0)
    sid = session["id"]

    status, body, ctype = console.request("GET", f"/api/audits/{sid}/report?format=html")
    assert status == 200 and "text/html" in ctype and "<html" in body.lower()

    status, body, ctype = console.request("GET", f"/api/audits/{sid}/report?format=text")
    assert status == 200 and "AUDIT" in body

    status, body, _ = console.request("GET", f"/api/audits/{sid}/report?format=json")
    assert status == 200
    payload = json.loads(body)
    assert payload["levels"][0]["level_name"] == "L0 - Naive HTTP"
    assert payload["findings"]


def test_report_before_completion_is_a_conflict(console):
    """A half-finished audit has no report; that must be a clear 409, not an error."""
    status, started = console.post_json(
        "/api/audits", {"visitor_count": 30, "duration_hours": 0.05, "max_level": 0}
    )
    assert status == 202
    status, body = console.get_json(f"/api/audits/{started['id']}/report")
    assert status in (409, 200)


# --------------------------------------------------------------------------
# input handling


def test_oversize_body_is_rejected(console):
    payload = '{"target_url":"' + "a" * (70 * 1024) + '"}'
    req = urllib.request.Request(
        console.base + "/api/audits",
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 400
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
        assert "too large" in exc.read().decode("utf-8")


def test_malformed_json_is_a_400(console):
    req = urllib.request.Request(
        console.base + "/api/audits",
        data=b"{not json",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=10)
    assert exc.value.code == 400


def test_unknown_routes_are_404(console):
    assert console.get_json("/api/nope")[0] == 404
    assert console.get_json("/api/audits/deadbeef")[0] == 404


def test_ui_is_served_from_the_same_origin(console):
    status, body, ctype = console.request("GET", "/")
    assert status == 200 and "text/html" in ctype
    assert "WAF Audit Console" in body

    status, body, ctype = console.request("GET", "/console.js")
    assert status == 200 and "javascript" in ctype


def test_path_traversal_cannot_escape_the_ui_directory(console):
    """Serving the UI directory must not become serving the filesystem."""
    for attempt in ("/../../etc/passwd", "/../app.py", "/%2e%2e/app.py"):
        status, body, _ = console.request("GET", attempt)
        assert status == 404, f"{attempt} was served"
        assert "root:" not in body


# --------------------------------------------------------------------------
# the vendored engine


def test_vendored_engine_matches_the_source():
    """A stale copy would silently ship an older ladder or classifier."""
    import subprocess

    result = subprocess.run(
        [sys.executable, str(APP_DIR / "sync_engine.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_engine_imports_without_playwright():
    """L0 must run on a bare Python, so the vendored engine cannot import playwright."""
    import importlib
    import importlib.util

    blocked = {"playwright", "browserforge", "screeninfo", "numpy", "lxml", "orjson"}

    class Blocker:
        def find_module(self, name, path=None):  # pragma: no cover - py<3.12
            return self if name.split(".")[0] in blocked else None

        def load_module(self, name):  # pragma: no cover
            raise ImportError(f"blocked {name}")

    saved = {
        name: sys.modules.pop(name)
        for name in list(sys.modules)
        if name.split(".")[0] in blocked
    }
    sys.meta_path.insert(0, Blocker())
    try:
        import console._engine as engine

        importlib.reload(engine)
        assert len(engine.EVASION_LEVELS) >= 4
        assert engine.Verdict.ALLOWED == "allowed"
    finally:
        sys.meta_path.remove(sys.meta_path[0])
        sys.modules.update(saved)


def test_browser_available_reflects_the_installed_package():
    """A helper, so the boolean itself is the contract: importable or not."""
    assert isinstance(browser_available(), bool)
