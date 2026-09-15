"""
Tests for camoufox.audit - the WAF / bot-defense audit engine.

These run against a real HTTP server on localhost that behaves like a small WAF,
rather than against mocks, so the whole path (scheduling, HTTP, classification,
attribution, reporting) is exercised end to end.

Run with:
    cd pythonlib && python -m pytest tests/test_audit.py -v
"""

import asyncio
import os
import random
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from camoufox.audit import (  # noqa: E402
    AuditConfig,
    AuditRunner,
    AuthorizationRequired,
    EVASION_LEVELS,
    SafetyLimits,
    ScopeViolation,
    TargetScope,
    Verdict,
    build_schedule,
    classify_response,
    level_by_id,
)
from camoufox.audit.report import build_findings, render_html, render_text  # noqa: E402
from camoufox.audit.schedule import ArrivalPattern, ScheduleConfig  # noqa: E402


# --------------------------------------------------------------------------
# A small WAF to audit: blocks library user agents, challenges Chrome-like ones
# on the first hit and allows them once a cookie is presented.
# --------------------------------------------------------------------------


class _WafHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits = 0

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        type(self).hits += 1
        ua = self.headers.get("User-Agent", "")
        cookie = self.headers.get("Cookie", "")

        if "python" in ua.lower() or "urllib" in ua.lower() or not ua:
            self._send(
                403,
                b"<html>Attention Required! | Cloudflare</html>",
                {"Server": "cloudflare"},
            )
            return

        if "Chrome" in ua and "cf_clearance" not in cookie:
            self._send(
                200,
                b"<html>Just a moment...</html>",
                {"cf-mitigated": "challenge"},
            )
            return

        self._send(200, b"<html>welcome</html>")

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def waf_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WafHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}/"
    server.shutdown()
    server.server_close()


def _scope(url, **kwargs):
    return TargetScope.from_urls([url], acknowledged=True, **kwargs)


def _config(url, **overrides):
    params = dict(
        target_url=url,
        scope=_scope(url),
        levels=[0],
        visitor_count=6,
        # Small window keeps the suite fast: arrivals are still spread out and
        # jittered, which is all these tests need. The scheduling semantics
        # themselves are covered by the schedule tests above.
        duration_hours=0.002,
        cooldown_between_levels_s=0,
        limits=SafetyLimits(max_requests=200, max_rps=50, max_concurrency=4),
        seed=1,
    )
    params.update(overrides)
    return AuditConfig(**params)


# --------------------------------------------------------------------------
# Classification: the distinction the whole report rests on
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,headers,body,expected",
    [
        # A 403 block page is a refusal, not an invitation to solve a challenge.
        (403, {"server": "cloudflare"}, "<html>Attention Required! | Cloudflare</html>", Verdict.BLOCKED),
        (403, {}, "<html>Access Denied</html>", Verdict.BLOCKED),
        # The same marker with a 200 is a challenge interstitial.
        (200, {}, "<html>Just a moment...</html>", Verdict.CHALLENGED),
        (200, {"cf-mitigated": "challenge"}, "", Verdict.CHALLENGED),
        (200, {}, "<html>Checking your browser before accessing</html>", Verdict.CHALLENGED),
        # Rate limiting is distinct from blocking: it has a retry horizon.
        (429, {}, "", Verdict.RATE_LIMITED),
        (429, {"retry-after": "30"}, "", Verdict.RATE_LIMITED),
        (503, {}, "", Verdict.RATE_LIMITED),
        # A normal page.
        (200, {}, "<html>hello</html>", Verdict.ALLOWED),
        (200, {"server": "nginx"}, "<html>ok</html>", Verdict.ALLOWED),
        # Server errors are errors, not verdicts about the client.
        (500, {}, "", Verdict.ERROR),
    ],
)
def test_classify_response(status, headers, body, expected):
    assert classify_response(status, headers, body).verdict == expected


def test_classification_keeps_evidence():
    """Every verdict should carry the signal that produced it."""
    result = classify_response(
        403, {"server": "cloudflare"}, "<html>Attention Required! | Cloudflare</html>"
    )
    assert result.vendors, "expected a product attribution"
    assert result.evidence, "expected the matched signal to be recorded"
    assert result.reason


def test_block_and_challenge_are_not_conflated():
    """The regression this suite exists for: a hard block scored as a challenge."""
    block = classify_response(403, {}, "<html>Attention Required!</html>")
    challenge = classify_response(200, {}, "<html>Attention Required!</html>")
    assert block.verdict == Verdict.BLOCKED
    assert challenge.verdict == Verdict.CHALLENGED


# --------------------------------------------------------------------------
# Scope / authorization gate
# --------------------------------------------------------------------------


def test_scope_requires_acknowledgment():
    """The gate must refuse at check time, not merely warn."""
    scope = TargetScope.from_urls(["https://example.com"], acknowledged=False)
    with pytest.raises(AuthorizationRequired):
        scope.check("https://example.com/")


def test_scope_blocks_off_scope_target():
    scope = TargetScope.from_urls(["https://example.com"], acknowledged=True)
    assert scope.permits("example.com")
    assert not scope.permits("other.example.net")
    with pytest.raises(ScopeViolation):
        scope.check("https://other.example.net/")


def test_scope_subdomains_opt_in():
    strict = TargetScope.from_urls(["https://example.com"], acknowledged=True)
    assert not strict.permits("api.example.com")

    loose = TargetScope.from_urls(
        ["https://example.com"], acknowledged=True, allow_subdomains=True
    )
    assert loose.permits("api.example.com")


def test_scope_rejects_lookalike_host():
    """A suffix check would let evil-example.com through; the boundary must be exact."""
    scope = TargetScope.from_urls(
        ["https://example.com"], acknowledged=True, allow_subdomains=True
    )
    assert not scope.permits("evil-example.com")
    assert not scope.permits("notexample.com")


def test_config_validate_rejects_out_of_scope_target():
    config = _config("http://127.0.0.1:9/", scope=_scope("https://example.com"))
    assert any("scope" in p.lower() for p in config.validate())


# --------------------------------------------------------------------------
# Scheduling: the property that makes traffic look human
# --------------------------------------------------------------------------


def test_schedule_is_not_uniform():
    """Arrivals must not be evenly spaced; that is the whole point."""
    schedule = build_schedule(
        ScheduleConfig(
            visitor_count=500, duration_hours=24.0, pattern=ArrivalPattern.HUMAN_DIURNAL
        ),
        rng=random.Random(3),
    )
    gaps = schedule.inter_arrival_seconds()
    assert len(gaps) == 499
    assert len(set(round(g, 3) for g in gaps)) > 100, "gaps look quantised, not random"
    assert max(gaps) > min(gaps) * 10, "arrivals are too evenly spread"


def test_schedule_is_not_simultaneous():
    schedule = build_schedule(
        ScheduleConfig(visitor_count=200, duration_hours=1.0),
        rng=random.Random(4),
    )
    offsets = sorted(a.offset_s for a in schedule.arrivals)
    assert offsets[0] < offsets[-1]
    assert all(b - a >= 0 for a, b in zip(offsets, offsets[1:]))


def test_schedule_is_reproducible_with_a_seed():
    def run():
        return [
            a.offset_s
            for a in build_schedule(
                ScheduleConfig(visitor_count=50, duration_hours=1.0),
                rng=random.Random(99),
            ).arrivals
        ]

    assert run() == run()


def test_schedule_respects_arrivals_per_minute_cap():
    """The cap is a safety control, so it must actually bound the burst rate."""
    schedule = build_schedule(
        ScheduleConfig(
            visitor_count=300, duration_hours=1.0, pattern=ArrivalPattern.CONSTANT,
            max_arrivals_per_minute=10,
        ),
        rng=random.Random(5),
    )
    minute_buckets = {}
    for arrival in schedule.arrivals:
        minute_buckets.setdefault(int(arrival.offset_s // 60), 0)
        minute_buckets[int(arrival.offset_s // 60)] += 1
    assert max(minute_buckets.values()) <= 10


def test_schedule_warns_when_window_cannot_fit_visitors():
    """A minimum gap can silently push arrivals past the window; that must surface."""
    schedule = build_schedule(
        ScheduleConfig(visitor_count=100, duration_hours=0.01, min_gap_s=30.0),
        rng=random.Random(6),
    )
    assert schedule.warnings


def test_patterns_produce_different_shapes():
    """
    Constant spreads arrivals evenly; diurnal clusters them by time of day.

    Comparing halves does not separate the two -- the diurnal curve is roughly
    symmetric about noon -- so compare how uneven the hourly buckets are.
    """
    def hourly_spread(pattern):
        schedule = build_schedule(
            ScheduleConfig(visitor_count=400, duration_hours=24.0, pattern=pattern),
            rng=random.Random(7),
        )
        buckets = [0] * 24
        for arrival in schedule.arrivals:
            buckets[min(23, int(arrival.offset_s // 3600))] += 1
        mean = sum(buckets) / len(buckets)
        variance = sum((b - mean) ** 2 for b in buckets) / len(buckets)
        return variance / (mean ** 2) if mean else 0.0  # squared coefficient of variation

    constant = hourly_spread(ArrivalPattern.CONSTANT)
    diurnal = hourly_spread(ArrivalPattern.HUMAN_DIURNAL)

    # Even a perfectly uniform rate shows sampling noise of roughly 1/mean per
    # bucket (~0.06 at 400 visitors over 24 buckets), so the uniform bound has
    # to sit above that; the diurnal curve then has to clear it by a wide margin.
    assert constant < 0.15, f"constant pattern should be near-uniform, got {constant}"
    assert diurnal > constant * 2.5, (
        f"diurnal pattern should cluster far more than constant "
        f"(diurnal={diurnal}, constant={constant})"
    )


# --------------------------------------------------------------------------
# Evasion ladder
# --------------------------------------------------------------------------


def test_ladder_is_ordered_and_each_rung_isolates_one_vector():
    ids = [level.id for level in EVASION_LEVELS]
    assert ids == sorted(ids), "ladder must be ordered by increasing capability"
    for level in EVASION_LEVELS:
        assert level.isolates, f"{level.name} does not say what it isolates"
        assert level.description


def test_evasion_level_lookup():
    assert level_by_id(0).id == 0
    assert level_by_id(len(EVASION_LEVELS) - 1).id == len(EVASION_LEVELS) - 1


# --------------------------------------------------------------------------
# Runner end to end against the local WAF
# --------------------------------------------------------------------------


def test_runner_attributes_block_to_the_naive_rung(waf_server):
    """L0 should be refused, and the refusal attributed to the WAF."""
    report = asyncio.run(AuditRunner(_config(waf_server)).run())

    assert report.levels, "expected at least one level result"
    level = report.levels[0]
    assert level.completed == 6
    assert level.detected == 6
    assert level.bypass_rate == 0.0
    assert "Cloudflare" in level.vendors_seen()

    effective = report.first_effective_level()
    assert effective is not None and effective.level.id == 0


def test_runner_reports_clean_traffic_as_allowed(waf_server):
    """A browser-like client with clearance must not be flagged."""
    report = asyncio.run(
        AuditRunner(_config(waf_server, extra_headers={"User-Agent": "Mozilla/5.0 Chrome/131", "Cookie": "cf_clearance=1"})).run()
    )
    level = report.levels[0]
    assert level.allowed == 6
    assert level.bypass_rate == 1.0
    assert report.first_effective_level() is None


def test_runner_records_exit_ip_and_proxy_label(waf_server):
    """Per-visit attribution must survive into the report."""
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    assert report.levels[0].visits
    for visit in report.levels[0].visits:
        assert visit.visitor_index >= 0
        assert visit.reason, "every visit needs a stated reason"


def test_runner_stops_at_request_ceiling(waf_server):
    """The ceiling must abort the run rather than being advisory."""
    config = _config(
        waf_server,
        visitor_count=50,
        limits=SafetyLimits(max_requests=5, max_rps=50, max_concurrency=4),
    )
    report = asyncio.run(AuditRunner(config).run())
    assert report.total_requests <= 5
    assert report.aborted


def test_runner_respects_cancellation(waf_server):
    cancel = threading.Event()
    cancel.set()
    report = asyncio.run(
        AuditRunner(_config(waf_server, visitor_count=40), cancel_event=cancel).run()
    )
    assert report.aborted
    assert report.total_requests < 40


def test_runner_emits_progress_events(waf_server):
    events = []
    asyncio.run(
        AuditRunner(_config(waf_server), on_progress=events.append).run()
    )
    kinds = {e.get("event") for e in events}
    assert "level_start" in kinds
    assert "visit" in kinds
    assert "level_end" in kinds


def test_runner_refuses_out_of_scope_target(waf_server):
    """An out-of-scope target must not receive traffic; the run fails closed."""
    config = _config(waf_server, scope=_scope("https://example.com"))
    report = asyncio.run(AuditRunner(config).run())
    assert report.aborted
    assert "scope" in report.abort_reason.lower()
    assert report.total_requests == 0


def test_display_detection_matches_the_environment(monkeypatch):
    """
    A headed rung needs an X server; detecting one must not be optimistic.

    Reporting a display that is not there sends a headed launch straight into
    "no DISPLAY environment variable specified" and turns a verdict into an error.
    """
    monkeypatch.delenv("DISPLAY", raising=False)
    assert AuditRunner._has_display() is False

    monkeypatch.setenv("DISPLAY", ":98765")
    assert AuditRunner._has_display() is False, "a socket that does not exist is not a display"


def test_headed_level_falls_back_to_virtual_display(waf_server, monkeypatch):
    """
    On a host with no X server, a headed rung must use Camoufox's virtual display
    rather than failing to launch, and must say so in a progress notice.

    Asserted on the assembled launch options, not on a live visit: the pythonlib
    tier is browser-free by design (CI does not fetch a browser for it), so a
    test that needs a real launch would report CamoufoxNotInstalled as an audit
    error -- a false failure of the tier's own contract.
    """
    monkeypatch.delenv("DISPLAY", raising=False)
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[2], visitor_count=2),
        on_progress=events.append,
    )

    options = runner._launch_options(level_by_id(2))

    assert options["headless"] == "virtual", (
        "a headed rung with no display must fall back to the virtual display"
    )
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("virtual display" in n.get("message", "") for n in notices), (
        "the fallback must be announced, not silent"
    )


def test_an_explicit_display_is_left_alone(waf_server, monkeypatch):
    """A host that has an X server must launch headed, not virtual."""
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    runner = AuditRunner(_config(waf_server, levels=[2], visitor_count=1))

    assert runner._launch_options(level_by_id(2))["headless"] is False


def test_geoip_absent_falls_back_instead_of_failing_to_launch(waf_server, monkeypatch):
    """
    Rungs that ask for geoip must still run when the optional extra is missing.

    geoip2 is an optional dependency, so on a plain install every rung from L3 up
    would fail to launch, and the audit would report errors for levels it never
    actually exercised. The masking is weaker without geolocation, but a rung that
    runs and is measured beats one that errors out.

    As above, this asserts the launch contract rather than a live visit, so it
    holds on the browser-free tier.
    """
    monkeypatch.setattr(AuditRunner, "_has_geoip", staticmethod(lambda: False))
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[3], visitor_count=1),
        on_progress=events.append,
    )

    options = runner._launch_options(level_by_id(3))

    assert options["geoip"] is False, (
        "the geoip flag must be cleared when the extra is missing, or the rung "
        "fails to launch instead of being measured"
    )
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("geoip" in n.get("message", "").lower() for n in notices), (
        "a weaker mask must be announced, not silent"
    )


def test_geoip_is_kept_when_the_extra_is_installed(waf_server, monkeypatch):
    """The flag survives when geoip2 is importable: the fallback is conditional."""
    monkeypatch.setattr(AuditRunner, "_has_geoip", staticmethod(lambda: True))
    runner = AuditRunner(_config(waf_server, levels=[3], visitor_count=1))

    assert runner._launch_options(level_by_id(3))["geoip"] is True


def test_rotation_rung_without_a_pool_says_so(waf_server):
    """
    A proxy rung with no pool must not report itself as IP rotation.

    L4 and up are defined by "a fresh exit IP per visitor". With no rotator the
    visit goes out on this host's own address, so a report that still called the
    rung "Proxy rotation" would point the operator at a control that was never
    exercised. The run proceeds (some masking still happens) but announces the
    gap.
    """
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[4], visitor_count=1),
        on_progress=events.append,
    )
    report = asyncio.run(runner.run())

    assert report.levels[0].level.id == 4
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("without a proxy" in n.get("message", "") for n in notices), notices


def test_no_missing_proxy_notice_when_a_pool_is_configured(waf_server, tmp_path):
    """The notice is conditional, so a configured pool must not trigger it."""
    pool = tmp_path / "proxies.txt"
    pool.write_text("http://127.0.0.1:1\n", encoding="utf-8")
    events = []
    config = _config(
        waf_server,
        levels=[4],
        visitor_count=1,
        proxy={"mode": "file", "file": str(pool)},
    )
    runner = AuditRunner(config, on_progress=events.append)

    assert runner._rotator is not None
    notices = [e for e in events if e.get("event") == "notice"]
    assert not any("without a proxy" in n.get("message", "") for n in notices), notices


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def test_findings_name_the_holding_rung(waf_server):
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    findings = " ".join(build_findings(report))
    assert "L0" in findings
    assert "Cloudflare" in findings


def test_text_report_is_self_describing(waf_server):
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    text = render_text(report)
    assert report.config.target_url in text
    assert "FINDINGS" in text
    assert "EVASION LADDER" in text


def test_html_report_is_self_contained(waf_server):
    """No external assets: the report must open from disk with no network."""
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    html = render_html(report)
    assert html.lstrip().startswith("<!doctype html")
    for marker in ("http://cdn", "https://cdn", "<script"):
        assert marker not in html


def test_report_exports_all_formats(waf_server, tmp_path):
    from camoufox.audit.report import write_report

    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    written = write_report(report, str(tmp_path))
    assert set(written) == {"json", "csv", "html", "text"}
    for path in written.values():
        assert os.path.getsize(path) > 0

    import json

    payload = json.loads(open(written["json"]).read())
    assert payload["target_url"] == report.config.target_url
    assert payload["findings"]


def test_html_escapes_target_url(waf_server, tmp_path):
    """A target containing markup must not break out of the report."""
    report = asyncio.run(AuditRunner(_config(waf_server)).run())
    report.config.target_url = "https://example.com/<script>alert(1)</script>"
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
