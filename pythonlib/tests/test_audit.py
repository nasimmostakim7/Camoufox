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
    SINGLE_LEVEL_VISITORS,
    AuditConfig,
    AuditReport,
    AuditRunner,
    AuthorizationRequired,
    CAPABILITIES,
    EVASION_LEVELS,
    LevelResult,
    SafetyLimits,
    ScopeViolation,
    TargetScope,
    Verdict,
    VisitResult,
    build_schedule,
    classify_response,
    ladder_problems,
    level_by_id,
)
from camoufox.audit.report import build_findings, render_html, render_text  # noqa: E402
from camoufox.audit.schedule import ArrivalPattern, ScheduleConfig  # noqa: E402
from camoufox.proxy import ProxyRotator  # noqa: E402


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
    # The two ways of naming rungs are mutually exclusive, and `levels=[0]` is
    # only here to keep an ordinary ladder test cheap. A single-rung config must
    # not inherit it, or every such test would fail validation instead of testing
    # what it meant to.
    if params.get("single_level_mode") and "levels" not in overrides:
        params["levels"] = None
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


# --------------------------------------------------------------------------
# The ladder must isolate exactly one capability per rung
# --------------------------------------------------------------------------


def test_ladder_adds_exactly_one_capability_per_rung():
    """Each rung's whole claim is that it differs from the one below by one axis.

    A rung that repeats the rung below it (L3/L4/L5 used to be byte-identical,
    with no launch-option difference at all) or that turns on two axes at once
    makes a verdict unattributable, which is the one thing the ladder exists to
    prevent.
    """
    assert ladder_problems() == []


def test_each_capability_is_introduced_exactly_once():
    seen = [level.adds for level in EVASION_LEVELS if level.adds is not None]
    assert len(seen) == len(set(seen)), f"a capability is introduced twice: {seen}"
    assert set(seen) <= set(CAPABILITIES)


def test_rungs_that_claim_behavior_are_the_only_ones_flagged():
    behavioral = [level.id for level in EVASION_LEVELS if level.is_behavioral]
    assert behavioral == [5, 6], (
        "only L5 and up may act like a human; lower rungs that scroll, type or "
        "carry a referer would credit behavior for a static-signal verdict"
    )


def test_rotation_is_claimed_only_by_the_rungs_that_rotate():
    rotating = [level.id for level in EVASION_LEVELS if level.requires_rotation]
    assert rotating == [4, 5, 6]


def test_the_rungs_below_behavior_do_not_carry_humanize():
    """humanize is Camoufox's cursor humanization: a behavioral capability."""
    for level in EVASION_LEVELS:
        if not level.is_behavioral:
            assert not (level.camoufox_options or {}).get("humanize"), (
                f"{level.name} enables humanize but does not claim behavior"
            )


def test_plan_visit_without_behavior_is_a_single_direct_request():
    """A non-behavioral rung must send one direct request, nothing more."""
    from camoufox.audit.journey import ArrivalSource, JourneyConfig, plan_visit

    plan = plan_visit(JourneyConfig(), random.Random(7), behavior=False)
    assert plan.source == ArrivalSource.DIRECT
    assert plan.referer is None
    assert plan.page_count == 1
    assert plan.scroll_steps == 0
    assert plan.will_type is False
    assert plan.follow_links is False


def test_plan_visit_with_behavior_still_produces_varied_journeys():
    """The gate must not flatten the behavioral rung's own session shape."""
    from camoufox.audit.journey import JourneyConfig, plan_visit

    rng = random.Random(3)
    plans = [plan_visit(JourneyConfig(), rng, behavior=True) for _ in range(40)]
    assert any(p.page_count > 1 for p in plans)
    assert any(p.will_type for p in plans)


# --------------------------------------------------------------------------
# Proxy acquisition is gated on the rung that is defined by rotation
# --------------------------------------------------------------------------


def _pool_file(tmp_path):
    pool = tmp_path / "proxies.txt"
    pool.write_text("http://127.0.0.1:1\n", encoding="utf-8")
    return pool


def test_a_rung_below_rotation_never_acquires_a_proxy(waf_server, tmp_path):
    """L3 is not defined by the exit IP, so it must go out on this host's address.

    Acquiring a session for it would make L3's verdict a product of an IP the rung
    never claimed to use, and would spend pool capacity before L4 ever runs.
    """
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[3],
            visitor_count=2,
            proxy={"mode": "file", "file": str(_pool_file(tmp_path))},
        )
    )

    def refuse():
        raise AssertionError("L3 must not acquire a proxy")

    runner._acquire_proxy = refuse
    report = asyncio.run(runner.run())
    assert report.levels[0].level.id == 3


def test_rotation_rung_still_acquires_a_proxy(waf_server, tmp_path):
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[4],
            visitor_count=1,
            proxy={"mode": "file", "file": str(_pool_file(tmp_path))},
        )
    )
    acquired = []
    original = runner._acquire_proxy

    def spy():
        acquired.append(True)
        return original()

    runner._acquire_proxy = spy
    asyncio.run(runner.run())
    assert acquired, "a rotation rung must acquire a proxy session"


def test_proxy_accounting_is_untouched_on_rungs_that_use_no_proxy(waf_server, tmp_path):
    """The per-proxy counter must stay empty for rungs that never take a proxy."""
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[0],
            visitor_count=3,
            proxy={"mode": "file", "file": str(_pool_file(tmp_path))},
        )
    )
    asyncio.run(runner.run())
    assert runner._proxy_counts == {}


def test_each_visitor_gets_its_own_proxy_session(waf_server, tmp_path):
    """The product claim is "a fresh exit IP per visitor", so pin it per visit.

    The rotator's own tests cover that `acquire_session()` advances; what they
    cannot see is whether the *runner* asks it once per visitor or reuses one
    session across a whole rung. A reused session would make L4's verdict the
    product of a single exit, which is the one thing the rung claims not to do.
    """
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[4],
            visitor_count=3,
            proxy={"mode": "file", "file": str(_pool_file(tmp_path))},
        )
    )
    seen = []
    original = runner._acquire_proxy

    def spy():
        session, reason = original()
        if session is not None:
            seen.append(session.session_id)
        return session, reason

    runner._acquire_proxy = spy
    asyncio.run(runner.run())

    assert len(seen) >= 2, f"a rotation rung must take a session per visitor: {seen}"
    assert len(seen) == len(set(seen)), f"a session was reused across visitors: {seen}"


def test_a_gateway_session_token_is_substituted_per_visitor(
    waf_server, tmp_path, monkeypatch
):
    """A gateway expresses stickiness through `{session}`, so each visit gets its own.

    Without the substitution every visitor would share one token and therefore
    one exit IP -- a rotation feature that silently rotates nothing.
    """
    # The gateway host is not real, so stub the reachability probe rather than
    # let a DNS failure be read as "the token was not substituted".
    monkeypatch.setattr(ProxyRotator, "_endpoint_reachable", lambda self, endpoint: True)
    runner = AuditRunner(
        _config(
            waf_server,
            levels=[4],
            visitor_count=3,
            proxy={
                "mode": "gateway",
                "gateway": "http://user-session-{session}:pw@gw.invalid:8000",
                "verify_ip": False,
            },
        )
    )
    tokens = []
    original = runner._acquire_proxy

    def spy():
        session, reason = original()
        if session is not None:
            tokens.append(session.endpoint.username)
        return session, reason

    runner._acquire_proxy = spy
    asyncio.run(runner.run())

    assert len(tokens) >= 2, f"expected a token per visitor, got {tokens}"
    assert all("{session}" not in (t or "") for t in tokens), tokens
    assert len(tokens) == len(set(tokens)), f"two visitors shared a gateway token: {tokens}"


# --------------------------------------------------------------------------
# The headless setting is an override, not a silent flattening of the ladder
# --------------------------------------------------------------------------


def test_default_config_leaves_each_rung_its_own_posture(waf_server, monkeypatch):
    """With no override, L1 launches headless and L2 launches headed.

    On a host with a real display the headed rung is `False`; with none it is
    `'virtual'`, Camoufox's own Xvfb. Either way it is *not* headless, which is
    the distinction the ladder depends on.
    """
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    runner = AuditRunner(_config(waf_server, levels=[1, 2], visitor_count=1))
    assert runner._launch_options(level_by_id(1))["headless"] is True
    assert runner._launch_options(level_by_id(2))["headless"] is False


def test_headless_rung_falls_back_to_virtual_on_a_displayless_host(waf_server, monkeypatch):
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: False))
    runner = AuditRunner(_config(waf_server, levels=[2], visitor_count=1))
    assert runner._launch_options(level_by_id(2))["headless"] == "virtual"


def test_headless_override_forces_every_rung_and_announces_it(waf_server, monkeypatch):
    """Ticking the box must actually force headless, and say that it overrode L2."""
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[1, 2], visitor_count=1, headless=True),
        on_progress=events.append,
    )
    assert runner._launch_options(level_by_id(1))["headless"] is True
    assert runner._launch_options(level_by_id(2))["headless"] is True
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("forced every rung headless" in n.get("message", "") for n in notices), notices


def test_headful_override_is_honoured_too(waf_server, monkeypatch):
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    runner = AuditRunner(_config(waf_server, levels=[1], visitor_count=1, headless=False))
    assert runner._launch_options(level_by_id(1))["headless"] is False


def test_no_override_notice_when_the_rung_agrees_with_the_setting(waf_server, monkeypatch):
    """Forcing headless for L1 agrees with L1, so there is nothing to announce."""
    monkeypatch.setattr(AuditRunner, "_has_display", staticmethod(lambda: True))
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[1], visitor_count=1, headless=True),
        on_progress=events.append,
    )
    runner._launch_options(level_by_id(1))
    notices = [e for e in events if e.get("event") == "notice"]
    assert not any("forced every rung" in n.get("message", "") for n in notices), notices


# --------------------------------------------------------------------------
# Single-level mode: one rung, a pinned count, and no false attribution
# --------------------------------------------------------------------------


def test_single_level_mode_runs_only_the_selected_rung(waf_server, monkeypatch):
    """L0 alone, with no L0..L4 preamble: one rung means one rung."""
    seen = []

    async def capture(self, level, schedule):
        seen.append(level.id)
        return LevelResult(level=level)

    monkeypatch.setattr(AuditRunner, "_run_level", capture)
    asyncio.run(
        AuditRunner(_config(waf_server, single_level_mode=True, single_level=0)).run()
    )
    assert seen == [0]


def test_single_level_mode_selects_a_browser_rung_without_a_preamble(waf_server):
    """
    A deeper rung is selected directly, with no cheaper rung planned.

    Asserted on the selection rather than by running it: CI never fetches a
    browser, so driving L5 would report a launch failure for the rung instead of
    proving which rungs were chosen.
    """
    config = _config(waf_server, single_level_mode=True, single_level=5)
    assert [level.id for level in config.selected_levels()] == [5]


def test_single_level_mode_pins_the_visitor_count(waf_server):
    """The count is 100 regardless of what the caller passed, so runs compare."""
    config = _config(waf_server, single_level_mode=True, single_level=0, visitor_count=7)
    assert config.visitor_count == SINGLE_LEVEL_VISITORS == 100
    # Asserted on the schedule the run would use: driving 100 visitors takes 100s
    # on the min-gap floor, and the count is decided before any traffic moves.
    assert build_schedule(config.schedule_config()).count == 100


def test_single_level_mode_needs_no_level_list(waf_server):
    """The rung comes from `single_level`, and `levels` is not consulted."""
    config = _config(waf_server, single_level_mode=True, single_level=2, levels=None)
    assert [level.id for level in config.selected_levels()] == [2]


def test_single_level_mode_rejects_a_competing_level_list(waf_server):
    """Two sources for the same decision is a config error, not a silent pick."""
    problems = _config(
        waf_server, single_level_mode=True, single_level=2, levels=[0, 1]
    ).validate()
    assert any("cannot also" in p for p in problems), problems


def test_single_level_mode_rejects_an_out_of_range_rung(waf_server):
    problems = _config(waf_server, single_level_mode=True, single_level=7).validate()
    assert any("single_level must be between 0 and 6" in p for p in problems), problems


def _visit(level_id, verdict, index):
    return VisitResult(
        visitor_index=index, level_id=level_id, started_at=0.0, verdict=verdict
    )


def _report(url, levels, single_level_mode=False, single_level=0, holds_at=None):
    """
    A report with a chosen shape, built without running any traffic.

    Pins the wording tests to the shape of the ladder and the verdicts rather
    than the clock: a real run costs one second per visitor on the min-gap floor,
    and these tests are about the sentence. `holds_at` picks the rung the defenses
    stop, so the attribution branch has something to attribute.
    """
    config = _config(
        url,
        single_level_mode=single_level_mode,
        single_level=single_level,
        # single_level_mode and levels are mutually exclusive by design, so a
        # single-rung config must not also carry a level list.
        levels=None if single_level_mode else levels,
    )
    results = []
    for level_id in levels:
        rung = level_by_id(level_id)
        verdict = (
            Verdict.BLOCKED if holds_at is not None and level_id >= holds_at else Verdict.ALLOWED
        )
        visits = [_visit(level_id, verdict, i) for i in range(4)]
        results.append(LevelResult(level=rung, visits=visits, scheduled=len(visits)))
    return AuditReport(config=config, levels=results)


def test_single_level_run_says_it_cannot_attribute(waf_server):
    """
    A ladder of one cannot name the control doing the work.

    The report's usual headline is "the defenses first hold at Lx", which is a
    claim about a rung *relative to the ones below it*. With none below it, the
    same sentence would be read as an attribution it cannot support.
    """
    report = _report(waf_server, [0], single_level_mode=True, single_level=0)
    findings = " ".join(build_findings(report))
    assert "Single-rung run" in findings
    assert "cannot attribute" in findings
    assert "first hold at" not in findings


def test_single_level_run_announces_the_mode(waf_server, monkeypatch):
    """
    The mode notice is emitted by a real run, without driving a real rung.

    `_run_level` is stubbed because a 100-visitor rung costs 100s on the min-gap
    floor; the notice is emitted before any traffic and is what this asserts.
    """
    events = []

    async def no_traffic(self, level, schedule):
        return LevelResult(level=level)

    monkeypatch.setattr(AuditRunner, "_run_level", no_traffic)
    runner = AuditRunner(
        _config(waf_server, single_level_mode=True, single_level=2),
        on_progress=events.append,
    )
    asyncio.run(runner.run())
    notices = [e.get("message", "") for e in events if e.get("event") == "notice"]
    assert any("Single-rung mode" in n and "L2" in n for n in notices), notices
    assert any(str(SINGLE_LEVEL_VISITORS) in n for n in notices), notices


def test_full_ladder_report_still_attributes(waf_server):
    """The single-rung wording must not leak into an ordinary ladder run."""
    findings = " ".join(build_findings(_report(waf_server, [0, 1, 2], holds_at=2)))
    assert "Single-rung run" not in findings
    assert "first hold at" in findings


def test_single_level_mode_is_serialized(waf_server):
    """A saved profile has to carry the mode, or reloading silently changes it."""
    data = _config(waf_server, single_level_mode=True, single_level=4).to_dict()
    assert data["single_level_mode"] is True
    assert data["single_level"] == 4
    assert data["visitor_count"] == SINGLE_LEVEL_VISITORS


def test_single_level_text_report_names_the_mode(waf_server):
    text = render_text(_report(waf_server, [0], single_level_mode=True, single_level=0))
    assert "SINGLE RUNG" in text
    assert "EVASION LADDER" not in text


def test_single_level_html_report_names_the_rung_it_ran(waf_server):
    """
    The summary row must show the rung that ran, not "none held".

    A rung that got through has no holding rung, so reusing that field would
    print "none held" under a "Rung tested" heading and hide the only result the
    run produced.
    """
    allowed = render_html(_report(waf_server, [0], single_level_mode=True, single_level=0))
    assert "<dt>Outcome</dt><dd>allowed</dd>" in allowed
    assert "none held" not in allowed

    stopped = render_html(
        _report(waf_server, [0], single_level_mode=True, single_level=0, holds_at=0)
    )
    assert "<dt>Outcome</dt><dd>stopped</dd>" in stopped


# --------------------------------------------------------------------------
# Honesty about the rungs whose named signal cannot be exercised
# --------------------------------------------------------------------------


def test_persistent_rung_says_the_profile_was_not_exercised(waf_server):
    """L6 is named for a durable profile the reused-browser design cannot give it."""
    events = []
    runner = AuditRunner(
        _config(waf_server, levels=[6], visitor_count=1),
        on_progress=events.append,
    )
    asyncio.run(runner.run())
    notices = [e for e in events if e.get("event") == "notice"]
    assert any("durable profile" in n.get("message", "") for n in notices), notices
