"""
Proxy rotation: parsing, selection, verification, and persistence.

The rotation guarantees are the point of this feature -- "a new IP per session"
is either true or it is a false claim in a product description -- so the tests
that matter here are the ones that pin the guarantees: that round-robin does not
repeat before the pool is exhausted, that a repeated exit IP is rejected rather
than accepted, that a gateway's failures accumulate on the gateway instead of
scattering per session, and that a restart resumes the rotation.

Network and browser access are stubbed. Nothing here launches anything.
"""

import json
import time
from pathlib import Path

import pytest

from camoufox.exceptions import InvalidProxyRotationConfig, ProxyPoolExhausted
from camoufox.proxy import (
    ProxyEndpoint,
    ProxyRotationConfig,
    ProxyRotator,
    build_rotator,
    parse_proxy_file,
    parse_proxy_string,
    redact,
)


@pytest.fixture
def pool_file(tmp_path: Path) -> Path:
    path = tmp_path / "proxies.txt"
    path.write_text("1.1.1.1:1111\n2.2.2.2:2222\n3.3.3.3:3333\n")
    return path


@pytest.fixture
def state_file(tmp_path: Path) -> Path:
    return tmp_path / "state.json"


def make_rotator(pool_file, state_file, **overrides) -> ProxyRotator:
    config = ProxyRotationConfig(
        mode="file", file=str(pool_file), verify_ip=False, **overrides
    )
    return ProxyRotator(config, state_path=state_file)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,server,username,password,port",
    [
        ("1.2.3.4:8080", "http://1.2.3.4:8080", None, None, 8080),
        ("user:pass@1.2.3.4:8080", "http://1.2.3.4:8080", "user", "pass", 8080),
        ("http://user:pass@1.2.3.4:8080", "http://1.2.3.4:8080", "user", "pass", 8080),
        ("socks5://1.2.3.4:1080", "socks5://1.2.3.4:1080", None, None, 1080),
        ("proxy.example.com:3128", "http://proxy.example.com:3128", None, None, 3128),
        # Vendor paste formats
        ("1.2.3.4:8080:user:pass", "http://1.2.3.4:8080", "user", "pass", 8080),
        ("1.2.3.4:8080@user:pass", "http://1.2.3.4:8080", "user", "pass", 8080),
        # IPv6. Only the part after ']' can be a port.
        ("[2001:db8::1]:8080", "http://[2001:db8::1]:8080", None, None, 8080),
        ("user:pass@[2001:db8::1]:8080", "http://[2001:db8::1]:8080", "user", "pass", 8080),
    ],
)
def test_parse_accepts_real_world_shapes(text, server, username, password, port):
    endpoint = parse_proxy_string(text)
    assert endpoint.server == server
    assert endpoint.username == username
    assert endpoint.password == password
    assert endpoint.port == port


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "1.2.3.4",  # no port
        "host:port",  # port never filled in from a template
        "a:b:c",  # three fields, no password
        "http://",
        "user:pass@",  # no host after '@'
        "[]:80",  # empty IPv6 host
        ":80",  # empty host
        "[2001:db8::1]",  # bracketed IPv6 with no port
        "[2001:db8::1",  # unclosed bracket
        "1.2.3.4:8080:user",  # port present, password missing
    ],
)
def test_parse_rejects_malformed_entries(text):
    with pytest.raises(InvalidProxyRotationConfig):
        parse_proxy_string(text)


def test_parse_error_message_never_contains_the_password():
    with pytest.raises(InvalidProxyRotationConfig) as excinfo:
        parse_proxy_string("user:s3cr3t@")
    assert "s3cr3t" not in str(excinfo.value)


def test_redact_hides_an_inline_password():
    assert redact("http://user:s3cr3t@host:8080") == "http://user:***@host:8080"
    assert redact("http://host:8080") == "http://host:8080"


def test_redacted_endpoint_hides_the_password():
    endpoint = parse_proxy_string("http://user:s3cr3t@host:8080")
    assert "s3cr3t" not in endpoint.redacted()
    assert endpoint.redacted() == "http://user:***@host:8080"


def test_pool_file_skips_blanks_comments_and_duplicates(tmp_path: Path):
    path = tmp_path / "pool.txt"
    path.write_text(
        "# a comment\n"
        "\n"
        "1.1.1.1:1111\n"
        "1.1.1.1:1111   # duplicate\n"
        "2.2.2.2:2222  # inline comment\n"
    )
    endpoints = parse_proxy_file(path)
    assert len(endpoints) == 2
    assert {e.host_port for e in endpoints} == {"1.1.1.1:1111", "2.2.2.2:2222"}


def test_pool_file_missing_reports_the_path(tmp_path: Path):
    with pytest.raises(InvalidProxyRotationConfig, match="Proxy file not found"):
        parse_proxy_file(tmp_path / "nope.txt")


def test_pool_file_with_no_entries_is_rejected(tmp_path: Path):
    path = tmp_path / "empty.txt"
    path.write_text("# nothing but comments\n\n")
    with pytest.raises(InvalidProxyRotationConfig, match="no usable entries"):
        parse_proxy_file(path)


def test_inline_password_is_not_part_of_the_identity_key():
    """The key is persisted, so the password must not be recoverable from it."""
    a = parse_proxy_string("http://user:first@host:8080")
    b = parse_proxy_string("http://user:second@host:8080")
    assert a.key == b.key  # same proxy, different password


def test_username_is_part_of_the_identity_key():
    """Per-session gateways differentiate exits by username; host:port alone
    would collapse distinct proxies into one health bucket."""
    a = parse_proxy_string("http://alice@host:8080")
    b = parse_proxy_string("http://bob@host:8080")
    assert a.key != b.key


def test_session_placeholder_is_substituted():
    endpoint = parse_proxy_string("http://user-session-{session}:pw@gw.io:8000")
    resolved = endpoint.with_session("abc123")
    assert resolved.username == "user-session-abc123"
    assert resolved.password == "pw"


def test_session_placeholder_in_the_host_is_substituted():
    endpoint = parse_proxy_string("http://{session}.gw.io:8000")
    assert endpoint.with_session("abc").server == "http://abc.gw.io:8000"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs,message",
    [
        (dict(mode="nope", file="x"), "Unknown proxy rotation mode"),
        (dict(mode="file"), "requires 'file'"),
        (dict(mode="gateway"), "requires 'gateway'"),
        (dict(mode="file", file="x", policy="wat"), "Unknown rotation policy"),
        (dict(mode="file", file="x", max_retries=0), "max_retries must be at least 1"),
        (dict(mode="file", file="x", failure_threshold=0), "failure_threshold must be at least 1"),
        (dict(mode="file", file="x", uniqueness_window=-1), "uniqueness_window cannot be negative"),
        (dict(mode="file", file="x", request_timeout=0), "request_timeout must be positive"),
    ],
)
def test_config_rejects_invalid_values(kwargs, message):
    with pytest.raises(InvalidProxyRotationConfig, match=message):
        ProxyRotationConfig(**kwargs)


def test_from_mapping_rejects_unknown_options():
    """A typo'd option must fail loudly; silently ignoring 'polcy' would leave
    rotation on the default and read as the feature not working."""
    with pytest.raises(InvalidProxyRotationConfig, match="Unknown proxy rotation option"):
        ProxyRotationConfig.from_mapping({"mode": "file", "file": "x", "polcy": "random"})


def test_gateway_verification_defaults_on_and_pool_defaults_off(pool_file):
    """A gateway fronts many exits behind one endpoint and must be asked; a pool
    of distinct endpoints is weaker evidence, so the network cost is opt-in."""
    gateway = ProxyRotationConfig(mode="gateway", gateway="http://gw.io:8000")
    pool = ProxyRotationConfig(mode="file", file=str(pool_file))
    assert gateway.verify_ip is True
    assert pool.verify_ip is False


def test_pool_key_is_stable_across_instances(pool_file):
    assert ProxyRotationConfig(mode="file", file=str(pool_file)).pool_key == ProxyRotationConfig(
        mode="file", file=str(pool_file)
    ).pool_key


def test_pool_key_changes_when_the_pool_changes(pool_file, tmp_path):
    other = tmp_path / "other.txt"
    other.write_text("9.9.9.9:9999\n")
    a = ProxyRotationConfig(mode="file", file=str(pool_file)).pool_key
    b = ProxyRotationConfig(mode="file", file=str(other)).pool_key
    assert a != b


def test_build_rotator_normalises_accepted_forms(pool_file, state_file):
    assert build_rotator(None) is None
    from_config = build_rotator(
        ProxyRotationConfig(mode="file", file=str(pool_file), verify_ip=False),
        state_path=state_file,
    )
    from_mapping = build_rotator(
        {"mode": "file", "file": str(pool_file), "verify_ip": False}, state_path=state_file
    )
    assert isinstance(from_config, ProxyRotator)
    assert isinstance(from_mapping, ProxyRotator)
    assert isinstance(build_rotator(from_config), ProxyRotator)


def test_build_rotator_rejects_a_bad_type():
    with pytest.raises(InvalidProxyRotationConfig, match="must be a ProxyRotationConfig"):
        build_rotator(42)


# ---------------------------------------------------------------------------
# Rotation guarantees
# ---------------------------------------------------------------------------


def test_round_robin_covers_the_pool_before_repeating(pool_file, state_file):
    """The guarantee that distinguishes round-robin from random: random returns
    the same proxy twice in a row, which is the exact failure this prevents."""
    rotator = make_rotator(pool_file, state_file, policy="round_robin")
    first_pass = [rotator.acquire_session().endpoint.host_port for _ in range(3)]
    assert len(set(first_pass)) == 3
    second_pass = [rotator.acquire_session().endpoint.host_port for _ in range(3)]
    assert second_pass == first_pass  # cycles in order


def test_cursor_persists_across_restarts(pool_file, state_file):
    """Without persistence every restart replays the head of the pool, so a
    long-running scraper's 'rotation' degrades to one or two proxies."""
    first = make_rotator(pool_file, state_file)
    used = {first.acquire_session().endpoint.host_port for _ in range(2)}

    resumed = make_rotator(pool_file, state_file)
    next_choice = resumed.acquire_session().endpoint.host_port
    assert next_choice not in used


def test_least_used_spreads_load(pool_file, state_file):
    rotator = make_rotator(pool_file, state_file, policy="least_used")
    for _ in range(6):
        rotator.acquire_session()
    uses = sorted(entry["uses"] for entry in rotator.stats()["endpoints"])
    assert max(uses) - min(uses) <= 1


def test_blacklisted_proxies_are_skipped(pool_file, state_file):
    rotator = make_rotator(pool_file, state_file, blacklist=["1.1.1.1"])
    chosen = {rotator.acquire_session().endpoint.host_port for _ in range(4)}
    assert "1.1.1.1:1111" not in chosen


def test_exhausted_pool_raises_rather_than_connecting_directly(pool_file, state_file):
    """Falling back to the host's own IP while the browser advertises a spoofed
    location is a detection vector, not a graceful degradation."""
    rotator = make_rotator(pool_file, state_file, blacklist=["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    with pytest.raises(ProxyPoolExhausted):
        rotator.acquire_session()


def test_direct_fallback_is_opt_in(pool_file, state_file):
    rotator = make_rotator(
        pool_file, state_file, blacklist=["1.1.1.1", "2.2.2.2", "3.3.3.3"], allow_direct_fallback=True
    )
    assert rotator.acquire_session() is None


def test_all_cooled_proxies_are_recycled_not_deadlocked(pool_file, state_file):
    """Refusing to launch while every cooldown ticks down would stall a long run
    indefinitely; retrying the least-bad candidate is the lesser evil."""
    rotator = make_rotator(pool_file, state_file)
    for endpoint in rotator.provider.candidates():
        rotator._state.health(rotator._health_key(endpoint)).cooldown_until = time.time() + 999
    assert rotator.acquire_session() is not None


def test_rotator_is_thread_safe(pool_file, state_file):
    """Contexts are routinely created from several threads; an unsynchronised
    cursor is how two sessions end up sharing a proxy.

    Asserted on `sequence`, not on the order the threads returned: concurrent
    callers finish in arbitrary order, so the returned list cannot be inspected
    positionally.
    """
    from concurrent.futures import ThreadPoolExecutor

    rotator = make_rotator(pool_file, state_file)
    with ThreadPoolExecutor(max_workers=8) as pool:
        sessions = list(pool.map(lambda _: rotator.acquire_session(), range(30)))

    by_assignment = sorted(sessions, key=lambda session: session.sequence)
    assert [session.sequence for session in by_assignment] == list(range(1, 31))
    keys = [session.endpoint.host_port for session in by_assignment]
    for start in range(0, 30, 3):
        assert len(set(keys[start : start + 3])) == 3, f"repeat in group at {start}"


def test_concurrent_sessions_get_distinct_ids(pool_file, state_file):
    from concurrent.futures import ThreadPoolExecutor

    rotator = make_rotator(pool_file, state_file)
    with ThreadPoolExecutor(max_workers=8) as pool:
        sessions = list(pool.map(lambda _: rotator.acquire_session(), range(50)))
    assert len({session.session_id for session in sessions}) == 50


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def test_repeated_exit_ip_is_rejected(pool_file, state_file, monkeypatch):
    """A gateway under load hands back a sticky IP, and two pool entries can
    exit from the same address; neither is visible without asking."""
    config = ProxyRotationConfig(
        mode="file", file=str(pool_file), verify_ip=True, max_retries=1
    )
    rotator = ProxyRotator(config, state_path=state_file)
    monkeypatch.setattr(rotator, "_probe_exit_ip", lambda endpoint: "9.9.9.9")

    first = rotator.acquire_session()
    assert first.exit_ip == "9.9.9.9"
    # Next session sees the same exit IP and, with one retry, must give up.
    with pytest.raises(ProxyPoolExhausted, match="repeated exit IP"):
        rotator.acquire_session()


def test_distinct_exit_ips_are_accepted(pool_file, state_file, monkeypatch):
    config = ProxyRotationConfig(mode="file", file=str(pool_file), verify_ip=True)
    rotator = ProxyRotator(config, state_path=state_file)
    counter = {"n": 0}

    def fake_probe(endpoint):
        counter["n"] += 1
        return f"9.9.9.{counter['n']}"

    monkeypatch.setattr(rotator, "_probe_exit_ip", fake_probe)
    ips = {rotator.acquire_session().exit_ip for _ in range(3)}
    assert len(ips) == 3


def test_unreachable_proxy_is_rejected(pool_file, state_file, monkeypatch):
    config = ProxyRotationConfig(mode="file", file=str(pool_file), verify_ip=True, max_retries=1)
    rotator = ProxyRotator(config, state_path=state_file)
    monkeypatch.setattr(rotator, "_probe_exit_ip", lambda endpoint: None)
    with pytest.raises(ProxyPoolExhausted, match="unreachable"):
        rotator.acquire_session()


def test_uniqueness_window_forgets_old_ips(pool_file, state_file, monkeypatch):
    """The window is bounded so a long run does not accumulate every IP it has
    ever used and slowly starve a small pool."""
    config = ProxyRotationConfig(
        mode="file", file=str(pool_file), verify_ip=True, uniqueness_window=2, max_retries=1
    )
    rotator = ProxyRotator(config, state_path=state_file)
    monkeypatch.setattr(rotator, "_probe_exit_ip", lambda endpoint: "8.8.8.8")

    rotator.acquire_session()  # remembers 8.8.8.8
    for _ in range(2):  # window slides past it
        rotator._remember_ip("7.7.7.7")
    assert rotator.acquire_session().exit_ip == "8.8.8.8"


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


def make_gateway(state_file, gateway="http://u-session-{session}:pw@gw.io:8000") -> ProxyRotator:
    rotator = ProxyRotator(
        ProxyRotationConfig(mode="gateway", gateway=gateway, verify_ip=False),
        state_path=state_file,
    )
    # The sandbox has no reachable gateway; substitution is what is under test.
    rotator._endpoint_reachable = lambda endpoint, timeout=5.0: True
    return rotator


def test_gateway_gets_a_distinct_session_token_per_session(state_file):
    rotator = make_gateway(state_file)
    tokens = {rotator.acquire_session().endpoint.username for _ in range(5)}
    assert len(tokens) == 5


def test_gateway_failures_accumulate_on_the_gateway(state_file):
    """Substituting the session token changes the endpoint key every call. If
    health were keyed on it, one gateway's failures would scatter across
    unbounded entries and its cooldown would never trip."""
    rotator = make_gateway(state_file)
    session = rotator.acquire_session()
    rotator.report_failure(session, "TimeoutError")
    rotator.report_failure(session, "TimeoutError")

    entries = rotator.stats()["endpoints"]
    assert len(entries) == 1  # one gateway, not one entry per session
    assert entries[0]["consecutive_failures"] == 2


def test_gateway_state_file_holds_no_credentials(state_file):
    rotator = make_gateway(state_file)
    for _ in range(3):
        rotator.acquire_session()
    content = state_file.read_text()
    assert "pw" not in content.replace('"pools"', "").replace('"successes"', "")
    assert "u-session-" not in content
    # Only the bare endpoint is tracked.
    stored = json.loads(content)["pools"][rotator.config.pool_key]["endpoints"]
    assert list(stored) == ["http://gw.io:8000"]


def test_gateway_without_a_session_token_warns(state_file, capsys):
    rotator = ProxyRotator(
        ProxyRotationConfig(mode="gateway", gateway="http://gw.io:8000", verify_ip=True),
        state_path=state_file,
    )
    assert rotator.config.verify_ip is True


def test_gateway_rotate_url_is_called(state_file, monkeypatch):
    calls = []

    rotator = ProxyRotator(
        ProxyRotationConfig(
            mode="gateway",
            gateway="http://gw.io:8000",
            rotate_url="http://gw.io/rotate?session={session}",
            verify_ip=False,
        ),
        state_path=state_file,
    )
    rotator._endpoint_reachable = lambda endpoint, timeout=5.0: True
    monkeypatch.setattr(rotator.provider, "request_rotation", lambda sid: calls.append(sid))

    rotator.acquire_session()
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Health feedback
# ---------------------------------------------------------------------------


def test_failures_trigger_a_cooldown_at_the_threshold(pool_file, state_file):
    rotator = make_rotator(pool_file, state_file, failure_threshold=2, cooldown_seconds=60)
    session = rotator.acquire_session()
    rotator.report_failure(session, "TimeoutError")
    assert not rotator.stats()["endpoints"][0]["cooling_down"]
    rotator.report_failure(session, "TimeoutError")
    assert rotator.stats()["endpoints"][0]["cooling_down"]


def test_a_success_resets_the_failure_streak(pool_file, state_file):
    rotator = make_rotator(pool_file, state_file, failure_threshold=2)
    session = rotator.acquire_session()
    rotator.report_failure(session)
    rotator.report_success(session)
    entry = rotator.stats()["endpoints"][0]
    assert entry["consecutive_failures"] == 0
    assert entry["successes"] == 1


def test_cooldown_survives_a_restart(pool_file, state_file):
    rotator = make_rotator(pool_file, state_file, failure_threshold=1, cooldown_seconds=600)
    session = rotator.acquire_session()
    rotator.report_failure(session, "TimeoutError")

    resumed = make_rotator(pool_file, state_file, failure_threshold=1, cooldown_seconds=600)
    cooled = [entry for entry in resumed.stats()["endpoints"] if entry["cooling_down"]]
    assert len(cooled) == 1


def test_last_session_is_readable(pool_file, state_file):
    """Callers need the exit IP of the browser they just launched."""
    rotator = make_rotator(pool_file, state_file)
    assert rotator.last_session is None
    session = rotator.acquire_session()
    assert rotator.last_session is session


# ---------------------------------------------------------------------------
# Persistence robustness
# ---------------------------------------------------------------------------


def test_corrupt_state_file_is_survived(pool_file, state_file):
    state_file.write_text("{not json at all")
    rotator = make_rotator(pool_file, state_file)
    assert rotator.acquire_session() is not None


def test_state_file_write_is_atomic_and_leaves_no_temp(pool_file, state_file):
    rotator = make_rotator(pool_file, state_file)
    rotator.acquire_session()
    assert state_file.exists()
    assert not state_file.with_suffix(".tmp").exists()
    json.loads(state_file.read_text())  # parses


def test_unwritable_state_directory_does_not_break_rotation(pool_file, tmp_path):
    """Rotation must still work without persistence; it just loses its place."""
    rotator = make_rotator(pool_file, tmp_path / "no" / "such" / "dir" / "s.json")
    assert rotator.acquire_session() is not None


def test_multiple_pools_coexist_in_one_state_file(pool_file, tmp_path):
    other = tmp_path / "other.txt"
    other.write_text("5.5.5.5:5555\n6.6.6.6:6666\n")
    state = tmp_path / "shared.json"

    a = ProxyRotator(ProxyRotationConfig(mode="file", file=str(pool_file)), state_path=state)
    b = ProxyRotator(ProxyRotationConfig(mode="file", file=str(other)), state_path=state)
    a.acquire_session()
    b.acquire_session()

    raw = json.loads(state.read_text())
    assert len(raw["pools"]) == 2  # separate cursor per pool


# ---------------------------------------------------------------------------
# Pool changes on disk
# ---------------------------------------------------------------------------


def test_pool_is_reloaded_when_the_file_changes(pool_file, state_file):
    """A scraper that refreshes its proxy list should not need a restart."""
    rotator = make_rotator(pool_file, state_file)
    assert len(rotator.provider.candidates()) == 3
    pool_file.write_text("1.1.1.1:1111\n2.2.2.2:2222\n3.3.3.3:3333\n4.4.4.4:4444\n")
    assert len(rotator.provider.candidates()) == 4


def test_reload_can_be_disabled(pool_file, state_file):
    rotator = make_rotator(pool_file, state_file, reload_pool=False)
    pool_file.write_text("9.9.9.9:9999\n")
    assert len(rotator.provider.candidates()) == 3


def test_reload_notices_a_rewrite_in_the_same_mtime_tick(pool_file, state_file):
    """A same-tick rewrite is indistinguishable by mtime on common filesystems,
    and that is exactly how a pool file is refreshed."""
    rotator = make_rotator(pool_file, state_file)
    assert len(rotator.provider.candidates()) == 3
    pool_file.write_text("5.5.5.5:5555\n6.6.6.6:6666\n")
    assert len(rotator.provider.candidates()) == 2


# ---------------------------------------------------------------------------
# launch_options integration
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_launch(monkeypatch):
    """Neutralise everything in launch_options that needs a binary or network."""
    from camoufox import utils

    monkeypatch.setattr(utils, "generate_fingerprint", lambda **k: object())
    monkeypatch.setattr(utils, "from_browserforge", lambda *a, **k: {})
    monkeypatch.setattr(utils, "get_screen_cons", lambda *a, **k: {})
    monkeypatch.setattr(utils, "_generate_random_font_subset", lambda *a, **k: [])
    monkeypatch.setattr(utils, "_generate_random_voice_subset", lambda *a, **k: [])
    monkeypatch.setattr(utils, "validate_config", lambda *a, **k: None)
    monkeypatch.setattr(utils, "ensure_browser_profile_dir", lambda *a, **k: None)
    monkeypatch.setattr(utils, "add_default_addons", lambda *a, **k: None)
    monkeypatch.setattr(utils, "fix_navigator_arch", lambda *a, **k: None)
    monkeypatch.setattr(utils, "fix_screen_no_taskbar", lambda *a, **k: None)
    monkeypatch.setattr(utils, "clamp_window_dimensions", lambda *a, **k: None)
    monkeypatch.setattr(utils, "clamp_window_position", lambda *a, **k: None)
    monkeypatch.setattr(utils, "clamp_screen_to_display", lambda *a, **k: None)
    monkeypatch.setattr(utils, "raise_screen_to_modern_floor", lambda *a, **k: None)
    monkeypatch.setattr(utils, "resolve_verstr", lambda *a, **k: "152.0")
    monkeypatch.setattr(utils, "installed_verstr", lambda *a, **k: "152.0")
    monkeypatch.setattr(utils, "launch_path", lambda *a, **k: "/camoufox")
    monkeypatch.setattr(utils, "get_env_vars", lambda config, os_, **k: {})
    monkeypatch.setattr(utils.LeakWarning, "warn", lambda *a, **k: None)
    return utils


class _FakeFirefox:
    """Just enough of playwright.firefox to stand in for a launch."""

    def __init__(self, launch):
        self._launch = launch

    def launch(self, **kwargs):
        return self._launch(**kwargs)


class _FakePlaywright:
    def __init__(self, launch):
        self.firefox = _FakeFirefox(launch)


def test_launch_success_is_reported_to_the_pool(stub_launch, pool_file, state_file, monkeypatch):
    """A proxy that answers is not necessarily one that can carry a browser."""
    from camoufox import sync_api

    monkeypatch.setattr(sync_api, "attach_no_viewport_default", lambda browser: None)
    rotator = make_rotator(pool_file, state_file)

    sync_api.NewBrowser(
        _FakePlaywright(lambda **kwargs: object()),
        proxy_rotator=rotator,
        i_know_what_im_doing=True,
    )

    assert rotator.stats()["endpoints"][0]["successes"] == 1


def test_launch_failure_is_reported_to_the_pool(stub_launch, pool_file, state_file, monkeypatch):
    """The browser failing to come up on a proxy is a proxy failure, and only
    the launcher is in a position to notice it."""
    from camoufox import sync_api

    monkeypatch.setattr(sync_api, "attach_no_viewport_default", lambda browser: None)
    rotator = make_rotator(pool_file, state_file, failure_threshold=1, cooldown_seconds=60)

    def boom(**kwargs):
        raise RuntimeError("launch failed")

    with pytest.raises(RuntimeError, match="launch failed"):
        sync_api.NewBrowser(
            _FakePlaywright(boom), proxy_rotator=rotator, i_know_what_im_doing=True
        )

    endpoint = rotator.stats()["endpoints"][0]
    assert endpoint["failures"] == 1
    assert endpoint["cooling_down"] is True


def test_async_launch_failure_is_reported_to_the_pool(
    stub_launch, pool_file, state_file, monkeypatch
):
    """The async launcher must record outcomes too, and must not block the loop."""
    import asyncio

    from camoufox import async_api

    monkeypatch.setattr(
        async_api,
        "launch_options",
        lambda **kwargs: {"headless": True, "proxy": kwargs["proxy_session"].playwright}
        if kwargs.get("proxy_session")
        else {"headless": True},
    )
    monkeypatch.setattr(async_api, "attach_no_viewport_default", lambda browser: None)
    monkeypatch.setattr(async_api, "spoofs_window_dimensions", lambda options: False)

    rotator = make_rotator(pool_file, state_file, failure_threshold=1, cooldown_seconds=60)

    async def boom(**kwargs):
        raise RuntimeError("async launch failed")

    class _AsyncFirefox:
        async def launch(self, **kwargs):
            return await boom(**kwargs)

    class _AsyncPlaywright:
        firefox = _AsyncFirefox()

    async def run():
        with pytest.raises(RuntimeError, match="async launch failed"):
            await async_api.AsyncNewBrowser(
                _AsyncPlaywright(), proxy_rotator=rotator, i_know_what_im_doing=True
            )

    asyncio.run(run())

    endpoint = rotator.stats()["endpoints"][0]
    assert endpoint["failures"] == 1
    assert endpoint["cooling_down"] is True


def test_launch_options_emits_the_rotated_proxy(stub_launch, pool_file, state_file):
    utils = stub_launch
    rotator = make_rotator(pool_file, state_file)
    options = utils.launch_options(
        proxy_rotator=rotator,
        block_webgl=True,
        i_know_what_im_doing=True,
        geoip=False,
    )
    assert options["proxy"]["server"] == "http://1.1.1.1:1111"


def test_launch_options_rotates_between_calls(stub_launch, pool_file, state_file):
    utils = stub_launch
    rotator = make_rotator(pool_file, state_file)
    first = utils.launch_options(
        proxy_rotator=rotator, block_webgl=True, i_know_what_im_doing=True, geoip=False
    )
    second = utils.launch_options(
        proxy_rotator=rotator, block_webgl=True, i_know_what_im_doing=True, geoip=False
    )
    assert first["proxy"]["server"] != second["proxy"]["server"]


def test_launch_options_leaks_no_private_keys(stub_launch, pool_file, state_file):
    """The returned mapping goes straight to Playwright, which rejects unknown
    keyword arguments."""
    utils = stub_launch
    options = utils.launch_options(
        proxy_rotator=make_rotator(pool_file, state_file),
        block_webgl=True,
        i_know_what_im_doing=True,
        geoip=False,
    )
    assert not [key for key in options if key.startswith("_")]


def test_launch_options_honours_an_externally_acquired_session(stub_launch, pool_file, state_file):
    """This is the path the launch wrappers use, so they can report the launch
    outcome back to the pool."""
    utils = stub_launch
    rotator = make_rotator(pool_file, state_file)
    session = rotator.acquire_session()
    options = utils.launch_options(
        proxy_session=session, block_webgl=True, i_know_what_im_doing=True, geoip=False
    )
    assert options["proxy"]["server"] == session.endpoint.server
    assert rotator.stats()["endpoints"][0]["uses"] == 1  # no second acquisition


def test_verified_exit_ip_is_used_for_geoip_without_a_second_lookup(
    stub_launch, pool_file, state_file, monkeypatch
):
    """Re-deriving the exit IP could race a rotating gateway onto a different
    exit than the browser will actually use."""
    utils = stub_launch
    config = ProxyRotationConfig(mode="file", file=str(pool_file), verify_ip=True)
    rotator = ProxyRotator(config, state_path=state_file)
    monkeypatch.setattr(rotator, "_probe_exit_ip", lambda endpoint: "203.0.113.9")

    called = {"geo": 0}
    monkeypatch.setattr(utils, "public_ip", lambda *a, **k: called.__setitem__("geo", called["geo"] + 1))
    monkeypatch.setattr(utils, "geoip_allowed", lambda: None)
    monkeypatch.setattr(utils, "get_geolocation", lambda ip, **k: _Geolocation())

    options = utils.launch_options(
        proxy_rotator=rotator,
        geoip=True,
        block_webrtc=False,
        block_webgl=True,
        i_know_what_im_doing=True,
    )
    assert called["geo"] == 0  # the verified IP was reused
    assert options["proxy"]["server"] == "http://1.1.1.1:1111"


class _Geolocation:
    def as_config(self) -> dict:
        return {}


def test_proxy_without_geoip_still_warns(stub_launch, pool_file, state_file, monkeypatch):
    """A rotating proxy makes the missing-geolocation warning *more* important,
    not less: the fingerprint must describe the exit IP, not the host."""
    utils = stub_launch
    warned = []
    monkeypatch.setattr(utils.LeakWarning, "warn", lambda key, *a: warned.append(key))
    utils.launch_options(
        proxy_rotator=make_rotator(pool_file, state_file),
        block_webgl=True,
        i_know_what_im_doing=True,
        geoip=False,
    )
    assert "proxy_without_geoip" in warned


@pytest.fixture
def stub_context_geo(monkeypatch):
    """Stop NewContext's geo lookup from dialling real proxies."""
    from camoufox import sync_api

    monkeypatch.setattr(
        sync_api, "_resolve_proxy_geo", lambda proxy: {"ip": "203.0.113.9", "timezone": None}
    )


def test_verified_ip_still_resolves_timezone_for_a_context(
    pool_file, state_file, monkeypatch
):
    """The exit IP is known, but the timezone is not, and a context that does not
    set it inherits the host's. Reusing the IP must not skip that lookup."""
    from camoufox import sync_api

    config = ProxyRotationConfig(mode="file", file=str(pool_file), verify_ip=True)
    rotator = ProxyRotator(config, state_path=state_file)
    monkeypatch.setattr(rotator, "_probe_exit_ip", lambda endpoint: "203.0.113.9")

    monkeypatch.setattr(
        sync_api,
        "_resolve_proxy_geo",
        lambda proxy: {"ip": "203.0.113.9", "timezone": "Europe/Berlin"},
    )
    fingerprint_args = {}

    def fake_generate(**kwargs):
        fingerprint_args.update(kwargs)
        return {"context_options": {}, "init_script": ""}

    monkeypatch.setattr(sync_api, "generate_context_fingerprint", fake_generate)

    context = sync_api.NewContext(_FakeBrowser(), proxy_rotator=rotator)

    assert context.options["proxy"]["server"] == "http://1.1.1.1:1111"
    assert context.options["timezone_id"] == "Europe/Berlin"
    # The verified IP feeds the fingerprint: WebRTC must not advertise the host.
    assert fingerprint_args["webrtc_ip"] == "203.0.113.9"


def test_context_rotator_rejects_a_fixed_proxy(pool_file, state_file, stub_context_geo):
    from camoufox import sync_api

    rotator = make_rotator(pool_file, state_file)
    with pytest.raises(ValueError, match="both 'proxy' and 'proxy_rotator'"):
        sync_api.NewContext(
            _FakeBrowser(),
            proxy={"server": "http://9.9.9.9:9999"},
            proxy_rotator=rotator,
        )


def test_context_assigns_a_new_proxy_each_time(pool_file, state_file, stub_context_geo):
    """The per-visit guarantee: reusing one browser must still rotate."""
    from camoufox import sync_api

    rotator = make_rotator(pool_file, state_file)
    browser = _FakeBrowser()
    servers = [
        sync_api.NewContext(browser, proxy_rotator=rotator).options["proxy"]["server"]
        for _ in range(3)
    ]
    assert len(set(servers)) == 3


class _FakeContext:
    def __init__(self, options):
        self.options = options
        self.init_scripts = []

    def add_init_script(self, script):
        self.init_scripts.append(script)


class _FakeBrowser:
    def __init__(self):
        self.calls = []

    def new_context(self, **options):
        self.calls.append(options)
        return _FakeContext(options)
