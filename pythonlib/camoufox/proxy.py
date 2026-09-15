"""
Per-session proxy rotation for Camoufox.

Every session -- a launched browser, or a context created from one -- should
leave through a *different* exit IP, and the fingerprint Camoufox generates
should describe that IP rather than the host's. This module owns the "different
IP" half; `utils.launch_options()` already owns the "fingerprint describes that
IP" half, and consumes the exit IP produced here.

Two strategies, selected by `ProxyRotationConfig.mode`:

**Gateway mode** (``mode="gateway"``)
    One endpoint speaks for many exit IPs -- a rotating-proxy gateway. Session
    uniqueness is requested from the gateway itself, in whichever dialect it
    offers. The common residential dialect is a session token embedded in the
    username or hostname (``user-session-<id>:pass@gateway:8000``), which the
    ``{session}`` placeholder generates for you. A gateway that exposes an HTTP
    rotate hook can be driven with ``rotate_url`` instead, or as well.

**File pool mode** (``mode="file"``)
    A text file of proxies, one per line. Each session is handed the next one
    under the configured policy. Round-robin is the default because it is the
    only policy that *guarantees* no endpoint repeats before the pool is
    exhausted -- "random" can and does hand back the same proxy twice in a row,
    which is the exact failure this module exists to prevent.

Both modes share the machinery below:

* **Uniqueness verification** -- fetch the exit IP through the chosen proxy and
  reject it if it matches a recent session. A rotating gateway under load
  cheerfully returns a sticky IP, and a pool can contain two proxies that exit
  from the same address; neither is visible without asking.
* **Health tracking and cooldown** -- a proxy that fails to launch is retried
  past a threshold and then parked for a cooldown, so one dead proxy cannot
  stall an automation run.
* **Persistence** -- the rotation cursor and health counters live in a state
  file, so a process restart resumes the rotation instead of replaying the head
  of the pool. Without this, every restart of a long-running scraper reuses the
  same handful of proxies and the "rotation" is cosmetic.
* **No silent direct fallback** -- when a pool is configured and every proxy is
  unusable, the launch fails. Quietly falling back to the host's own IP while
  the browser advertises a spoofed timezone and locale is a worse outcome than
  not launching at all; `allow_direct_fallback` opts into it explicitly.

Credentials never enter the state file, log lines, or exception messages. State
is keyed by a hash of the credential material; rendering is via `redacted()`.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .exceptions import (
    InvalidProxyRotationConfig,
    ProxyPoolExhausted,
    ProxyRotationError,
)
from .pkgman import INSTALL_DIR, rprint

__all__ = [
    "ProxyEndpoint",
    "ProxySession",
    "ProxyRotationConfig",
    "ProxyRotator",
    "build_rotator",
    "parse_proxy_string",
    "parse_proxy_file",
    "redact",
]

DEFAULT_STATE_FILE = INSTALL_DIR / "proxy_state.json"
DEFAULT_COOLDOWN_S = 300.0
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_UNIQUENESS_WINDOW = 32
DEFAULT_MAX_RETRIES = 4
GATEWAY_SESSION_PLACEHOLDER = "{session}"

_POLICIES = ("round_robin", "random", "least_used")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProxyEndpoint:
    """
    A single proxy, in the shape Playwright and requests both accept.

    `server` always carries an explicit scheme so callers never have to guess;
    `username`/`password` are kept separate from it because Playwright takes
    credentials as distinct fields rather than inline in the URL.
    """

    server: str
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def scheme(self) -> str:
        return self.server.split("://", 1)[0]

    @property
    def host_port(self) -> str:
        return self.server.split("://", 1)[-1]

    @property
    def host(self) -> str:
        host_port = self.host_port
        if host_port.startswith("["):
            return host_port.split("]")[0] + "]"
        return host_port.rsplit(":", 1)[0] if ":" in host_port else host_port

    @property
    def hostname(self) -> str:
        """Host with any IPv6 brackets removed, for socket/display use."""
        return self.host.strip("[]")

    @property
    def port(self) -> Optional[int]:
        host_port = self.host_port
        if host_port.startswith("["):
            # Inside brackets the colons belong to the address, so only the part
            # after ']' can be a port. `[::1]:8080` has one; `[::1]` and
            # `[::1:8080]` do not.
            close = host_port.rfind("]")
            if close == -1:
                return None
            host_port = host_port[close + 1 :]
        if ":" not in host_port:
            return None
        try:
            return int(host_port.rsplit(":", 1)[-1])
        except ValueError:
            return None

    @property
    def key(self) -> str:
        """
        Stable identity for state tracking, safe to persist.

        The username is folded in as a hash because per-session residential
        gateways differentiate exits by username, so `host:port` alone would
        collapse distinct proxies into one bucket. The password is never
        included, in any form.
        """
        if self.username:
            digest = hashlib.sha256(self.username.encode("utf-8")).hexdigest()[:10]
            return f"{self.server}#u{digest}"
        return self.server

    def as_playwright(self) -> Dict[str, str]:
        """Render as a Playwright `proxy=` mapping."""
        options: Dict[str, str] = {"server": self.server}
        if self.username:
            options["username"] = self.username
        if self.password:
            options["password"] = self.password
        return options

    def as_url(self) -> str:
        """Render as a single URL with inline credentials, for requests/urllib."""
        if not self.username:
            return self.server
        credentials = self.username
        if self.password:
            credentials += f":{self.password}"
        return f"{self.scheme}://{credentials}@{self.host_port}"

    def with_session(self, session_id: str) -> "ProxyEndpoint":
        """
        Substitute `{session}` in whichever fields carry it.

        Gateways express per-session stickiness in the username, the password,
        or occasionally the hostname, so all three are candidates.
        """
        def sub(value: Optional[str]) -> Optional[str]:
            if value and GATEWAY_SESSION_PLACEHOLDER in value:
                return value.replace(GATEWAY_SESSION_PLACEHOLDER, session_id)
            return value

        return ProxyEndpoint(
            server=sub(self.server) or self.server,
            username=sub(self.username),
            password=sub(self.password),
        )

    def redacted(self) -> str:
        """Human-readable form with the password withheld."""
        if not self.username:
            return self.server
        return f"{self.scheme}://{self.username}:***@{self.host_port}"


def redact(value: str) -> str:
    """
    Strip any inline password from a proxy URL for display.
    """
    match = re.match(r"^(?P<scheme>\w+://)?(?P<user>[^:/@]+):(?P<pw>[^@]*)@(?P<rest>.*)$", value)
    if not match:
        return value
    scheme = match.group("scheme") or ""
    return f"{scheme}{match.group('user')}:***@{match.group('rest')}"


def parse_proxy_string(raw: str) -> ProxyEndpoint:
    """
    Parse one proxy line.

    Accepts the shapes resellers actually hand out::

        scheme://user:pass@host:port
        scheme://host:port
        user:pass@host:port
        host:port
        host:port:user:pass          (the "vendor CSV paste" form)
        host:port@user:pass
        [::1]:8080

    Raises `InvalidProxyRotationConfig` for anything else, naming the offending
    line (credentials redacted).
    """
    text = raw.strip()
    if not text:
        raise InvalidProxyRotationConfig("Empty proxy entry")

    scheme = "http"
    remainder = text
    if "://" in text:
        scheme, remainder = text.split("://", 1)
        if not scheme:
            raise InvalidProxyRotationConfig(f"Proxy entry has an empty scheme: {redact(text)}")

    # Bracketed IPv6 host: isolate it so its colons are not mistaken for separators.
    if remainder.startswith("["):
        close = remainder.find("]")
        if close == -1:
            raise InvalidProxyRotationConfig(f"Unclosed IPv6 bracket: {redact(text)}")
        ipv6_prefix, remainder = remainder[: close + 1], remainder[close + 1 :]
        remainder = remainder.lstrip(":")
        host_part, _, after = remainder.partition(":")
        host_port = f"{ipv6_prefix}:{host_part}" if host_part else ipv6_prefix
        return _validated(
            _with_trailing_credentials(ProxyEndpoint(f"{scheme}://{host_port}"), after, text), text
        )

    if "@" in remainder:
        left, right = remainder.rsplit("@", 1)
        if not right:
            raise InvalidProxyRotationConfig(f"Proxy entry has no credentials after '@': {redact(text)}")

        # `host:port@user:pass` is a real vendor format and collides with the
        # conventional `user:pass@host:port`. They are distinguishable: only the
        # first has a port on the left and a non-numeric host on the right.
        left_port = left.rsplit(":", 1)[-1]
        right_host_looks_numeric = _is_numeric_host(right.rsplit(":", 1)[0] if ":" in right else right)
        if left_port.isdigit() and not right_host_looks_numeric:
            user, _, password = right.partition(":")
            return _validated(
                ProxyEndpoint(
                    server=_normalize_server(scheme, left, text),
                    username=user or None,
                    password=password or None,
                ),
                text,
            )

        credentials, host_port = left, right
        if ":" in credentials:
            user, password = credentials.split(":", 1)
        else:
            user, password = credentials, None
        return _validated(
            ProxyEndpoint(
                server=_normalize_server(scheme, host_port, text),
                username=user or None,
                password=password or None,
            ),
            text,
        )

    parts = remainder.split(":")
    if len(parts) == 2:
        host, port = parts
        if not host:
            raise InvalidProxyRotationConfig(f"Proxy entry is missing a host: {redact(text)}")
        return _validated(ProxyEndpoint(server=_normalize_server(scheme, remainder, text)), text)
    if len(parts) == 3:
        # host:port:user -- a password cannot be inferred.
        raise InvalidProxyRotationConfig(
            f"Proxy entry has three fields but no password: {redact(text)}. "
            "Use host:port:user:pass, or user:pass@host:port."
        )
    if len(parts) == 4:
        host, port, user, password = parts
        return _validated(
            ProxyEndpoint(
                server=_normalize_server(scheme, f"{host}:{port}", text),
                username=user or None,
                password=password or None,
            ),
            text,
        )

    raise InvalidProxyRotationConfig(
        f"Unrecognised proxy entry: {redact(text)}. Expected host:port, "
        "user:pass@host:port, host:port:user:pass, or a URL."
    )


def _validated(endpoint: ProxyEndpoint, source: str) -> ProxyEndpoint:
    """
    Last check before an endpoint leaves the parser.

    A missing or non-numeric port is the failure a hand-edited proxy list
    actually produces (`host:port` from a template that was never filled in),
    and it fails silently at launch time if it gets through, so it is rejected
    here where the offending line can still be named.
    """
    if not endpoint.hostname:
        raise InvalidProxyRotationConfig(f"Proxy entry has no host: {redact(source)}")
    if endpoint.port is None:
        raise InvalidProxyRotationConfig(
            f"Proxy entry has no numeric port: {redact(source)}. "
            "Use host:port, user:pass@host:port, host:port:user:pass, or a URL."
        )
    return endpoint


def _is_numeric_host(value: str) -> bool:
    """
    True when a string looks like an IP or a bracketed IPv6 address.

    Used to tell `host:port@user:pass` from `user:pass@host:port`, which differ
    only in which side carries the port.
    """
    candidate = value.strip("[]")
    if not candidate:
        return False
    try:
        import ipaddress

        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _normalize_server(scheme: str, host_port: str, source: str) -> str:
    if not host_port:
        raise InvalidProxyRotationConfig(f"Proxy entry has no host: {redact(source)}")
    if "://" in host_port:
        return host_port
    return f"{scheme}://{host_port}"


def _with_trailing_credentials(endpoint: ProxyEndpoint, after: str, source: str) -> ProxyEndpoint:
    """Attach credentials that followed a bracketed IPv6 host (`[::1]:8080:u:p`)."""
    if not after:
        return endpoint
    parts = after.split(":")
    if len(parts) == 1:
        return ProxyEndpoint(server=endpoint.server, username=parts[0] or None)
    if len(parts) == 2:
        return ProxyEndpoint(server=endpoint.server, username=parts[0] or None, password=parts[1] or None)
    raise InvalidProxyRotationConfig(f"Unrecognised proxy entry: {redact(source)}")


def parse_proxy_file(path: os.PathLike | str) -> List[ProxyEndpoint]:
    """
    Read a text file of proxies, one per line.

    Blank lines and `#` comments are skipped, trailing inline `#` comments are
    dropped, and duplicates are collapsed so a pool with a repeated line does
    not consume two rotation slots.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise InvalidProxyRotationConfig(f"Proxy file not found: {file_path}")
    if file_path.is_dir():
        raise InvalidProxyRotationConfig(f"Proxy file is a directory: {file_path}")

    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise InvalidProxyRotationConfig(f"Could not read proxy file {file_path}: {exc}") from exc

    seen: Dict[str, None] = {}
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        endpoint = parse_proxy_string(entry)
        seen.setdefault(endpoint.key, endpoint)

    if not seen:
        raise InvalidProxyRotationConfig(f"Proxy file contains no usable entries: {file_path}")
    return list(seen.values())


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ProxyRotationConfig:
    """
    Declarative description of a rotation strategy.

    Build it from a mapping with `ProxyRotationConfig.from_mapping`, which is
    what `launch_options()` accepts, or construct it directly.
    """

    mode: str = "file"
    # File pool
    file: Optional[str] = None
    policy: str = "round_robin"
    # Gateway
    gateway: Optional[str] = None
    rotate_url: Optional[str] = None
    # Shared behaviour
    verify_ip: Optional[bool] = None
    uniqueness_window: int = DEFAULT_UNIQUENESS_WINDOW
    max_retries: int = DEFAULT_MAX_RETRIES
    cooldown_seconds: float = DEFAULT_COOLDOWN_S
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
    allow_direct_fallback: bool = False
    state_file: Optional[str] = None
    blacklist: List[str] = field(default_factory=list)
    ip_endpoint: Optional[str] = None
    request_timeout: float = 10.0
    reload_pool: bool = True

    def __post_init__(self) -> None:
        self.mode = (self.mode or "").strip().lower()
        self.policy = (self.policy or "").strip().lower()

        if self.mode not in ("file", "gateway"):
            raise InvalidProxyRotationConfig(
                f"Unknown proxy rotation mode: {self.mode!r}. Use 'file' or 'gateway'."
            )
        if self.policy not in _POLICIES:
            raise InvalidProxyRotationConfig(
                f"Unknown rotation policy: {self.policy!r}. Use one of {', '.join(_POLICIES)}."
            )
        if self.mode == "file" and not self.file:
            raise InvalidProxyRotationConfig("Proxy rotation mode 'file' requires 'file' (path to a proxy list).")
        if self.mode == "gateway" and not self.gateway:
            raise InvalidProxyRotationConfig("Proxy rotation mode 'gateway' requires 'gateway' (endpoint URL).")

        if self.max_retries < 1:
            raise InvalidProxyRotationConfig("max_retries must be at least 1.")
        if self.failure_threshold < 1:
            raise InvalidProxyRotationConfig("failure_threshold must be at least 1.")
        if self.uniqueness_window < 0:
            raise InvalidProxyRotationConfig("uniqueness_window cannot be negative.")
        if self.request_timeout <= 0:
            raise InvalidProxyRotationConfig("request_timeout must be positive.")

        # Verification is what makes "new IP per session" true rather than
        # aspirational. A gateway must be asked, because one endpoint fronts
        # many exits and may hand back a sticky one. A pool of distinct
        # endpoints is weaker evidence but usually enough, so it is opt-in.
        if self.verify_ip is None:
            self.verify_ip = self.mode == "gateway"

        # Asking a gateway to rotate on its own schedule would race the
        # uniqueness check; the session token is the reliable lever.
        if self.mode == "gateway" and not self._gateway_is_session_aware() and self.rotate_url is None:
            if self.verify_ip:
                rprint(
                    "Proxy gateway has no '{session}' placeholder and no rotate_url; "
                    "uniqueness can only be verified, not requested.",
                    fg="yellow",
                )

    def _gateway_is_session_aware(self) -> bool:
        assert self.gateway is not None
        return GATEWAY_SESSION_PLACEHOLDER in self.gateway

    @property
    def state_path(self) -> Path:
        return Path(self.state_file) if self.state_file else DEFAULT_STATE_FILE

    @property
    def pool_key(self) -> str:
        """
        Identity of this configuration for state-file namespacing.

        Only the location of the proxies is hashed, never their contents, so the
        state file stays free of credentials and usable across pool edits.
        """
        if self.mode == "gateway":
            anchor = self.gateway or ""
        else:
            resolved = Path(self.file or "").expanduser().resolve()
            anchor = str(resolved)
            try:
                anchor += f":{resolved.stat().st_mtime_ns}"
            except OSError:
                pass
        digest = hashlib.sha256(anchor.encode("utf-8")).hexdigest()[:12]
        return f"{self.mode}-{digest}"

    @classmethod
    def from_mapping(cls, data: Dict[str, Any]) -> "ProxyRotationConfig":
        """
        Build from the dict form accepted by `launch_options(proxy_rotator=...)`.

        Unknown keys are rejected rather than ignored: a typo'd `polcy` that
        silently left rotation on round-robin would look like the feature not
        working.
        """
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        unknown = set(data) - known
        if unknown:
            raise InvalidProxyRotationConfig(
                f"Unknown proxy rotation option(s): {', '.join(sorted(unknown))}. "
                f"Valid options: {', '.join(sorted(known))}."
            )
        return cls(**data)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@dataclass
class ProxySession:
    """
    One proxy assigned to one session, plus what was learned about it.

    `exit_ip` is the address the proxy actually exits from, when verification
    ran. Pass it to `launch_options(geoip=...)` so the generated timezone,
    locale and WebRTC IP describe the proxy rather than the host.
    """

    endpoint: ProxyEndpoint
    session_id: str
    strategy: str
    exit_ip: Optional[str] = None
    attempts: int = 1
    verified: bool = False
    # Monotonic position of this assignment within the rotator. Rotation order is
    # only observable at assignment time: concurrent callers complete out of
    # order, so a list of returned sessions cannot be inspected positionally.
    sequence: int = 0

    @property
    def playwright(self) -> Dict[str, str]:
        return self.endpoint.as_playwright()

    def describe(self) -> str:
        exit_note = f" exit={self.exit_ip}" if self.exit_ip else " exit=unverified"
        return f"{self.endpoint.redacted()} [{self.strategy}]{exit_note}"


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


class ProxyProvider:
    """
    Source of candidate endpoints. Providers are stateless selectors; cursor and
    health live in the rotator so both strategies share one bookkeeping path.
    """

    name = "provider"

    def candidates(self) -> List[ProxyEndpoint]:
        raise NotImplementedError

    def refresh(self) -> None:
        """Re-read the backing source, if it can change underneath us."""


class FileProxyProvider(ProxyProvider):
    """A pool read from a text file, re-read when the file changes on disk."""

    name = "file"

    def __init__(self, path: str, reload_pool: bool = True) -> None:
        self.path = Path(path).expanduser()
        self.reload_pool = reload_pool
        self._endpoints: List[ProxyEndpoint] = []
        self._digest: Optional[bytes] = None
        self._load()

    def _digest_of_current_file(self) -> Optional[bytes]:
        try:
            data = self.path.read_bytes()
        except OSError:
            return None
        return hashlib.blake2b(data, digest_size=16).digest()

    def _load(self) -> None:
        self._endpoints = parse_proxy_file(self.path)
        self._digest = self._digest_of_current_file()

    def refresh(self) -> None:
        if not self.reload_pool:
            return
        # Content, not mtime: a proxy list is a small text file, and a rewrite
        # that lands in the same mtime tick (which this and many filesystems
        # report at coarse granularity) would otherwise go unnoticed until the
        # timestamp moved on. Hashing costs microseconds and candidates() is
        # called once per launch, not per request.
        digest = self._digest_of_current_file()
        if digest is not None and digest != self._digest:
            self._load()

    def candidates(self) -> List[ProxyEndpoint]:
        self.refresh()
        return list(self._endpoints)


class GatewayProxyProvider(ProxyProvider):
    """
    A single rotating-proxy gateway, optionally requesting a fresh exit per
    session.

    The `{session}` placeholder is the portable dialect: residential gateways
    universally accept a per-session identifier somewhere in the credentials,
    and rotating on it is immediate and atomic, unlike a separate rotate call
    that mutates global gateway state and races concurrent sessions.
    """

    name = "gateway"

    def __init__(self, gateway: str, rotate_url: Optional[str] = None, request_timeout: float = 10.0) -> None:
        self.endpoint = parse_proxy_string(gateway)
        self.rotate_url = rotate_url
        self.request_timeout = request_timeout
        self.session_aware = GATEWAY_SESSION_PLACEHOLDER in gateway

    def candidates(self) -> List[ProxyEndpoint]:
        return [self.endpoint]

    def new_session_id(self) -> str:
        # Short, alphanumeric, and lowercase: every gateway dialect observed
        # accepts this shape, and some reject punctuation outright.
        return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))  # nosec

    def request_rotation(self, session_id: str) -> None:
        """
        Ask a gateway with an HTTP rotate hook to move to a new exit.

        Best-effort: gateways answer this in several different ways (204, a JSON
        body, a plain-text IP), and some rate-limit it. A failure here is not
        fatal because the uniqueness check that follows is the real gate.
        """
        if not self.rotate_url:
            return
        url = self.rotate_url.replace(GATEWAY_SESSION_PLACEHOLDER, session_id)
        handler = urllib.request.ProxyHandler(
            {"http": self.endpoint.as_url(), "https": self.endpoint.as_url()}
        )
        opener = urllib.request.build_opener(handler)
        try:
            with opener.open(url, timeout=self.request_timeout) as resp:
                resp.read(256)
        except (urllib.error.URLError, OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Health + persistence
# ---------------------------------------------------------------------------


@dataclass
class EndpointHealth:
    """Per-endpoint counters, persisted so restarts do not forget bad proxies."""

    uses: int = 0
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    cooldown_until: float = 0.0
    last_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uses": self.uses,
            "successes": self.successes,
            "failures": self.failures,
            "consecutive_failures": self.consecutive_failures,
            "cooldown_until": round(self.cooldown_until, 3),
            "last_ip": self.last_ip,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EndpointHealth":
        return cls(
            uses=int(data.get("uses", 0)),
            successes=int(data.get("successes", 0)),
            failures=int(data.get("failures", 0)),
            consecutive_failures=int(data.get("consecutive_failures", 0)),
            cooldown_until=float(data.get("cooldown_until", 0.0)),
            last_ip=data.get("last_ip"),
        )


class RotationState:
    """
    Cursor and health for one pool, backed by a JSON file.

    Writes are atomic (temp file + `os.replace`) because a scraper killed
    mid-write must not leave a truncated state file that turns every future run
    into a cold start.
    """

    def __init__(self, path: Path, pool_key: str) -> None:
        self.path = path
        self.pool_key = pool_key
        self.cursor = 0
        self.endpoints: Dict[str, EndpointHealth] = {}
        self._load()

    def health(self, key: str) -> EndpointHealth:
        return self.endpoints.setdefault(key, EndpointHealth())

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            entry = raw.get("pools", {}).get(self.pool_key, {})
            self.cursor = int(entry.get("cursor", 0))
            self.endpoints = {
                key: EndpointHealth.from_dict(value)
                for key, value in entry.get("endpoints", {}).items()
            }
        except (OSError, ValueError, AttributeError, TypeError):
            # A corrupt state file costs a cold start, nothing more.
            self.cursor = 0
            self.endpoints = {}

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            raw: Dict[str, Any] = {}
            if self.path.exists():
                try:
                    raw = json.loads(self.path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    raw = {}
            pools = raw.setdefault("pools", {})
            pools[self.pool_key] = {
                "cursor": self.cursor,
                "endpoints": {key: health.to_dict() for key, health in self.endpoints.items()},
            }
            raw["version"] = 1
            temp = self.path.with_suffix(".tmp")
            temp.write_text(json.dumps(raw, indent=2), encoding="utf-8")
            os.replace(temp, self.path)
        except OSError:
            # Rotation still works without persistence; it just loses its place.
            pass


# ---------------------------------------------------------------------------
# Rotator
# ---------------------------------------------------------------------------


class ProxyRotator:
    """
    Assigns a distinct exit IP to each session and records whether it worked.

    Thread-safe: automation routinely creates contexts from several threads, and
    an unsynchronised cursor is how two sessions end up sharing a proxy.

    Usage::

        rotator = ProxyRotator(ProxyRotationConfig(mode="file", file="proxies.txt"))
        session = rotator.acquire_session()
        browser = playwright.firefox.launch(proxy=session.playwright)
        rotator.report_launch_result(session, success=True)
    """

    def __init__(self, config: ProxyRotationConfig, *, state_path: Optional[Path] = None) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._provider: ProxyProvider = self._build_provider()
        self._state = RotationState(state_path or config.state_path, config.pool_key)
        self._recent_ips: List[str] = []
        self._session_counter = 0
        self._assignment_counter = 0
        # Most recent assignment, so callers can read back the exit IP that a
        # launched browser is actually using.
        self.last_session: Optional[ProxySession] = None

    def _build_provider(self) -> ProxyProvider:
        if self.config.mode == "gateway":
            assert self.config.gateway is not None
            return GatewayProxyProvider(
                self.config.gateway,
                rotate_url=self.config.rotate_url,
                request_timeout=self.config.request_timeout,
            )
        assert self.config.file is not None
        return FileProxyProvider(self.config.file, reload_pool=self.config.reload_pool)

    @property
    def provider(self) -> ProxyProvider:
        return self._provider

    # -- selection ---------------------------------------------------------

    def _health_key(self, endpoint: ProxyEndpoint) -> str:
        """
        Bucket an endpoint for health tracking.

        In gateway mode the *endpoint* is what fails, not the session: one
        endpoint fronts many exits, and substituting the `{session}` token
        changes `key` on every call. Tracking per-key there would scatter one
        gateway's failures across an unbounded number of entries, so its
        failure threshold and cooldown would never trip. The gateway is therefore
        tracked as its bare host:port; a pool tracks each endpoint individually.
        """
        if self.config.mode == "gateway":
            return endpoint.server
        return endpoint.key

    def _is_blacklisted(self, endpoint: ProxyEndpoint) -> bool:
        for entry in self.config.blacklist:
            if entry == endpoint.key or entry in (endpoint.host_port, endpoint.host):
                return True
        return False

    def _select_candidates(self, endpoints: Sequence[ProxyEndpoint]) -> Tuple[List[ProxyEndpoint], bool]:
        """
        Order the pool by policy, preferring healthy endpoints.

        Returns the ordered candidates and whether unhealthy endpoints had to be
        recycled (all of them were cooling down).
        """
        now = time.time()
        usable = [
            endpoint
            for endpoint in endpoints
            if not self._is_blacklisted(endpoint)
            and self._state.health(self._health_key(endpoint)).cooldown_until <= now
        ]
        recycled = False
        if not usable:
            # Every proxy is in cooldown. Refusing to launch would stall a long
            # run indefinitely, so the cooldowns are cleared and the least-bad
            # candidates are retried.
            usable = [endpoint for endpoint in endpoints if not self._is_blacklisted(endpoint)]
            if usable:
                recycled = True
                for endpoint in usable:
                    self._state.health(self._health_key(endpoint)).cooldown_until = 0.0

        if self.config.mode == "file" and self.config.policy == "round_robin":
            if usable:
                offset = self._state.cursor % len(usable)
                usable = usable[offset:] + usable[:offset]
            return usable, recycled

        if self.config.mode == "file" and self.config.policy == "least_used":
            usable.sort(key=lambda endpoint: (self._state.health(self._health_key(endpoint)).uses, endpoint.key))
            return usable, recycled

        if self.config.policy == "random" and len(usable) > 1:
            shuffled = list(usable)
            random.shuffle(shuffled)  # nosec
            return shuffled, recycled

        return usable, recycled

    def _next_session_id(self) -> str:
        self._session_counter += 1
        suffix = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10))  # nosec
        return f"{int(time.time() * 1000):x}{self._session_counter:x}{suffix}"

    def _remember_ip(self, ip: str) -> None:
        self._recent_ips.append(ip)
        excess = len(self._recent_ips) - self.config.uniqueness_window
        if excess > 0:
            del self._recent_ips[:excess]

    # -- acquisition -------------------------------------------------------

    def acquire_session(self, *, session_id: Optional[str] = None) -> Optional[ProxySession]:
        """
        Choose a proxy and return everything needed to launch with it.

        Returns `None` only when `allow_direct_fallback` is set and no proxy
        could be used. Otherwise raises `ProxyPoolExhausted`, because launching
        on the host's own IP while pretending to be elsewhere is a detection
        vector, not a graceful degradation.
        """
        with self._lock:
            endpoints = self._provider.candidates()
            if not endpoints:
                return self._give_up("proxy pool is empty")

            ordered, recycled = self._select_candidates(endpoints)
            if not ordered:
                return self._give_up("every proxy is blacklisted")

            if recycled:
                rprint(
                    "Every proxy in the pool was cooling down; retrying them.",
                    fg="yellow",
                )

            attempts = 0
            rejection_reasons: List[str] = []
            for endpoint in ordered:
                if attempts >= self.config.max_retries:
                    break
                attempts += 1

                resolved_id = session_id or self._next_session_id()
                candidate = endpoint.with_session(resolved_id)

                if self.config.mode == "gateway" and isinstance(self._provider, GatewayProxyProvider):
                    if self._provider.session_aware:
                        pass  # uniqueness comes from the substituted token
                    else:
                        self._provider.request_rotation(resolved_id)

                exit_ip: Optional[str] = None
                if self.config.verify_ip:
                    exit_ip = self._probe_exit_ip(candidate)
                    if exit_ip is None:
                        rejection_reasons.append(f"{candidate.redacted()}: unreachable")
                        continue
                    if exit_ip in self._recent_ips:
                        rejection_reasons.append(f"{candidate.redacted()}: repeated exit IP")
                        continue
                elif self.config.mode == "gateway" and not self._endpoint_reachable(candidate):
                    # A gateway is one endpoint fronting many workers; individual
                    # workers die while the endpoint stays up. Nothing else in
                    # this path would notice until the browser launch failed.
                    rejection_reasons.append(f"{candidate.redacted()}: not reachable")
                    continue

                health = self._state.health(self._health_key(candidate))
                health.uses += 1
                if exit_ip:
                    health.last_ip = exit_ip
                    self._remember_ip(exit_ip)

                self._advance_cursor(endpoint, endpoints)
                self._state.save()

                self._assignment_counter += 1
                session = ProxySession(
                    endpoint=candidate,
                    session_id=resolved_id,
                    strategy=f"{self.config.mode}/{self.config.policy}",
                    exit_ip=exit_ip,
                    attempts=attempts,
                    verified=exit_ip is not None,
                    sequence=self._assignment_counter,
                )
                self.last_session = session
                return session

            reason = "; ".join(rejection_reasons) if rejection_reasons else "no candidates survived selection"
            return self._give_up(reason)

    def _advance_cursor(self, chosen: ProxyEndpoint, endpoints: Sequence[ProxyEndpoint]) -> None:
        if self.config.mode != "file":
            return
        try:
            index = list(endpoints).index(chosen)
        except ValueError:
            self._state.cursor = (self._state.cursor + 1) % len(endpoints)
            return
        self._state.cursor = (index + 1) % len(endpoints)

    def _give_up(self, reason: str) -> Optional[ProxySession]:
        if self.config.allow_direct_fallback:
            rprint(
                f"Proxy rotation could not provide a proxy ({reason}); "
                "launching without one because allow_direct_fallback is set.",
                fg="yellow",
            )
            return None
        raise ProxyPoolExhausted(
            f"Proxy rotation could not provide a proxy: {reason}. "
            "Refusing to launch without one, because the browser would advertise a "
            "spoofed location from this host's real IP. Fix the pool, or pass "
            "allow_direct_fallback=True to permit a direct connection."
        )

    # -- verification ------------------------------------------------------

    def _probe_exit_ip(self, endpoint: ProxyEndpoint) -> Optional[str]:
        """
        Ask what IP the world sees through this proxy.

        Imported lazily so this module stays importable without the network
        stack that `camoufox.ip` pulls in, and so tests can substitute it.
        """
        from .ip import public_ip

        try:
            return public_ip(endpoint.as_url())
        except Exception:
            return None

    def _endpoint_reachable(self, endpoint: ProxyEndpoint, timeout: float = 5.0) -> bool:
        """
        Cheap TCP connect to the proxy's own host:port.

        Used when exit-IP verification is off, so a gateway whose endpoint is
        simply down is skipped rather than handed to Playwright to fail on.
        """
        import socket

        host, port = endpoint.hostname, endpoint.port
        if not host or port is None:
            return True  # nothing to check; let Playwright decide
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    # -- feedback ----------------------------------------------------------

    def report_launch_result(self, session: ProxySession, *, success: bool, reason: str = "") -> None:
        """
        Record whether the browser actually came up on the assigned proxy.

        A proxy that exits cleanly but cannot carry a launch is still a bad
        proxy, and only the caller knows the difference.
        """
        with self._lock:
            health = self._state.health(self._health_key(session.endpoint))
            if success:
                health.successes += 1
                health.consecutive_failures = 0
            else:
                health.failures += 1
                health.consecutive_failures += 1
                if health.consecutive_failures >= self.config.failure_threshold:
                    health.cooldown_until = time.time() + self.config.cooldown_seconds
                    note = f" ({reason})" if reason else ""
                    rprint(
                        f"Proxy {session.endpoint.redacted()} failed "
                        f"{health.consecutive_failures}x{note}; cooling down for "
                        f"{int(self.config.cooldown_seconds)}s.",
                        fg="yellow",
                    )
            self._state.save()

    def report_failure(self, session: ProxySession, reason: str = "") -> None:
        """Convenience wrapper for `report_launch_result(success=False)`."""
        self.report_launch_result(session, success=False, reason=reason)

    def report_success(self, session: ProxySession) -> None:
        """Convenience wrapper for `report_launch_result(success=True)`."""
        self.report_launch_result(session, success=True)

    # -- introspection -----------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Snapshot of pool health, for `camoufox proxy status` and debugging."""
        with self._lock:
            endpoints = self._provider.candidates()
            now = time.time()
            entries = []
            for endpoint in endpoints:
                health = self._state.health(self._health_key(endpoint))
                entries.append(
                    {
                        "proxy": endpoint.redacted(),
                        "host": endpoint.host,
                        "uses": health.uses,
                        "successes": health.successes,
                        "failures": health.failures,
                        "consecutive_failures": health.consecutive_failures,
                        "cooling_down": health.cooldown_until > now,
                        "cooldown_remaining": max(0.0, health.cooldown_until - now),
                        "last_ip": health.last_ip,
                        "blacklisted": self._is_blacklisted(endpoint),
                    }
                )
            return {
                "mode": self.config.mode,
                "policy": self.config.policy,
                "verify_ip": bool(self.config.verify_ip),
                "pool_key": self.config.pool_key,
                "cursor": self._state.cursor,
                "size": len(endpoints),
                "state_file": str(self._state.path),
                "endpoints": entries,
            }


# ---------------------------------------------------------------------------
# Construction helpers
# ---------------------------------------------------------------------------


def build_rotator(
    spec: Any,
    *,
    state_path: Optional[Path] = None,
) -> Optional[ProxyRotator]:
    """
    Normalise the several accepted forms of a rotation spec into a rotator.

    Accepts a `ProxyRotationConfig`, a mapping of its fields, a `ProxyRotator`
    (returned unchanged), or `None` (meaning "no rotation").
    """
    if spec is None:
        return None
    if isinstance(spec, ProxyRotator):
        return spec
    if isinstance(spec, ProxyRotationConfig):
        return ProxyRotator(spec, state_path=state_path)
    if isinstance(spec, dict):
        return ProxyRotator(ProxyRotationConfig.from_mapping(spec), state_path=state_path)
    raise InvalidProxyRotationConfig(
        "proxy_rotator must be a ProxyRotationConfig, a dict of its fields, or a ProxyRotator; "
        f"got {type(spec).__name__}."
    )
