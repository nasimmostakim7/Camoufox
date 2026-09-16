"""
The console's proxy pool: what L4 and up rotate through.

Levels 4 and up claim "a fresh exit IP per visitor". Without a pool there is
nothing to rotate, and running those rungs direct would report this host's own IP
under a rung that says otherwise. So the pool is a real input, and the console is
honest about its absence: the rotation rungs are pruned and the caller is told why.

Secrets. A proxy URL routinely carries a password. Nothing here persists one: the
state kept in memory is the redacted label only, which is what the API returns and
what a session records. `ProxySession.describe()` and `Endpoint.redacted()` already
withhold the password for reports; this module keeps it from being *stored* in the
first place.
"""

from __future__ import annotations

import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:  # The vendored engine is the single source of truth for the ladder.
    from ._engine.evasion import EVASION_LEVELS as _LADDER
except Exception:  # pragma: no cover - only if the engine is absent/broken
    _LADDER = ()

#: Rungs whose definition is the exit IP. Pruned when no pool is configured.
#:
#: Derived from the ladder rather than restated: a second hand-kept list of
#: "which rungs rotate" is exactly how the runner and the console drift apart,
#: and then one of them reports an IP-rotation verdict for a rung that never
#: rotated. Falls back to the known ids only if the engine cannot be read.
ROTATION_LEVEL_IDS = tuple(
    level.id for level in _LADDER if getattr(level, "requires_rotation", False)
) or (4, 5, 6)

#: A gateway fronts many exits behind one endpoint and rotates per session token.
_GATEWAY_TOKEN = "{session}"

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def _looks_like_url(value: str) -> bool:
    return bool(_SCHEME_RE.match(value.strip()))


def redact(value: str) -> str:
    """
    Strip an inline password from a proxy string for display.

    Deliberately local rather than imported from `camoufox.proxy`: the console has
    to run with nothing installed, and this is the one piece of that module the UI
    needs on a host with no camoufox.
    """
    text = (value or "").strip()
    scheme = ""
    remainder = text
    if "://" in text:
        scheme, remainder = text.split("://", 1)
        scheme += "://"
    # user:pass@host:port -> user:***@host:port
    if "@" in remainder:
        creds, host = remainder.rsplit("@", 1)
        if ":" in creds:
            user = creds.split(":", 1)[0]
            return f"{scheme}{user}:***@{host}"
    return text


@dataclass
class ProxyPool:
    """
    The rotation spec, in the engine's own accepted form.

    Holds the spec (which may contain a password) in memory for the lifetime of
    the console process, and a redacted description for every outward-facing use.
    `pool_file` is a path this module created and therefore owns; it is removed
    when the pool is replaced so a spent credential list does not sit on disk.
    """

    spec: Dict[str, Any]
    labels: List[str] = field(default_factory=list)
    mode: str = "file"
    gateway: str = ""
    pool_file: Optional[str] = None

    def summary(self) -> Dict[str, Any]:
        """The pool as the API may report it: never the password."""
        return {
            "configured": True,
            "mode": self.mode,
            "count": len(self.labels),
            "labels": list(self.labels),
            "gateway": redact(self.gateway) if self.gateway else "",
        }

    def dispose(self) -> None:
        """Delete the backing file, if this pool created one."""
        if not self.pool_file:
            return
        try:
            os.unlink(self.pool_file)
        except OSError:
            pass
        self.pool_file = None


class ProxyPoolStore:
    """Holds at most one pool for the console, or none."""

    def __init__(self) -> None:
        self._pool: Optional[ProxyPool] = None
        self._lock = threading.Lock()

    def get(self) -> Optional[ProxyPool]:
        with self._lock:
            return self._pool

    def has_pool(self) -> bool:
        return self.get() is not None

    def clear(self) -> None:
        with self._lock:
            previous, self._pool = self._pool, None
        if previous is not None:
            previous.dispose()

    def set_gateway(self, gateway: str) -> ProxyPool:
        """
        One endpoint that rotates for us.

        Verified per session when it carries the `{session}` token, because a
        gateway returning the same exit twice is the exact failure this feature
        exists to rule out.
        """
        text = (gateway or "").strip()
        if not text:
            raise ValueError("gateway URL is required")
        if not _looks_like_url(text):
            raise ValueError("gateway must be a proxy URL, e.g. http://user:pass@host:port")
        spec: Dict[str, Any] = {
            "mode": "gateway",
            "gateway": text,
            "allow_direct_fallback": False,
        }
        if _GATEWAY_TOKEN in text:
            spec["verify_ip"] = True
        pool = ProxyPool(
            spec=spec,
            labels=[redact(text)],
            mode="gateway",
            gateway=text,
        )
        return self._install(pool)

    def set_list(self, entries: List[str]) -> ProxyPool:
        """
        An explicit list, one proxy per line.

        Written to a temporary file because that is the engine's `file` mode; the
        file lives for the process's lifetime and is created with owner-only
        permissions, since a proxy list is credentials.
        """
        cleaned = [e.strip() for e in (entries or []) if e and e.strip()]
        if not cleaned:
            raise ValueError("at least one proxy entry is required")
        path = _write_pool_file(cleaned)
        spec: Dict[str, Any] = {
            "mode": "file",
            "file": str(path),
            "allow_direct_fallback": False,
        }
        pool = ProxyPool(
            spec=spec,
            labels=[redact(e) for e in cleaned],
            mode="file",
            pool_file=str(path),
        )
        try:
            return self._install(pool)
        except Exception:
            pool.dispose()
            raise

    def _install(self, pool: ProxyPool) -> ProxyPool:
        """Swap in a new pool, removing the file the old one owned."""
        with self._lock:
            previous, self._pool = self._pool, pool
        if previous is not None:
            previous.dispose()
        return pool


def _write_pool_file(entries: List[str]) -> str:
    """Write the pool to a 0600 file outside the served tree."""
    fd, name = tempfile.mkstemp(prefix="waf-console-pool-", suffix=".txt")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            # fdopen takes ownership of fd, so the `with` closes it on any error
            # below; do not also close it here, or the second close raises.
            handle.write("\n".join(entries) + "\n")
    except Exception:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise
    return name