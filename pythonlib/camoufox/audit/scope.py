"""
Scope enforcement for the WAF / bot-defense audit tool.

The audit tool drives Camoufox at a target the operator does not control from
inside this process. Everything in this package is therefore gated behind an
explicit, narrow, verifiable scope: a target must be named *and* acknowledged as
authorized before any request is allowed to leave.

The gate is enforced here, at the single point every scheduled request passes
through, rather than trusted to the caller. A UI checkbox is a reminder, not a
security control; this is the control.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List, Sequence
from urllib.parse import urlparse

__all__ = [
    "ScopeViolation",
    "AuthorizationRequired",
    "TargetScope",
]


class ScopeViolation(RuntimeError):
    """A request was aimed outside the authorized target scope."""


class AuthorizationRequired(RuntimeError):
    """The audit was started without an authorization acknowledgment."""


def _normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass
class TargetScope:
    """
    The set of hosts an audit is permitted to touch.

    Matching is exact-host plus explicitly listed subdomains; a bare domain does
    *not* implicitly authorize every subdomain, because a wildcard scope is how
    an audit accidentally reaches a third-party property that shares a suffix.
    """

    hosts: List[str] = field(default_factory=list)
    allow_subdomains: bool = False
    acknowledged: bool = False
    acknowledgment_note: str = ""

    def __post_init__(self) -> None:
        self.hosts = [_normalize_host(h) for h in self.hosts if _normalize_host(h)]

    # -- construction ------------------------------------------------------

    @classmethod
    def from_urls(
        cls,
        urls: Sequence[str],
        *,
        allow_subdomains: bool = False,
        acknowledged: bool = False,
        acknowledgment_note: str = "",
    ) -> "TargetScope":
        hosts: List[str] = []
        for url in urls:
            parsed = urlparse(url if "//" in url else f"//{url}")
            host = parsed.hostname
            if not host:
                raise ValueError(f"Could not parse a host out of {url!r}")
            hosts.append(host)
        return cls(
            hosts=hosts,
            allow_subdomains=allow_subdomains,
            acknowledged=acknowledged,
            acknowledgment_note=acknowledgment_note,
        )

    # -- the gate ----------------------------------------------------------

    def check(self, url: str) -> str:
        """
        Return the normalized host for `url`, or raise.

        Every navigation goes through here, so there is exactly one place that
        decides whether a request is in scope.
        """
        if not self.acknowledged:
            raise AuthorizationRequired(
                "Refusing to send traffic: the audit has not been acknowledged as "
                "authorized. The operator must confirm they own the target or have "
                "written permission to test it."
            )
        if not self.hosts:
            raise ScopeViolation(
                "Refusing to send traffic: the target scope is empty. Name the "
                "hosts under test before starting the audit."
            )

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ScopeViolation(
                f"Refusing to fetch {url!r}: only http/https targets are audited."
            )

        host = _normalize_host(parsed.hostname or "")
        if not host:
            raise ScopeViolation(f"Refusing to fetch {url!r}: no host in URL.")
        if not self.permits(host):
            raise ScopeViolation(
                f"Refusing to fetch {host!r}: outside the authorized scope "
                f"({', '.join(self.hosts)}). The audit will not touch hosts that "
                f"were not named."
            )
        return host

    def permits(self, host: str) -> bool:
        """Host-only check, for pre-flight validation without raising."""
        host = _normalize_host(host)
        if not host:
            return False
        for allowed in self.hosts:
            if host == allowed:
                return True
            if self.allow_subdomains and not _is_ip_literal(allowed):
                if host.endswith("." + allowed):
                    return True
        return False

    def permits_url(self, url: str) -> bool:
        host = _normalize_host(urlparse(url).hostname or "")
        return self.permits(host)

    # -- description -------------------------------------------------------

    def describe(self) -> str:
        scope = ", ".join(self.hosts) if self.hosts else "(none)"
        suffix = " + subdomains" if self.allow_subdomains else ""
        return f"{scope}{suffix}"

    def to_dict(self) -> dict:
        return {
            "hosts": list(self.hosts),
            "allow_subdomains": self.allow_subdomains,
            "acknowledged": self.acknowledged,
            "acknowledgment_note": self.acknowledgment_note,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TargetScope":
        return cls(
            hosts=list(data.get("hosts") or []),
            allow_subdomains=bool(data.get("allow_subdomains")),
            acknowledged=bool(data.get("acknowledged")),
            acknowledgment_note=str(data.get("acknowledgment_note") or ""),
        )