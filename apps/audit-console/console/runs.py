"""
Running audits for the console: one session per request, streamed as it happens.

An audit is slow by design -- arrivals are spread over a window rather than fired at
once -- so the console cannot answer with a single blocking response. Each session
owns a thread running its own event loop, appends progress events as the runner
emits them, and keeps the finished report for export.

The scope gate is the important part. This console can be hosted, and a hosted
console that will audit any URL it is handed is an open request forwarder: anyone
could point it at a third party and use it to send traffic from our address. So the
session is constructed with an explicit allow-list of hosts, and any target not in
it is refused before a single request leaves. The hosted build passes only its own
demo WAF; a local operator can pass their own hosts deliberately.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ._engine import (
    AuditConfig,
    AuditRunner,
    SafetyLimits,
    ScopeViolation,
    TargetScope,
    levels_up_to,
)
from ._engine.report import build_findings, render_text, write_report
from .proxies import ROTATION_LEVEL_IDS, ProxyPoolStore

#: Ceilings the console applies regardless of what the request asks for. The
#: console is shared, so the brake cannot be something the caller sets.
CONSOLE_LIMITS = SafetyLimits(
    max_requests=500,
    max_concurrency=6,
    max_rps=25.0,
    max_arrivals_per_minute=120,
    abort_after_consecutive_errors=15,
)

MAX_VISITORS = 400
#: L6 is the end of the engine's ladder; nothing above it exists to climb.
MAX_LEVELS = 6


def browser_available() -> bool:
    """
    Whether an installed camoufox can drive the browser rungs.

    Levels 1 and up launch a real Camoufox; L0 does not. The console is built to
    run on a bare Python, so "no browser here" is a normal state, not an error --
    it caps the ladder at L0 and says so, rather than accepting a max_level and
    then reporting a launch failure for every rung.
    """
    try:
        import camoufox.async_api  # noqa: F401
    except Exception:
        return False
    return True


class TargetNotAllowed(RuntimeError):
    """The requested target is not on this console's allow-list."""


@dataclass
class AuditSession:
    """One console-initiated audit, its progress log, and its result."""

    id: str
    target_url: str
    visitor_count: int
    duration_hours: float
    max_level: int
    seed: Optional[int]
    #: The rungs actually run, after a missing browser or pool pruned some.
    levels: List[int] = field(default_factory=list)
    #: True when the request asked for one rung rather than the ladder.
    single_level_mode: bool = False
    #: Redacted description of the pool, or None. Never carries a password.
    proxy_summary: Optional[Dict[str, Any]] = None
    status: str = "running"  # running | done | failed | cancelled
    error: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    events: List[Dict[str, Any]] = field(default_factory=list)
    report: Optional[Any] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _cancel: Optional[threading.Event] = field(default=None, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, repr=False)

    # -- progress ----------------------------------------------------------

    def _append(self, event: Dict[str, Any]) -> None:
        with self._lock:
            event = {"seq": len(self.events), **event}
            self.events.append(event)

    def events_since(self, seq: int) -> List[Dict[str, Any]]:
        with self._lock:
            return [e for e in self.events if e["seq"] >= seq]

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "target_url": self.target_url,
                "status": self.status,
                "error": self.error,
                "visitor_count": self.visitor_count,
                "duration_hours": self.duration_hours,
                "max_level": self.max_level,
                "levels": self.levels,
                "single_level_mode": self.single_level_mode,
                "proxy": self.proxy_summary,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "event_count": len(self.events),
                "summary": self._summary(),
            }

    def _summary(self) -> Optional[Dict[str, Any]]:
        if self.report is None:
            return None
        report = self.report
        levels = []
        for lr in report.levels:
            entry = lr.to_dict()
            # The result carries what happened; the rung definition carries what
            # it *means*. The report needs both to be readable.
            entry["description"] = lr.level.description
            entry["isolates"] = lr.level.isolates
            levels.append(entry)
        return {
            "total_requests": report.total_requests,
            "total_visits": report.total_visits,
            "findings": build_findings(report),
            "first_effective_level": (
                report.first_effective_level().level.name
                if report.first_effective_level()
                else None
            ),
            "aborted": report.aborted,
            "abort_reason": report.abort_reason,
            "levels": levels,
        }

    # -- execution ---------------------------------------------------------

    def start(self, config: AuditConfig) -> None:
        self._cancel = threading.Event()
        self._thread = threading.Thread(
            target=self._run, args=(config, self._cancel), daemon=True
        )
        self._thread.start()

    def cancel(self) -> bool:
        if self._cancel is not None and self.status == "running":
            self._cancel.set()
            return True
        return False

    def _run(self, config: AuditConfig, cancel: threading.Event) -> None:
        # A fresh loop in this thread: the session must not borrow the HTTP
        # server's loop, and asyncio.run cannot be called from a running one.
        try:
            asyncio.run(self._run_async(config, cancel))
        except Exception as exc:  # a crash must be visible, not a stuck session
            self.error = f"{type(exc).__name__}: {exc}"
            self._append({"event": "error", "message": self.error})
            self.status = "failed"
        finally:
            self.finished_at = time.time()
            if self.status == "running":
                self.status = "done"
            self._append({"event": "end", "status": self.status})

    async def _run_async(self, config: AuditConfig, cancel: threading.Event) -> None:
        runner = AuditRunner(
            config,
            on_progress=self._append,
            cancel_event=cancel,
        )
        report = await runner.run()
        self.report = report
        if report.aborted:
            self.status = "failed"
            self.error = report.abort_reason

    # -- export ------------------------------------------------------------

    def export(self, fmt: str) -> Optional[str]:
        if self.report is None:
            return None
        if fmt == "json":
            import json

            payload = self.report.to_dict()
            payload["findings"] = build_findings(self.report)
            return json.dumps(payload, indent=2, default=str)
        if fmt == "text":
            return render_text(self.report)
        return None

    def export_html(self) -> Optional[str]:
        if self.report is None:
            return None
        from ._engine.report import render_html

        return render_html(self.report)


class AuditService:
    """Holds the sessions and the allow-list that scopes them."""

    def __init__(
        self,
        allowed_hosts: Optional[List[str]] = None,
        demo_target: str = "",
    ) -> None:
        self.allowed_hosts = [h.lower() for h in (allowed_hosts or [])]
        self.demo_target = demo_target
        self.proxies = ProxyPoolStore()
        self._sessions: Dict[str, AuditSession] = {}
        self._lock = threading.Lock()
        self._cap = 20

    # -- scope -------------------------------------------------------------

    def authorize(self, target_url: str) -> str:
        """
        Return the host if this console may audit it, else raise.

        This is the console's own gate, in front of the engine's. The engine
        refuses anything outside its scope; this decides what scope the console is
        willing to *declare* in the first place, which is what keeps a hosted
        instance from being pointed at a third party.
        """
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            raise TargetNotAllowed("target must be an http(s) URL")
        host = (parsed.hostname or "").lower()
        if not host:
            raise TargetNotAllowed("target URL has no host")
        if self.allowed_hosts and host not in self.allowed_hosts:
            raise TargetNotAllowed(
                f"host {host!r} is not on this console's allow-list "
                f"({', '.join(self.allowed_hosts)}). A hosted console only audits "
                f"its own demo target."
            )
        return host

    # -- sessions ----------------------------------------------------------

    def start_audit(
        self,
        *,
        target_url: str,
        visitor_count: int,
        duration_hours: float,
        max_level: int,
        seed: Optional[int],
        extra_headers: Optional[Dict[str, str]] = None,
        single_level: Optional[int] = None,
    ) -> AuditSession:
        host = self.authorize(target_url)

        visitor_count = max(1, min(int(visitor_count), MAX_VISITORS))
        max_level = max(0, min(int(max_level), MAX_LEVELS))
        duration_hours = max(0.001, float(duration_hours))
        single_level_mode = single_level is not None

        notices: List[str] = []

        available = browser_available()
        if not available and max_level > 0:
            max_level = 0
            notices.append(
                "No installed camoufox to drive the browser rungs, so the ladder is "
                "capped at L0 (naive HTTP). Levels 1+ need the browser; see pythonlib/."
            )

        pool = self.proxies.get()
        if single_level_mode:
            requested_levels = [max(0, min(int(single_level), MAX_LEVELS))]
        else:
            requested_levels = list(range(0, max_level + 1))
        selected = [i for i in requested_levels if pool is not None or i not in ROTATION_LEVEL_IDS]
        dropped = [i for i in requested_levels if i not in selected]
        if single_level_mode and not selected:
            # The one rung that was asked for is exactly the one that cannot run
            # here. Silently returning a session with no levels would look like a
            # clean result; refuse instead, and name the rung as clamped, since
            # that is what will appear in the report.
            raise TargetNotAllowed(
                f"L{requested_levels[0]} is defined by a rotating exit IP and no proxy "
                f"pool is configured, so this console cannot run it. Add a pool, or "
                f"pick another rung."
            )
        if single_level_mode and not available and requested_levels[0] > 0:
            raise TargetNotAllowed(
                f"L{requested_levels[0]} needs the browser, which is not installed on "
                f"this host. Only L0 can run here."
            )
        if dropped:
            # L4+ are defined by a rotating exit IP. Running them with no pool
            # would measure this host's own IP while the report still said
            # "proxy rotation", which points the operator at the wrong control.
            # Prune and say so, the same way a missing browser prunes L1+.
            notices.append(
                "Rungs "
                + ", ".join(f"L{i}" for i in dropped)
                + " are defined by a rotating exit IP, and no proxy pool is "
                "configured, so they were left out rather than run directly and "
                "reported as IP rotation. Add a pool to climb them."
            )

        scope = TargetScope.from_urls(
            [target_url],
            acknowledged=True,
            acknowledgment_note="hosted demo console; operator acknowledged at launch",
        )
        config = AuditConfig(
            target_url=target_url,
            scope=scope,
            # In single-rung mode the engine derives the rung from `single_level`;
            # passing `levels` too would be two sources for the same decision, and
            # validate() rejects that rather than pick one silently.
            levels=None if single_level_mode else selected,
            single_level_mode=single_level_mode,
            single_level=requested_levels[0],
            visitor_count=visitor_count,
            duration_hours=duration_hours,
            cooldown_between_levels_s=0.0,
            seed=seed,
            limits=CONSOLE_LIMITS,
            extra_headers=dict(extra_headers or {}),
            # Each rung runs the posture it defines; on this host the headed rungs
            # fall back to Camoufox's virtual display, which is a real headed
            # browser rather than a headless one. Forcing headless here would
            # collapse L1 into the rungs above it and quietly change what L2+
            # measures.
            headless=None,
            proxy=pool.spec if pool is not None else None,
        )
        problems = config.validate()
        if problems:
            raise TargetNotAllowed("; ".join(problems))

        session = AuditSession(
            id=uuid.uuid4().hex[:12],
            target_url=target_url,
            visitor_count=config.visitor_count,
            duration_hours=duration_hours,
            max_level=max(requested_levels, default=0),
            levels=selected,
            single_level_mode=single_level_mode,
            proxy_summary=pool.summary() if pool is not None else None,
            seed=seed,
        )
        with self._lock:
            self._sessions[session.id] = session
            if len(self._sessions) > self._cap:
                for stale in sorted(self._sessions, key=lambda k: self._sessions[k].started_at)[
                    : len(self._sessions) - self._cap
                ]:
                    self._sessions.pop(stale, None)
        session.start(config)
        for message in notices:
            session._append({"event": "notice", "message": message})
        return session

    def get(self, session_id: str) -> Optional[AuditSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def levels(self) -> List[Dict[str, Any]]:
        """
        Every rung, annotated with whether this console can currently climb it.

        The UI needs to distinguish "reachable now" from "needs a proxy pool", and
        it must not be the UI's job to know which rungs are defined by the exit IP.
        """
        pool = self.proxies.get()
        has_browser = browser_available()
        out: List[Dict[str, Any]] = []
        for level in levels_up_to(MAX_LEVELS):
            entry = level.to_dict()
            needs_pool = level.id in ROTATION_LEVEL_IDS
            needs_browser = level.client == "browser"
            runnable = (not needs_browser or has_browser) and (
                not needs_pool or pool is not None
            )
            entry["reachable"] = runnable
            entry["requires_pool"] = needs_pool
            if needs_pool and pool is None:
                entry["unreachable_reason"] = (
                    "needs a proxy pool: this rung is defined by a rotating exit IP"
                )
            elif needs_browser and not has_browser:
                entry["unreachable_reason"] = (
                    "needs the browser: camoufox is not installed on this host"
                )
            out.append(entry)
        return out

    def proxy_state(self) -> Dict[str, Any]:
        """The pool as the API may report it: never a password."""
        pool = self.proxies.get()
        if pool is None:
            return {"configured": False, "mode": None, "count": 0, "labels": [], "gateway": ""}
        return pool.summary()

    def configure_proxy(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Set or clear the rotation pool.

        Two accepted shapes, matching the engine's own: `entries` (a list of proxy
        strings) or `gateway` (one rotating endpoint). Anything else is refused
        rather than guessed at.
        """
        if body.get("clear"):
            self.proxies.clear()
            return self.proxy_state()
        gateway = str(body.get("gateway") or "").strip()
        entries = body.get("entries")
        if gateway and entries:
            raise ValueError("pass either 'gateway' or 'entries', not both")
        if gateway:
            pool = self.proxies.set_gateway(gateway)
        elif entries:
            if isinstance(entries, str):
                entries = entries.splitlines()
            if not isinstance(entries, list):
                raise ValueError("'entries' must be a list of proxy strings")
            pool = self.proxies.set_list([str(e) for e in entries])
        else:
            raise ValueError("provide 'entries' (a list of proxies) or 'gateway'")
        return pool.summary()
