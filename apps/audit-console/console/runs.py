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
MAX_LEVELS = 4


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
    ) -> AuditSession:
        host = self.authorize(target_url)

        visitor_count = max(1, min(int(visitor_count), MAX_VISITORS))
        max_level = max(0, min(int(max_level), MAX_LEVELS))
        duration_hours = max(0.001, float(duration_hours))

        available = browser_available()
        if not available and max_level > 0:
            max_level = 0
            capped = True
        else:
            capped = False

        scope = TargetScope.from_urls(
            [target_url],
            acknowledged=True,
            acknowledgment_note="hosted demo console; operator acknowledged at launch",
        )
        config = AuditConfig(
            target_url=target_url,
            scope=scope,
            levels=list(range(0, max_level + 1)),
            visitor_count=visitor_count,
            duration_hours=duration_hours,
            cooldown_between_levels_s=0.0,
            seed=seed,
            limits=CONSOLE_LIMITS,
            extra_headers=dict(extra_headers or {}),
            headless=True,
        )
        problems = config.validate()
        if problems:
            raise TargetNotAllowed("; ".join(problems))

        session = AuditSession(
            id=uuid.uuid4().hex[:12],
            target_url=target_url,
            visitor_count=visitor_count,
            duration_hours=duration_hours,
            max_level=max_level,
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
        if capped:
            session._append(
                {
                    "event": "notice",
                    "message": (
                        "No installed camoufox to drive the browser rungs, so the "
                        "ladder is capped at L0 (naive HTTP). Levels 1+ need the "
                        "browser; see pythonlib/."
                    ),
                }
            )
        return session

    def get(self, session_id: str) -> Optional[AuditSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def levels(self) -> List[Dict[str, Any]]:
        return [level.to_dict() for level in levels_up_to(MAX_LEVELS)]
