"""
Audit configuration and result containers.

A single object describing what to test, plus the records produced by running it.
Keeping these declarative (and serializable) is what lets the same audit be
launched from the CLI, from the GUI, or from a saved profile.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .detection import Verdict
from .evasion import EvasionLevel, level_by_id, levels_up_to
from .journey import JourneyConfig
from .schedule import ArrivalPattern, ScheduleConfig
from .scope import TargetScope

__all__ = [
    "SafetyLimits",
    "AuditConfig",
    "VisitResult",
    "LevelResult",
    "AuditReport",
]


@dataclass
class SafetyLimits:
    """
    Hard ceilings the runner enforces regardless of what the schedule asks for.

    A schedule is a plan; these are the brakes. They exist because the most
    common way an authorized audit causes real damage is a misconfigured count
    or pattern, not malice -- and once the traffic is leaving, a wrong request
    cannot be un-sent.
    """

    #: Absolute ceiling on requests, across the whole audit. 0 = unlimited.
    max_requests: int = 20000
    #: Ceiling on concurrent visitor sessions / browser contexts.
    max_concurrency: int = 8
    #: Ceiling on requests per second, computed from a rolling window.
    max_rps: float = 10.0
    #: Ceiling on arrivals per minute. 0 = no ceiling.
    max_arrivals_per_minute: int = 60
    #: Ceiling on visitors in any single proxy's rotation slot. 0 = unlimited.
    max_per_proxy: int = 0
    #: Abort the whole audit after this many consecutive transport errors.
    abort_after_consecutive_errors: int = 15

    def to_dict(self) -> dict:
        return {
            "max_requests": self.max_requests,
            "max_concurrency": self.max_concurrency,
            "max_rps": self.max_rps,
            "max_arrivals_per_minute": self.max_arrivals_per_minute,
            "max_per_proxy": self.max_per_proxy,
            "abort_after_consecutive_errors": self.abort_after_consecutive_errors,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SafetyLimits":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})


@dataclass
class AuditConfig:
    """Everything needed to run an audit."""

    target_url: str
    scope: TargetScope = field(default_factory=TargetScope)
    #: Highest rung of the ladder to climb. Use max_evasion_level for a full audit.
    max_evasion_level: int = 3
    #: Alternative to max_evasion_level: run exactly these levels.
    levels: Optional[List[int]] = None
    visitor_count: int = 100
    duration_hours: float = 1.0
    pattern: str = ArrivalPattern.HUMAN_DIURNAL
    journey: JourneyConfig = field(default_factory=JourneyConfig)
    limits: SafetyLimits = field(default_factory=SafetyLimits)
    #: Proxy rotation config (mapping) or a rotator; used from L4 up.
    proxy: Optional[Any] = None
    #: Seed for reproducibility. None means random.
    seed: Optional[int] = None
    #: Extra in-scope paths to sample, e.g. ["/pricing", "/docs"].
    paths: List[str] = field(default_factory=list)

    #: Headers every request carries. Use this to supply a session cookie or an
    #: authorization token when auditing a page behind a login, so the audit can
    #: reach the protected surface instead of measuring the login redirect.
    extra_headers: Dict[str, str] = field(default_factory=dict)
    #: Seconds to wait between completing one level and starting the next.
    cooldown_between_levels_s: float = 30.0
    #: Where per-level artifacts (screenshots, HTML) are written. None = none.
    artifact_dir: Optional[str] = None
    #: Keep the browser open between visitors (much cheaper) or relaunch per visit.
    reuse_browser: bool = True
    #: Force the headed/headless posture for every browser rung.
    #:
    #: None (the default) honours each rung's own posture, which is what makes the
    #: ladder mean anything -- L1 is defined by being headless and L2 by being
    #: headful. True/False overrides the posture for a host that cannot provide a
    #: display (or an operator who wants every rung run the same way); the runner
    #: announces the override when it contradicts a rung, so a verdict is never
    #: silently credited to a posture that was not actually used.
    headless: Optional[bool] = None

    def selected_levels(self) -> List[EvasionLevel]:
        if self.levels:
            return [level_by_id(i) for i in self.levels]
        return levels_up_to(self.max_evasion_level)

    def schedule_config(self) -> ScheduleConfig:
        return ScheduleConfig(
            visitor_count=self.visitor_count,
            duration_hours=self.duration_hours,
            pattern=self.pattern,
            max_arrivals_per_minute=self.limits.max_arrivals_per_minute,
        )

    def validate(self) -> List[str]:
        """Return a list of problems; empty means the config is runnable."""
        problems: List[str] = []
        if not self.target_url:
            problems.append("target_url is required")
        if not self.scope.hosts:
            problems.append("scope must name at least one host")
        elif not self.scope.acknowledged:
            problems.append(
                "scope is not acknowledged -- confirm you are authorized to test it"
            )
        if self.target_url and self.scope.hosts:
            from urllib.parse import urlparse

            host = (urlparse(self.target_url).hostname or "").lower()
            if host and not self.scope.permits(host):
                problems.append(
                    f"target_url host {host!r} is not inside the declared scope "
                    f"({self.scope.describe()})"
                )
        if self.visitor_count < 0:
            problems.append("visitor_count cannot be negative")
        if self.duration_hours <= 0:
            problems.append("duration_hours must be positive")
        if self.max_evasion_level < 0 or self.max_evasion_level > 6:
            problems.append("max_evasion_level must be between 0 and 6")
        if self.visitor_count > self.limits.max_requests > 0:
            problems.append(
                f"visitor_count ({self.visitor_count}) exceeds max_requests "
                f"({self.limits.max_requests}); the audit would be cut off partway"
            )
        return problems

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "scope": self.scope.to_dict(),
            "max_evasion_level": self.max_evasion_level,
            "levels": self.levels,
            "visitor_count": self.visitor_count,
            "duration_hours": self.duration_hours,
            "pattern": self.pattern,
            "limits": self.limits.to_dict(),
            "seed": self.seed,
            "paths": list(self.paths),
            "cooldown_between_levels_s": self.cooldown_between_levels_s,
            "reuse_browser": self.reuse_browser,
            "headless": self.headless,
        }


@dataclass
class VisitResult:
    """What happened to one visitor."""

    visitor_index: int
    level_id: int
    started_at: float
    finished_at: float = 0.0
    verdict: str = Verdict.ERROR
    vendors: List[str] = field(default_factory=list)
    reason: str = ""
    http_status: Optional[int] = None
    requests_made: int = 0
    pages_loaded: int = 0
    source: str = ""
    referer: Optional[str] = None
    proxy_label: Optional[str] = None
    exit_ip: Optional[str] = None
    launcher_error: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    #: Per-request latencies in seconds.
    latencies: List[float] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    @property
    def detected(self) -> bool:
        return self.verdict in Verdict.DETECTED

    @property
    def p50_latency(self) -> Optional[float]:
        return _percentile(self.latencies, 50)

    @property
    def p95_latency(self) -> Optional[float]:
        return _percentile(self.latencies, 95)

    def to_dict(self) -> dict:
        return {
            "visitor_index": self.visitor_index,
            "level_id": self.level_id,
            "verdict": self.verdict,
            "detected": self.detected,
            "vendors": list(self.vendors),
            "reason": self.reason,
            "http_status": self.http_status,
            "requests_made": self.requests_made,
            "pages_loaded": self.pages_loaded,
            "duration_s": round(self.duration_s, 3),
            "source": self.source,
            "referer": self.referer,
            "proxy_label": self.proxy_label,
            "exit_ip": self.exit_ip,
            "launcher_error": self.launcher_error,
            "evidence": list(self.evidence),
            "latencies": [round(x, 4) for x in self.latencies],
            "p50_latency": self.p50_latency,
            "p95_latency": self.p95_latency,
        }


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 4)
    rank = (pct / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return round(ordered[low] + frac * (ordered[high] - ordered[low]), 4)


@dataclass
class LevelResult:
    """Aggregate outcome for one rung of the ladder."""

    level: EvasionLevel
    visits: List[VisitResult] = field(default_factory=list)
    scheduled: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0
    aborted: bool = False
    abort_reason: str = ""

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {v: 0 for v in Verdict.ALL}
        for visit in self.visits:
            out[visit.verdict] = out.get(visit.verdict, 0) + 1
        return out

    @property
    def completed(self) -> int:
        return len(self.visits)

    @property
    def allowed(self) -> int:
        return sum(1 for v in self.visits if v.verdict == Verdict.ALLOWED)

    @property
    def detected(self) -> int:
        return sum(1 for v in self.visits if v.detected)

    @property
    def detection_rate(self) -> float:
        return 0.0 if not self.visits else self.detected / len(self.visits)

    @property
    def bypass_rate(self) -> float:
        return 0.0 if not self.visits else self.allowed / len(self.visits)

    def vendors_seen(self) -> List[str]:
        seen: Dict[str, int] = {}
        for visit in self.visits:
            for vendor in visit.vendors:
                seen[vendor] = seen.get(vendor, 0) + 1
        return sorted(seen, key=lambda v: (-seen[v], v))

    def p95_latency(self) -> Optional[float]:
        all_latencies = [x for v in self.visits for x in v.latencies]
        return _percentile(all_latencies, 95)

    def to_dict(self) -> dict:
        return {
            "level_id": self.level.id,
            "level_key": self.level.key,
            "level_name": self.level.name,
            "scheduled": self.scheduled,
            "completed": self.completed,
            "allowed": self.allowed,
            "detected": self.detected,
            "detection_rate": round(self.detection_rate, 4),
            "bypass_rate": round(self.bypass_rate, 4),
            "counts": self.counts(),
            "vendors": self.vendors_seen(),
            "p95_latency": self.p95_latency(),
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "duration_s": round(max(0.0, self.finished_at - self.started_at), 2),
            "visits": [v.to_dict() for v in self.visits],
        }


@dataclass
class AuditReport:
    """The full audit: every rung, plus the conclusion."""

    config: AuditConfig
    levels: List[LevelResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    aborted: bool = False
    abort_reason: str = ""
    schedule_warnings: List[str] = field(default_factory=list)

    @property
    def total_visits(self) -> int:
        return sum(lr.completed for lr in self.levels)

    @property
    def total_requests(self) -> int:
        return sum(v.requests_made for lr in self.levels for v in lr.visits)

    def first_effective_level(self) -> Optional[LevelResult]:
        """
        The lowest rung the defenses actually stopped.

        This is the headline finding: it is the defense that is doing the work.
        Below it, controls are already defeated; a defense that never holds is
        not a defense.
        """
        for lr in self.levels:
            if lr.visits and lr.detection_rate >= 0.5:
                return lr
        return None

    def highest_bypassing_level(self) -> Optional[LevelResult]:
        """The most advanced posture that still got through cleanly."""
        bypassing = [lr for lr in self.levels if lr.visits and lr.bypass_rate >= 0.5]
        return bypassing[-1] if bypassing else None

    def to_dict(self) -> dict:
        return {
            "target_url": self.config.target_url,
            "scope": self.config.scope.describe(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(max(0.0, self.finished_at - self.started_at), 2),
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "schedule_warnings": list(self.schedule_warnings),
            "config": self.config.to_dict(),
            "totals": {
                "visits": self.total_visits,
                "requests": self.total_requests,
            },
            "levels": [lr.to_dict() for lr in self.levels],
        }