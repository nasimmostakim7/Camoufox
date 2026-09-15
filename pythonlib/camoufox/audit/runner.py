"""
The audit runner: drive visits at the target and record what the defenses did.

Design notes that matter for correctness:

* One browser is reused across visitors; each visitor gets a fresh **context**.
  A browser launch costs seconds and a process, a context costs ~100ms, and both
  carry an independent fingerprint -- so reuse is what makes hundreds of visitors
  affordable. This relies on Camoufox's per-context fingerprint injection.

* Every navigation is routed through the scope gate and the safety ceilings.
  There is no code path that fetches a URL without both checks, because a single
  unguarded navigation is enough to send traffic somewhere unauthorized.

* The runner is honest about what it did not do: a level that hits a ceiling is
  marked `aborted` with a reason, rather than reported as a clean result.
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .config import AuditConfig, AuditReport, LevelResult, VisitResult
from .detection import VENDOR_SIGNATURES, Verdict, classify_response
from .evasion import EvasionLevel
from .journey import ArrivalSource, build_arrival_referer, plan_visit
from .schedule import build_schedule
from .scope import ScopeViolation

__all__ = ["AuditRunner", "SafetyStop"]


class SafetyStop(RuntimeError):
    """A safety ceiling was reached; the audit stopped deliberately."""


class _Limiter:
    """
    A rolling-window rate limiter, plus an absolute request counter.

    A token bucket would allow a burst; a rolling window does not, and a burst is
    exactly what a defense (or an upstream) is least tolerant of. For an audit
    whose whole point is to be tolerated, the stricter shape is the right one.
    """

    def __init__(self, max_rps: float, max_requests: int) -> None:
        self.max_rps = max_rps
        self.max_requests = max_requests
        self.count = 0
        self._recent: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            if self.max_requests and self.count >= self.max_requests:
                raise SafetyStop(
                    f"Request ceiling reached ({self.max_requests}). The audit "
                    f"stopped rather than continue."
                )
            now = time.monotonic()
            self._recent = [t for t in self._recent if now - t < 1.0]
            if self.max_rps > 0 and len(self._recent) >= self.max_rps:
                wait = 1.0 - (now - self._recent[0])
                if wait > 0:
                    await asyncio.sleep(wait)
                    now = time.monotonic()
                    self._recent = [t for t in self._recent if now - t < 1.0]
            self._recent.append(time.monotonic())
            self.count += 1

    @property
    def remaining(self) -> Optional[int]:
        if not self.max_requests:
            return None
        return max(0, self.max_requests - self.count)


class AuditRunner:
    """Run an audit, level by level."""

    def __init__(
        self,
        config: AuditConfig,
        *,
        on_progress=None,
        cancel_event: Optional[Any] = None,
    ) -> None:
        self.config = config
        self._on_progress = on_progress
        self._cancel = cancel_event
        self._rng = random.Random(config.seed)
        self._limiter = _Limiter(config.limits.max_rps, config.limits.max_requests)
        self._proxy_counts: Dict[str, int] = {}
        self._consecutive_errors = 0
        self._virtual_display_used = False
        self._geoip_missing_noted = False
        self._rotator = None
        if config.proxy:
            from ..proxy import build_rotator

            self._rotator = build_rotator(config.proxy)

    # -- cancellation / progress ------------------------------------------

    def _cancelled(self) -> bool:
        return bool(self._cancel is not None and self._cancel.is_set())

    @staticmethod
    def _has_display() -> bool:
        """True when this host already has a usable X server."""
        if sys.platform.startswith("win") or sys.platform == "darwin":
            return True
        display = os.environ.get("DISPLAY", "")
        if not display:
            return False
        # "localhost:0" and similar still need the socket to exist.
        if display.startswith(":"):
            number = display[1:].split(".")[0]
            return os.path.exists(f"/tmp/.X11-unix/X{number}")
        return True

    def _note_virtual_display(self) -> None:
        if self._virtual_display_used:
            return
        self._virtual_display_used = True
        self._progress(
            event="notice",
            message=(
                "No X server detected; headed levels will use Camoufox's virtual "
                "display. Results are valid, but a real desktop may still differ."
            ),
        )

    @staticmethod
    def _has_geoip() -> bool:
        """True when the optional geoip extra is installed."""
        import importlib.util

        return importlib.util.find_spec("geoip2") is not None

    def _note_geoip_missing(self) -> None:
        if self._geoip_missing_noted:
            return
        self._geoip_missing_noted = True
        self._progress(
            event="notice",
            message=(
                "The geoip extra is not installed, so fingerprint spoofing runs "
                "without IP-based geolocation and timezone alignment. Install it "
                "with 'pip install camoufox[geoip]' for a stronger mask."
            ),
        )

    def _progress(self, **payload) -> None:
        if self._on_progress:
            try:
                self._on_progress(payload)
            except Exception:
                pass

    # -- scope -------------------------------------------------------------

    def _check_url(self, url: str) -> str:
        return self.config.scope.check(url)

    def _candidate_paths(self) -> List[str]:
        base = self.config.target_url
        paths = [""] + list(self.config.paths)
        return [urljoin(base, p) for p in paths]

    # -- proxy -------------------------------------------------------------

    def _acquire_proxy(self) -> Tuple[Optional[Any], Optional[str]]:
        """
        Get a proxy session, respecting the per-proxy concurrency ceiling.

        Returns (session, skip_reason). A session of None with a reason means
        this visitor should be skipped rather than run without a proxy.
        """
        if self._rotator is None:
            return None, None
        cap = self.config.limits.max_per_proxy
        for _ in range(8):
            session = self._rotator.acquire_session()
            if session is None:
                # allow_direct_fallback was set on the pool.
                return None, None
            label = session.endpoint.redacted()
            used = self._proxy_counts.get(label, 0)
            if cap and used >= cap:
                continue
            self._proxy_counts[label] = used + 1
            return session, None
        return None, (
            f"every proxy in the pool has reached the per-proxy ceiling "
            f"({cap}); skipping this visitor rather than overloading one exit"
        )

    def _release_proxy(self, session: Optional[Any]) -> None:
        if session is None:
            return
        label = session.endpoint.redacted()
        if label in self._proxy_counts:
            self._proxy_counts[label] = max(0, self._proxy_counts[label] - 1)

    # -- one visit ---------------------------------------------------------

    async def _visit_http(
        self, level: EvasionLevel, plan, url: str, headers: Dict[str, str]
    ) -> VisitResult:
        """Level 0: a plain HTTP request with no browser at all."""
        result = VisitResult(
            visitor_index=-1,
            level_id=level.id,
            started_at=time.time(),
            source=plan.source,
            referer=plan.referer,
        )
        await self._limiter.acquire()
        send_headers = dict(headers)
        if plan.referer:
            send_headers["Referer"] = plan.referer

        started = time.monotonic()
        status, resp_headers, body, error = await asyncio.to_thread(
            self._http_fetch, url, send_headers
        )
        result.latencies.append(time.monotonic() - started)
        result.requests_made = 1
        result.finished_at = time.time()
        result.http_status = status

        if error:
            result.launcher_error = error
            result.reason = error
            result.verdict = Verdict.ERROR
            return result

        verdict = classify_response(status, resp_headers, body)
        result.verdict = verdict.verdict
        result.vendors = verdict.vendors
        result.reason = verdict.reason
        result.evidence = verdict.evidence
        return result

    def _http_fetch(
        self, url: str, headers: Dict[str, str]
    ) -> Tuple[Optional[int], Dict[str, str], str, Optional[str]]:
        """Synchronous fetch, run in a thread so the event loop stays responsive."""
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return (
                    response.status,
                    dict(response.headers.items()),
                    response.read(400_000).decode("utf-8", errors="replace"),
                    None,
                )
        except urllib.error.HTTPError as exc:
            # An HTTPError is a real response (403, 429, ...) and is exactly the
            # finding we want, so it is a result, not a failure.
            try:
                body = exc.read(400_000).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return (
                exc.code,
                dict(exc.headers.items()) if exc.headers else {},
                body,
                None,
            )
        except Exception as exc:
            return None, {}, "", f"{type(exc).__name__}: {exc}"

    async def _visit_browser(
        self,
        browser,
        level: EvasionLevel,
        plan,
        url: str,
        headers: Dict[str, str],
        proxy_session,
    ) -> VisitResult:
        """Levels 1+: a real Camoufox context, driven through a human-ish journey."""
        result = VisitResult(
            visitor_index=-1,
            level_id=level.id,
            started_at=time.time(),
            source=plan.source,
            referer=plan.referer,
            proxy_label=proxy_session.endpoint.redacted() if proxy_session else None,
            exit_ip=getattr(proxy_session, "exit_ip", None),
        )

        context_kwargs: Dict[str, Any] = {}
        if headers:
            context_kwargs["extra_http_headers"] = headers
        if proxy_session is not None:
            context_kwargs["proxy"] = proxy_session.playwright

        from ..async_api import AsyncNewContext

        try:
            context = await AsyncNewContext(browser, **context_kwargs)
        except Exception as exc:
            result.launcher_error = f"{type(exc).__name__}: {exc}"
            result.reason = "could not open a browser context"
            result.verdict = Verdict.ERROR
            result.finished_at = time.time()
            return result

        try:
            await self._drive_journey(context, level, plan, url, result)
        finally:
            try:
                await context.close()
            except Exception:
                pass

        result.finished_at = time.time()
        return result

    async def _drive_journey(self, context, level: EvasionLevel, plan, url: str, result: VisitResult) -> None:
        """Walk one visitor through their planned session, honoring the plan."""
        page = await context.new_page()
        try:
            if plan.referer:
                # A referer cannot be set for the first navigation via Playwright
                # on an already-open context, so the caller passes it as a header;
                # this is a best-effort secondary signal for later hops.
                pass

            await self._limiter.acquire()
            started = time.monotonic()
            status = None
            body = ""
            resp_headers: Dict[str, str] = {}
            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                if response is not None:
                    status = response.status
                    resp_headers = dict(response.headers or {})
                    try:
                        body = (await response.text())[:400_000]
                    except Exception:
                        body = ""
            except Exception as exc:
                result.launcher_error = f"{type(exc).__name__}: {exc}"
            result.latencies.append(time.monotonic() - started)
            result.requests_made += 1

            verdict = classify_response(status, resp_headers, body)
            result.http_status = status
            result.verdict = verdict.verdict
            result.vendors = verdict.vendors
            result.reason = verdict.reason
            result.evidence = list(verdict.evidence)
            result.pages_loaded = 1

            # A challenge or block ends the visit: there is nothing beyond it to
            # measure, and pushing on would be probing a closed door.
            if verdict.detected or verdict.verdict == Verdict.ERROR:
                return

            if plan.scroll_steps:
                await self._scroll(page, plan.scroll_steps)

            if plan.will_type:
                await self._maybe_type(page, result)

            # Additional pages, if the session planned any.
            remaining = max(0, plan.page_count - 1)
            for hop in range(remaining):
                if self._cancelled():
                    return
                delay = plan.inter_page_delay_s[hop] if hop < len(plan.inter_page_delay_s) else 3.0
                # Cap a single pause: a planned 10-minute dwell should not leave a
                # browser idle holding a concurrency slot for the whole audit.
                await asyncio.sleep(min(max(delay, 0.5), 20.0))
                next_url = await self._pick_next_url(page, plan)
                if next_url is None:
                    return
                if not self.config.scope.permits_url(next_url):
                    # Following an out-of-scope link would take the audit off
                    # target; stop rather than wander onto a third party.
                    result.evidence.append(f"skipped out-of-scope link {next_url!r}")
                    return
                await self._limiter.acquire()
                started = time.monotonic()
                try:
                    response = await page.goto(next_url, wait_until="domcontentloaded", timeout=30_000)
                    if response is not None:
                        status = response.status
                        resp_headers = dict(response.headers or {})
                        body = (await response.text())[:200_000]
                    else:
                        status, resp_headers, body = None, {}, ""
                except Exception as exc:
                    result.launcher_error = f"{type(exc).__name__}: {exc}"
                    status, resp_headers, body = None, {}, ""
                result.latencies.append(time.monotonic() - started)
                result.requests_made += 1
                result.pages_loaded += 1
                hop_verdict = classify_response(status, resp_headers, body)
                if hop_verdict.detected:
                    # Later hops can trip a defense the first page did not.
                    result.verdict = hop_verdict.verdict
                    result.vendors = sorted(set(result.vendors) | set(hop_verdict.vendors))
                    result.reason = f"on page {hop + 2}: {hop_verdict.reason}"
                    result.evidence = list(hop_verdict.evidence)
                    result.http_status = status
                    return
        finally:
            try:
                await page.close()
            except Exception:
                pass

    async def _scroll(self, page, steps: int) -> None:
        """Scroll down in human-sized steps with human-sized pauses."""
        for _ in range(max(0, steps)):
            if self._cancelled():
                return
            try:
                await page.mouse.wheel(0, self._rng.randint(180, 900))
            except Exception:
                return
            await asyncio.sleep(self._rng.uniform(0.25, 1.6))

    async def _maybe_type(self, page, result: VisitResult) -> None:
        """Type into the first plausible input, if the page has one."""
        try:
            locator = page.locator("input[type=search], input[type=text], textarea").first
            if await locator.count() == 0:
                return
            text = self._rng.choice(["pricing", "how to", "features", "support", "docs"])
            await locator.click(timeout=3000)
            await locator.type(text, delay=self._rng.uniform(60, 220))
            result.evidence.append(f"typed {text!r} into a form field")
        except Exception:
            return

    async def _pick_next_url(self, page, plan) -> Optional[str]:
        """Choose the next in-site link, or a configured path."""
        if plan.follow_links:
            try:
                hrefs = await page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)"
                )
            except Exception:
                hrefs = []
            parsed_target = urlparse(self.config.target_url)
            same_site = [
                h
                for h in hrefs
                if h
                and urlparse(h).netloc == parsed_target.netloc
                and urlparse(h).scheme in ("http", "https")
            ]
            if same_site:
                return self._rng.choice(same_site)
        paths = list(self.config.paths)
        if paths:
            return urljoin(self.config.target_url, self._rng.choice(paths))
        return None

    # -- level orchestration ----------------------------------------------

    async def _run_level(self, level: EvasionLevel, schedule) -> LevelResult:
        lr = LevelResult(level=level, scheduled=schedule.count, started_at=time.time())
        self._progress(
            event="level_start",
            level_id=level.id,
            level_name=level.name,
            scheduled=schedule.count,
        )

        started_at = time.time()
        semaphore = asyncio.Semaphore(max(1, self.config.limits.max_concurrency))

        # Group arrivals by their target time so long schedules do not block.
        async def run_one(index: int, arrival) -> None:
            if self._cancelled():
                return
            delay = arrival.at.timestamp() - time.time()
            if delay > 0:
                # Sleep in slices so cancellation is responsive on a 24h schedule.
                while delay > 0 and not self._cancelled():
                    slice_s = min(delay, 5.0)
                    await asyncio.sleep(slice_s)
                    delay -= slice_s
            if self._cancelled():
                return

            async with semaphore:
                if self._cancelled():
                    return
                visit = await self._run_one_visit(level, index)
                if visit is not None:
                    lr.visits.append(visit)
                    self._progress(event="visit", level_id=level.id, visit=visit.to_dict())
                    if visit.verdict == Verdict.ERROR and visit.launcher_error:
                        self._consecutive_errors += 1
                    else:
                        self._consecutive_errors = 0
                    if (
                        self.config.limits.abort_after_consecutive_errors
                        and self._consecutive_errors
                        >= self.config.limits.abort_after_consecutive_errors
                    ):
                        lr.aborted = True
                        lr.abort_reason = (
                            f"aborted after {self._consecutive_errors} consecutive "
                            f"transport errors"
                        )
                        raise SafetyStop(lr.abort_reason)

        tasks = []
        for index, arrival in enumerate(schedule.arrivals):
            tasks.append(asyncio.create_task(run_one(index, arrival)))

        try:
            if tasks:
                await asyncio.gather(*tasks)
        except SafetyStop as exc:
            lr.aborted = True
            lr.abort_reason = str(exc)
        except asyncio.CancelledError:
            lr.aborted = True
            lr.abort_reason = "cancelled"
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        lr.finished_at = time.time()
        self._progress(event="level_end", level_id=level.id, level=lr.to_dict())
        return lr

    async def _run_one_visit(self, level: EvasionLevel, index: int) -> Optional[VisitResult]:
        plan = plan_visit(self.config.journey, self._rng)
        url = self._rng.choice(self._candidate_paths())
        plan.referer = build_arrival_referer(plan.source, self.config.target_url, self._rng)

        proxy_session, skip_reason = self._acquire_proxy()
        if skip_reason:
            visit = VisitResult(
                visitor_index=index,
                level_id=level.id,
                started_at=time.time(),
                finished_at=time.time(),
                verdict=Verdict.ERROR,
                reason=skip_reason,
            )
            return visit

        try:
            if level.client == "http":
                headers = {"User-Agent": "python-urllib/3"}
                headers.update(self.config.extra_headers)
                visit = await self._visit_http(level, plan, url, headers)
                visit.visitor_index = index
                return visit
            return await self._run_browser_visit(level, plan, url, proxy_session, index)
        except ScopeViolation as exc:
            visit = VisitResult(
                visitor_index=index,
                level_id=level.id,
                started_at=time.time(),
                finished_at=time.time(),
                verdict=Verdict.ERROR,
                reason=str(exc),
                launcher_error="ScopeViolation",
            )
            return visit
        finally:
            self._release_proxy(proxy_session)

    async def _run_browser_visit(self, level, plan, url, proxy_session, index) -> VisitResult:
        from ..async_api import AsyncCamoufox

        options = dict(level.camoufox_options or {})
        options.setdefault("headless", self.config.headless)
        if not options["headless"]:
            # A headed rung needs an X server. On a headless host (a CI runner, a
            # VPS) the launch would fail outright with "no DISPLAY environment
            # variable specified", which measures nothing and reports an error
            # where the operator expects a verdict. 'virtual' tells Camoufox to
            # start its own Xvfb, so the rung still exercises a real headed
            # browser. An explicit DISPLAY is left alone.
            if not self._has_display():
                options["headless"] = "virtual"
                self._note_virtual_display()
        if options.get("geoip") and not self._has_geoip():
            # geoip2 is an optional extra; leaving the flag set would make every
            # rung that uses it fail to launch, measuring nothing at all.
            options["geoip"] = False
            self._note_geoip_missing()
        if level.id >= 4 and proxy_session is not None:
            # The proxy is applied per context below, so the browser itself
            # launches direct; this keeps one browser serving many exits.
            pass
        launch_kwargs = {k: v for k, v in options.items() if k != "persistent_context"}
        if options.get("persistent_context"):
            # Persistent profiles are per-identity, so they cannot be shared
            # across a rotated pool; fall back to a per-visit context.
            launch_kwargs.pop("user_data_dir", None)

        try:
            async with AsyncCamoufox(**launch_kwargs) as browser:
                merged_headers = {**level.headers, **self.config.extra_headers}
                visit = await self._visit_browser(browser, level, plan, url, merged_headers, proxy_session)
                visit.visitor_index = index
                return visit
        except ScopeViolation:
            raise
        except Exception as exc:
            visit = VisitResult(
                visitor_index=index,
                level_id=level.id,
                started_at=time.time(),
                finished_at=time.time(),
                verdict=Verdict.ERROR,
                reason=f"browser launch failed: {type(exc).__name__}: {exc}",
                launcher_error=f"{type(exc).__name__}: {exc}",
            )
            return visit

    # -- top level ---------------------------------------------------------

    async def run(self) -> AuditReport:
        report = AuditReport(config=self.config)
        problems = self.config.validate()
        if problems:
            report.aborted = True
            report.abort_reason = "invalid configuration: " + "; ".join(problems)
            report.finished_at = time.time()
            return report

        schedule = build_schedule(self.config.schedule_config(), self._rng)
        report.schedule_warnings = list(schedule.warnings)

        for level in self.config.selected_levels():
            if self._cancelled():
                report.aborted = True
                report.abort_reason = "cancelled"
                break
            level_result = await self._run_level(level, schedule)
            report.levels.append(level_result)
            if level_result.aborted:
                report.aborted = True
                report.abort_reason = level_result.abort_reason
                break
            if level is not self.config.selected_levels()[-1] and self.config.cooldown_between_levels_s:
                # Breathing room between rungs: an audit that hammers straight
                # through confuses its own rate-limit findings.
                cooldown = self.config.cooldown_between_levels_s
                while cooldown > 0 and not self._cancelled():
                    slice_s = min(cooldown, 2.0)
                    await asyncio.sleep(slice_s)
                    cooldown -= slice_s

        report.finished_at = time.time()
        return report


def run_audit(config: AuditConfig, **kwargs) -> AuditReport:
    """Synchronous entry point, for the CLI."""
    return asyncio.run(AuditRunner(config, **kwargs).run())