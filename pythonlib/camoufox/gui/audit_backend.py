"""
QML bridge for the WAF / bot-defense audit tab.

The audit runs on a worker thread and reports back through signals, because the
GUI must stay responsive while a 24-hour schedule is pending -- a blocked event
loop would make Stop unclickable, which is the one control that must always work.

Two things are deliberately enforced here rather than in QML:

* the authorization acknowledgment and the scope, so a UI bug cannot start an
  unauthorized run;
* the safety ceilings, so a mistyped visitor count cannot become real traffic.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import (
    Property,
    QAbstractListModel,
    QModelIndex,
    QObject,
    Qt,
    QThread,
    Signal,
    Slot,
)

from ..audit import (
    AuditConfig,
    AuditRunner,
    SafetyLimits,
    TargetScope,
    build_schedule,
)
from ..audit.detection import Verdict as _Verdict
from ..audit.report import build_findings, render_text, write_report
from ..audit.schedule import ArrivalPattern

__all__ = ["AuditVisitModel", "AuditBackend"]


_VERDICT_COLOR = {
    _Verdict.ALLOWED: "#6b9e7e",
    _Verdict.CHALLENGED: "#d7a44a",
    _Verdict.RATE_LIMITED: "#d7a44a",
    _Verdict.BLOCKED: "#f14c4c",
    _Verdict.ERROR: "#a0a0a0",
}


class AuditVisitModel(QAbstractListModel):
    """Live list of visits for the results table."""

    VisitorRole = Qt.ItemDataRole.UserRole + 1
    LevelRole = Qt.ItemDataRole.UserRole + 2
    VerdictRole = Qt.ItemDataRole.UserRole + 3
    StatusRole = Qt.ItemDataRole.UserRole + 4
    ReasonRole = Qt.ItemDataRole.UserRole + 5
    ColorRole = Qt.ItemDataRole.UserRole + 6
    SourceRole = Qt.ItemDataRole.UserRole + 7
    ProxyRole = Qt.ItemDataRole.UserRole + 8
    RequestsRole = Qt.ItemDataRole.UserRole + 9

    #: Keep the table bounded; a 24h run can produce thousands of rows and the
    #: operator only ever reads the tail. Dropping the oldest keeps memory flat.
    MAX_ROWS = 500

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[Dict[str, Any]] = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._rows)):
            return None
        row = self._rows[index.row()]
        return {
            self.VisitorRole: row.get("visitor_index", 0),
            self.LevelRole: row.get("level_name", ""),
            self.VerdictRole: row.get("verdict", ""),
            self.StatusRole: row.get("http_status") or "-",
            self.ReasonRole: row.get("reason", ""),
            self.ColorRole: _VERDICT_COLOR.get(row.get("verdict"), "#a0a0a0"),
            self.SourceRole: row.get("source", ""),
            self.ProxyRole: row.get("proxy_label") or "-",
            self.RequestsRole: row.get("requests_made", 0),
        }.get(role)

    def roleNames(self):
        return {
            self.VisitorRole: b"visitorIndex",
            self.LevelRole: b"levelName",
            self.VerdictRole: b"verdict",
            self.StatusRole: b"httpStatus",
            self.ReasonRole: b"reason",
            self.ColorRole: b"verdictColor",
            self.SourceRole: b"source",
            self.ProxyRole: b"proxyLabel",
            self.RequestsRole: b"requestsMade",
        }

    def append(self, row: Dict[str, Any]) -> None:
        if len(self._rows) >= self.MAX_ROWS:
            drop = len(self._rows) - self.MAX_ROWS + 1
            self.beginRemoveRows(QModelIndex(), 0, drop - 1)
            del self._rows[:drop]
            self.endRemoveRows()
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(row)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self._rows)


class AuditWorker(QThread):
    """Runs one audit off the GUI thread."""

    progress = Signal(dict)
    finished_report = Signal(dict, str)
    failed = Signal(str)

    def __init__(self, config: AuditConfig, out_dir: Optional[str], parent=None):
        super().__init__(parent)
        self.config = config
        self.out_dir = out_dir
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            report = asyncio.run(
                AuditRunner(
                    self.config,
                    on_progress=self._emit_progress,
                    cancel_event=self._cancel,
                ).run()
            )
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return

        payload = report.to_dict()
        payload["findings"] = build_findings(report)
        payload["text_report"] = render_text(report)

        written: Dict[str, str] = {}
        if self.out_dir:
            try:
                written = write_report(report, self.out_dir)
            except Exception as exc:
                payload.setdefault("findings", []).append(
                    f"Could not write reports to {self.out_dir}: {exc}"
                )
        payload["written"] = written
        self.finished_report.emit(payload, json.dumps(payload, default=str))

    def _emit_progress(self, payload: dict) -> None:
        self.progress.emit(payload)


class AuditBackend(QObject):
    """State and slots the Audit tab binds to."""

    changed = Signal()
    visitsChanged = Signal()
    logChanged = Signal()
    runningChanged = Signal()
    summaryChanged = Signal()
    findingsChanged = Signal()
    schedulePreviewChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._visits = AuditVisitModel(self)
        self._running = False
        self._worker: Optional[AuditWorker] = None

        # --- target / scope ---------------------------------------------
        self._target = ""
        self._scope_hosts = ""
        self._allow_subdomains = False
        self._acknowledged = False
        self._ack_note = ""

        # --- traffic plan ------------------------------------------------
        self._visitors = 100
        self._hours = 24.0
        self._pattern_index = 0
        self._max_level = 3
        self._single_level_mode = False
        self._single_level = 5
        self._max_requests = 5000
        self._max_rps = 5.0
        self._max_concurrency = 4
        self._max_per_minute = 30
        self._max_per_proxy = 0
        #: Force headless for every browser rung. False (the default) honours each
        #: rung's own posture, which is what lets L1 be headless and L2 headful;
        #: ticking the box overrides them all, and the run announces the override.
        self._force_headless = False
        self._seed = ""

        # --- proxy --------------------------------------------------------
        self._proxy_mode_index = 0  # 0 none, 1 file, 2 gateway
        self._proxy_file = ""
        self._proxy_gateway = ""
        self._proxy_policy_index = 0

        self._out_dir = ""
        self._log: List[str] = []
        self._findings: List[str] = []
        self._summary: Dict[str, Any] = {}
        self._preview: List[str] = []
        self._preview_summary = ""
        self._error = ""

    # -- models ------------------------------------------------------------

    @Property(QObject, constant=True)
    def visits(self):
        return self._visits

    @Property(list, notify=logChanged)
    def log(self):
        return self._log[-300:]

    @Property(list, notify=findingsChanged)
    def findings(self):
        return self._findings

    @Property("QVariantMap", notify=summaryChanged)
    def summary(self):
        return self._summary

    @Property(list, notify=schedulePreviewChanged)
    def schedulePreview(self):
        return self._preview

    @Property(str, notify=schedulePreviewChanged)
    def schedulePreviewSummary(self):
        return self._preview_summary

    @Slot(result=int)
    def maxPreview(self) -> int:
        """Largest bucket in the arrival preview, for scaling the bar chart."""
        return max(self._preview) if self._preview else 1

    @Property(str, notify=changed)
    def error(self):
        return self._error

    @Property(bool, notify=runningChanged)
    def running(self):
        return self._running

    @Property(bool, notify=changed)
    def canRun(self):
        return bool(
            not self._running
            and self._target
            and self._acknowledged
            and self._scope_hosts.strip()
            and self._visitors > 0
        )

    # -- target ------------------------------------------------------------

    @Property(str, notify=changed)
    def target(self):
        return self._target

    @Slot(str)
    def setTarget(self, value: str) -> None:
        self._target = (value or "").strip()
        # Default the scope to the target's host so the common case is one field.
        if self._target and not self._scope_hosts.strip():
            from urllib.parse import urlparse

            parsed = urlparse(self._target if "//" in self._target else f"//{self._target}")
            if parsed.hostname:
                self._scope_hosts = parsed.hostname
        self.changed.emit()
        self._refresh_preview()

    @Property(str, notify=changed)
    def scopeHosts(self):
        return self._scope_hosts

    @Slot(str)
    def setScopeHosts(self, value: str) -> None:
        self._scope_hosts = value or ""
        self.changed.emit()
        self._refresh_preview()

    @Property(bool, notify=changed)
    def allowSubdomains(self):
        return self._allow_subdomains

    @Slot(bool)
    def setAllowSubdomains(self, value: bool) -> None:
        self._allow_subdomains = bool(value)
        self.changed.emit()
        self._refresh_preview()

    @Property(bool, notify=changed)
    def acknowledged(self):
        return self._acknowledged

    @Slot(bool)
    def setAcknowledged(self, value: bool) -> None:
        self._acknowledged = bool(value)
        self.changed.emit()

    @Property(str, notify=changed)
    def acknowledgmentNote(self):
        return self._ack_note

    @Slot(str)
    def setAcknowledgmentNote(self, value: str) -> None:
        self._ack_note = value or ""
        self.changed.emit()

    # -- traffic plan ------------------------------------------------------

    @Property(int, notify=changed)
    def visitors(self):
        return self._visitors

    @Slot(int)
    def setVisitors(self, value: int) -> None:
        self._visitors = max(0, int(value))
        self.changed.emit()
        self._refresh_preview()

    @Property(float, notify=changed)
    def hours(self):
        return self._hours

    @Slot(float)
    def setHours(self, value: float) -> None:
        self._hours = max(0.01, float(value))
        self.changed.emit()
        self._refresh_preview()

    @Property(list, constant=True)
    def patternOptions(self):
        return ["Human (diurnal)", "Constant", "Ramp up", "Spike", "Sustained"]

    @Property(int, notify=changed)
    def patternIndex(self):
        return self._pattern_index

    @Slot(int)
    def setPatternIndex(self, value: int) -> None:
        self._pattern_index = max(0, min(int(value), len(ArrivalPattern.ALL) - 1))
        self.changed.emit()
        self._refresh_preview()

    @Property(int, notify=changed)
    def maxLevel(self):
        return self._max_level

    @Slot(int)
    def setMaxLevel(self, value: int) -> None:
        self._max_level = max(0, min(int(value), 6))
        self.changed.emit()

    @Property(bool, notify=changed)
    def singleLevelMode(self):
        return self._single_level_mode

    @Slot(bool)
    def setSingleLevelMode(self, value: bool) -> None:
        """Run one rung on its own instead of the ladder from L0.

        The visitor count is pinned by the engine in this mode, so a repeat run
        at the same rung is directly comparable.
        """
        self._single_level_mode = bool(value)
        self.changed.emit()
        self._refresh_preview()

    @Property(int, notify=changed)
    def singleLevel(self):
        return self._single_level

    @Slot(int)
    def setSingleLevel(self, value: int) -> None:
        self._single_level = max(0, min(int(value), 6))
        self.changed.emit()

    @Property(int, notify=changed)
    def maxRequests(self):
        return self._max_requests

    @Slot(int)
    def setMaxRequests(self, value: int) -> None:
        self._max_requests = max(0, int(value))
        self.changed.emit()

    @Property(float, notify=changed)
    def maxRps(self):
        return self._max_rps

    @Slot(float)
    def setMaxRps(self, value: float) -> None:
        self._max_rps = max(0.0, float(value))
        self.changed.emit()

    @Property(int, notify=changed)
    def maxConcurrency(self):
        return self._max_concurrency

    @Slot(int)
    def setMaxConcurrency(self, value: int) -> None:
        self._max_concurrency = max(1, int(value))
        self.changed.emit()

    @Property(int, notify=changed)
    def maxPerMinute(self):
        return self._max_per_minute

    @Slot(int)
    def setMaxPerMinute(self, value: int) -> None:
        self._max_per_minute = max(1, int(value))
        self.changed.emit()
        self._refresh_preview()

    @Property(int, notify=changed)
    def maxPerProxy(self):
        return self._max_per_proxy

    @Slot(int)
    def setMaxPerProxy(self, value: int) -> None:
        self._max_per_proxy = max(0, int(value))
        self.changed.emit()

    @Property(bool, notify=changed)
    def headless(self):
        return self._force_headless

    @Slot(bool)
    def setHeadless(self, value: bool) -> None:
        """Force every browser rung to run headless (True) or honour each rung's
        declared posture (False, the default)."""
        self._force_headless = bool(value)
        self.changed.emit()

    @Property(str, notify=changed)
    def seed(self):
        return self._seed

    @Slot(str)
    def setSeed(self, value: str) -> None:
        self._seed = (value or "").strip()
        self.changed.emit()
        self._refresh_preview()

    # -- proxy -------------------------------------------------------------

    @Property(list, constant=True)
    def proxyModeOptions(self):
        return ["No proxy", "Proxy list file", "Rotating gateway"]

    @Property(int, notify=changed)
    def proxyModeIndex(self):
        return self._proxy_mode_index

    @Slot(int)
    def setProxyModeIndex(self, value: int) -> None:
        self._proxy_mode_index = max(0, min(int(value), 2))
        self.changed.emit()

    @Property(str, notify=changed)
    def proxyFile(self):
        return self._proxy_file

    @Slot(str)
    def setProxyFile(self, value: str) -> None:
        self._proxy_file = (value or "").strip()
        self.changed.emit()

    @Slot(result="QVariantMap")
    def browseProxyFile(self) -> dict:
        """
        Open a file chooser for the proxy list and adopt whatever is picked.

        The chosen path is validated here rather than in QML, so the operator
        sees "37 usable proxies" the moment they pick a file instead of finding
        out when the run starts. Picking a file also sets the field, so the
        displayed path and the path the run will use cannot drift apart.

        QFileDialog needs QtWidgets, which this app does not otherwise use, and
        its native path wants a QApplication rather than the QGuiApplication the
        app creates. Both are handled: the built-in Qt dialog is requested, and
        any failure falls back to telling the operator to paste the path, which
        the text field still accepts.
        """
        try:
            from PySide6.QtWidgets import QFileDialog
        except Exception:
            return {
                "ok": False,
                "path": "",
                "message": "A file chooser is unavailable in this build; paste the path instead.",
            }

        start_dir = str(Path(self._proxy_file).expanduser().parent) if self._proxy_file else str(Path.home())
        try:
            path, _ = QFileDialog.getOpenFileName(
                None,
                "Select a proxy list",
                start_dir,
                "Proxy lists (*.txt *.csv *.list);;All files (*)",
                options=QFileDialog.Option.DontUseNativeDialog,
            )
        except Exception as exc:
            return {
                "ok": False,
                "path": "",
                "message": f"Could not open a file chooser ({exc}); paste the path instead.",
            }

        if not path:
            return {"ok": False, "path": "", "message": "No file selected."}

        self._proxy_file = path
        self.changed.emit()
        result = self.validateProxyFile(path)
        return {"ok": result.get("ok", False), "path": path, "message": result.get("message", "")}

    @Property(str, notify=changed)
    def proxyGateway(self):
        return self._proxy_gateway

    @Slot(str)
    def setProxyGateway(self, value: str) -> None:
        self._proxy_gateway = (value or "").strip()
        self.changed.emit()

    @Property(list, constant=True)
    def proxyPolicyOptions(self):
        return ["Round robin", "Least used", "Random"]

    @Property(int, notify=changed)
    def proxyPolicyIndex(self):
        return self._proxy_policy_index

    @Slot(int)
    def setProxyPolicyIndex(self, value: int) -> None:
        self._proxy_policy_index = max(0, min(int(value), 2))
        self.changed.emit()

    @Property(str, notify=changed)
    def outDir(self):
        return self._out_dir

    @Slot(str)
    def setOutDir(self, value: str) -> None:
        self._out_dir = (value or "").strip()
        self.changed.emit()

    # -- proxy validation --------------------------------------------------

    @Slot(str, result="QVariantMap")
    def validateProxyFile(self, path: str) -> dict:
        """
        Parse a proxy list and report what was usable.

        Passwords are never echoed back; the UI shows redacted endpoints so a
        screenshot of the app does not leak the pool's credentials.
        """
        from ..proxy import parse_proxy_file

        if not path:
            return {"ok": False, "message": "No file selected.", "endpoints": []}
        try:
            endpoints = parse_proxy_file(path)
        except Exception as exc:
            return {"ok": False, "message": str(exc), "endpoints": []}
        if not endpoints:
            return {
                "ok": False,
                "message": "No usable proxies found. Expected one per line.",
                "endpoints": [],
            }
        return {
            "ok": True,
            "message": f"{len(endpoints)} usable proxies.",
            "endpoints": [e.redacted() for e in endpoints],
        }

    # -- schedule preview --------------------------------------------------

    def _refresh_preview(self) -> None:
        """
        Show what the current settings will actually do, before anything runs.

        A count and a duration are easy to set and hard to picture; the preview
        turns them into a concrete arrival pattern so an operator can see that
        1000 visitors over 24h is ~42/hour before they commit to it.
        """
        if self._visitors <= 0 or self._hours <= 0:
            self._preview = []
            self._preview_summary = ""
            self.schedulePreviewChanged.emit()
            return
        try:
            cfg = AuditConfig(
                target_url=self._target or "http://example.invalid/",
                visitor_count=self._visitors,
                duration_hours=self._hours,
                pattern=ArrivalPattern.ALL[self._pattern_index],
                limits=SafetyLimits(max_arrivals_per_minute=self._max_per_minute),
                single_level_mode=self._single_level_mode,
                single_level=self._single_level,
            )
            schedule = build_schedule(cfg.schedule_config())
        except Exception as exc:
            self._preview = []
            self._preview_summary = f"Could not preview: {exc}"
            self.schedulePreviewChanged.emit()
            return

        buckets = 24
        width = self._hours * 3600.0 / buckets
        counts = [0] * buckets
        for arrival in schedule.arrivals:
            idx = min(buckets - 1, int(arrival.offset_s / width)) if width > 0 else 0
            counts[idx] += 1

        self._preview = counts
        gaps = schedule.inter_arrival_seconds()
        per_hour = cfg.visitor_count / self._hours if self._hours else 0
        self._preview_summary = (
            f"{schedule.count} arrivals over {self._hours:g}h (~{per_hour:.1f}/hour). "
            f"Busiest bucket {max(counts) if counts else 0}, quietest "
            f"{min(counts) if counts else 0}. "
            f"Gap {min(gaps):.0f}s-{max(gaps):.0f}s."
            if gaps
            else f"{schedule.count} arrivals."
        )
        if self._single_level_mode:
            self._preview_summary += (
                f" Single-rung mode pins the count to {cfg.visitor_count}."
            )
        self.schedulePreviewChanged.emit()

    # -- run ---------------------------------------------------------------

    @Slot()
    def start(self) -> None:
        if self._running:
            return
        self._error = ""
        self._log = []
        self._findings = []
        self._summary = {}
        self._visits.clear()
        self.findingsChanged.emit()
        self.summaryChanged.emit()
        self.logChanged.emit()
        self.visitsChanged.emit()

        if not self._acknowledged:
            self._error = (
                "Confirm you are authorized to test this target before starting."
            )
            self.changed.emit()
            return

        hosts = [h.strip() for h in self._scope_hosts.replace(",", " ").split() if h.strip()]
        try:
            scope = TargetScope.from_urls(
                hosts, allow_subdomains=self._allow_subdomains, acknowledged=True
            )
        except Exception as exc:
            self._error = f"Invalid scope: {exc}"
            self.changed.emit()
            return

        proxy: Optional[Any] = None
        if self._proxy_mode_index == 1:
            if not self._proxy_file:
                self._error = "Select a proxy list file, or choose 'No proxy'."
                self.changed.emit()
                return
            proxy = {
                "mode": "file",
                "file": self._proxy_file,
                "policy": ["round_robin", "least_used", "random"][self._proxy_policy_index],
            }
        elif self._proxy_mode_index == 2:
            if not self._proxy_gateway:
                self._error = "Enter a gateway URL, or choose 'No proxy'."
                self.changed.emit()
                return
            proxy = {"mode": "gateway", "gateway": self._proxy_gateway}

        seed: Optional[int] = None
        if self._seed:
            try:
                seed = int(self._seed)
            except ValueError:
                self._error = "Seed must be a whole number, or empty."
                self.changed.emit()
                return

        config = AuditConfig(
            target_url=self._target,
            scope=scope,
            max_evasion_level=self._max_level,
            single_level_mode=self._single_level_mode,
            single_level=self._single_level,
            visitor_count=self._visitors,
            duration_hours=self._hours,
            pattern=ArrivalPattern.ALL[self._pattern_index],
            limits=SafetyLimits(
                max_requests=self._max_requests,
                max_rps=self._max_rps,
                max_concurrency=self._max_concurrency,
                max_arrivals_per_minute=self._max_per_minute,
                max_per_proxy=self._max_per_proxy,
            ),
            proxy=proxy,
            seed=seed,
            headless=True if self._force_headless else None,
        )

        problems = config.validate()
        if problems:
            self._error = "; ".join(problems)
            self.changed.emit()
            return

        if self._single_level_mode:
            self._append_log(
                f"Starting audit of {self._target} - single rung "
                f"{config.selected_levels()[0].name}, {config.visitor_count} "
                f"visitors over {self._hours:g}h"
            )
        else:
            self._append_log(
                f"Starting audit of {self._target} - {self._visitors} visitors over "
                f"{self._hours:g}h, levels 0-{self._max_level}"
            )
        self._append_log(
            f"Ceilings: {self._max_requests} requests, {self._max_rps}/s, "
            f"{self._max_concurrency} concurrent, {self._max_per_minute}/min"
        )

        self._running = True
        self.runningChanged.emit()
        self._worker = AuditWorker(config, self._out_dir or None, self)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_report.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    @Slot()
    def stop(self) -> None:
        if self._worker is not None and self._running:
            self._append_log("Stop requested; finishing in-flight visits...")
            self._worker.cancel()

    @Slot()
    def clearLog(self) -> None:
        self._log = []
        self.logChanged.emit()

    @Slot()
    def clearResults(self) -> None:
        self._visits.clear()
        self._findings = []
        self._summary = {}
        self.visitsChanged.emit()
        self.findingsChanged.emit()
        self.summaryChanged.emit()

    def _append_log(self, line: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self._log.append(f"[{stamp}] {line}")
        self.logChanged.emit()

    @Slot(dict)
    def _on_progress(self, payload: dict) -> None:
        event = payload.get("event")
        if event == "level_start":
            self._append_log(
                f"{payload.get('level_name')}: starting {payload.get('scheduled')} visits"
            )
        elif event == "visit":
            visit = payload.get("visit") or {}
            self._visits.append(visit)
            self.visitsChanged.emit()
        elif event == "level_end":
            level = payload.get("level") or {}
            self._append_log(
                f"{level.get('level_name')}: bypass {level.get('bypass_rate', 0):.0%}, "
                f"detected {level.get('detection_rate', 0):.0%}"
            )

    @Slot(dict, str)
    def _on_finished(self, payload: dict, payload_json: str) -> None:
        self._running = False
        self._worker = None
        self.runningChanged.emit()

        self._findings = list(payload.get("findings") or [])
        self.findingsChanged.emit()

        totals = payload.get("totals") or {}
        levels = payload.get("levels") or []
        self._summary = {
            "visits": totals.get("visits", 0),
            "requests": totals.get("requests", 0),
            "duration": round(payload.get("duration_s", 0.0), 1),
            "aborted": payload.get("aborted", False),
            "abortReason": payload.get("abort_reason", ""),
            "levels": [
                {
                    "name": lv.get("level_name", ""),
                    "completed": lv.get("completed", 0),
                    "bypassRate": lv.get("bypass_rate", 0.0),
                    "detectionRate": lv.get("detection_rate", 0.0),
                    "vendors": ", ".join(lv.get("vendors") or []),
                    "aborted": lv.get("aborted", False),
                    "abortReason": lv.get("abort_reason", ""),
                }
                for lv in levels
            ],
            "written": payload.get("written") or {},
        }
        self.summaryChanged.emit()

        for fmt, path in (payload.get("written") or {}).items():
            self._append_log(f"Wrote {fmt} report to {path}")
        self._append_log("Audit complete.")

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self._running = False
        self._worker = None
        self.runningChanged.emit()
        self._error = message
        self.changed.emit()
        self._append_log(f"Audit failed: {message}")

    # -- export ------------------------------------------------------------

    @Slot(str, result=bool)
    def exportText(self, path: str) -> bool:
        """Write a plain-text report of the last run to `path`."""
        if not path:
            return False
        try:
            body = "\n".join(self._findings) if self._findings else "(no findings)"
            header = (
                f"WAF / bot-defense audit\n"
                f"Target: {self._target}\n"
                f"Scope: {self._scope_hosts}\n"
                f"Visitors: {self._visitors} over {self._hours:g}h\n\n"
            )
            Path(path).write_text(header + body + "\n", encoding="utf-8")
            self._append_log(f"Wrote summary to {path}")
            return True
        except Exception as exc:
            self._error = f"Export failed: {exc}"
            self.changed.emit()
            return False