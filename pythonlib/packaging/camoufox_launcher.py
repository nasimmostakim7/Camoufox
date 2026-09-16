"""
Frozen-app entry point: open the Camoufox Manager GUI.

`camoufox.__main__:cli` is the CLI group, which prints usage and exits when run
with no arguments -- wrong behaviour for a double-clicked exe. This calls the GUI
directly instead.

When the GUI cannot start (no PySide6, no display), the failure is written to a
log file next to the executable and shown in a message box, because a windowed
build has no console for a traceback to land in.
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path


def _log_path() -> Path:
    """A writable place for the crash log: beside the exe, else the temp dir."""
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).parent
    else:
        base = Path(__file__).resolve().parent
    try:
        probe = base / ".write-probe"
        probe.touch()
        probe.unlink()
        return base / "CamoufoxGUI-error.log"
    except OSError:
        import tempfile

        return Path(tempfile.gettempdir()) / "CamoufoxGUI-error.log"


def _self_check_path() -> Path:
    """Where `--self-check` records its verdict, beside the executable."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "CamoufoxGUI-selfcheck.log"
    return Path(__file__).resolve().parent / "CamoufoxGUI-selfcheck.log"


def _emit(text: str) -> None:
    """Echo to stderr when there is a stderr to write to.

    A windowed PyInstaller build leaves sys.stderr as None, so a bare
    sys.stderr.write() here would raise AttributeError and lose the very
    diagnostic it was called to deliver.
    """
    stream = sys.stderr
    if stream is None:
        return
    try:
        stream.write(text)
    except (OSError, ValueError):
        pass


def _record(text: str) -> None:
    """Write the self-check verdict where CI can read it.

    Needed because a windowed build has no console: output from a `console=False`
    executable goes nowhere, so the exit code alone would be an unexplained 1.
    """
    try:
        _self_check_path().write_text(text, encoding="utf-8")
    except OSError:
        pass
    _emit(text)


def _self_check() -> int:
    """Load the real QML with the offscreen Qt platform and report.

    This is the packaging gate. It exercises exactly what a missing `datas` entry
    breaks -- the QML file resolving, its imports resolving, the backend modules
    importing, the Qt QML modules being present -- without needing a desktop, so
    it can run on a CI runner.

    A failure here is the interesting case: without it, a broken bundle looks
    like a window that never appears.
    """
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    try:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtQml import QQmlApplicationEngine

        from camoufox.gui import backend as gui_backend
        from camoufox.gui import audit_backend as gui_audit

        qml = Path(gui_backend.__file__).parent / "qml" / "main.qml"
        if not qml.exists():
            _record(f"self-check FAILED: QML missing at {qml}\n")
            return 1

        #: Offscreen still needs a QGuiApplication, but never a window.
        app = QGuiApplication([])
        engine = QQmlApplicationEngine()

        # The QML refers to these three context properties by name; without them
        # it fails to instantiate and rootObjects() comes back empty.
        engine.rootContext().setContextProperty("debugMode", False)
        backend = gui_backend.Backend()
        backend.setParent(engine)
        engine.rootContext().setContextProperty("backend", backend)
        audit_backend = gui_audit.AuditBackend()
        audit_backend.setParent(engine)
        engine.rootContext().setContextProperty("auditBackend", audit_backend)

        engine.load(QUrl.fromLocalFile(str(qml)))
        roots = engine.rootObjects()
        if not roots:
            _record(
                "self-check FAILED: QML loaded no root object. Usually a missing "
                "Qt QML module or a data file left out of the bundle.\n"
            )
            return 1

        # The audit tab is the reason this fork exists, so assert its bridge
        # survived: a missing hiddenimport leaves the object defined but with no
        # callable slots, and the QML then binds to nothing.
        required = (
            "start",
            "stop",
            "setTarget",
            "setProxyModeIndex",
            "setProxyFile",
            "setProxyGateway",
            "validateProxyFile",
        )
        missing = [name for name in required if not hasattr(audit_backend, name)]
        if missing:
            _record(
                "self-check FAILED: AuditBackend is missing slot(s): "
                + ", ".join(missing)
                + "\n"
            )
            return 1

        _record(
            f"self-check OK: QML {qml.name}, {len(roots)} root object(s), "
            f"audit bridge present\n"
        )
        del engine
        del app
        return 0
    except Exception as exc:  # noqa: BLE001 - the whole point is to catch it
        text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        _record("self-check FAILED:\n" + text)
        return 1


def _report(exc: Exception) -> None:
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    try:
        _log_path().write_text(text, encoding="utf-8")
    except OSError:
        pass
    _emit(text)

    # A windowed build swallows stderr, so surface it in a dialog too -- but only
    # when Qt already has an application object. Constructing one here would abort
    # the whole process at the C++ level if no platform plugin can initialize,
    # and that abort is not catchable from Python. The log above is already on
    # disk by this point, which is why the write comes first.
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox

        app = QApplication.instance()
        if app is None:
            return
        QMessageBox.critical(
            None,
            "Camoufox Manager could not start",
            f"{type(exc).__name__}: {exc}\n\nFull details written to:\n{_log_path()}",
        )
    except Exception:
        pass


def main() -> int:
    if "--self-check" in sys.argv:
        return _self_check()

    # Set before the GUI package is imported, matching what camoufox/gui/__init__
    # does; kept here as well so a Qt plugin mismatch is avoided during the
    # windowed-bootloader startup.
    os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Basic")
    os.environ.setdefault("QT_QPA_PLATFORMTHEME", "")
    os.environ.setdefault("QT_STYLE_OVERRIDE", "")

    try:
        from camoufox.gui import main as gui_main
    except Exception as exc:  # PySide6 missing, or a data file left out
        _report(exc)
        return 1

    try:
        gui_main(debug="--debug" in sys.argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 0
    except Exception as exc:
        _report(exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
