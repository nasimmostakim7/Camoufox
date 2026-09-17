"""
PyInstaller hook for the camoufox package.

Two kinds of file have to travel with a frozen GUI, and neither is discovered
automatically:

* the QML tree and its assets, which the GUI loads by filesystem path
  (`Path(__file__).parent / "qml/main.qml"`), so a missing data file is a blank
  window with no traceback;
* the JSON/YAML/db data the fingerprint and geolocation code reads at runtime.

`playwright` keeps its Node driver under `playwright/driver`, and the package
resolves it relative to `playwright.__file__`, so the whole subtree is collected
rather than just the Python modules.
"""

import importlib.util

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = []

#: Everything non-Python shipped inside camoufox: QML, fonts, icon, JSON, YAML,
#: territory database, WebGL data.
datas += collect_data_files("camoufox")

#: Playwright's bundled Node driver (a large directory of .js/.json plus the
#: node binary). Without it the browser never launches.
datas += collect_data_files("playwright", include_py_files=False)

#: BrowserForge reads its Bayesian-network and header data out of these .zip/.json
#: files at import time. Missing them raises FileNotFoundError from inside
#: browserforge before any of our code runs.
datas += collect_data_files("apify_fingerprint_datapoints")
datas += collect_data_files("browserforge")

#: language_tags loads its ISO registry from JSON at import time.
datas += collect_data_files("language_tags")

hiddenimports = []

#: The GUI is imported lazily inside the `gui` CLI command, and the audit engine
#: is imported inside the worker thread, so neither is visible to the static
#: analyser.
hiddenimports += collect_submodules("camoufox.gui")
hiddenimports += collect_submodules("camoufox.audit")

#: Loaded through importlib inside the audit runner and pkgman.
hiddenimports += ["camoufox.pkgman", "camoufox.async_api", "camoufox.sync_api"]

#: PySide6 QML/QtQuick support is pulled in by the GUI but not by any import
#: statement a static scan can follow.
hiddenimports += [
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuickControls2",
    "PySide6.QtGui",
    "PySide6.QtCore",
    "PySide6.QtWidgets",
    "PySide6.QtNetwork",
    "PySide6.QtSvg",
    "PySide6.QtOpenGL",
    "PySide6.QtSvgWidgets",
    "PySide6.QtPrintSupport",
]

#: Optional at runtime: the audit reports the weaker mask when absent, and the
#: launcher checks with importlib.util.find_spec, which a scan cannot see. Listed
#: only when actually installed, otherwise PyInstaller logs a hard ERROR.
for _mod in ("geoip2", "geoip2.database", "maxminddb"):
    try:
        if importlib.util.find_spec(_mod) is not None:
            hiddenimports.append(_mod)
    except (ImportError, ValueError):
        pass
