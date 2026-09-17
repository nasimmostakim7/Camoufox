# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the Camoufox Manager GUI (Audit tab included).

Build (from the repository root, with the package installed into the build env):

    pyinstaller pythonlib/packaging/camoufox-gui.spec --noconfirm

Output:

    dist/CamoufoxGUI/CamoufoxGUI.exe      (Windows)
    dist/CamoufoxGUI/CamoufoxGUI          (Linux / macOS)

`--onedir` is used on purpose. It starts far faster than `--onefile` (which
unpacks ~200 MB to a temp directory on every launch) and it keeps the Qt plugins
on disk where Qt can find them. The folder is the deliverable: zip it.

What is deliberately NOT bundled:

* the Camoufox browser itself (~470 MB per platform). It is fetched on first use
  by the GUI's own Browsers tab, and it is platform-specific, so bundling it
  would triple the download and still break if the user moved the folder.
"""

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

#: The name of the Qt libraries and data files this GUI never loads, kept beside
#: the spec so both it and hook-camoufox.py filter the same list. See the module
#: docstring for why `excludes` alone cannot do this.
sys.path.insert(0, str(Path(SPECPATH)))
from _qt_trim import report as _trim_report  # noqa: E402
from _qt_trim import is_denied_artifact  # noqa: E402
from _qt_trim import trim_binaries, trim_datas  # noqa: E402

#: SPECPATH is the directory holding this spec file, i.e. <repo>/pythonlib/packaging.
#: The python library itself is one level up, NOT two: `parent.parent` resolves to
#: the repository root, which has no `camoufox/` package. The icon path below is
#: derived from this, and only Windows and macOS validate the icon -- on Linux
#: PyInstaller ignores it, so a wrong value there fails silently.
LIB_ROOT = Path(SPECPATH).parent

#: Checked here rather than left to PyInstaller, which only validates the icon on
#: Windows and macOS. Without this, a wrong path passes CI on Linux and then fails
#: on the other two, which is exactly how this went unnoticed.
ICON = LIB_ROOT / "camoufox" / "gui" / "assets" / "icon.ico"
if not ICON.exists():
    raise SystemExit(f"icon not found: {ICON} (LIB_ROOT={LIB_ROOT})")

datas = []
binaries = []
hiddenimports = []

# NOTE: the datas/hiddenimports below overlap with hook-camoufox.py, which
# PyInstaller also loads. The duplication is deliberate: PyInstaller merges both
# lists and drops exact duplicates, so a spec alone says everything the bundle
# needs. Keep the two in sync when either changes.

# camoufox: QML tree, fonts, icon, JSON/YAML/db data
datas += collect_data_files("camoufox")

# playwright's Node driver, resolved relative to playwright.__file__
datas += collect_data_files("playwright", include_py_files=False)

# BrowserForge loads its Bayesian-network/header data from these packages at
# import time; without them the frozen app dies before reaching our code.
datas += collect_data_files("apify_fingerprint_datapoints")
datas += collect_data_files("browserforge")
datas += collect_data_files("language_tags")

# PySide6 ships Qt plugins as shared libraries under PySide6/Qt/plugins, plus the
# Qt6 shared libraries themselves. Neither is found by a plain module scan.
#
# Both collections are pruned by name before they join the bundle. They are asked
# for "all of PySide6", which is why the spec's `excludes` cannot reach them: the
# analyzer is handed files, not module names, so a 195 MB WebEngine and the whole
# Qt 3D/Charts/Designer set travel along unopposed.
_binaries_before = collect_dynamic_libs("PySide6")

#: Qt's own plugin directory layout must survive, or Qt reports
#: "could not find or load the Qt platform plugin windows".
_datas_before = collect_data_files("PySide6", include_py_files=False)

binaries += trim_binaries(_binaries_before)
datas += trim_datas(_datas_before)
print(_trim_report(_binaries_before, binaries, _datas_before, datas))

#: Lazy imports: the GUI (imported inside the `gui` command) and the audit engine
#: (imported inside the worker thread).
hiddenimports += [
    "camoufox.gui",
    "camoufox.gui.backend",
    "camoufox.gui.audit_backend",
    "camoufox.audit",
    "camoufox.audit.runner",
    "camoufox.audit.report",
    "camoufox.audit.schedule",
    "camoufox.audit.evasion",
    "camoufox.audit.journey",
    "camoufox.audit.detection",
    "camoufox.audit.scope",
    "camoufox.audit.config",
    "camoufox.pkgman",
    "camoufox.proxy",
    "camoufox.async_api",
    "camoufox.sync_api",
    "camoufox.fingerprints",
    "camoufox.geolocation",
    "camoufox.locales",
    "camoufox.utils",
]

#: QML runtime. Without QtQml/QtQuick registered the engine loads no root object
#: and the process exits with -1 and no message.
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
    "PySide6.QtStateMachine",
]

#: Checked with importlib.util.find_spec, so invisible to static analysis. Added
#: only when installed: naming an absent module makes PyInstaller log an ERROR
#: that reads like a build failure.
import importlib.util as _ilu

for _mod in ("geoip2", "geoip2.database", "maxminddb"):
    try:
        if _ilu.find_spec(_mod) is not None:
            hiddenimports.append(_mod)
    except (ImportError, ValueError):
        pass

#: Third-party runtime dependencies that are imported dynamically or by name.
hiddenimports += [
    "browserforge",
    "browserforge.headers",
    "browserforge.fingerprints",
    "rich",
    "rich_click",
    "orjson",
    "platformdirs",
    "numpy",
    "yaml",
    "requests",
    "screeninfo",
    "language_tags",
    "socks",
    "inquirer",
    "ua_parser",
]

a = Analysis(
    ["camoufox_launcher.py"],
    pathex=[str(LIB_ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[str(Path(SPECPATH))],
    hooksconfig={},
    runtime_hooks=[],
    #: Trim what is demonstrably unused and large. tkinter in particular adds
    #: ~10 MB and is never touched.
    #:
    #: These names steer the module graph, so they work on Python packages: with
    #: `tkinter`, `pandas`, `scipy` and `lxml` listed the built bundle really does
    #: lose those trees. They do NOT cover Qt's shared libraries -- those arrive
    #: through collect_dynamic_libs/collect_data_files as files, before the
    #: analyzer ever looks at a module name, and are pruned by _qt_trim instead.
    #: The PySide6 entries below are a second line of defence: they stop the
    #: interpreter from importing the binding even if a library slipped through.
    excludes=[
        "tkinter",
        "matplotlib",
        "pandas",
        "scipy",
        "PIL",
        "pytest",
        "IPython",
        "lxml",
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebEngineQuick",
        "PySide6.QtMultimedia",
        "PySide6.QtMultimediaWidgets",
        "PySide6.Qt3DCore",
        "PySide6.QtCharts",
        "PySide6.QtDataVisualization",
        "PySide6.QtGraphs",
        "PySide6.QtQuick3D",
        "PySide6.QtDesigner",
        "PySide6.QtHelp",
        "PySide6.QtPdf",
        "PySide6.QtPdfWidgets",
        "PySide6.QtLocation",
        "PySide6.QtPositioning",
        "PySide6.QtNfc",
        "PySide6.QtBluetooth",
        "PySide6.QtSerialPort",
        "PySide6.QtSensors",
        "PySide6.QtScxml",
        "PySide6.QtStateMachine",
        "PySide6.QtTest",
        "PySide6.QtTextToSpeech",
        "PySide6.QtRemoteObjects",
        "PySide6.QtSpatialAudio",
        "PySide6.QtVirtualKeyboard",
        "PySide6.QtWaylandClient",
        "PySide6.QtHttpServer",
        "PySide6.QtNetworkAuth",
        "PySide6.QtLottie",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

# The collected-file filters above run before the analysis, and that is not
# enough: PyInstaller's own `hook-PySide6.QtWebEngineCore` (and its Quick,
# Widgets and WebChannel siblings) add their libraries to the analysis TOC
# directly, and the binary dependency walk then pulls `libQt6WebEngineCore` back
# in from a `DT_NEEDED` entry -- a 194 MB Chromium re-entering after the copy
# that would have removed it had already run.
#
# Pruning the finished TOC is mechanism-independent: whatever route a file took
# to get here, it is judged by its name on the way out. The keep side is
# unaffected because `is_denied_*` is a denylist -- anything unrecognised
# survives, so a future PySide6 addition costs disk rather than a blank window.
_binaries_before_toc = len(a.binaries)
_datas_before_toc = len(a.datas)
a.binaries = [entry for entry in a.binaries if not is_denied_artifact(entry[0])]
a.datas = [entry for entry in a.datas if not is_denied_artifact(entry[0])]
print(
    "Qt trim (post-analysis): "
    f"binaries {_binaries_before_toc} -> {len(a.binaries)}, "
    f"datas {_datas_before_toc} -> {len(a.datas)}"
)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CamoufoxGUI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # GUI subsystem on Windows: no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CamoufoxGUI",
)

# macOS gets a real .app bundle on top of the folder: a bare Mach-O executable
# has no Info.plist, so the Dock shows a generic icon and the window cannot be
# focused or activated normally.
if sys.platform == "darwin":
    # BUNDLE accepts only .icns. PyInstaller converts the .ico for us, but only
    # when Pillow is importable; without it the build fails rather than falling
    # back, so the icon is dropped instead of taking down the whole bundle.
    try:
        import PIL  # noqa: F401

        bundle_icon = str(ICON)
    except ImportError:
        bundle_icon = None

    app = BUNDLE(
        coll,
        name="CamoufoxGUI.app",
        icon=bundle_icon,
        bundle_identifier="com.camoufox.manager",
        info_plist={
            "CFBundleName": "Camoufox Manager",
            "CFBundleDisplayName": "Camoufox Manager",
            "CFBundleShortVersionString": "0.5.6",
            # The GUI drives a browser and downloads releases, so it is not
            # sandboxed; saying otherwise makes macOS kill it on launch.
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
        },
    )
