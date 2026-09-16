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

#: Repository-relative root of the python library. The spec is run from the repo
#: root, so this resolves without depending on the installed copy's location.
LIB_ROOT = Path(SPECPATH).parent.parent

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
binaries += collect_dynamic_libs("PySide6")

#: Qt's own plugin directory layout must survive, or Qt reports
#: "could not find or load the Qt platform plugin windows".
datas += collect_data_files("PySide6", include_py_files=False)

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
    "lxml",
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
    excludes=[
        "tkinter",
        "matplotlib",
        "pandas",
        "scipy",
        "PIL",
        "pytest",
        "IPython",
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtMultimedia",
        "PySide6.Qt3DCore",
        "PySide6.QtCharts",
        "PySide6.QtDataVisualization",
        "PySide6.QtQuick3D",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

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
    icon=str(LIB_ROOT / "camoufox" / "gui" / "assets" / "icon.ico"),
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
    app = BUNDLE(
        coll,
        name="CamoufoxGUI.app",
        icon=str(LIB_ROOT / "camoufox" / "gui" / "assets" / "icon.ico"),
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
