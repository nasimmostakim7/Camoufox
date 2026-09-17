"""
Trim what a frozen Camoufox GUI demonstrably never loads.

`excludes` in the spec is not enough for Qt, and that is the trap this module
exists for. An excludes name steers the *module graph*, so it works on Python
packages: `tkinter`, `pandas` and `lxml` really do disappear from the bundle.
It does nothing to `collect_dynamic_libs("PySide6")`, which copies every shared
library under `PySide6/Qt/lib` by filename, and nothing to
`collect_data_files("PySide6")`, which copies the rest of the tree. Both helpers
are asked for "all of PySide6", so the analyzer never sees a module named
`PySide6.QtWebEngineCore` to exclude -- it sees a file on disk.

The result is a bundle carrying the whole of Qt, including a 195 MB Chromium
(`libQt6WebEngineCore`) that nothing in this project imports. Naming those
modules in `excludes` looks right and changes nothing; the collected files have
to be filtered by name.

The filter is deliberately a denylist, so anything not named here survives. A
library added by a future PySide6 stays in the bundle -- an unknown extra costs
disk, a wrongly dropped one costs a blank window, and those are not equally bad.

Only the Qt families this GUI provably never touches are listed. The app's whole
surface is `QtQuick`, `QtQuick.Controls` and `QtQuick.Layouts` in QML, plus
`QtCore`, `QtGui`, `QtQml`, `QtQuickControls2` and `QtWidgets` from Python.
Anything reachable from those is kept, which is why the Qt Quick stack, every
Controls 2 style, the platform plugins and the image/icon plugins are all absent
from the lists below.
"""

import re

#: Qt module families no code path in this project imports or instantiates.
#:
#: Matched against a normalised module token rather than the raw filename, because
#: Qt names the same module differently in each place it appears: the library is
#: `libQt6WebEngineCore.so.6`, while the QML plugin that pulls it in is the
#: lower-case, unversioned `libqtwebenginequickplugin.so`. Matching raw names
#: caught the first and missed the second -- and the second is the one that
#: matters, since its `DT_NEEDED` entry drags the 194 MB core library back into
#: the bundle after the library itself was filtered out.
#:
#: libav*/libsw* are FFmpeg, reached only through Multimedia and WebEngine.
#: ffmpegstub covers `libQt6FFmpegStub-*`, the stubs those two link against.
_DENIED_FAMILIES = [
    # Chromium. Nothing here embeds a web page.
    "webengine", "webview", "webchannel", "websockets",
    "avcodec", "avformat", "avutil", "swresample", "swscale", "ffmpegstub",
    # Media, 3D and the data-visualisation add-ons.
    "multimedia", "3d", "quick3d", "charts", "datavisualization", "graphs",
    "lottie", "spatialaudio", "texttospeech", "pdf",
    # Devices and protocols this app never speaks.
    "bluetooth", "nfc", "serialport", "serialbus", "sensors", "positioning",
    "location", "remoteobjects", "httpserver", "networkauth",
    # Authoring and automation extras.
    "designer", "help", "uitools", "test", "scxml", "statemachine",
    "virtualkeyboard", "wayland", "wlshellintegration",
]

#: QML module directories under `PySide6/Qt/qml` belonging to the families above.
#: The QML tree ships as data, so the plugin inside it is collected even when the
#: Python binding is excluded.
_DENIED_QML_MODULES = [
    "QtWebEngine", "QtWebView", "QtWebChannel", "QtWebSockets",
    "QtMultimedia", "QtCharts", "QtDataVisualization", "QtGraphs", "QtPdf",
    "QtQuick3D", "Qt3D", "QtLottie", "QtSpatialAudio", "QtTextToSpeech",
    "QtBluetooth", "QtNfc", "QtSerialPort", "QtSensors", "QtPositioning",
    "QtLocation", "QtRemoteObjects", "QtTest", "QtScxml", "QtStateMachine",
    "QtVirtualKeyboard", "QtWayland", "QtDesigner", "QtHelp",
]

#: Subdirectories of `PySide6/Qt/plugins` belonging to the families above.
#: `platforms`, `imageformats`, `iconengines`, `platformthemes`, `tls`,
#: `networkinformation`, `generic`, `xcbglintegrations`, `egldeviceintegrations`,
#: `platforminputcontexts`, `renderers`, `qmltooling` and `vectorimageformats`
#: are all reachable from Qt Quick and stay.
_QT_PLUGIN_DENY = [
    "webview",
    "multimedia",
    "designer",
    "sceneparsers",
    "assetimporters",
    "sqldrivers",
    "canbus",
    "geoservices",
    "position",
    "sensors",
    "texttospeech",
    "scxmldatamodel",
    "wayland-decoration-client",
    "wayland-graphics-integration-client",
    "wayland-graphics-integration-server",
    "wayland-shell-integration",
]

#: Qt tooling that is only meaningful while writing or translating code, plus the
#: C++ glue, docs and type stubs that PySide6 ships for IDE and binding authors.
#: None of it is read at runtime.
_QT_TOOL_DENY = [
    "qmlls", "qmlformat", "qmlimportscanner", "designer", "assistant",
    "linguist", "lupdate", "lrelease", "include", "typesystems", "scripts",
    "glue", "doc", "docs", "examples", "support",
]

_SO_SUFFIX = re.compile(r"\.so(\..*)?$")
_LIB_PREFIX = re.compile(r"^lib")
#: `libQt6Core` -> `core`. At most ONE digit is the version: `libQt63DCore` is
#: Qt 6's 3D module, not version 63, so stripping a variable-length run of digits
#: ate the module's own leading `3` and left `dcore`, which matched no family and
#: let the whole Qt 3D set through. The digit is also optional: the QML plugin is
#: `libqtwebenginequickplugin.so`, with no version in its name at all.
_QT_PREFIX = re.compile(r"^qt\d?")


def module_token(name: str) -> str:
    """
    Reduce a Qt shared-library filename to the module name it implements.

    `libQt6WebEngineCore.so.6` and `libqtwebenginequickplugin.so` both keep the
    text that identifies their family, which is what the caller matches on.
    """
    token = name.lower()
    token = _SO_SUFFIX.sub("", token)
    token = re.sub(r"\.(dylib|dll)$", "", token)
    token = _LIB_PREFIX.sub("", token)
    token = _QT_PREFIX.sub("", token)
    return token


def is_denied_library(path) -> bool:
    """True when a collected binary belongs to a Qt family the GUI never loads."""
    import os

    token = module_token(os.path.basename(str(path)))
    return any(token.startswith(family) for family in _DENIED_FAMILIES)


def is_denied_qt_data(path) -> bool:
    """
    True when a collected PySide6 data file is a dev tool, stub or unused module.

    `path` is the destination path inside the bundle, so it looks like
    `PySide6/qmlls` or `PySide6/Qt/plugins/multimedia`. Both separators are
    handled because the destination is built with the host's separator.
    """
    parts = str(path).replace("\\", "/").split("/")
    if "PySide6" not in parts:
        return False

    # `.pyi` stubs are editor metadata for the Python modules; PySide6 ships them
    # beside the .so files and PyInstaller copies them as data.
    if parts[-1].endswith(".pyi"):
        return True

    for tool in _QT_TOOL_DENY:
        if tool in parts:
            return True

    if "qml" in parts:
        index = parts.index("qml")
        if index + 1 < len(parts):
            module = parts[index + 1]
            if any(module == denied or module.startswith(denied) for denied in _DENIED_QML_MODULES):
                return True

    # `PySide6/Qt/resources` holds Chromium's payload -- icudtl.dat, the V8
    # snapshot and the .pak resource files. Qt itself keeps translations under
    # `translations` and its fonts under `lib`, so the whole directory belongs to
    # the WebEngine we are removing. Nothing else in the Qt stack reads it.
    if "Qt" in parts:
        index = parts.index("Qt")
        if index + 1 < len(parts) and parts[index + 1] == "resources":
            return True

    if "plugins" in parts:
        index = parts.index("plugins")
        if index + 1 < len(parts) and parts[index + 1] in _QT_PLUGIN_DENY:
            return True

    if parts[-1].startswith("libqwebengine"):
        return True

    return False


def is_denied_artifact(path) -> bool:
    """
    True when a finished TOC entry belongs to a Qt family the GUI never loads.

    This is the entry point the spec filters with, and it deliberately does not
    assume a `PySide6/...` prefix. PyInstaller's own PySide6 hooks place Qt shared
    libraries in `datas` with the prefix stripped, so `libQt6WebEngineCore.so.6`
    arrives at the bundle root. A filter that only recognised the prefixed layout
    dropped the plugin and kept the 194 MB library it linked against.
    """
    parts = str(path).replace("\\", "/").split("/")
    base = parts[-1].lower()

    # A Qt library, wherever the hook chose to put it.
    if is_denied_library(base) and any(
        marker in base for marker in (".so", ".dylib", ".dll")
    ):
        return True

    # Chromium's non-library payload: `qtwebengine*.pak`, the `.qm` translations
    # and `icudtl.dat`. The name survives the plugin that would have loaded it.
    if "webengine" in base:
        return True

    return is_denied_qt_data(path)


def trim_binaries(binaries):
    """Drop denied Qt shared libraries from a `collect_dynamic_libs` result."""
    return [entry for entry in binaries if not is_denied_library(entry[0])]


def trim_datas(datas):
    """Drop dev tools, stubs and unused plugin trees from collected PySide6 data."""
    return [entry for entry in datas if not is_denied_qt_data(entry[0])]


def report(before_binaries, after_binaries, before_datas, after_datas) -> str:
    """A one-line summary for the build log, so a silent no-op is visible."""
    return (
        f"Qt trim: binaries {len(before_binaries)} -> {len(after_binaries)}, "
        f"datas {len(before_datas)} -> {len(after_datas)}"
    )
