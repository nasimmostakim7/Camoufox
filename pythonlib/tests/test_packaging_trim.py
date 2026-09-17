"""Coverage for the packaging trim, and the Qt modules it must never drop.

The desktop bundle used to ship all of Qt: a 195 MB Chromium
(``libQt6WebEngineCore``), the Qt 3D/Charts/Designer families, and the qmlls /
linguist developer tools, none of which any code path loads. Naming them in the
spec's ``excludes`` did not remove them, because ``collect_dynamic_libs`` and
``collect_data_files`` hand the analyzer filenames rather than module names.

``_qt_trim`` filters those collections by name. The risk in a filter like this is
the opposite failure -- dropping a library the GUI needs -- so the tests below
pin the keep side as hard as the drop side: every module reachable from the
QML's ``import QtQuick`` / ``QtQuick.Controls`` / ``QtQuick.Layouts`` and from
the Python imports of ``camoufox.gui`` has to survive.
"""

import sys
from pathlib import Path

import pytest

# `packaging/` is not an importable package -- PyInstaller loads the spec and the
# hook from it by path -- so the directory is added here rather than relying on a
# conftest, which would change collection for the whole suite.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packaging"))

from _qt_trim import (  # noqa: E402
    is_denied_library,
    is_denied_qt_data,
    trim_binaries,
    trim_datas,
)

#: Libraries that must stay. Every one is reachable from the Qt Quick stack, a
#: Controls 2 style, a Qt plugin that resolves at startup, or a Python import in
#: camoufox.gui. A regression here is a bundle that fails to draw a window.
REQUIRED_LIBRARIES = [
    "libQt6Core.so.6.11.2",
    "libQt6Gui.so.6.11.2",
    "libQt6Widgets.so.6.11.2",
    "libQt6DBus.so.6.11.2",
    "libQt6Network.so.6.11.2",
    "libQt6OpenGL.so.6.11.2",
    "libQt6OpenGLWidgets.so.6.11.2",
    "libQt6Svg.so.6.11.2",
    "libQt6SvgWidgets.so.6.11.2",
    "libQt6PrintSupport.so.6.11.2",
    "libQt6XcbQpa.so.6.11.2",
    # The QML engine and the Qt Quick scene graph.
    "libQt6Qml.so.6.11.2",
    "libQt6QmlModels.so.6.11.2",
    "libQt6QmlMeta.so.6.11.2",
    "libQt6QmlWorkerScript.so.6.11.2",
    "libQt6QmlCompiler.so.6.11.2",
    "libQt6QmlCore.so.6.11.2",
    "libQt6QmlLocalStorage.so.6.11.2",
    "libQt6QmlXmlListModel.so.6.11.2",
    "libQt6QmlNetwork.so.6.11.2",
    "libQt6Quick.so.6.11.2",
    "libQt6QuickControls2.so.6.11.2",
    "libQt6QuickControls2Impl.so.6.11.2",
    "libQt6QuickTemplates2.so.6.11.2",
    "libQt6QuickLayouts.so.6.11.2",
    "libQt6QuickEffects.so.6.11.2",
    "libQt6QuickDialogs2.so.6.11.2",
    "libQt6QuickDialogs2QuickImpl.so.6.11.2",
    "libQt6QuickDialogs2Utils.so.6.11.2",
    "libQt6QuickShapes.so.6.11.2",
    "libQt6QuickWidgets.so.6.11.2",
    "libQt6QuickVectorImage.so.6.11.2",
    "libQt6ShaderTools.so.6.11.2",
    # Every Controls 2 style ships as its own library, and the active style is
    # chosen at runtime by name.
    "libQt6QuickControls2Basic.so.6.11.2",
    "libQt6QuickControls2BasicStyleImpl.so.6.11.2",
    "libQt6QuickControls2Fusion.so.6.11.2",
    "libQt6QuickControls2FusionStyleImpl.so.6.11.2",
    "libQt6QuickControls2Imagine.so.6.11.2",
    "libQt6QuickControls2ImagineStyleImpl.so.6.11.2",
    "libQt6QuickControls2Material.so.6.11.2",
    "libQt6QuickControls2MaterialStyleImpl.so.6.11.2",
    "libQt6QuickControls2Universal.so.6.11.2",
    "libQt6QuickControls2UniversalStyleImpl.so.6.11.2",
    "libQt6QuickControls2FluentWinUI3StyleImpl.so.6.11.2",
]

#: Libraries the trim is expected to remove, with the reason it is safe.
DENIED_LIBRARIES = [
    "libQt6WebEngineCore.so.6.11.2",
    "libQt6WebEngineWidgets.so.6.11.2",
    "libQt6WebEngineQuick.so.6.11.2",
    "libQt6WebEngineQuickDelegatesQml.so.6.11.2",
    "libQt6WebChannel.so.6.11.2",
    "libQt6WebSockets.so.6.11.2",
    "libQt6WebView.so.6.11.2",
    "libavcodec.so.61.19.101",
    "libavformat.so.61.7.100",
    "libavutil.so.59.39.100",
    "libswresample.so.5.3.100",
    "libswscale.so.8.3.100",
    "libQt6FFmpegStub-crypto.so.6",
    "libQt6Multimedia.so.6.11.2",
    "libQt6MultimediaQuick.so.6.11.2",
    "libQt63DCore.so.6.11.2",
    "libQt63DRender.so.6.11.2",
    "libQt63DQuick.so.6.11.2",
    "libQt6Quick3DRuntimeRender.so.6.11.2",
    "libQt6Quick3DHelpers.so.6.11.2",
    "libQt6Charts.so.6.11.2",
    "libQt6ChartsQml.so.6.11.2",
    "libQt6DataVisualization.so.6.11.2",
    "libQt6Graphs.so.6.11.2",
    "libQt6Lottie.so.6.11.2",
    "libQt6SpatialAudio.so.6.11.2",
    "libQt6TextToSpeech.so.6.11.2",
    "libQt6Bluetooth.so.6.11.2",
    "libQt6Nfc.so.6.11.2",
    "libQt6SerialPort.so.6.11.2",
    "libQt6Sensors.so.6.11.2",
    "libQt6Positioning.so.6.11.2",
    "libQt6Location.so.6.11.2",
    "libQt6RemoteObjects.so.6.11.2",
    "libQt6HttpServer.so.6.11.2",
    "libQt6NetworkAuth.so.6.11.2",
    "libQt6Designer.so.6.11.2",
    "libQt6DesignerComponents.so.6.11.2",
    "libQt6Help.so.6.11.2",
    "libQt6UiTools.so.6.11.2",
    "libQt6Test.so.6.11.2",
    "libQt6Scxml.so.6.11.2",
    "libQt6StateMachine.so.6.11.2",
    "libQt6VirtualKeyboard.so.6.11.2",
    "libQt6WaylandClient.so.6.11.2",
    "libQt6WlShellIntegration.so.6.11.2",
]


@pytest.mark.parametrize("name", REQUIRED_LIBRARIES)
def test_required_library_is_kept(name):
    assert not is_denied_library(name), f"{name} is needed by the GUI but the trim would drop it"


@pytest.mark.parametrize("name", DENIED_LIBRARIES)
def test_unused_library_is_dropped(name):
    assert is_denied_library(name), f"{name} is unused and should not be bundled"


@pytest.mark.parametrize(
    "path",
    [
        "PySide6/qmlls",
        "PySide6/qmlformat",
        "PySide6/assistant",
        "PySide6/linguist",
        "PySide6/designer",
        "PySide6/lupdate",
        "PySide6/lrelease",
        "PySide6/QtWebEngineCore.pyi",
        "PySide6/QtCharts.pyi",
        "PySide6/Qt3DCore.pyi",
        "PySide6/Qt/plugins/multimedia",
        "PySide6/Qt/plugins/designer",
        "PySide6/Qt/plugins/sceneparsers",
        "PySide6/Qt/plugins/sqldrivers",
        "PySide6/Qt/plugins/wayland-graphics-integration-client",
        "PySide6\\Qt\\plugins\\assetimporters",
    ],
)
def test_developer_tools_and_unused_plugins_are_dropped(path):
    assert is_denied_qt_data(path), f"{path} is not needed at runtime"


@pytest.mark.parametrize(
    "path",
    [
        # The platform plugin is what makes a window exist at all.
        "PySide6/Qt/plugins/platforms",
        "PySide6/Qt/plugins/platforms/libqoffscreen.so",
        "PySide6/Qt/plugins/platforms/libqxcb.so",
        # Icon and image decoding, for the app icon and the QML assets.
        "PySide6/Qt/plugins/imageformats/libqjpeg.so",
        "PySide6/Qt/plugins/iconengines/libqsvgicon.so",
        "PySide6/Qt/plugins/tls",
        "PySide6/Qt/plugins/networkinformation",
        "PySide6/Qt/plugins/generic",
        "PySide6/Qt/plugins/renderers",
        "PySide6/Qt/plugins/qmltooling",
        "PySide6/Qt/plugins/vectorimageformats",
        "PySide6/Qt/plugins/xcbglintegrations",
        "PySide6/Qt/plugins/egldeviceintegrations",
        "PySide6/Qt/plugins/platforminputcontexts",
        "PySide6/Qt/plugins/platformthemes",
        # Qt Quick's QML modules ship as data, not as Python modules.
        "PySide6/Qt/qml/QtQuick/Controls/qmldir",
        "PySide6/Qt/qml/QtQuick/Layouts/qmldir",
        "PySide6/Qt/lib/libQt6Core.so.6.11.2",
    ],
)
def test_required_qt_data_is_kept(path):
    assert not is_denied_qt_data(path), f"{path} is needed at runtime but the trim would drop it"


def test_non_pyside6_data_is_untouched():
    # The trim must not reach outside PySide6; the fingerprint and QML data are
    # the files whose absence shows up as a blank window with no traceback.
    for path in (
        "camoufox/gui/qml/main.qml",
        "camoufox/gui/assets/icon.ico",
        "camoufox/territoryInfo.xml",
        "browserforge/headers.zip",
        "playwright/driver/node",
    ):
        assert not is_denied_qt_data(path)


def test_trim_binaries_keeps_only_the_expected_side():
    collected = [(name, name) for name in REQUIRED_LIBRARIES + DENIED_LIBRARIES]
    kept = [entry[0] for entry in trim_binaries(collected)]

    assert kept == REQUIRED_LIBRARIES
    assert len(kept) < len(collected)


def test_trim_datas_keeps_the_platform_plugin():
    collected = [
        ("PySide6/Qt/plugins/platforms/libqoffscreen.so", "x"),
        ("PySide6/Qt/plugins/multimedia/libffmpeg.so", "x"),
        ("PySide6/qmlls", "x"),
    ]
    kept = [entry[0] for entry in trim_datas(collected)]

    assert kept == ["PySide6/Qt/plugins/platforms/libqoffscreen.so"]


def test_unknown_library_is_kept():
    # A denylist, not an allowlist: a library this list has never heard of costs
    # disk if it stays, and a blank window if it goes.
    assert not is_denied_library("libQt6SomethingAddedInAFutureRelease.so.6.99.0")


def test_qtbleed_guard_keeps_the_3d_modules_detectable():
    # Qt's 3D module names start with a digit right after the version --
    # `libQt63DCore`, not `libQt6_3DCore`. A greedy `qt\d*` prefix strip ate that
    # `3` and produced `dcore`, which matched nothing and let the whole Qt 3D set
    # through. The token must still contain the module name.
    from _qt_trim import module_token

    assert module_token("libQt63DCore.so.6.11.2") == "3dcore"
    assert module_token("libQt6Core.so.6.11.2") == "core"
    assert is_denied_library("libQt63DCore.so.6.11.2")
    assert not is_denied_library("libQt6Core.so.6.11.2")


def test_qml_plugins_are_matched_by_their_lowercase_names():
    # The QML plugin directory contains `libqtwebenginequickplugin.so`: lower
    # case, unversioned, and the thing whose DT_NEEDED entry drags the 194 MB
    # Chromium back in. A match on the versioned library name alone misses it.
    assert is_denied_library("libqtwebenginequickplugin.so")
    assert is_denied_qt_data("PySide6/Qt/qml/QtWebEngine/libqtwebenginequickplugin.so")
    assert is_denied_qt_data("PySide6/Qt/qml/QtQuick3D/qmldir")


def test_required_qml_modules_are_kept():
    for path in (
        "PySide6/Qt/qml/QtQuick/qmldir",
        "PySide6/Qt/qml/QtQuick/Controls/qmldir",
        "PySide6/Qt/qml/QtQuick/Layouts/qmldir",
        "PySide6/Qt/qml/QtQml/qmldir",
        "PySide6/Qt/qml/QtQuick/Window/qmldir",
    ):
        assert not is_denied_qt_data(path), f"{path} is needed by the GUI"


def test_webengine_family_is_dropped_as_a_group():
    # The single largest saving. Asserted as a group so a regex typo that lets
    # one Chromium library through is caught even if the names change.
    webengine = [
        "libQt6WebEngineCore.so.6.11.2",
        "libQt6WebEngineQuick.so.6.11.2",
        "libQt6WebEngineQuickDelegatesQml.so.6.11.2",
        "libQt6WebEngineWidgets.so.6.11.2",
    ]
    assert all(is_denied_library(name) for name in webengine)
