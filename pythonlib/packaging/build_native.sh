#!/usr/bin/env bash
#
# Build the Camoufox Manager GUI as a native application.
#
# Run this on the OS you are targeting. PyInstaller does not cross-compile: this
# script on macOS produces a macOS app, and on Linux a Linux binary. For a
# Windows .exe, use build_windows.bat on Windows.
#
# Usage:
#     pythonlib/packaging/build_native.sh
#
# Output:
#     dist/CamoufoxGUI/CamoufoxGUI          (Linux)
#     dist/CamoufoxGUI/CamoufoxGUI.app      (macOS)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

echo "=== Step 1/5: Python ==="
python3 --version

echo
echo "=== Step 2/5: Build environment ==="
# A dedicated venv keeps unrelated system packages from being bundled, which
# would both bloat the output and risk version conflicts with PySide6.
if [ ! -x ".build-venv/bin/python" ]; then
    echo "Creating .build-venv ..."
    python3 -m venv .build-venv
fi
# shellcheck disable=SC1091
source .build-venv/bin/activate

echo
echo "=== Step 3/5: Installing camoufox[gui] and PyInstaller ==="
# From the git URL, not PyPI: the Audit tab is this fork's addition and the
# published package is upstream's.
python -m pip install --upgrade pip --quiet
python -m pip install "camoufox[gui] @ git+https://github.com/mostakimnasim3/camoufox.git@main#subdirectory=pythonlib"
python -m pip install pyinstaller

echo
echo "=== Step 4/5: Building ==="
# --clean discards cached analysis; a stale cache ships an old bundle silently.
python -m PyInstaller pythonlib/packaging/camoufox-gui.spec --noconfirm --clean

echo
echo "=== Step 5/5: Smoke test ==="
APP="dist/CamoufoxGUI/CamoufoxGUI"
if [ ! -x "$APP" ]; then
    echo "ERROR: build produced no executable."
    exit 1
fi

rm -f dist/CamoufoxGUI/CamoufoxGUI-error.log

# Needs a display. On a headless host, run under Xvfb:
#     xvfb-run -s "-screen 0 1440x900x24" pythonlib/packaging/build_native.sh
if [ -n "${DISPLAY:-}" ] || [ "$(uname)" = "Darwin" ]; then
    "$APP" &
    APP_PID=$!
    sleep 20
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
else
    echo "No DISPLAY: skipping the launch test. The binary is built; test it on a desktop."
fi

if [ -f dist/CamoufoxGUI/CamoufoxGUI-error.log ]; then
    echo
    echo "FAILED: the app wrote an error log:"
    echo "---------------------------------------------------------------"
    cat dist/CamoufoxGUI/CamoufoxGUI-error.log
    echo "---------------------------------------------------------------"
    echo "Most often a hidden import or a data file is missing from the spec."
    exit 1
fi

echo
echo "==============================================================="
echo " BUILD OK"
echo "==============================================================="
echo
echo " Application: $REPO_ROOT/dist/CamoufoxGUI/CamoufoxGUI"
du -sh dist/CamoufoxGUI
echo
echo " Ship the whole dist/CamoufoxGUI folder, not the binary alone:"
echo " _internal/ holds the Qt libraries, QML data and the Playwright driver."
echo
echo " The user still needs the browser once, via the Browsers tab or"
echo " 'camoufox fetch'."
