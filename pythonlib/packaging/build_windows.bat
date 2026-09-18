@echo off
REM ============================================================================
REM  Build CamoufoxGUI.exe on Windows.
REM
REM  Run this ON a Windows machine. PyInstaller does not cross-compile: a Linux
REM  or macOS host can never produce a working .exe, so this script exists to be
REM  run where the target is.
REM
REM  Usage:
REM      packaging\build_windows.bat
REM
REM  Output:
REM      dist\CamoufoxGUI\CamoufoxGUI.exe
REM
REM  Everything must run in ONE environment where camoufox[gui] is installed, or
REM  PyInstaller will bundle a different set of dependencies than you tested with.
REM ============================================================================

setlocal

REM Repository root is the parent of this script's directory.
set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%..\.."
cd /d "%REPO_ROOT%" || (
    echo ERROR: could not enter the repository root.
    exit /b 1
)

echo.
echo === Step 1/5: Python version ===
python --version || (
    echo ERROR: python not found on PATH. Install Python 3.10+ and tick
    echo        "Add python.exe to PATH" in the installer.
    exit /b 1
)

echo.
echo === Step 2/5: Build environment ===
REM Use a dedicated venv: a system-wide install mixes in packages that
REM PyInstaller will happily bundle, bloating the output and adding conflicts.
if not exist ".build-venv\Scripts\python.exe" (
    echo Creating .build-venv ...
    python -m venv .build-venv || exit /b 1
)
call ".build-venv\Scripts\activate.bat" || exit /b 1

echo.
echo === Step 3/5: Installing camoufox[gui] and PyInstaller ===
REM Installed from the git URL, not PyPI: the Audit tab lives in this fork and
REM the published package is upstream's, without it.
python -m pip install --upgrade pip --quiet
python -m pip install "camoufox[gui] @ git+https://github.com/nasimmostakim7/Camoufox.git@main#subdirectory=pythonlib" || exit /b 1
python -m pip install pyinstaller || exit /b 1

echo.
echo === Step 4/5: Building ===
REM --clean discards cached analysis: a stale cache silently ships an old bundle.
python -m PyInstaller pythonlib\packaging\camoufox-gui.spec --noconfirm --clean || exit /b 1

echo.
echo === Step 5/5: Smoke test ===
REM The GUI is a windowed build, so a failure writes a log next to the exe
REM instead of printing to a console. Start it, wait, and check for that log.
if not exist "dist\CamoufoxGUI\CamoufoxGUI.exe" (
    echo ERROR: build produced no exe.
    exit /b 1
)

del /q "dist\CamoufoxGUI\CamoufoxGUI-error.log" 2>nul
start "" "dist\CamoufoxGUI\CamoufoxGUI.exe"
timeout /t 20 /nobreak >nul

if exist "dist\CamoufoxGUI\CamoufoxGUI-error.log" (
    echo.
    echo FAILED: the app wrote an error log:
    echo ---------------------------------------------------------------
    type "dist\CamoufoxGUI\CamoufoxGUI-error.log"
    echo ---------------------------------------------------------------
    echo That is the real failure. Most often a hidden import or a data file
    echo is missing from the spec's datas/hiddenimports lists.
    exit /b 1
)

echo.
echo ===============================================================
echo  BUILD OK
echo ===============================================================
echo.
echo  Executable : %REPO_ROOT%\dist\CamoufoxGUI\CamoufoxGUI.exe
echo  Folder size: (see below)
echo.
echo  Ship the WHOLE dist\CamoufoxGUI folder, not the exe alone --
echo  _internal\ holds the Qt libraries, QML data and the Playwright driver.
echo.
echo  The user still needs the browser once:
echo      1. open the app, Browsers tab, install a version, or
echo      2. run:  camoufox fetch
echo.
dir /s "dist\CamoufoxGUI" | findstr /C:"File(s)" /C:"Dir(s)"

echo.
echo  Zipping for distribution ...
powershell -NoProfile -Command "Compress-Archive -Path 'dist\CamoufoxGUI\*' -DestinationPath 'dist\CamoufoxGUI-windows-x64.zip' -Force"
if exist "dist\CamoufoxGUI-windows-x64.zip" (
    echo  Archive: %REPO_ROOT%\dist\CamoufoxGUI-windows-x64.zip
)

endlocal
