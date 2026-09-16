# Packaging the Camoufox Manager GUI as a standalone application

This directory builds the Qt GUI (Audit tab included) into a runnable
application, so the person running it does not need Python or pip.

## What you get

| Host | Command | Output |
|------|---------|--------|
| Windows | `packaging\build_windows.bat` | `dist\CamoufoxGUI\CamoufoxGUI.exe` |
| Linux | `packaging/build_native.sh` | `dist/CamoufoxGUI/CamoufoxGUI` |
| macOS | `packaging/build_native.sh` | `dist/CamoufoxGUI/CamoufoxGUI` |

The output is a **folder**, not a single file. Ship the whole folder: `_internal/`
carries the Qt libraries, the QML tree and the Playwright driver, and the app will
not start without it.

## The one rule: build on the target OS

PyInstaller does not cross-compile. A Linux or macOS machine cannot produce a
Windows `.exe` — the executable has to be assembled where it will run. So:

* for a Windows `.exe`, run `build_windows.bat` **on Windows**;
* for a Linux binary, run `build_native.sh` on Linux;
* for a macOS app, run `build_native.sh` on macOS.

There is no flag that changes this.

## The browser is not bundled

The Camoufox browser is a separate ~470 MB download per platform, fetched at
runtime from GitHub Releases by `camoufox fetch` and stored under the platform
cache directory (`%LOCALAPPDATA%\camoufox` on Windows, `~/.cache/camoufox` on
Linux). It is not in the application folder.

That is deliberate. Bundling it would add ~470 MB per supported OS, and it would
break the moment a user moved the folder, because the path is recorded at install
time. The first run therefore needs one of:

* the GUI's **Browsers** tab → install a version, or
* `camoufox fetch` from a command line.

The audit performs its first three rungs without any browser, so the app is
usable immediately; only the browser rungs (L1–L6) need it.

## What the spec has to get right

Three things are invisible to PyInstaller's static analysis and must be listed
explicitly. Each one was found by building and running the result, and each
failure looked like something other than its cause.

**1. QML and package data.** The GUI loads its interface by filesystem path:

```python
engine.load(QUrl.fromLocalFile(str(Path(__file__).parent / "qml/main.qml")))
```

A missing `main.qml` gives a process that exits with `-1` and prints nothing. The
spec collects the whole `camoufox` data tree for this.

**2. Data files read at import time by dependencies.** These fail before any of
our code runs, so the traceback points into a third-party package:

| Package | File it needs | Symptom if absent |
|---------|---------------|-------------------|
| `apify_fingerprint_datapoints` | `data/input-network-definition.zip` | `FileNotFoundError` from `browserforge` |
| `language_tags` | `data/json/*.json` | `FileNotFoundError` from `language_tags` |
| `playwright` | `driver/` (Node runtime) | browser never launches |

**3. Qt plugins and QML modules.** `PySide6` loads these dynamically by name, so
none appear as an import. Without them Qt reports that it cannot find the platform
plugin, or the QML engine loads no root object.

`hiddenimports` therefore includes `camoufox.gui` and `camoufox.audit` (both
imported lazily), the Qt modules the QML uses, and `geoip2` (checked at runtime
with `importlib.util.find_spec`).

## Windows notes

* **The `--onedir` layout is used on purpose.** `--onefile` would unpack ~200 MB
  to a temp directory on every launch, which is slow and trips antivirus
  heuristics far more often.
* **Unsigned executables get flagged.** Windows SmartScreen will warn on first
  run because the binary is not code-signed. Signing needs a certificate; there
  is no way around the warning without one.
* **`console=False`** is set, so no terminal window appears. That also means a
  crash prints nowhere — which is exactly why `camoufox_launcher.py` writes
  `CamoufoxGUI-error.log` next to the executable and shows a dialog.
* **Antivirus false positives** are common with PyInstaller output. A code-signing
  certificate is the only reliable fix.

## Building without a local machine: GitHub Actions

`.github/workflows/package-gui.yml` runs on a tag push or on demand, and produces
three archives. Nothing needs to be installed locally.

**To build and download the executables:**

1. Repository → **Actions** → **Build desktop app** → **Run workflow**.
2. When it finishes, download from the run's **Artifacts** section:
   `CamoufoxGUI-windows-x64`, `CamoufoxGUI-linux-x64`, `CamoufoxGUI-macos-arm64`.

**To publish them as a release:**

```bash
git tag v0.5.6-gui
git push origin v0.5.6-gui
```

The three archives are attached to that tag's release automatically. The `release`
job only runs for tags: an artifact from a manual run has no release to attach to.

Each archive is built on its own runner (`windows-latest`, `ubuntu-24.04`,
`macos-14`) because of the no-cross-compilation rule above.

### The self-check the pipeline runs

`--self-check` loads the real `main.qml` under Qt's **offscreen** platform and
asserts that a root object appears and that every `auditBackend.…` name the QML
binds to exists on `AuditBackend`:

```bash
./dist/CamoufoxGUI/CamoufoxGUI --self-check
cat dist/CamoufoxGUI/CamoufoxGUI-selfcheck.log
```

A passing run reports how many bindings it resolved:

```
self-check OK: QML main.qml, 1 root object(s), 59 audit bindings resolved
```

The names are read out of the QML rather than kept in a list here, because a
hand-maintained list only covers what someone remembered to add — and the failure
this guards against is the binding nobody thought about.

That is what catches a missing `datas` entry. Without it, a bad bundle presents as
a window that never opens, with nothing in any log. The verdict goes to a file
because a `console=False` build has no stderr to print to.

The pipeline then checks the shipped files by name — `main.qml`, the icon,
`browserforge.yml`, `language_tags`, the apify fingerprint archive, and
Playwright's Node driver — so a failure names the file that went missing rather
than just reporting a dead app.

On Windows the log is written before the process exits, so the gate reads the log
rather than the exit code. A GUI-subsystem executable is not waited for by
PowerShell, which makes the exit code unreliable there.

macOS is the exception: its runners have no window server and the PySide6 wheel
has no offscreen plugin there, so that leg verifies the bundle by its data files
and executable instead.

## Testing a build

```bat
REM The launcher writes this only when startup failed:
type dist\CamoufoxGUI\CamoufoxGUI-error.log
```

A clean start leaves no such file. Then confirm the Audit tab appears and the
**PROXY** section is reachable by scrolling within the form — it sits below the
Traffic Plan block, not at the top.

For a headless Linux check:

```bash
xvfb-run -s "-screen 0 1440x900x24" dist/CamoufoxGUI/CamoufoxGUI
```

## Update this when the GUI changes

If the QML gains an import, or a new dependency is added that reads a data file at
import time, add it to `hook-camoufox.py` and `camoufox-gui.spec`. The failure mode
is a missing-files error from a library you never called directly, which is easy
to misdiagnose as a bug in that library.
