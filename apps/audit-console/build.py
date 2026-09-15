#!/usr/bin/env python3
"""
Build the console as one self-contained executable file.

`python3 waf-audit-console.pyz` is the deliverable: a zipapp carrying the console,
the vendored audit engine and the UI, runnable on any Python 3.10+ with nothing
installed. That constraint is the whole reason the console avoids a web framework,
and it is what CI asserts.

The engine is re-synced first so the bundle can never contain a stale copy.

Run:
    python3 apps/audit-console/build.py --out dist/waf-audit-console.pyz
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import List

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))

#: Copied into the archive. `console/_engine` is included because it is generated
#: at build time; everything else is the app itself.
SOURCE_DIRS = ("console",)
ROOT_FILES = ("app.py",)
UI_EXTENSIONS = (".html", ".js", ".css")


def _resync(python: Path) -> None:
    proc = subprocess.run(
        [str(python), str(APP_DIR / "sync_engine.py")],
        cwd=APP_DIR,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"engine sync failed: {proc.stderr or proc.stdout}")


def _collect() -> List[Path]:
    files: List[Path] = []
    for name in ROOT_FILES:
        path = APP_DIR / name
        if not path.is_file():
            raise SystemExit(f"missing {path}")
        files.append(path)
    for dirname in SOURCE_DIRS:
        root = APP_DIR / dirname
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts:
                continue
            if path.suffix in (".pyc", ".pyo"):
                continue
            if path.suffix and path.suffix not in (".py", *UI_EXTENSIONS):
                continue
            files.append(path)
    return files


def build(out: Path, python: Path) -> Path:
    _resync(python)

    out.parent.mkdir(parents=True, exist_ok=True)
    files = _collect()

    # __main__.py is what makes the archive runnable as `python3 <file>.pyz`.
    main_shim = APP_DIR / "__main__.py"
    main_shim.write_text(
        "import sys\n"
        "from app import main\n\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n",
        encoding="utf-8",
    )
    files.append(main_shim)

    try:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in files:
                zf.write(path, path.relative_to(APP_DIR).as_posix())
    finally:
        main_shim.unlink(missing_ok=True)

    out.chmod(0o755)
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=APP_DIR.parent.parent / "dist" / "waf-audit-console.pyz",
        help="where to write the archive",
    )
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    args = parser.parse_args(argv)

    out = build(args.out.resolve(), args.python)
    print(f"built {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
