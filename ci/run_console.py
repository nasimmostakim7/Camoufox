#!/usr/bin/env python3
"""console gate: the WAF Audit Console's own suite, plus its packaging.

Runs before the console is built, so a console that cannot pass its own tests is
never published as a release asset. The suite is browser-free (it audits the demo
WAF over plain HTTP), which keeps this gate in the same cheap tier as pythonlib.

Two things are asserted beyond the tests themselves:

* the vendored engine is not stale -- the console copies `camoufox.audit` at build
  time, so a change to the ladder or the classifier that was not synced would ship
  an old engine under a new version;
* the single-file build actually imports and serves with no third-party packages
  installed, which is the property the released artifact is bought for.

Run:
    python3 -m ci.run_console
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import List, Optional

from . import results as evidence
from ._util import EVIDENCE_DIR, REPO_ROOT, WORK_DIR
from ._pytest import parse_junit, run_pytest

APP_DIR = REPO_ROOT / "apps" / "audit-console"
BUILD_SCRIPT = APP_DIR / "build.py"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=EVIDENCE_DIR)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)

    result = evidence.GateResult(gate="console")

    if not (APP_DIR / "tests").is_dir():
        result.note("apps/audit-console/tests does not exist")
        result.finish(evidence.ERROR).save(args.evidence_dir)
        return 1

    # 1. The vendored engine must match its source. Checked here as well as in the
    #    pytest suite so the failure reads as a drift, not a test failure.
    drift = subprocess.run(
        [str(args.python), str(APP_DIR / "sync_engine.py"), "--check"],
        cwd=APP_DIR,
        capture_output=True,
        text=True,
    )
    if drift.returncode != 0:
        result.note((drift.stderr or drift.stdout).strip())
        result.finish(evidence.ERROR).save(args.evidence_dir)
        return 1

    # 2. The suite, driven through the console's real HTTP surface.
    junit = WORK_DIR / "junit-console.xml"
    proc = run_pytest(
        cwd=APP_DIR,
        python=args.python,
        args=["tests/"],
        junit=junit,
        timeout=args.timeout,
    )
    outcomes = parse_junit(junit)
    if not outcomes:
        result.note(f"pytest exited {proc.code} with no junit output; the suite did not run")
        result.finish(evidence.ERROR).save(args.evidence_dir)
        return 1
    for tid, outcome in outcomes.items():
        result.record(tid, outcome)

    # 3. Build the single file and assert it carries no third-party code. This is
    #    the release shape, so it is checked on every run rather than only at tag.
    out = WORK_DIR / "waf-audit-console.pyz"
    build = subprocess.run(
        [str(args.python), str(BUILD_SCRIPT), "--out", str(out)],
        cwd=APP_DIR,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0 or not out.is_file():
        result.note(f"single-file build failed: {(build.stderr or build.stdout).strip()[:400]}")
        result.finish(evidence.ERROR).save(args.evidence_dir)
        return 1

    result.artifacts.append(out.name)
    vendored = _top_level_packages(out)
    foreign = sorted(
        pkg
        for pkg in vendored
        if pkg not in {"console", "_engine", "camoufox", "__main__", "app", "zipimport"}
    )
    if foreign:
        # A dependency slipped in; the artifact would no longer run on a bare
        # Python, which is the one thing it promises.
        result.note(f"bundle carries non-stdlib packages: {', '.join(foreign)}")
        result.finish(evidence.ERROR).save(args.evidence_dir)
        return 1
    result.metrics["bundle_bytes"] = out.stat().st_size
    result.metrics["bundle_modules"] = len(vendored)

    smoke = _smoke_run(args.python, out)
    if smoke is not None:
        result.note(smoke)
        result.finish(evidence.ERROR).save(args.evidence_dir)
        return 1

    tally = result.tally()
    result.metrics["exit_code"] = proc.code
    result.note(
        f"{tally.get('pass', 0)} passed, {tally.get('fail', 0)} failed, "
        f"{tally.get('error', 0)} errored ({tally.get('total', 0)} collected); "
        f"bundle {out.stat().st_size} bytes, {len(vendored)} modules"
    )
    failing = tally.get("fail", 0) + tally.get("error", 0)
    status = evidence.PASS if failing == 0 else evidence.FAIL
    result.finish(status).save(args.evidence_dir)
    return 0 if status == evidence.PASS else 1


def _top_level_packages(bundle: Path) -> List[str]:
    """Top-level importable names inside the zipapp."""
    names = set()
    with zipfile.ZipFile(bundle) as zf:
        for entry in zf.namelist():
            head = entry.split("/", 1)[0]
            if head.endswith(".py"):
                names.add(head[:-3])
            elif "/" in entry:
                names.add(head)
    return sorted(names)


def _smoke_run(python: Path, bundle: Path) -> Optional[str]:
    """
    Run the built file end to end against its own demo, headlessly.

    Catches the failures that only appear once packaged: a module the zipapp
    cannot find, a data file the build forgot, a UI asset left out of the archive.
    """
    proc = subprocess.run(
        [
            str(python),
            str(bundle),
            "--self-test",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        return f"bundled app self-test failed: {(proc.stderr or proc.stdout).strip()[:400]}"
    return None


if __name__ == "__main__":
    sys.exit(main())
