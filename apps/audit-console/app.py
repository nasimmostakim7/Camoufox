#!/usr/bin/env python3
"""
WAF Audit Console -- a self-contained front end for the camoufox audit engine.

Answers one question for a site owner: as a client looks less and less like a bot,
which of my defenses is the one actually holding? It runs the engine's ordered
evasion ladder and reports which rung the defense first stops, and which rungs sail
through, so a finding points at a single control instead of "turn everything up".

Runs on a bare Python 3.10+ with nothing installed. The audit engine is vendored into
`console/_engine/` (see sync_engine.py), and the HTTP surface is stdlib `http.server`
-- that is what lets CI build this as one file.

Safety. This ships with a demo WAF of its own, and by default it will audit only
that. It does not become an open request forwarder: the target host is checked
against an allow-list before any request leaves, and `--target` is how a local
operator deliberately adds their own.

Usage:
    python3 app.py                      # audit the bundled demo, print a URL
    python3 app.py --port 8000
    python3 app.py --target https://staging.example.com/ --i-am-authorized
    python3 app.py --export ./out       # write json/csv/html/text and exit
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from console import demo_waf  # noqa: E402
from console.proxies import ROTATION_LEVEL_IDS, ProxyPoolStore  # noqa: E402
from console.runs import AuditService  # noqa: E402
from console.server import serve  # noqa: E402


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="waf-audit-console",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="bind port (default: 8000)")
    parser.add_argument(
        "--target",
        default="",
        help="audit this URL instead of the bundled demo. Requires --i-am-authorized.",
    )
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="confirm you own the --target host or have written permission to test it",
    )
    parser.add_argument(
        "--visitors", type=int, default=18, help="visitors for --export runs (default: 18)"
    )
    parser.add_argument(
        "--hours", type=float, default=0.02, help="window for --export runs (default: 0.02)"
    )
    parser.add_argument(
        "--max-level", type=int, default=2, help="highest rung to climb (default: 2)"
    )
    parser.add_argument("--seed", type=int, default=7, help="schedule seed (default: 7)")
    parser.add_argument(
        "--proxy",
        action="append",
        default=[],
        metavar="URL",
        help=(
            "a proxy for the L4+ rotation rungs, repeatable. Without at least one, "
            "those rungs are left out rather than run on this host's own IP."
        ),
    )
    parser.add_argument(
        "--proxy-file",
        default="",
        help="a file with one proxy per line, for the L4+ rotation rungs",
    )
    parser.add_argument(
        "--proxy-gateway",
        default="",
        help=(
            "one rotating endpoint for L4+. Include the {session} token if the "
            "gateway supports per-session rotation."
        ),
    )
    parser.add_argument(
        "--export",
        default="",
        help="run one audit headlessly, write reports here, and exit",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="audit the bundled demo at L0 and exit nonzero on failure (packaging check)",
    )
    return parser.parse_args(argv)


def _self_test() -> int:
    """
    Audit the demo end to end, in-process, and report.

    Used by the packaging gate: it exercises the bundled archive the way a user
    would, which catches a module or UI asset the build left out -- things that
    only surface once everything is inside a zipapp.
    """
    import asyncio

    from console._engine import AuditConfig, AuditRunner, TargetScope, Verdict
    from console.runs import CONSOLE_LIMITS

    waf, target = demo_waf.start_demo_waf()
    try:
        scope = TargetScope.from_urls([target], acknowledged=True)
        config = AuditConfig(
            target_url=target,
            scope=scope,
            levels=[0],
            visitor_count=4,
            duration_hours=0.002,
            cooldown_between_levels_s=0.0,
            seed=1,
            limits=CONSOLE_LIMITS,
            headless=True,
        )
        problems = config.validate()
        if problems:
            print("self-test: invalid config: " + "; ".join(problems), file=sys.stderr)
            return 1

        report = asyncio.run(AuditRunner(config).run())
        level = report.levels[0]
        verdicts = [v.verdict for v in level.visits]
        if len(verdicts) != 4:
            print(f"self-test: expected 4 visits, got {len(verdicts)}", file=sys.stderr)
            return 1
        if not all(v == Verdict.BLOCKED for v in verdicts):
            print(f"self-test: demo defense did not block: {verdicts}", file=sys.stderr)
            return 1
        if "Cloudflare" not in level.vendors_seen():
            print("self-test: vendor not attributed", file=sys.stderr)
            return 1

        # The UI must be reachable through the same reader the server uses, which
        # is the only form that works inside the zipapp.
        from console.server import read_ui_asset

        for asset in ("index.html", "console.js"):
            if read_ui_asset(asset) is None:
                print(f"self-test: UI asset missing: {asset}", file=sys.stderr)
                return 1

        print(f"self-test OK: {len(verdicts)} visits, vendor {level.vendors_seen()}")
        return 0
    finally:
        waf.stop()


def _read_pool_entries(args) -> List[str]:
    """The proxy strings named on the command line, comments and blanks removed."""
    entries = list(args.proxy)
    if args.proxy_file:
        text = Path(args.proxy_file).expanduser().read_text(encoding="utf-8", errors="replace")
        entries.extend(
            line.split("#", 1)[0].strip()
            for line in text.splitlines()
            if line.split("#", 1)[0].strip()
        )
    return entries


def _configure_pool(store, args) -> None:
    """
    Fill a store from the CLI, or leave it empty.

    Goes through the store rather than building a spec by hand so that a pool set
    at launch and one set from the UI are the same object, with the same redaction
    and the same 0600 temp file. Raises ValueError on bad input.
    """
    if args.proxy_gateway:
        store.set_gateway(args.proxy_gateway)
        return
    entries = _read_pool_entries(args)
    if entries:
        store.set_list(entries)


def _warn_if_rotation_skipped(args) -> None:
    """Tell the operator up front when L4+ cannot run."""
    if args.max_level >= min(ROTATION_LEVEL_IDS) and not (
        args.proxy or args.proxy_file or args.proxy_gateway
    ):
        print(
            "No proxy supplied: L4+ are defined by a rotating exit IP, so they "
            "will be left out rather than run on this host's address.",
            file=sys.stderr,
        )


def _export(target_url: str, args) -> int:
    """Run one audit without the server, write every format, and return an exit code."""
    from console._engine import AuditConfig, AuditRunner, TargetScope
    from console._engine.report import render_text, write_report
    from console.runs import CONSOLE_LIMITS

    _warn_if_rotation_skipped(args)
    store = ProxyPoolStore()
    _configure_pool(store, args)
    pool = store.get()
    pool_spec = pool.spec if pool is not None else None
    selected = [
        i
        for i in range(0, args.max_level + 1)
        if pool_spec is not None or i not in ROTATION_LEVEL_IDS
    ]

    scope = TargetScope.from_urls([target_url], acknowledged=True)
    config = AuditConfig(
        target_url=target_url,
        scope=scope,
        levels=selected,
        visitor_count=args.visitors,
        duration_hours=args.hours,
        cooldown_between_levels_s=0.0,
        seed=args.seed,
        limits=CONSOLE_LIMITS,
        headless=True,
        proxy=pool_spec,
    )
    problems = config.validate()
    if problems:
        print("invalid configuration: " + "; ".join(problems), file=sys.stderr)
        return 2

    import asyncio

    report = asyncio.run(AuditRunner(config).run())
    written = write_report(report, args.export, stem="audit")
    print(render_text(report))
    for fmt, path in written.items():
        print(f"wrote {fmt}: {path}")
    return 0 if not report.aborted else 1


def main(argv=None) -> int:
    args = _parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.target and not args.i_am_authorized:
        print(
            "Refusing to audit an external target without --i-am-authorized.\n"
            "Confirm you own the host or have written permission to test it.",
            file=sys.stderr,
        )
        return 2

    if args.target:
        # A local operator named their own target deliberately. Nothing is served:
        # this is the headless export path, so there is no console for anyone else
        # to point anywhere.
        return _export(args.target, args)

    if args.export:
        print("--export needs --target and --i-am-authorized", file=sys.stderr)
        return 2

    waf, target_url = demo_waf.start_demo_waf()
    host = target_url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
    service = AuditService(allowed_hosts=[host], demo_target=target_url)

    _warn_if_rotation_skipped(args)
    try:
        _configure_pool(service.proxies, args)
        pool = service.proxies.get()
        if pool is not None:
            print(f"Proxy pool: {pool.summary()['count']} endpoint(s)")
    except (OSError, ValueError) as exc:
        print(f"proxy pool rejected: {exc}", file=sys.stderr)
        waf.stop()
        return 2

    print(f"Demo WAF listening on {target_url}")
    print(f"Audit console on http://{args.host}:{args.port}/")
    print("Press Ctrl+C to stop.")

    thread = threading.Thread(
        target=serve, args=(args.host, args.port, service), daemon=True
    )
    thread.start()
    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        waf.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
