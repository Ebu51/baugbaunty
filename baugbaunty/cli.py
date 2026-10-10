"""Command-line interface and pipeline orchestration for baugbaunty."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core.config import DEFAULTS, Config
from .core.logging import configure
from .core.scope import Scope
from .core.store import Store
from .integrations import external
from .modules.base import Context
from .modules.content import ContentModule
from .modules.nuclei import NucleiModule
from .modules.ports import PortsModule
from .modules.probe import ProbeModule
from .modules.subdomains import SubdomainModule
from .report import generate_reports

BANNER = r"""
  _                      _                     _
 | |__   __ _ _   _  __ _| |__   __ _ _   _ _ __ | |_ _   _
 | '_ \ / _` | | | |/ _` | '_ \ / _` | | | | '_ \| __| | | |
 | |_) | (_| | |_| | (_| | |_) | (_| | |_| | | | | |_| |_| |
 |_.__/ \__,_|\__,_|\__, |_.__/ \__,_|\__,_|_| |_|\__|\__, |
                    |___/                             |___/
 scope-first bug bounty toolkit  v{ver}
""".format(ver=__version__)

# Ordered phases of the default pipeline.
PHASES = ["subdomains", "probe", "content", "ports", "nuclei"]
ACTIVE_PHASES = {"probe", "content", "ports", "nuclei"}  # send traffic to target


def _build_context(cfg: Config, log) -> tuple[Context, Store]:
    out_dir = Path(cfg.get("output.dir", "output"))
    program = cfg.get("program.name", "engagement")
    db_path = out_dir / f"{program}.sqlite"
    store = Store.open(db_path)
    ctx = Context.build(cfg, store, log)
    return ctx, store


def _require_authorization(cfg: Config, phases: list[str], log) -> bool:
    active = [p for p in phases if p in ACTIVE_PHASES]
    if active and not cfg.authorized:
        log.error(
            "Active phases request traffic to the target but the engagement is "
            "NOT authorized."
        )
        log.error(
            "Set program.authorized: true in your config ONLY if you have "
            "explicit permission to test this program's scope."
        )
        log.error(f"Blocked active phases: {', '.join(active)}")
        return False
    return True


# --- subcommands ---------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    log = configure(args.log_level)
    path = Path(args.output)
    if path.exists() and not args.force:
        log.error(f"{path} already exists (use --force to overwrite)")
        return 1

    import json

    sample = json.loads(json.dumps(DEFAULTS))
    sample["program"]["name"] = args.name or "my-program"
    sample["scope"]["include"] = ["*.example.com"]
    sample["scope"]["exclude"] = ["*.staging.example.com"]
    path.write_text(json.dumps(sample, indent=2), encoding="utf-8")
    log.success(f"Wrote starter config to {path}")
    log.info("Edit scope.include / scope.exclude, then flip program.authorized "
             "to true once you have permission.")
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    log = configure(args.log_level)
    print(BANNER)
    avail = external.available_tools()
    for tool, ok in avail.items():
        mark = "\033[32m✓\033[0m" if ok else "\033[31m✗\033[0m"
        print(f"  {mark}  {tool}")
    missing = [t for t, ok in avail.items() if not ok]
    if missing:
        print("\nThe toolkit works without these, but installs unlock more power.")
        print("ProjectDiscovery suite: https://github.com/projectdiscovery")
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    log = configure(args.log_level)
    cfg = Config.load(args.config)
    scope = Scope.from_lists(cfg.get("scope.include", []), cfg.get("scope.exclude", []))
    exit_code = 0
    for asset in args.assets:
        decision = scope.check(asset)
        tag = {
            "in_scope": "\033[32mIN-SCOPE\033[0m",
            "out_of_scope": "\033[31mOUT-OF-SCOPE\033[0m",
            "not_listed": "\033[33mNOT-LISTED\033[0m",
        }[decision.verdict.value]
        print(f"  {tag}  {asset}  — {decision.reason}")
        if not decision.allowed:
            exit_code = 2
    return exit_code


def cmd_run(args: argparse.Namespace) -> int:
    log = configure(args.log_level)
    print(BANNER)
    cfg = Config.load(args.config)

    # CLI overrides for scope and limits.
    if args.domain:
        inc = cfg.get("scope.include", []) or []
        for d in args.domain:
            if d not in inc:
                inc.append(d)
        cfg.set("scope.include", inc)
    if args.rps:
        cfg.set("limits.global_rps", args.rps)
    if args.name:
        cfg.set("program.name", args.name)
    if args.authorize:
        cfg.set("program.authorized", True)

    scope = Scope.from_lists(cfg.get("scope.include", []), cfg.get("scope.exclude", []))
    if not scope:
        log.error("No scope defined. Use --domain or set scope.include in config.")
        return 1

    phases = args.phases or PHASES
    bad = [p for p in phases if p not in PHASES]
    if bad:
        log.error(f"Unknown phase(s): {', '.join(bad)}. Valid: {', '.join(PHASES)}")
        return 1

    if not _require_authorization(cfg, phases, log):
        return 3

    log.info(f"Program: {cfg.get('program.name')}  |  phases: {', '.join(phases)}")
    log.info(f"In-scope rules: {cfg.get('scope.include')}")
    log.info(f"Rate limit: {cfg.get('limits.global_rps')} req/s global, "
             f"{cfg.get('limits.per_host_rps')} req/s per host")

    ctx, store = _build_context(cfg, log)
    try:
        # Seed in-scope root domains as assets.
        for rule in cfg.get("scope.include", []):
            root = rule.lstrip("*.")
            store.add_asset(root, "domain", source="scope", in_scope=scope.is_allowed(root))

        domains = [r.lstrip("*.") for r in cfg.get("scope.include", [])]
        results: dict[str, dict] = {}

        if "subdomains" in phases:
            results["subdomains"] = SubdomainModule(domains).run(ctx)
        if "probe" in phases:
            results["probe"] = ProbeModule().run(ctx)
        if "content" in phases:
            results["content"] = ContentModule().run(ctx)
        if "ports" in phases:
            results["ports"] = PortsModule().run(ctx)
        if "nuclei" in phases:
            results["nuclei"] = NucleiModule().run(ctx)

        # Always produce a report at the end of a run.
        reports = generate_reports(store, cfg, cfg.get("output.dir", "output"))
        counts = store.counts()
        log.success(
            f"Done. {counts['assets']} assets, {counts['services']} services, "
            f"{counts['findings']} findings."
        )
        for r in reports:
            log.success(f"Report: {r}")
    finally:
        store.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    log = configure(args.log_level)
    cfg = Config.load(args.config)
    out_dir = Path(cfg.get("output.dir", "output"))
    program = cfg.get("program.name", "engagement")
    db_path = Path(args.db) if args.db else out_dir / f"{program}.sqlite"
    if not db_path.exists():
        log.error(f"No database at {db_path}. Run a scan first.")
        return 1
    if args.formats:
        cfg.set("output.formats", args.formats)
    store = Store.open(db_path)
    try:
        reports = generate_reports(store, cfg, out_dir)
        for r in reports:
            log.success(f"Report: {r}")
    finally:
        store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="baugbaunty",
        description="Scope-first bug bounty reconnaissance toolkit "
                    "(authorized testing only).",
    )
    p.add_argument("--version", action="version", version=f"baugbaunty {__version__}")
    p.add_argument("--log-level", default="info",
                   choices=["debug", "info", "warn", "error"])
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="write a starter config file")
    pi.add_argument("-o", "--output", default="config.json")
    pi.add_argument("-n", "--name", default="")
    pi.add_argument("--force", action="store_true")
    pi.set_defaults(func=cmd_init)

    pt = sub.add_parser("tools", help="show which external tools are installed")
    pt.set_defaults(func=cmd_tools)

    ps = sub.add_parser("scope", help="check assets against the config scope")
    ps.add_argument("-c", "--config", required=True)
    ps.add_argument("assets", nargs="+")
    ps.set_defaults(func=cmd_scope)

    pr = sub.add_parser("run", help="run the recon/testing pipeline")
    pr.add_argument("-c", "--config", help="config file (json/yaml)")
    pr.add_argument("-d", "--domain", action="append", help="add an in-scope domain")
    pr.add_argument("-n", "--name", help="program name override")
    pr.add_argument("--phases", nargs="+", metavar="PHASE",
                    help=f"subset of: {', '.join(PHASES)}")
    pr.add_argument("--rps", type=float, help="global requests/sec override")
    pr.add_argument("--authorize", action="store_true",
                    help="confirm you are authorized to test this scope")
    pr.set_defaults(func=cmd_run)

    prep = sub.add_parser("report", help="regenerate reports from a results DB")
    prep.add_argument("-c", "--config", help="config file")
    prep.add_argument("--db", help="path to the sqlite results db")
    prep.add_argument("--formats", nargs="+", choices=["json", "markdown", "html"])
    prep.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
