"""Command-line interface and pipeline orchestration for baugbaunty."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .core.config import DEFAULTS, Config
from .core.logging import configure
from .core.notify import Notifier
from .core.scope import Scope
from .core.store import Store
from .integrations import external
from .modules.base import Context
from .integrations import programs
from .modules.content import ContentModule
from .modules.cvecheck import CveCheckModule
from .modules.dns import DnsModule
from .modules.githubdork import GithubDorkModule
from .modules.jsintel import JsIntelModule
from .modules.nuclei import NucleiModule
from .modules.params import ParamsModule
from .modules.ports import PortsModule
from .modules.probe import ProbeModule
from .modules.screenshot import ScreenshotModule
from .modules.seeds import SeedsModule
from .modules.subdomains import SubdomainModule
from .modules.takeover import TakeoverModule
from .modules.vhost import VhostModule
from .modules.wayback import WaybackModule
from .modules.webchecks import WebChecksModule
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
PHASES = [
    "subdomains",  # passive OSINT
    "wayback",     # passive archive mining
    "githubdork",  # passive GitHub leak search
    "dns",         # resolution + wildcard filtering (non-intrusive)
    "takeover",    # subdomain takeover detection (active)
    "probe",       # live HTTP probing + fingerprint (active)
    "seeds",       # robots/sitemap/favicon seeding (active)
    "vhost",       # virtual-host discovery (active)
    "jsintel",     # JS endpoint + secret extraction (active)
    "content",     # content discovery (active)
    "params",      # hidden parameter discovery (active)
    "webchecks",   # CORS / open redirect / reflection (active)
    "cvecheck",    # version -> known-CVE correlation (analysis, no traffic)
    "screenshot",  # visual triage of live services (active)
    "ports",       # port scanning (active)
    "nuclei",      # template vuln scan (active)
]
# Phases that send traffic to the target (require authorization).
ACTIVE_PHASES = {
    "takeover", "probe", "seeds", "vhost", "jsintel",
    "content", "params", "webchecks", "screenshot", "ports", "nuclei",
}

# Preset scan profiles: politeness + which phases to run by default.
PROFILES: dict[str, dict] = {
    "quiet": {
        "limits": {"global_rps": 3.0, "per_host_rps": 1.5, "concurrency": 8},
        "phases": ["subdomains", "wayback", "dns", "probe", "seeds", "cvecheck"],
    },
    "normal": {
        "limits": {"global_rps": 10.0, "per_host_rps": 5.0, "concurrency": 20},
        "phases": PHASES,
    },
    "aggressive": {
        "limits": {"global_rps": 25.0, "per_host_rps": 10.0, "concurrency": 40},
        "phases": PHASES,
    },
}


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

    # Apply a preset profile first, so explicit flags still override it.
    profile_phases: list[str] | None = None
    if getattr(args, "profile", None):
        prof = PROFILES.get(args.profile)
        if not prof:
            log.error(f"Unknown profile '{args.profile}'. Valid: {', '.join(PROFILES)}")
            return 1
        for k, v in prof.get("limits", {}).items():
            cfg.set(f"limits.{k}", v)
        profile_phases = list(prof.get("phases", []))
        log.info(f"Profile '{args.profile}' applied")

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

    phases = args.phases or profile_phases or PHASES
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
    # Remember the previous run's checkpoint so we can diff/notify new results.
    prev_run = float(store.get_meta("last_run_ts", "0") or 0)
    try:
        # Seed in-scope root domains as assets.
        for rule in cfg.get("scope.include", []):
            root = rule.lstrip("*.")
            store.add_asset(root, "domain", source="scope", in_scope=scope.is_allowed(root))

        domains = [r.lstrip("*.") for r in cfg.get("scope.include", [])]
        dispatch = {
            "subdomains": lambda: SubdomainModule(domains).run(ctx),
            "wayback": lambda: WaybackModule(domains).run(ctx),
            "dns": lambda: DnsModule().run(ctx),
            "githubdork": lambda: GithubDorkModule(domains).run(ctx),
            "takeover": lambda: TakeoverModule().run(ctx),
            "probe": lambda: ProbeModule().run(ctx),
            "seeds": lambda: SeedsModule().run(ctx),
            "vhost": lambda: VhostModule().run(ctx),
            "jsintel": lambda: JsIntelModule().run(ctx),
            "content": lambda: ContentModule().run(ctx),
            "params": lambda: ParamsModule().run(ctx),
            "webchecks": lambda: WebChecksModule().run(ctx),
            "cvecheck": lambda: CveCheckModule().run(ctx),
            "screenshot": lambda: ScreenshotModule().run(ctx),
            "ports": lambda: PortsModule().run(ctx),
            "nuclei": lambda: NucleiModule().run(ctx),
        }
        results: dict[str, dict] = {}
        for phase in PHASES:  # run in canonical order regardless of arg order
            if phase in phases:
                results[phase] = dispatch[phase]()

        # Always produce a report at the end of a run.
        reports = generate_reports(store, cfg, cfg.get("output.dir", "output"))
        counts = store.counts()
        log.success(
            f"Done. {counts['assets']} assets, {counts['services']} services, "
            f"{counts['findings']} findings."
        )
        for r in reports:
            log.success(f"Report: {r}")

        # Diff vs the previous run + notifications (monitor mode).
        diff = store.new_since(prev_run)
        _report_diff(diff, log, first_run=prev_run == 0)
        notifier = Notifier.from_config(cfg.get("notifications", {}))
        notifier.log = log
        if notifier.enabled and prev_run > 0:
            notifier.send_diff(cfg.get("program.name", "engagement"), diff)
        store.set_meta("last_run_ts", str(time.time()))
    finally:
        store.close()
    return 0


def _report_diff(diff: dict, log, first_run: bool) -> None:
    new_assets = diff.get("assets", [])
    new_services = diff.get("services", [])
    new_findings = diff.get("findings", [])
    if first_run:
        return  # nothing to compare against on the first run
    if not (new_assets or new_services or new_findings):
        log.info("[diff] no new assets, services or findings since last run")
        return
    log.success(
        f"[diff] NEW since last run: {len(new_assets)} assets, "
        f"{len(new_services)} services, {len(new_findings)} findings"
    )
    for f in new_findings[:20]:
        log.warn(f"[diff]  + [{f.get('severity','').upper()}] {f.get('name')} "
                 f"({f.get('target')})")


def cmd_import(args: argparse.Namespace) -> int:
    import json as _json

    log = configure(args.log_level)
    text = Path(args.file).read_text(encoding="utf-8")
    result = programs.import_scope(text, platform=args.platform)
    if args.name:
        result.name = args.name
    if not result.include:
        log.error("No in-scope web assets found. Check the file/platform.")
        return 1
    cfg = programs.to_config_dict(result, name=args.name)
    out = Path(args.output)
    if out.exists() and not args.force:
        log.error(f"{out} exists (use --force)")
        return 1
    out.write_text(_json.dumps(cfg, indent=2), encoding="utf-8")
    log.success(f"Imported {len(result.include)} in-scope, "
                f"{len(result.exclude)} out-of-scope rule(s) -> {out}")
    if result.skipped:
        log.info(f"Skipped {len(result.skipped)} non-web asset(s): "
                 f"{', '.join(result.skipped[:8])}" + (" ..." if len(result.skipped) > 8 else ""))
    log.warn("Review the generated scope, then set program.authorized=true "
             "before running active phases.")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    # Monitor is a thin wrapper over run: cheaper default phases for change
    # detection, and it leans on run's built-in diff + notifications.
    if not args.phases and not getattr(args, "profile", None):
        args.phases = ["subdomains", "dns", "probe"]
    return cmd_run(args)


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

    pimp = sub.add_parser("import", help="build a config from a HackerOne/Bugcrowd scope file")
    pimp.add_argument("-f", "--file", required=True, help="scope file (JSON or plain list)")
    pimp.add_argument("--platform", default="auto",
                      choices=["auto", "hackerone", "bugcrowd", "list"])
    pimp.add_argument("-o", "--output", default="config.json")
    pimp.add_argument("-n", "--name", default="", help="program name")
    pimp.add_argument("--force", action="store_true")
    pimp.set_defaults(func=cmd_import)

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
    pr.add_argument("--profile", choices=list(PROFILES), help="preset scan profile")
    pr.add_argument("--authorize", action="store_true",
                    help="confirm you are authorized to test this scope")
    pr.set_defaults(func=cmd_run)

    pm = sub.add_parser(
        "monitor",
        help="run the pipeline and report/notify what is NEW since last run "
             "(ideal for cron/scheduled continuous recon)",
    )
    pm.add_argument("-c", "--config", help="config file (json/yaml)")
    pm.add_argument("-d", "--domain", action="append", help="add an in-scope domain")
    pm.add_argument("-n", "--name", help="program name override")
    pm.add_argument("--phases", nargs="+", metavar="PHASE",
                    help=f"subset of: {', '.join(PHASES)} "
                         "(default: subdomains dns probe for cheap change detection)")
    pm.add_argument("--rps", type=float, help="global requests/sec override")
    pm.add_argument("--profile", choices=list(PROFILES), help="preset scan profile")
    pm.add_argument("--authorize", action="store_true",
                    help="confirm you are authorized to test this scope")
    pm.set_defaults(func=cmd_monitor)

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
