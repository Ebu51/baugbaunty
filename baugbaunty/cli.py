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
from .modules.asn import AsnModule
from .modules.buckets import BucketsModule
from .modules.cluster import ClusterModule
from .modules.content import ContentModule
from .modules.crawl import CrawlModule
from .modules.cvecheck import CveCheckModule
from .modules.dns import DnsModule
from .modules.dnsbrute import DnsBruteModule
from .modules.githubdork import GithubDorkModule
from .modules.secheaders import SecHeadersModule
from .modules.graphql import GraphqlModule
from .modules.jsintel import JsIntelModule
from .modules.nuclei import NucleiModule
from .modules.openapi import OpenApiModule
from .modules.params import ParamsModule
from .modules.ports import PortsModule
from .modules.probe import ProbeModule
from .modules.ratecal import RateCalModule
from .modules.screenshot import ScreenshotModule
from .modules.seeds import SeedsModule
from .modules.subdomains import SubdomainModule
from .modules.takeover import TakeoverModule
from .modules.urltriage import UrlTriageModule
from .modules.vhost import VhostModule
from .modules.waf import WafModule
from .modules.wayback import WaybackModule
from .modules.webchecks import WebChecksModule
from .report import generate_reports, generate_submissions

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
    "asn",         # ASN/org -> CIDR expansion (third-party, passive)
    "wayback",     # passive archive mining
    "githubdork",  # passive GitHub leak search
    "buckets",     # cloud storage bucket enumeration (third-party, passive)
    "dnsbrute",    # active DNS brute-force + permutation (resolution only)
    "dns",         # resolution + wildcard filtering (non-intrusive)
    "takeover",    # subdomain takeover detection (active)
    "probe",       # live HTTP probing + fingerprint (active)
    "waf",         # WAF detection (active)
    "ratecal",     # rate-limit calibration (active)
    "seeds",       # robots/sitemap/favicon seeding (active)
    "secheaders",  # CSP + cookie security analysis (active)
    "vhost",       # virtual-host discovery (active)
    "jsintel",     # JS endpoint + secret extraction (active)
    "graphql",     # GraphQL discovery + introspection (active)
    "openapi",     # OpenAPI/Swagger spec discovery (active)
    "crawl",       # in-scope web crawler / spider (active)
    "content",     # content discovery (active)
    "urltriage",   # gf-style URL prioritisation (analysis, no traffic)
    "cluster",     # response clustering (analysis, no traffic)
    "params",      # hidden parameter discovery (active)
    "webchecks",   # CORS / open redirect / reflection (active)
    "cvecheck",    # version -> known-CVE correlation (analysis, no traffic)
    "screenshot",  # visual triage of live services (active)
    "ports",       # port scanning (active)
    "nuclei",      # template vuln scan (active)
]
# Phases that send traffic to the target (require authorization).
ACTIVE_PHASES = {
    "takeover", "probe", "waf", "ratecal", "seeds", "secheaders", "vhost", "jsintel",
    "graphql", "openapi", "crawl", "content", "params", "webchecks", "screenshot",
    "ports", "nuclei",
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
            "asn": lambda: AsnModule().run(ctx),
            "githubdork": lambda: GithubDorkModule(domains).run(ctx),
            "buckets": lambda: BucketsModule().run(ctx),
            "dnsbrute": lambda: DnsBruteModule(domains).run(ctx),
            "takeover": lambda: TakeoverModule().run(ctx),
            "probe": lambda: ProbeModule().run(ctx),
            "waf": lambda: WafModule().run(ctx),
            "ratecal": lambda: RateCalModule().run(ctx),
            "seeds": lambda: SeedsModule().run(ctx),
            "secheaders": lambda: SecHeadersModule().run(ctx),
            "vhost": lambda: VhostModule().run(ctx),
            "jsintel": lambda: JsIntelModule().run(ctx),
            "graphql": lambda: GraphqlModule().run(ctx),
            "openapi": lambda: OpenApiModule().run(ctx),
            "crawl": lambda: CrawlModule().run(ctx),
            "content": lambda: ContentModule().run(ctx),
            "urltriage": lambda: UrlTriageModule().run(ctx),
            "cluster": lambda: ClusterModule().run(ctx),
            "params": lambda: ParamsModule().run(ctx),
            "webchecks": lambda: WebChecksModule().run(ctx),
            "cvecheck": lambda: CveCheckModule().run(ctx),
            "screenshot": lambda: ScreenshotModule().run(ctx),
            "ports": lambda: PortsModule().run(ctx),
            "nuclei": lambda: NucleiModule().run(ctx),
        }
        results: dict[str, dict] = {}
        durations: dict[str, float] = {}
        ordered = [p for p in PHASES if p in phases]
        for idx, phase in enumerate(ordered, 1):
            log.info(f"[{idx}/{len(ordered)}] ▶ {phase}")
            t0 = time.time()
            results[phase] = dispatch[phase]()
            durations[phase] = time.time() - t0

        # Recursive discovery: feed newly found in-scope hosts back through
        # resolution, probing and crawling until stable (bbot-style).
        rounds = getattr(args, "recursive", 0) or 0
        if rounds and any(p in ordered for p in ("probe", "crawl", "jsintel", "openapi")):
            _recursive_expand(ctx, rounds, log)

        # Always produce a report at the end of a run.
        reports = generate_reports(store, cfg, cfg.get("output.dir", "output"))
        _print_summary(log, results, durations, store)
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


def _recursive_expand(ctx, rounds: int, log) -> None:
    """Iteratively resolve + probe + crawl hosts discovered mid-run."""

    for r in range(1, rounds + 1):
        probed = {s.get("host") for s in ctx.store.services()}
        candidates = [
            a["value"] for a in ctx.store.assets()
            if a["kind"] in ("subdomain", "domain")
            and ctx.scope.is_allowed(a["value"])
            and a["value"] not in probed
        ]
        if not candidates:
            log.info(f"[recursive] round {r}: no new in-scope hosts — done")
            break
        log.info(f"[recursive] round {r}: expanding {len(candidates)} new host(s)")
        before_urls = {s["url"] for s in ctx.store.services()}
        DnsModule(hosts=candidates).run(ctx)
        ProbeModule(hosts=candidates).run(ctx)
        new_urls = [s["url"] for s in ctx.store.services() if s["url"] not in before_urls]
        if new_urls:
            CrawlModule(services=new_urls).run(ctx)
        else:
            log.info(f"[recursive] round {r}: no new live services — done")
            break


def _print_summary(log, results: dict, durations: dict, store) -> None:
    """Print a per-phase table and a findings-by-severity breakdown."""

    print("\n  Phase        Result                                   Time", file=sys.stderr)
    print("  " + "-" * 64, file=sys.stderr)
    for phase, res in results.items():
        metrics = ", ".join(
            f"{k}={v}" for k, v in res.items()
            if isinstance(v, (int, float, bool, str)) and k != "by_severity"
        )
        dur = durations.get(phase, 0.0)
        print(f"  {phase:<12} {metrics[:40]:<40} {dur:6.1f}s", file=sys.stderr)
    print("  " + "-" * 64, file=sys.stderr)

    # Findings by severity.
    sev_counts: dict[str, int] = {}
    for f in store.findings():
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    sev_line = "  ".join(f"{s}:{sev_counts.get(s, 0)}" for s in order)
    counts = store.counts()
    log.success(
        f"Done. {counts['assets']} assets, {counts['services']} services, "
        f"{counts['findings']} findings  [{sev_line}]"
    )


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


def cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import main as mcp_main

    return mcp_main()


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


def cmd_submission(args: argparse.Namespace) -> int:
    log = configure(args.log_level)
    cfg = Config.load(args.config)
    out_dir = Path(cfg.get("output.dir", "output"))
    program = cfg.get("program.name", "engagement")
    db_path = Path(args.db) if args.db else out_dir / f"{program}.sqlite"
    if not db_path.exists():
        log.error(f"No database at {db_path}. Run a scan first.")
        return 1
    store = Store.open(db_path)
    try:
        path = generate_submissions(
            store, cfg, out_dir,
            min_severity=args.min_severity, platform=args.platform, fmt=args.format,
        )
        log.success(f"Submissions written: {path}")
    finally:
        store.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    import json as _json

    log = configure(args.log_level)
    cfg = Config.load(args.config) if args.config else Config()
    out_dir = Path(cfg.get("output.dir", "output"))
    program = cfg.get("program.name", "engagement")
    db_path = Path(args.db) if args.db else out_dir / f"{program}.sqlite"
    if not db_path.exists():
        log.error(f"No database at {db_path}. Run a scan first.")
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    store = Store.open(db_path)
    what = set(args.what)
    written: list[Path] = []
    try:
        assets = store.assets()
        if {"all", "subdomains"} & what:
            vals = sorted({a["value"] for a in assets if a["kind"] in ("subdomain", "domain")})
            p = out_dir / f"{program}-subdomains.txt"
            p.write_text("\n".join(vals) + ("\n" if vals else ""), encoding="utf-8")
            written.append(p)
        if {"all", "urls"} & what:
            vals = sorted({a["value"] for a in assets if a["kind"] in ("url", "endpoint")})
            p = out_dir / f"{program}-urls.txt"
            p.write_text("\n".join(vals) + ("\n" if vals else ""), encoding="utf-8")
            written.append(p)
        if {"all", "services"} & what:
            vals = sorted({s["url"] for s in store.services()})
            p = out_dir / f"{program}-services.txt"
            p.write_text("\n".join(vals) + ("\n" if vals else ""), encoding="utf-8")
            written.append(p)
        if {"all", "findings"} & what:
            p = out_dir / f"{program}-findings.json"
            p.write_text(_json.dumps(store.findings(), indent=2, default=str), encoding="utf-8")
            written.append(p)
    finally:
        store.close()
    for w in written:
        log.success(f"Exported: {w}")
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

    pmcp = sub.add_parser("mcp", help="run the MCP server (stdio) for use with Claude")
    pmcp.set_defaults(func=cmd_mcp)

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
    pr.add_argument("--recursive", type=int, default=0, metavar="ROUNDS",
                    help="feed newly discovered in-scope hosts back through "
                         "dns/probe/crawl for up to ROUNDS iterations")
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

    psub = sub.add_parser("submission",
                          help="draft platform-ready vulnerability submissions from findings")
    psub.add_argument("-c", "--config", required=True)
    psub.add_argument("--db", help="path to the sqlite results db")
    psub.add_argument("--min-severity", default="medium",
                      choices=["info", "low", "medium", "high", "critical"])
    psub.add_argument("--platform", default="generic",
                      choices=["generic", "hackerone", "bugcrowd"])
    psub.add_argument("--format", default="markdown", choices=["markdown", "json", "pdf"])
    psub.set_defaults(func=cmd_submission)

    pexp = sub.add_parser("export",
                          help="export assets/urls/services/findings as plain lists for tool chaining")
    pexp.add_argument("-c", "--config", help="config file")
    pexp.add_argument("--db", help="path to the sqlite results db")
    pexp.add_argument("--what", nargs="+", default=["all"],
                      choices=["all", "subdomains", "urls", "services", "findings"])
    pexp.set_defaults(func=cmd_export)

    prep = sub.add_parser("report", help="regenerate reports from a results DB")
    prep.add_argument("-c", "--config", help="config file")
    prep.add_argument("--db", help="path to the sqlite results db")
    prep.add_argument("--formats", nargs="+", choices=["json", "markdown", "html", "pdf"])
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
