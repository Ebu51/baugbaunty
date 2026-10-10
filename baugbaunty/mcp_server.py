"""A dependency-free MCP (Model Context Protocol) server for baugbaunty.

This exposes the toolkit to Claude (Claude Code, Claude Desktop, or any MCP
client) as a set of tools, so you can run recon and reason over findings
conversationally — while the same scope, rate-limit and authorization
guardrails still apply.

The server speaks MCP over stdio using newline-delimited JSON-RPC 2.0, hand
-rolled on the standard library so it adds no dependencies. Protocol logging and
all toolkit logging go to stderr; stdout carries only protocol messages.

Tools exposed:
  * scope_check     — classify assets against a scope (read-only, safe)
  * import_scope    — turn a HackerOne/Bugcrowd/list scope into config rules
  * tools_status    — which external CLIs are installed
  * summary         — counts + severity breakdown from a results DB (read-only)
  * list_findings   — query stored findings (read-only)
  * list_assets     — query stored assets (read-only)
  * run             — run pipeline phases (active phases still require the
                      engagement to be authorized in the config)

Active scanning is gated exactly as on the CLI: the ``run`` tool refuses active
phases unless the config has ``program.authorized: true`` (or ``authorize`` is
passed), so an assistant cannot silently start touching a target.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .core.config import Config
from .core.scope import Scope
from .core.store import Store
from .integrations import external, programs
from .report import generate_reports, generate_submissions

PROTOCOL_VERSION = "2024-11-05"


def _log(msg: str) -> None:
    print(f"[baugbaunty-mcp] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Tool implementations (return a plain string; raise for errors)
# --------------------------------------------------------------------------

def _scope_from_args(args: dict) -> Scope:
    if args.get("config"):
        cfg = Config.load(args["config"])
        return Scope.from_lists(cfg.get("scope.include", []), cfg.get("scope.exclude", []))
    return Scope.from_lists(args.get("include", []), args.get("exclude", []))


def tool_scope_check(args: dict) -> str:
    scope = _scope_from_args(args)
    assets = args.get("assets", [])
    if not assets:
        return "No assets provided."
    lines = []
    for a in assets:
        d = scope.check(a)
        lines.append(f"{d.verdict.value.upper():<13} {a}  — {d.reason}")
    return "\n".join(lines)


def tool_import_scope(args: dict) -> str:
    text = args.get("text", "")
    if args.get("file"):
        text = Path(args["file"]).read_text(encoding="utf-8")
    if not text:
        raise ValueError("Provide 'text' or 'file'.")
    res = programs.import_scope(text, platform=args.get("platform", "auto"))
    out = {
        "name": args.get("name") or res.name,
        "include": res.include,
        "exclude": res.exclude,
        "skipped_non_web": res.skipped,
    }
    if args.get("output"):
        cfg = programs.to_config_dict(res, name=args.get("name"))
        Path(args["output"]).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        out["written_config"] = args["output"]
        out["note"] = "Review scope, then set program.authorized=true before active phases."
    return json.dumps(out, indent=2)


def tool_tools_status(_args: dict) -> str:
    avail = external.available_tools()
    return json.dumps(avail, indent=2)


def _open_store(args: dict) -> Store:
    db = args.get("db")
    if not db:
        # Derive from config if given.
        if args.get("config"):
            cfg = Config.load(args["config"])
            db = str(Path(cfg.get("output.dir", "output")) /
                     f"{cfg.get('program.name', 'engagement')}.sqlite")
        else:
            raise ValueError("Provide 'db' (sqlite path) or 'config'.")
    if not Path(db).exists():
        raise FileNotFoundError(f"No results DB at {db}. Run a scan first.")
    return Store.open(db)


def tool_summary(args: dict) -> str:
    store = _open_store(args)
    try:
        counts = store.counts()
        sev: dict[str, int] = {}
        for f in store.findings():
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        return json.dumps({"counts": counts, "by_severity": sev}, indent=2)
    finally:
        store.close()


def tool_list_findings(args: dict) -> str:
    store = _open_store(args)
    try:
        rows = store.findings()
        if args.get("severity"):
            want = set(args["severity"]) if isinstance(args["severity"], list) else {args["severity"]}
            rows = [r for r in rows if r["severity"] in want]
        if args.get("module"):
            rows = [r for r in rows if r["module"] == args["module"]]
        limit = int(args.get("limit", 100))
        rows = rows[:limit]
        slim = [
            {"severity": r["severity"], "module": r["module"], "name": r["name"],
             "target": r["target"], "evidence": r["evidence"]}
            for r in rows
        ]
        return json.dumps(slim, indent=2)
    finally:
        store.close()


def tool_list_assets(args: dict) -> str:
    store = _open_store(args)
    try:
        rows = store.assets(in_scope_only=bool(args.get("in_scope_only", False)))
        if args.get("kind"):
            rows = [r for r in rows if r["kind"] == args["kind"]]
        limit = int(args.get("limit", 500))
        slim = [{"value": r["value"], "kind": r["kind"], "in_scope": bool(r["in_scope"])}
                for r in rows[:limit]]
        return json.dumps(slim, indent=2)
    finally:
        store.close()


def _config_for(args: dict) -> Config:
    if args.get("config"):
        return Config.load(args["config"])
    cfg = Config()
    if args.get("db"):
        p = Path(args["db"])
        cfg.set("output.dir", str(p.parent))
        cfg.set("program.name", p.stem)
    return cfg


def tool_generate_report(args: dict) -> str:
    store = _open_store(args)
    try:
        cfg = _config_for(args)
        if args.get("formats"):
            cfg.set("output.formats", args["formats"])
        paths = generate_reports(store, cfg, cfg.get("output.dir", "output"))
        return json.dumps({"reports": [str(p) for p in paths]}, indent=2)
    finally:
        store.close()


def tool_read_report(args: dict) -> str:
    cfg = _config_for(args)
    fmt = args.get("format", "markdown")
    ext = {"markdown": "md", "json": "json", "html": "html"}.get(fmt, "md")
    program = cfg.get("program.name", "engagement")
    path = Path(cfg.get("output.dir", "output")) / f"{program}-report.{ext}"
    if not path.exists():
        raise FileNotFoundError(f"No {fmt} report at {path}. Generate it first.")
    text = path.read_text(encoding="utf-8")
    return text[:200_000]


def tool_generate_submission(args: dict) -> str:
    store = _open_store(args)
    try:
        cfg = _config_for(args)
        path = generate_submissions(
            store, cfg, cfg.get("output.dir", "output"),
            min_severity=args.get("min_severity", "medium"),
            platform=args.get("platform", "generic"),
            fmt=args.get("format", "markdown"),
        )
        content = path.read_text(encoding="utf-8")[:200_000]
        return json.dumps({"path": str(path), "content": content}, indent=2)
    finally:
        store.close()


def tool_run(args: dict) -> str:
    config = args.get("config")
    if not config:
        raise ValueError("'config' (path) is required for run.")
    argv = [sys.executable, "-m", "baugbaunty", "run", "-c", config]
    if args.get("phases"):
        argv += ["--phases", *args["phases"]]
    if args.get("profile"):
        argv += ["--profile", args["profile"]]
    if args.get("authorize"):
        argv += ["--authorize"]
    _log(f"run: {' '.join(argv)}")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=args.get("timeout", 3600))
    tail = "\n".join(proc.stderr.strip().splitlines()[-25:])
    result = {"exit_code": proc.returncode, "log_tail": tail}
    # Attach a summary if the DB is now present.
    try:
        result["summary"] = json.loads(tool_summary({"config": config}))
    except Exception:
        pass
    if proc.returncode == 3:
        result["note"] = ("Active phases were blocked: the engagement is not "
                          "authorized. Set program.authorized=true in the config "
                          "or pass authorize=true only if you have permission.")
    return json.dumps(result, indent=2)


TOOLS: dict[str, dict[str, Any]] = {
    "scope_check": {
        "handler": tool_scope_check,
        "description": "Classify assets (hosts/URLs/IPs) against a program scope. "
                       "Read-only and safe. Provide a config path, or include/exclude lists.",
        "schema": {
            "type": "object",
            "properties": {
                "assets": {"type": "array", "items": {"type": "string"},
                           "description": "Assets to classify."},
                "config": {"type": "string", "description": "Path to a config file."},
                "include": {"type": "array", "items": {"type": "string"}},
                "exclude": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["assets"],
        },
    },
    "import_scope": {
        "handler": tool_import_scope,
        "description": "Convert a HackerOne/Bugcrowd scope export or plain list into "
                       "scope rules, optionally writing a ready-to-use config.",
        "schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Raw scope text/JSON."},
                "file": {"type": "string", "description": "Path to a scope file."},
                "platform": {"type": "string", "enum": ["auto", "hackerone", "bugcrowd", "list"]},
                "name": {"type": "string"},
                "output": {"type": "string", "description": "If set, write a config here."},
            },
        },
    },
    "tools_status": {
        "handler": tool_tools_status,
        "description": "Report which optional external CLIs (subfinder/httpx/naabu/"
                       "nuclei/dnsx/nmap) are installed.",
        "schema": {"type": "object", "properties": {}},
    },
    "summary": {
        "handler": tool_summary,
        "description": "Counts and severity breakdown from a results DB. Read-only. "
                       "Provide 'db' or 'config'.",
        "schema": {
            "type": "object",
            "properties": {"db": {"type": "string"}, "config": {"type": "string"}},
        },
    },
    "list_findings": {
        "handler": tool_list_findings,
        "description": "Query stored findings (optionally filter by severity/module). Read-only.",
        "schema": {
            "type": "object",
            "properties": {
                "db": {"type": "string"}, "config": {"type": "string"},
                "severity": {"type": "array", "items": {"type": "string"}},
                "module": {"type": "string"},
                "limit": {"type": "integer"},
            },
        },
    },
    "list_assets": {
        "handler": tool_list_assets,
        "description": "Query stored assets (optionally filter by kind). Read-only.",
        "schema": {
            "type": "object",
            "properties": {
                "db": {"type": "string"}, "config": {"type": "string"},
                "kind": {"type": "string"}, "in_scope_only": {"type": "boolean"},
                "limit": {"type": "integer"},
            },
        },
    },
    "generate_report": {
        "handler": tool_generate_report,
        "description": "Generate JSON/Markdown/HTML reports from a results DB.",
        "schema": {
            "type": "object",
            "properties": {
                "db": {"type": "string"}, "config": {"type": "string"},
                "formats": {"type": "array", "items": {"type": "string",
                            "enum": ["json", "markdown", "html"]}},
            },
        },
    },
    "read_report": {
        "handler": tool_read_report,
        "description": "Return the text of a previously generated report (markdown by default).",
        "schema": {
            "type": "object",
            "properties": {
                "db": {"type": "string"}, "config": {"type": "string"},
                "format": {"type": "string", "enum": ["markdown", "json", "html"]},
            },
        },
    },
    "generate_submission": {
        "handler": tool_generate_submission,
        "description": "Draft platform-ready vulnerability submissions (HackerOne/"
                       "Bugcrowd/generic) from findings at or above min_severity, and "
                       "return the document text. Drafts are automated leads — verify "
                       "before submitting.",
        "schema": {
            "type": "object",
            "properties": {
                "db": {"type": "string"}, "config": {"type": "string"},
                "min_severity": {"type": "string",
                                 "enum": ["info", "low", "medium", "high", "critical"]},
                "platform": {"type": "string", "enum": ["generic", "hackerone", "bugcrowd"]},
                "format": {"type": "string", "enum": ["markdown", "json"]},
            },
        },
    },
    "run": {
        "handler": tool_run,
        "description": "Run pipeline phases for a program config. PASSIVE phases "
                       "(subdomains, wayback, githubdork, dns, cvecheck) need no "
                       "authorization; ACTIVE phases require program.authorized=true "
                       "in the config or authorize=true, and are refused otherwise.",
        "schema": {
            "type": "object",
            "properties": {
                "config": {"type": "string", "description": "Path to a config file."},
                "phases": {"type": "array", "items": {"type": "string"},
                           "description": "Subset of pipeline phases to run."},
                "profile": {"type": "string", "enum": ["quiet", "normal", "aggressive"]},
                "authorize": {"type": "boolean",
                              "description": "Confirm you are authorized to actively test this scope."},
            },
            "required": ["config"],
        },
    },
}


# --------------------------------------------------------------------------
# JSON-RPC / MCP plumbing
# --------------------------------------------------------------------------

def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _result(req_id: Any, result: dict) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "result": result})


def _error(req_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def _handle(req: dict) -> None:
    method = req.get("method")
    req_id = req.get("id")
    is_notification = req_id is None

    if method == "initialize":
        _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "baugbaunty", "version": __version__},
        })
        return
    if method in ("notifications/initialized", "initialized"):
        return  # notification, no response
    if method == "ping":
        _result(req_id, {})
        return
    if method == "tools/list":
        tools = [
            {"name": name, "description": spec["description"], "inputSchema": spec["schema"]}
            for name, spec in TOOLS.items()
        ]
        _result(req_id, {"tools": tools})
        return
    if method == "tools/call":
        params = req.get("params", {})
        name = params.get("name")
        arguments = params.get("arguments", {}) or {}
        spec = TOOLS.get(name)
        if not spec:
            _error(req_id, -32601, f"Unknown tool: {name}")
            return
        try:
            text = spec["handler"](arguments)
            _result(req_id, {"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as e:  # surface tool errors as tool results, not RPC errors
            _result(req_id, {
                "content": [{"type": "text", "text": f"Error: {e}"}],
                "isError": True,
            })
        return

    if not is_notification:
        _error(req_id, -32601, f"Method not found: {method}")


def main(argv: list[str] | None = None) -> int:
    _log(f"baugbaunty MCP server {__version__} ready (stdio)")
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(req, list):  # batch
                for r in req:
                    _handle(r)
            else:
                _handle(req)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
