"""Thin, safe wrappers around external security CLIs.

The toolkit is useful with zero external dependencies, but it gets much more
powerful when the ProjectDiscovery suite (and friends) are installed:

    subfinder   passive subdomain enumeration
    httpx       fast HTTP probing & tech detection
    naabu       SYN/CONNECT port scanning
    nuclei      template-based vulnerability scanning
    dnsx        DNS resolution / bruteforce

We never build shell strings; every call uses an argv list (no ``shell=True``)
so target-derived values can't be interpreted as shell. Output is parsed from
JSON lines where the tool supports it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, Iterator


@dataclass
class ToolResult:
    ok: bool
    stdout: str
    stderr: str
    code: int


def have(tool: str) -> bool:
    """Return True if ``tool`` is on PATH."""

    return shutil.which(tool) is not None


def available_tools() -> dict[str, bool]:
    return {
        t: have(t)
        for t in ("subfinder", "httpx", "naabu", "nuclei", "dnsx", "nmap")
    }


def run(
    argv: list[str],
    *,
    stdin: str | None = None,
    timeout: float | None = None,
) -> ToolResult:
    """Run an external tool by argv. Never uses a shell."""

    if not argv:
        return ToolResult(False, "", "empty argv", 1)
    if not have(argv[0]):
        return ToolResult(False, "", f"{argv[0]} not found on PATH", 127)
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return ToolResult(proc.returncode == 0, proc.stdout, proc.stderr, proc.returncode)
    except subprocess.TimeoutExpired:
        return ToolResult(False, "", f"{argv[0]} timed out", 124)
    except Exception as e:  # pragma: no cover - env dependent
        return ToolResult(False, "", str(e), 1)


def stream_jsonl(
    argv: list[str],
    *,
    stdin: str | None = None,
    timeout: float | None = None,
) -> Iterator[dict]:
    """Run a tool that emits JSON lines and yield parsed objects."""

    res = run(argv, stdin=stdin, timeout=timeout)
    if not res.ok and not res.stdout:
        return
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


# --- high level helpers --------------------------------------------------

def subfinder(domain: str, timeout: float = 120) -> list[str]:
    res = run(["subfinder", "-silent", "-d", domain], timeout=timeout)
    if not res.ok:
        return []
    return [l.strip() for l in res.stdout.splitlines() if l.strip()]


def httpx_probe(hosts: Iterable[str], timeout: float = 180) -> list[dict]:
    argv = [
        "httpx", "-silent", "-json", "-no-color",
        "-status-code", "-title", "-tech-detect", "-server", "-content-length",
    ]
    data = "\n".join(hosts)
    return list(stream_jsonl(argv, stdin=data, timeout=timeout))


def naabu(hosts: Iterable[str], top_ports: int = 100, timeout: float = 300) -> list[dict]:
    argv = ["naabu", "-silent", "-json", "-top-ports", str(top_ports)]
    data = "\n".join(hosts)
    return list(stream_jsonl(argv, stdin=data, timeout=timeout))


def nuclei_update_templates(timeout: float = 300) -> ToolResult:
    """Run ``nuclei -update-templates`` to refresh the template corpus."""

    return run(["nuclei", "-update-templates", "-silent"], timeout=timeout)


def nuclei(
    targets: Iterable[str],
    severities: Iterable[str],
    rate_limit: int = 150,
    timeout: float = 1800,
    templates: str = "",
    tags: Iterable[str] | None = None,
    exclude_severities: Iterable[str] | None = None,
    extra_args: Iterable[str] | None = None,
) -> list[dict]:
    argv = [
        "nuclei", "-silent", "-jsonl", "-no-color",
        "-rate-limit", str(rate_limit),
    ]
    if severities:
        argv += ["-severity", ",".join(severities)]
    if exclude_severities:
        argv += ["-exclude-severity", ",".join(exclude_severities)]
    if templates:
        argv += ["-templates", templates]
    if tags:
        argv += ["-tags", ",".join(tags)]
    if extra_args:
        argv += list(extra_args)
    data = "\n".join(targets)
    return list(stream_jsonl(argv, stdin=data, timeout=timeout))
