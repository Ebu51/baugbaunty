"""Turn findings into platform-ready vulnerability submissions.

Writing up a report is the slow part of bounty hunting. This module renders each
qualifying finding into a structured submission (title, severity, affected
asset, steps to reproduce, impact, remediation, references) in the house style
of HackerOne / Bugcrowd, so you can review, confirm and paste.

These are DRAFTS generated from automated signals. You must verify every finding
by hand before submitting — automated leads (reflection/CRLF/SSRF/takeover) are
not proof, and submitting unverified reports is noise that hurts your
reputation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..core.config import Config
from ..core.store import Store

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Rough Bugcrowd VRT priority per our severity (P1 highest .. P5 lowest/info).
_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P5"}


@dataclass
class _Template:
    cls: str
    title: str
    summary: str
    impact: str
    remediation: str
    references: list[str]
    repro: list[str]


# Vulnerability-class templates. ``{target}``/``{evidence}`` are filled per finding.
_TEMPLATES: dict[str, _Template] = {
    "subdomain_takeover": _Template(
        "subdomain_takeover",
        "Subdomain Takeover on {target}",
        "The subdomain {target} points (via CNAME) at a third-party service whose "
        "resource is unclaimed, allowing an attacker to register it and serve "
        "arbitrary content from the target's subdomain.",
        "An attacker can host arbitrary content on a trusted subdomain, enabling "
        "convincing phishing, cookie theft for the parent domain, CSP bypass and "
        "reputation damage.",
        "Remove the dangling DNS record, or (re)claim the resource at the "
        "third-party provider so the subdomain resolves to content you control.",
        ["https://github.com/EdOverflow/can-i-take-over-xyz",
         "https://owasp.org/www-community/attacks/Subdomain_takeover"],
        ["Resolve {target} and observe the CNAME to the third-party provider.",
         "Request {target} over HTTP(S) and observe the provider's "
         "'unclaimed resource' response.",
         "Register/claim the resource at the provider to take control (do not "
         "actually host content; stop at proof)."],
    ),
    "cors": _Template(
        "cors",
        "CORS Misconfiguration on {target}",
        "The endpoint {target} reflects an arbitrary Origin in "
        "Access-Control-Allow-Origin and allows credentials, so any origin can "
        "read authenticated responses.",
        "A malicious site can issue credentialed cross-origin requests and read "
        "the responses, exposing authenticated user data (account info, tokens).",
        "Do not reflect arbitrary Origins. Allow only a strict allow-list of "
        "trusted origins, and never combine a wildcard/reflected origin with "
        "Access-Control-Allow-Credentials: true.",
        ["https://portswigger.net/web-security/cors"],
        ["Send a request to {target} with header `Origin: https://evil.example`.",
         "Observe the response reflects that Origin in "
         "`Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`."],
    ),
    "open_redirect": _Template(
        "open_redirect",
        "Open Redirect on {target}",
        "A parameter on {target} redirects to an attacker-controlled external URL "
        "without validation.",
        "Facilitates phishing (trusted domain redirecting to a malicious site) and "
        "can be chained into OAuth token theft or SSRF in some contexts.",
        "Validate redirect targets against an allow-list of relative paths or "
        "trusted hosts; reject absolute/external URLs.",
        ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
        ["Request {target} (the redirect parameter is set to an external canary).",
         "Observe the 3xx `Location` header pointing to the external host."],
    ),
    "xss": _Template(
        "xss",
        "Reflected XSS (candidate) on {target}",
        "User input in a parameter on {target} is reflected into the response "
        "without output encoding, indicating a potential reflected XSS.",
        "If exploitable, an attacker can execute JavaScript in a victim's browser "
        "in the target's origin: session hijacking, credential theft, defacement.",
        "Context-aware output encoding for all reflected input; a strict "
        "Content-Security-Policy as defense in depth.",
        ["https://owasp.org/www-community/attacks/xss/"],
        ["Request {target} with a marker containing HTML metacharacters.",
         "Observe the marker reflected unencoded in the response body.",
         "Craft a working payload for the reflection context to confirm script "
         "execution before reporting."],
    ),
    "crlf": _Template(
        "crlf",
        "CRLF / HTTP Header Injection on {target}",
        "A parameter on {target} is placed into a response header without "
        "sanitising CR/LF, allowing header injection / response splitting.",
        "Enables setting arbitrary response headers (e.g. Set-Cookie), cache "
        "poisoning and, in some contexts, reflected XSS.",
        "Strip or reject CR/LF in any value echoed into response headers; use the "
        "framework's header API rather than string concatenation.",
        ["https://owasp.org/www-community/vulnerabilities/CRLF_Injection"],
        ["Request {target} with a CR/LF-encoded payload in the parameter.",
         "Observe the injected header appear in the response."],
    ),
    "host_header": _Template(
        "host_header",
        "Host Header Injection on {target}",
        "{target} reflects an attacker-supplied Host / X-Forwarded-Host value into "
        "the response (links or redirects).",
        "Can enable password-reset poisoning, cache poisoning and routing-based "
        "attacks depending on how the host value is used.",
        "Validate the Host header against an allow-list; build absolute URLs from "
        "a fixed configured domain, not the request's Host.",
        ["https://portswigger.net/web-security/host-header"],
        ["Request {target} with `Host: evil.example` (or X-Forwarded-Host).",
         "Observe the value reflected in the response body or Location header."],
    ),
    "ssrf": _Template(
        "ssrf",
        "Server-Side Request Forgery on {target}",
        "A parameter on {target} causes the server to make a request to a "
        "user-supplied URL (confirmed via an out-of-band canary interaction).",
        "Lets an attacker reach internal services, cloud metadata endpoints "
        "(e.g. 169.254.169.254) and otherwise unreachable hosts.",
        "Validate and allow-list outbound destinations; block internal/link-local "
        "ranges; disable unused URL schemes; require explicit egress.",
        ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
        ["Request {target} with the fetch parameter set to your canary URL.",
         "Observe the inbound hit in your canary logs, confirming server-side "
         "fetch of attacker-controlled URLs."],
    ),
    "secret_disclosure": _Template(
        "secret_disclosure",
        "Sensitive Credential Disclosure at {target}",
        "A secret/API key pattern was found exposed in client-side JavaScript "
        "served from {target}.",
        "Exposed credentials may grant access to third-party services or internal "
        "APIs, depending on scope and whether the key is live.",
        "Rotate the exposed credential immediately; move secrets server-side; "
        "never ship secrets in client-side assets; add secret scanning to CI.",
        ["https://cwe.mitre.org/data/definitions/312.html"],
        ["Fetch the JavaScript asset at {target}.",
         "Locate the credential pattern (redacted in this report).",
         "Validate out-of-band whether the key is live before reporting; do not "
         "use it."],
    ),
    "sensitive_file": _Template(
        "sensitive_file",
        "Sensitive File Exposure at {target}",
        "A sensitive file/path is accessible without authentication at {target}.",
        "May disclose credentials, source, configuration or backups, leading to "
        "further compromise.",
        "Restrict access to sensitive paths; remove backups/config from the web "
        "root; return 404/403 and add authentication/authorization.",
        ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing"],
        ["Request {target} and observe the sensitive content is served (HTTP 200)."],
    ),
    "vulnerable_component": _Template(
        "vulnerable_component",
        "Vulnerable / Outdated Component on {target}",
        "{target} discloses a software version matching a known vulnerability.",
        "Known CVEs in the running version may be exploitable; at minimum, version "
        "disclosure aids targeted attacks.",
        "Upgrade to a fixed version; suppress verbose version banners; track "
        "dependencies against a vulnerability feed.",
        ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        ["Request {target} and read the Server / version banner.",
         "Confirm the version is in the vulnerable range for the referenced CVE."],
    ),
    "security_headers": _Template(
        "security_headers",
        "Missing Security Headers on {target}",
        "{target} is served without one or more recommended security response "
        "headers.",
        "Weakens defense-in-depth (clickjacking, MIME sniffing, weak transport "
        "security). Usually low severity on its own.",
        "Add the missing headers (CSP, X-Frame-Options, X-Content-Type-Options, "
        "HSTS) with appropriate values.",
        ["https://owasp.org/www-project-secure-headers/"],
        ["Request {target} and note the absent security header(s) in the response."],
    ),
    "generic": _Template(
        "generic",
        "{name}",
        "Automated finding on {target}.",
        "See evidence; assess impact in context before reporting.",
        "Review and remediate per the finding details.",
        [],
        ["Reproduce the observation described in the evidence for {target}."],
    ),
}


def classify(finding: dict) -> str:
    module = finding.get("module", "")
    name = (finding.get("name") or "").lower()
    if module == "takeover":
        return "subdomain_takeover"
    if module == "cvecheck":
        return "vulnerable_component" if "version disclosed" not in name else "generic"
    if module == "jsintel":
        return "secret_disclosure" if ("secret" in name or "key" in name or "token" in name or "jwt" in name) else "generic"
    if module == "content":
        return "sensitive_file" if "sensitive" in name else "generic"
    if module == "probe":
        return "security_headers" if "missing" in name else "generic"
    if module == "webchecks":
        # Order matters: more specific names (which may also contain generic
        # words like "reflected") are classified before the xss catch-all.
        if "cors" in name:
            return "cors"
        if "open redirect" in name:
            return "open_redirect"
        if "crlf" in name:
            return "crlf"
        if "host header" in name:
            return "host_header"
        if "ssrf" in name:
            return "ssrf"
        if "xss" in name or "reflected" in name:
            return "xss"
    return "generic"


def build_submission(finding: dict, platform: str = "generic") -> str:
    tpl = _TEMPLATES.get(classify(finding), _TEMPLATES["generic"])
    target = finding.get("target", "")
    evidence = finding.get("evidence", "") or "—"
    name = finding.get("name", "")
    severity = finding.get("severity", "info")

    def fmt(s: str) -> str:
        return s.format(target=target, evidence=evidence, name=name)

    sev_line = f"**Severity:** {severity.capitalize()}"
    if platform == "bugcrowd":
        sev_line += f"  (VRT priority ~{_PRIORITY.get(severity, 'P5')})"

    lines = [
        f"## {fmt(tpl.title)}",
        "",
        sev_line,
        f"**Asset:** `{target}`",
        f"**Detected by:** baugbaunty `{finding.get('module','')}` (automated lead — verify before submitting)",
        "",
        "### Summary",
        fmt(tpl.summary),
        "",
        "### Steps to Reproduce",
    ]
    lines += [f"{i}. {fmt(step)}" for i, step in enumerate(tpl.repro, 1)]
    lines += [
        "",
        "### Evidence",
        f"```\n{evidence}\n```",
        "",
        "### Impact",
        fmt(tpl.impact),
        "",
        "### Remediation",
        fmt(tpl.remediation),
    ]
    if tpl.references:
        lines += ["", "### References"]
        lines += [f"- {r}" for r in tpl.references]
    lines += ["", "---", ""]
    return "\n".join(lines)


def generate_submissions(
    store: Store,
    config: Config,
    out_dir: str | Path,
    min_severity: str = "medium",
    platform: str = "generic",
    fmt: str = "markdown",
) -> Path:
    """Write a single submissions document for all findings >= min_severity.

    Returns the path written.
    """

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    program = config.get("program.name", "engagement")
    threshold = _SEV_RANK.get(min_severity, 2)

    findings = [f for f in store.findings() if _SEV_RANK.get(f.get("severity", "info"), 0) >= threshold]

    if fmt == "json":
        data = [
            {**f, "vuln_class": classify(f), "submission_markdown": build_submission(f, platform)}
            for f in findings
        ]
        path = out / f"{program}-submissions.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    header = [
        f"# {program} — Vulnerability Submissions ({platform})",
        "",
        f"_Generated by baugbaunty. {len(findings)} finding(s) at or above "
        f"**{min_severity}**._",
        "",
        "> These are automated drafts. Verify each finding by hand before "
        "submitting; confirm impact and remove false positives.",
        "",
        "---",
        "",
    ]
    body = [build_submission(f, platform) for f in findings] or ["_No findings at or above the threshold._\n"]
    path = out / f"{program}-submissions.md"
    path.write_text("\n".join(header) + "\n".join(body), encoding="utf-8")
    return path
