"""Lightweight technology fingerprinting from HTTP responses.

This is intentionally simple and signature-based (headers, cookies, body
markers). For deep detection, install ``httpx`` which has a far larger
signature set; this module is the dependency-free fallback.
"""

from __future__ import annotations

import re
from ..core.http import Response

# (label, where, pattern) — where in {"header", "cookie", "body", "server"}
_SIGNATURES: list[tuple[str, str, re.Pattern[str]]] = [
    ("nginx", "server", re.compile(r"nginx", re.I)),
    ("Apache", "server", re.compile(r"apache", re.I)),
    ("IIS", "server", re.compile(r"iis|microsoft-httpapi", re.I)),
    ("Cloudflare", "header", re.compile(r"cf-ray|cloudflare", re.I)),
    ("Akamai", "header", re.compile(r"akamai|x-akamai", re.I)),
    ("WordPress", "body", re.compile(r"wp-content|wp-includes", re.I)),
    ("Drupal", "body", re.compile(r"Drupal\.settings|/sites/default/files", re.I)),
    ("Joomla", "body", re.compile(r"/media/jui/|com_content", re.I)),
    ("Laravel", "cookie", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
    ("Django", "cookie", re.compile(r"csrftoken|sessionid", re.I)),
    ("Express", "header", re.compile(r"x-powered-by:\s*express", re.I)),
    ("PHP", "header", re.compile(r"x-powered-by:\s*php|\.php", re.I)),
    ("ASP.NET", "header", re.compile(r"asp\.net|x-aspnet-version", re.I)),
    ("React", "body", re.compile(r"__REACT_DEVTOOLS|data-reactroot", re.I)),
    ("Next.js", "body", re.compile(r"/_next/|__NEXT_DATA__", re.I)),
    ("Vue.js", "body", re.compile(r"data-v-[0-9a-f]{8}|__vue__", re.I)),
    ("jQuery", "body", re.compile(r"jquery(\.min)?\.js", re.I)),
    ("Shopify", "header", re.compile(r"x-shopify|shopify", re.I)),
    ("Varnish", "header", re.compile(r"x-varnish|via:.*varnish", re.I)),
    ("Kubernetes Ingress", "header", re.compile(r"x-kubernetes|ingress-nginx", re.I)),
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def extract_title(body: bytes) -> str:
    text = body[:200_000].decode("utf-8", errors="replace")
    m = _TITLE_RE.search(text)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:300]


def fingerprint(resp: Response) -> list[str]:
    tech: set[str] = set()
    header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    server = resp.header("server")
    cookie = resp.header("set-cookie")
    body_text = resp.text(limit=200_000)

    haystacks = {
        "header": header_blob,
        "server": server,
        "cookie": cookie,
        "body": body_text,
    }
    for label, where, pattern in _SIGNATURES:
        if pattern.search(haystacks.get(where, "")):
            tech.add(label)

    # Generic X-Powered-By passthrough.
    xpb = resp.header("x-powered-by")
    if xpb:
        tech.add(xpb.split("/")[0].strip()[:40])

    return sorted(tech)
