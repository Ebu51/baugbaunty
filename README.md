# baugbaunty

**Scope-first bug bounty reconnaissance toolkit for _authorized_ security testing.**

A modular recon + light-testing framework built the way a professional bounty
hunter works: safety and scope discipline first, then a repeatable pipeline from
asset discovery to a clean report. The core runs on the **Python standard library
alone** (zero required dependencies) and transparently upgrades to best-in-class
external tools (`subfinder`, `httpx`, `naabu`, `nuclei`) when they're installed.

---

## ⚖️ Authorized use only

This tool is for targets you are **explicitly permitted** to test: public/private
bug bounty programs within their stated scope, your own assets, or systems for
which you hold written authorization. Three guardrails are built in and should
stay on:

1. **Default-deny scope engine** — every outbound request is checked; anything
   not explicitly in scope is refused before a packet is sent. Out-of-scope rules
   always beat in-scope rules.
2. **Rate limiting** — a global + per-host token bucket keeps you a polite guest
   and well clear of denial-of-service territory.
3. **Authorization gate** — active phases (which send traffic to the target)
   refuse to run until you confirm authorization (`program.authorized: true` or
   `--authorize`).

Always read and follow each program's policy and respect `out-of-scope`,
rate, and testing-window rules. Report responsibly.

---

## Install

```bash
git clone <this-repo> && cd baugbaunty
python -m baugbaunty --help          # runs immediately, no deps

# optional: editable install so `baugbaunty` is on your PATH
pip install -e .
# optional extras
pip install -e ".[yaml,dev]"
```

Optional external tools (massively boost power; install separately):

```bash
# ProjectDiscovery suite
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

baugbaunty tools   # check what's detected
```

---

## Quick start

```bash
# 1. Create a config
python -m baugbaunty init -n acme-program -o acme.json

# 2. Edit acme.json: set scope.include / scope.exclude to the PROGRAM scope.
#    Flip program.authorized to true ONLY once you have permission.

# 3. Sanity-check your scope rules before touching anything
python -m baugbaunty scope -c acme.json www.acme.com evil.com

# 4. Passive-only recon (safe, no traffic to target) — subdomain discovery
python -m baugbaunty run -c acme.json --phases subdomains

# 5. Full pipeline once authorized
python -m baugbaunty run -c acme.json --authorize

# 6. Regenerate reports in another format anytime
python -m baugbaunty report -c acme.json --formats html markdown
```

You can also skip the config file for a quick pass:

```bash
python -m baugbaunty run -d "*.example.com" --phases subdomains
```

---

## The pipeline (A → Z)

| Phase        | Traffic to target? | What it does | Powered by |
|--------------|:---:|--------------|------------|
| `subdomains` | ❌ passive | Certificate-transparency (crt.sh) + aggregated passive sources | built-in / `subfinder` |
| `wayback`    | ❌ passive | Historical URL mining from Wayback Machine + AlienVault OTX; flags interesting archived URLs | built-in |
| `dns`        | ❌ passive¹ | Resolve hosts, extract CNAMEs, detect & filter wildcard DNS | built-in / `dnsx` |
| `takeover`   | ✅ active | Subdomain-takeover detection via CNAME + response fingerprints (14+ providers) | built-in |
| `probe`      | ✅ active | Which hosts are live over HTTP(S); status, title, server, tech; passive security-header checks | built-in / `httpx` |
| `seeds`      | ✅ active | Seeds paths from robots.txt & sitemap.xml; captures favicon hashes (mmh3/md5) | built-in |
| `vhost`      | ✅ active | Virtual-host discovery — finds sites served on an in-scope IP via the Host header | built-in |
| `jsintel`    | ✅ active | Extracts endpoints & hard-coded secrets (AWS/GCP/Slack/Stripe/JWT…) from live JavaScript | built-in |
| `content`    | ✅ active | Directory/endpoint discovery with soft-404 calibration; flags sensitive paths | built-in |
| `params`     | ✅ active | Hidden GET-parameter discovery via reflection + response-diff | built-in |
| `webchecks`  | ✅ active | Safe CORS / open-redirect / reflection (XSS-candidate) checks | built-in |
| `ports`      | ✅ active | Open-port discovery | built-in / `naabu` |
| `nuclei`     | ✅ active | Template-based vulnerability checks | `nuclei` |
| _report_     | — | JSON + Markdown + self-contained HTML | always runs |

¹ DNS resolution queries public/authoritative resolvers, not the target's web
app, so it is treated as non-intrusive recon and doesn't require the auth gate.

### Continuous monitoring (`monitor`)

`monitor` runs the pipeline, then reports (and optionally pushes a notification
for) everything **new since the last run** — perfect for a cron job that alerts
you the moment a target exposes a new subdomain or service:

```bash
# cheap change-detection every few hours
baugbaunty monitor -c acme.json --authorize --phases subdomains dns probe
```

Configure alerts under `notifications` in your config (Slack / Discord /
Telegram / generic webhook), with a `min_severity` filter:

```json
"notifications": {
  "enabled": true,
  "slack_webhook": "https://hooks.slack.com/services/...",
  "telegram_bot_token": "", "telegram_chat_id": "",
  "min_severity": "medium"
}
```

A per-program run checkpoint is stored in the results DB, so diffs are accurate
across runs and the first run never spams you with everything at once.

Everything discovered is stored in a per-program SQLite database
(`output/<program>.sqlite`) so runs are **resumable, de-duplicated and
queryable**. Reports are regenerated from it on demand.

---

## Architecture

```
baugbaunty/
├── core/            # infrastructure — trusted, unit-tested
│   ├── scope.py       default-deny scope engine (deny beats allow)
│   ├── ratelimit.py   token-bucket limiter (global + per-host)
│   ├── http.py        scope-gated, rate-limited stdlib HTTP client
│   ├── config.py      JSON/YAML config with deep-merged defaults
│   ├── store.py       SQLite result store (assets/services/findings)
│   └── logging.py     tiny structured logger
├── modules/         # one file per pipeline phase
│   ├── subdomains.py  wayback.py  dns.py  takeover.py
│   ├── probe.py  seeds.py  vhost.py  jsintel.py  content.py
│   ├── params.py  webchecks.py  ports.py  nuclei.py
│   └── fingerprint.py tech detection signatures
├── integrations/    # safe argv-only wrappers for external CLIs
├── report/          # JSON / Markdown / HTML renderers
└── cli.py           # argparse CLI + orchestration
```

Design principles: **scope is checked at the lowest layer** (the HTTP client),
so no module can accidentally reach out of scope; external tools are invoked by
argv lists (never a shell string) so target-derived values can't inject
commands; and the core degrades gracefully to pure Python when tools are absent.

---

## Configuration reference

See [`config/example.json`](config/example.json). Key fields:

- `program.authorized` — **must be `true`** (or pass `--authorize`) for active
  phases to run.
- `scope.include` / `scope.exclude` — rules support `*.wildcard`, exact hosts,
  IPs, `CIDR/ranges`, and `re:<regex>`.
- `limits.*` — `global_rps`, `per_host_rps`, `concurrency`, `timeout`.
- `http.user_agent` — keep it honest and identifiable (add your contact) so
  target teams can distinguish your traffic.
- `modules.content.wordlist` — point at a bigger list (e.g. SecLists) for real
  content discovery.

---

## Tests

```bash
pip install pytest
pytest -q
```

---

## Proxy / Burp passthrough

Route every request through Burp or mitmproxy for manual inspection and replay:

```json
"http": { "proxy": "http://127.0.0.1:8080", "verify_tls": false }
```

## Roadmap

Shipped (Tier 1): DNS resolution + wildcard filtering, subdomain-takeover
detection, historical-URL mining, JS endpoint/secret extraction, diff/monitor
mode with notifications.

Shipped (Tier 2): hidden-parameter discovery, safe CORS/open-redirect/
reflection checks, virtual-host discovery, robots/sitemap seeding +
favicon-hash correlation, and Burp/mitmproxy passthrough.

Planned next (Tier 3): HackerOne/Bugcrowd scope import, screenshotting,
GitHub dorking, CVE correlation, scan profiles.

---

## Disclaimer

Provided as-is for lawful, authorized security research. You are responsible for
ensuring you have permission to test any target. The authors accept no liability
for misuse.
