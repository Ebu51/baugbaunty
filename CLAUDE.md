# Using baugbaunty with Claude

This repository ships an MCP server so Claude (Claude Code or Claude Desktop)
can drive the toolkit as tools. This file tells Claude how to use it **safely**.

## Golden rules (do not break these)

1. **Authorized targets only.** Only ever scan assets that are in a bug bounty
   program's scope, the user's own property, or targets with explicit written
   permission. If authorization is unclear, ask the user before any active phase.
2. **Scope first.** Before running anything, confirm the scope with the
   `scope_check` tool. Never add an asset to scope on the user's behalf without
   their say-so.
3. **Passive before active.** Prefer passive phases (`subdomains`, `wayback`,
   `githubdork`, `dns`, `cvecheck`) — they send no traffic to the target.
   Active phases require `program.authorized: true` in the config (or
   `authorize: true`); the `run` tool refuses them otherwise. Do not set
   `authorize: true` unless the user has confirmed they are authorized.
4. **Be a good guest.** Keep the configured rate limits. Don't crank `--rps` or
   switch to the `aggressive` profile unless the user asks.
5. **Handle findings responsibly.** Treat discovered secrets, tokens and PII as
   sensitive. Report them to the user; never test or reuse a credential, and
   never paste raw secret values back — reference where they were found.

## Typical workflow

1. `import_scope` — turn the program's scope export into a config (or the user
   writes one; see `config/example.json`).
2. `scope_check` — sanity-check a few in-scope and out-of-scope hosts.
3. `run` with passive phases to map the attack surface:
   `{"config": "program.json", "phases": ["subdomains","wayback","dns","cvecheck"]}`
4. Review with `summary` and `list_findings`.
5. Only once the user confirms authorization, `run` active phases
   (`probe`, `takeover`, `seeds`, `jsintel`, `content`, `params`, `webchecks`,
   `screenshot`, `ports`, `nuclei`) — or set `program.authorized: true` in the
   config.
6. Summarise findings by severity and suggest which to verify manually. Findings
   from `webchecks` (reflection/CRLF/SSRF) and `takeover` are **leads to confirm
   by hand**, not proven vulnerabilities.

## MCP tools available

- `scope_check`, `import_scope`, `tools_status` — safe, read-only / planning.
- `summary`, `list_findings`, `list_assets`, `read_report` — read a results DB.
- `generate_report`, `generate_submission` — produce reports and platform-ready
  submission drafts (HackerOne/Bugcrowd/generic).
- `run` — execute phases (active phases gated by authorization).

When drafting submissions: these are automated DRAFTS. Present them to the user
for review, make clear which findings are unverified leads, and never submit on
the user's behalf.

Results are stored in `output/<program>.sqlite`; reports are written to
`output/` as JSON, Markdown and HTML.

## Project conventions

- Core has zero required dependencies (standard library only). Keep it that way;
  put anything heavier behind an optional import that degrades gracefully.
- Every network-facing module must route through the scope gate and rate
  limiter. Never bypass `core/scope.py` or `core/http.py` for target traffic.
- Run `python -m pytest -q` before committing; keep the suite green.
