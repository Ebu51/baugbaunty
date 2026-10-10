# Security & Responsible-Use Policy

> ⚠️ **baugbaunty is an offensive security tool. Use it only against systems you
> are explicitly authorized to test.** Running it against systems you do not own
> or lack written permission to test may be illegal and can cause harm, even
> with the built-in safeguards.

## Intended use

baugbaunty is for **authorized security testing only**:

- public or private bug bounty programs, **within their stated scope**;
- assets you own; or
- targets for which you hold **explicit written permission** (e.g. a signed
  pentest engagement).

Always read and follow each program's policy, respect its `out-of-scope` list,
honor rate and testing-window rules, and report findings responsibly.

## Prohibited use

Do **not** use this tool to:

- scan, probe, or attack systems without authorization;
- perform denial-of-service, mass/indiscriminate targeting, or any destructive
  action;
- access, exfiltrate, retain, or share data you are not authorized to;
- test or reuse any credential, token, or secret that it surfaces; or
- do anything prohibited by applicable law or by a program's rules.

You are solely responsible for ensuring you have permission to test any target
and for complying with all applicable laws.

## Built-in safeguards — do not remove

The toolkit is deliberately conservative. These controls should stay enabled:

1. **Default-deny scope engine** (`core/scope.py`), enforced at the HTTP layer:
   anything not explicitly in scope is refused before a packet is sent.
2. **Rate limiting** (`core/ratelimit.py`): global + per-host budgets keep you a
   polite guest and well clear of denial-of-service territory.
3. **Authorization gate**: active phases (those that send traffic to the target)
   refuse to run until the engagement is explicitly authorized
   (`program.authorized: true` or `--authorize`).

Findings from heuristic checks (reflection, CRLF, SSRF, subdomain takeover,
version→CVE correlation) are **leads to verify by hand**, not proven
vulnerabilities. Any discovered secret is sensitive: report it through the
program, never test or reuse it, and never paste raw secret values around.

## Reporting a vulnerability in baugbaunty itself

If you find a security issue **in this project's code** (not in a target you
scanned), please report it privately rather than opening a public issue:

- open a GitHub [private security advisory](https://docs.github.com/en/code-security/security-advisories)
  on this repository, or
- contact the maintainer through the repository's profile.

Please include a description, affected version/commit, and reproduction steps.
We aim to acknowledge reports promptly and will credit reporters who wish to be
named once a fix is available.

## No warranty

This software is provided "as is", without warranty of any kind, as stated in
the [LICENSE](LICENSE). The authors accept no liability for misuse or for any
damage arising from its use. By using baugbaunty you accept full responsibility
for your actions.
