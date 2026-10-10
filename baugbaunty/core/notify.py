"""Outbound notifications for monitor/diff mode.

Sends short messages to Slack, Discord, Telegram or a generic webhook when a
scan turns up something new. These endpoints are YOUR infrastructure (third
party relative to the target), so they are called directly and are never
subject to the target scope gate — but they are still best-effort and never
raise into the pipeline.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from .logging import Logger, get_logger

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Notifier:
    slack_webhook: str = ""
    discord_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    generic_webhook: str = ""
    enabled: bool = False
    min_severity: str = "medium"
    log: Logger | None = None

    @classmethod
    def from_config(cls, cfg: dict) -> "Notifier":
        return cls(
            slack_webhook=cfg.get("slack_webhook", ""),
            discord_webhook=cfg.get("discord_webhook", ""),
            telegram_bot_token=cfg.get("telegram_bot_token", ""),
            telegram_chat_id=cfg.get("telegram_chat_id", ""),
            generic_webhook=cfg.get("generic_webhook", ""),
            enabled=bool(cfg.get("enabled", False)),
            min_severity=cfg.get("min_severity", "medium"),
        )

    @property
    def _log(self) -> Logger:
        return self.log or get_logger()

    def severity_passes(self, severity: str) -> bool:
        return _SEV_RANK.get(severity, 0) >= _SEV_RANK.get(self.min_severity, 2)

    def _post(self, url: str, payload: dict) -> bool:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, OSError, ValueError) as e:
            self._log.warn(f"[notify] delivery failed: {e}")
            return False

    def send(self, title: str, body: str) -> None:
        """Send a notification to every configured channel. Never raises."""

        if not self.enabled:
            return
        text = f"*{title}*\n{body}" if body else title
        sent_any = False
        if self.slack_webhook:
            sent_any |= self._post(self.slack_webhook, {"text": text})
        if self.discord_webhook:
            sent_any |= self._post(self.discord_webhook, {"content": text[:1900]})
        if self.telegram_bot_token and self.telegram_chat_id:
            tg_url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            sent_any |= self._post(
                tg_url,
                {"chat_id": self.telegram_chat_id, "text": text, "parse_mode": "Markdown"},
            )
        if self.generic_webhook:
            sent_any |= self._post(self.generic_webhook, {"title": title, "body": body})
        if sent_any:
            self._log.success("[notify] alert delivered")

    def send_diff(self, program: str, diff: dict) -> None:
        """Summarise and send newly discovered items (filtered by severity)."""

        if not self.enabled:
            return
        new_assets = diff.get("assets", [])
        new_services = diff.get("services", [])
        new_findings = [
            f for f in diff.get("findings", []) if self.severity_passes(f.get("severity", "info"))
        ]
        if not (new_assets or new_services or new_findings):
            return

        lines = [f"New results for `{program}`:"]
        if new_assets:
            lines.append(f"• {len(new_assets)} new asset(s)")
            for a in new_assets[:10]:
                lines.append(f"    - {a['value']} ({a['kind']})")
        if new_services:
            lines.append(f"• {len(new_services)} new live service(s)")
            for s in new_services[:10]:
                lines.append(f"    - {s['url']} [{s.get('status','')}]")
        if new_findings:
            lines.append(f"• {len(new_findings)} new finding(s) >= {self.min_severity}")
            for f in new_findings[:15]:
                lines.append(f"    - [{f.get('severity','').upper()}] {f.get('name')} ({f.get('target')})")
        self.send(f"baugbaunty · {program}", "\n".join(lines[1:]))
