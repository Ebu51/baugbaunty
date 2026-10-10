"""Minimal, dependency-free structured logging with optional colour."""

from __future__ import annotations

import sys
import threading
import time

_LEVELS = {"debug": 10, "info": 20, "success": 25, "warn": 30, "error": 40}
_COLORS = {
    "debug": "\033[90m",
    "info": "\033[36m",
    "success": "\033[32m",
    "warn": "\033[33m",
    "error": "\033[31m",
}
_RESET = "\033[0m"


class Logger:
    def __init__(self, level: str = "info", use_color: bool | None = None) -> None:
        self.level = _LEVELS.get(level, 20)
        if use_color is None:
            use_color = sys.stderr.isatty()
        self.use_color = use_color
        self._lock = threading.Lock()

    def _emit(self, level: str, msg: str) -> None:
        if _LEVELS[level] < self.level:
            return
        ts = time.strftime("%H:%M:%S")
        tag = level.upper()[:4]
        if self.use_color:
            color = _COLORS.get(level, "")
            line = f"{color}[{ts}] {tag:<4}{_RESET} {msg}"
        else:
            line = f"[{ts}] {tag:<4} {msg}"
        with self._lock:
            print(line, file=sys.stderr, flush=True)

    def debug(self, msg: str) -> None:
        self._emit("debug", msg)

    def info(self, msg: str) -> None:
        self._emit("info", msg)

    def success(self, msg: str) -> None:
        self._emit("success", msg)

    def warn(self, msg: str) -> None:
        self._emit("warn", msg)

    def error(self, msg: str) -> None:
        self._emit("error", msg)


_default = Logger()


def get_logger() -> Logger:
    return _default


def configure(level: str = "info", use_color: bool | None = None) -> Logger:
    global _default
    _default = Logger(level=level, use_color=use_color)
    return _default
