from __future__ import annotations

import datetime
import sys
from typing import Iterable, Tuple


class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    if not supports_color():
        return text
    return f"{color}{text}{Colors.RESET}"


def normalize_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        return str(ip).strip()
    except Exception:
        return None


def common_port_name(port: int) -> str | None:
    mapping = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS"}
    return mapping.get(port)


def decode_payload(payload: bytes, limit: int = 100) -> Tuple[str, str]:
    if not payload:
        return "", ""
    try:
        decoded = payload.decode("utf-8", errors="replace")
    except Exception:
        decoded = str(payload)
    preview = decoded
    if len(preview) > limit:
        preview = preview[: limit - 3] + "..."
    return preview, decoded


def format_timestamp(timestamp: float | None) -> str:
    if not timestamp:
        return datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
    return datetime.datetime.fromtimestamp(timestamp).isoformat(sep=" ", timespec="seconds")


def safe_join(items: Iterable[str], sep: str = ", ") -> str:
    return sep.join(str(x) for x in items if x)


def truncate_text(text: str | None, length: int) -> str:
    if text is None:
        return ""
    s = str(text)
    if len(s) <= length:
        return s
    return s[: max(0, length - 3)] + "..."


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    # compute column widths
    cols = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i in range(cols):
            if i < len(row):
                widths[i] = max(widths[i], len(str(row[i])))
    sep = " | "
    header_line = sep.join(h.ljust(widths[i]) for i, h in enumerate(headers))
    divider = "-" * len(header_line)
    row_lines = [sep.join(str(row[i]).ljust(widths[i]) for i in range(cols)) for row in rows]
    return header_line + "\n" + divider + "\n" + "\n".join(row_lines)
