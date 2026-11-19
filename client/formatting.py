"""Display helpers shared by the terminal client and the GUI."""

import time
from datetime import datetime, timedelta
from typing import Optional


def format_time(ts: float) -> str:
    """Unix time -> '10:42 PM' (WhatsApp style)."""
    return datetime.fromtimestamp(ts).strftime("%I:%M %p").lstrip("0")


def format_chat_time(ts: float, now: Optional[float] = None) -> str:
    """Time shown in the chat list: '10:42 PM' today, 'Yesterday', 'Monday', or '12/11/2026'."""
    when = datetime.fromtimestamp(ts)
    today = datetime.fromtimestamp(now if now is not None else time.time()).date()
    days_ago = (today - when.date()).days
    if days_ago <= 0:
        return format_time(ts)
    if days_ago == 1:
        return "Yesterday"
    if days_ago < 7:
        return when.strftime("%A")
    return when.strftime("%d/%m/%Y")


def format_date_chip(ts: float, now: Optional[float] = None) -> str:
    """Date separator inside a chat: 'TODAY', 'YESTERDAY', 'MONDAY' or '12/11/2026'."""
    label = format_chat_time(ts, now)
    if ":" in label:          # today -> format_chat_time returned a clock time
        return "TODAY"
    return label.upper()


def initials(name: str) -> str:
    """'Alice Sharma' -> 'AS', 'bob' -> 'B' (shown on avatars)."""
    words = [w for w in name.replace("_", " ").split() if w]
    if not words:
        return "?"
    return (words[0][0] + (words[1][0] if len(words) > 1 else "")).upper()


def format_last_seen(online: bool, last_seen: Optional[float], now: Optional[float] = None) -> str:
    """'online', 'last seen today at 9:41 PM', 'last seen yesterday at ...', 'last seen 12/11/2026'."""
    if online:
        return "online"
    if not last_seen:
        return "offline"
    when = datetime.fromtimestamp(last_seen)
    today = datetime.fromtimestamp(now if now is not None else time.time()).date()
    if when.date() == today:
        return f"last seen today at {format_time(last_seen)}"
    if when.date() == today - timedelta(days=1):
        return f"last seen yesterday at {format_time(last_seen)}"
    return f"last seen {when.strftime('%d/%m/%Y')}"
