"""
Shared utility functions used across all layers.
No imports from data_layer or discord_handler — pure helpers only.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

SYDNEY_TZ = ZoneInfo("Australia/Sydney")

_SEVERITY_ICONS = {
    "SEVERE":  "🔴",
    "WARNING": "🟡",
    "INFO":    "🔵",
}

# Accepts both numeric API codes and human-readable mode names.
_MODE_ICONS: dict[str, str] = {
    # Numeric (as returned by TfNSW API product.class)
    "1": "🚆",   # Train
    "2": "🚇",   # Metro
    "4": "🚃",   # Light Rail
    "5": "🚌",   # Bus
    "7": "🚌",   # Coach
    "9": "⛴️",   # Ferry
    "11": "🚌",  # On-demand
    "99": "🚌",
    # Human-readable (for mocks / formatted output)
    "Train":      "🚆",
    "Metro":      "🚇",
    "Light Rail": "🚃",
    "Bus":        "🚌",
    "Coach":      "🚌",
    "Ferry":      "⛴️",
}

_MODE_NAMES: dict[str, str] = {
    "1": "Train", "2": "Metro", "4": "Light Rail",
    "5": "Bus", "7": "Coach", "9": "Ferry",
    "11": "Bus", "99": "Bus",
}

# ── Timestamp helpers ─────────────────────────────────────────────────────────

def parse_iso(ts: str) -> datetime | None:
    """
    Parse an ISO-8601 timestamp, normalising the Z suffix.
    Returns None on parse failure instead of raising.
    """
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def format_timestamp(timestamp: str) -> str:
    """
    Convert an ISO-8601 timestamp to a human-readable Sydney-local string.
    Falls back to the raw string when parsing fails.
    """
    dt = parse_iso(timestamp)
    if dt is None:
        return timestamp
    return dt.astimezone(SYDNEY_TZ).strftime("%Y-%m-%d %H:%M %Z")


def validate_stop_id(stop_id: str) -> bool:
    """Return True when *stop_id* is a non-empty, non-whitespace string."""
    return bool(stop_id and stop_id.strip())


def calculate_delay_minutes(scheduled_iso: str, actual_iso: str) -> int:
    """
    Return signed delay in whole minutes (positive = late, negative = early).
    Raises ValueError when either timestamp cannot be parsed.
    """
    scheduled = parse_iso(scheduled_iso)
    actual = parse_iso(actual_iso)
    if scheduled is None or actual is None:
        raise ValueError(
            f"Cannot parse timestamps: {scheduled_iso!r}, {actual_iso!r}"
        )
    return int((actual - scheduled).total_seconds() / 60)


def is_quiet_hours(hour: int | None = None, start: int = 23, end: int = 5) -> bool:
    """
    Return True when the current Sydney time falls in the quiet window [start, end).
    The window wraps midnight, e.g. start=23, end=5 covers 23:00–04:59.
    """
    if hour is None:
        hour = datetime.now(SYDNEY_TZ).hour
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


# ── Duration parsing (for reminder system) ────────────────────────────────────

_DURATION_RE = re.compile(
    r"""
    (?:in\s+)?                          # optional leading "in"
    (?:(\d+)\s*(?:hours?|h(?:rs?)?))?   # hours
    \s*
    (?:(\d+)\s*(?:minutes?|mins?|m))?   # minutes
    \s*
    (?:(\d+)\s*(?:seconds?|secs?|s))?   # seconds
    """,
    re.IGNORECASE | re.VERBOSE,
)


def parse_duration(text: str) -> timedelta | None:
    """
    Parse a natural-language duration string into a timedelta.

    Accepted forms:
      "30m", "30 minutes", "2h", "2 hours", "1h30m",
      "in 30 minutes", "1 hour 30 minutes", "90s"

    Returns None when the string cannot be parsed or yields a zero duration.
    """
    m = _DURATION_RE.match(text.strip())
    if not m:
        return None
    hours = int(m.group(1) or 0)
    minutes = int(m.group(2) or 0)
    seconds = int(m.group(3) or 0)
    delta = timedelta(hours=hours, minutes=minutes, seconds=seconds)
    return delta if delta.total_seconds() > 0 else None


# ── Formatting helpers ────────────────────────────────────────────────────────

def mode_icon(mode: str) -> str:
    """Return the emoji for a transport mode (numeric code or name)."""
    return _MODE_ICONS.get(mode, "🚍")


def mode_name(mode_code: str) -> str:
    """Return the human-readable mode name for a numeric API mode code."""
    return _MODE_NAMES.get(mode_code, mode_code)


def format_trip_report(legs: list[dict], target_datetime: datetime | None = None) -> str:
    """Render a trip-plan *legs* list as a Discord-markdown Scheduled Trip Report."""
    if not legs:
        return "No journey options found for the requested time."

    anchor_str = (
        target_datetime.strftime("%A %d %b %Y at %H:%M")
        if target_datetime
        else "now"
    )
    lines: list[str] = [
        "## 🗺️ Scheduled Trip Report",
        f"**Departing:** {anchor_str}",
        "",
    ]
    total_mins = sum(leg.get("duration_min", 0) for leg in legs)

    for i, leg in enumerate(legs, 1):
        icon = mode_icon(leg.get("mode", ""))
        platform = f" • {leg['platform']}" if leg.get("platform") else ""
        dep_time = _fmt_time(leg.get("dep_time", ""))
        arr_time = _fmt_time(leg.get("arr_time", ""))
        lines += [
            f"**Leg {i}** — {icon} {leg.get('mode', '?')} {leg.get('line', '')}  _{leg.get('headsign', '')}_",
            f"> Depart **{leg.get('dep_stop', '?')}** at {dep_time}{platform}",
            f"> Arrive **{leg.get('arr_stop', '?')}** at {arr_time} ({leg.get('duration_min', '?')} min)",
            "",
        ]

    lines.append(f"**Total journey time:** {total_mins} min")
    return "\n".join(lines)


def format_departures_board(stop_name: str, departures: list[dict]) -> str:
    """Render a live departures board for a stop as Discord markdown."""
    if not departures:
        return f"No upcoming departures found for **{stop_name}**."

    lines: list[str] = [f"## 🚏 Departures — {stop_name}", ""]
    for dep in departures:
        icon = mode_icon(dep.get("mode", ""))
        line = dep.get("line", "?")
        headsign = dep.get("headsign", "")
        dep_time = _fmt_time(dep.get("dep_time", ""))
        platform = f"  _{dep.get('platform')}_" if dep.get("platform") else ""
        delay_s = dep.get("delay_seconds", 0) or 0
        if delay_s >= 60:
            delay_tag = f"  ⚠️ +{delay_s // 60}min"
        elif delay_s <= -60:
            delay_tag = f"  ✅ -{abs(delay_s) // 60}min early"
        else:
            delay_tag = ""
        lines.append(f"{icon} **{dep_time}** {line}  _{headsign}_{platform}{delay_tag}")

    return "\n".join(lines)


def format_alert_card(alerts: list[dict]) -> str:
    """Render a list of service alert dicts as a Discord-markdown disruption card."""
    if not alerts:
        return "✅ No active service disruptions at this time."

    lines: list[str] = ["## 🚨 Service Disruption Dashboard", ""]
    for alert in alerts:
        icon = _SEVERITY_ICONS.get(alert.get("severity", "INFO"), "🔵")
        affected = ", ".join(alert.get("affected_lines", []))
        start = _fmt_time(alert.get("start_time") or "")
        end_raw = alert.get("end_time")
        end = _fmt_time(end_raw) if end_raw else "ongoing"
        lines += [
            f"{icon} **{alert.get('header', 'Service Alert')}**",
            f"> **Lines affected:** {affected or 'All services'}",
            f"> {alert.get('description', '')}",
            f"> **Active:** {start} → {end}",
            "",
        ]
    return "\n".join(lines).rstrip()


def format_delay_alert(
    trip_id: str,
    stop_name: str,
    delay_minutes: int,
    scheduled_iso: str,
    predicted_iso: str,
    mode: str = "",
    line: str = "",
) -> str:
    """Return a formatted delay alert message for Discord."""
    direction = "late" if delay_minutes > 0 else "early"
    icon = mode_icon(mode) if mode else "⚠️"
    label = f"{icon} {line}".strip() if line else icon
    return (
        f"⚠️ **Delay Alert** — {label} Trip `{trip_id}`\n"
        f"> Service to **{stop_name}** is **{abs(delay_minutes)} min {direction}**\n"
        f"> Scheduled: {_fmt_time(scheduled_iso)}  •  Predicted: {_fmt_time(predicted_iso)}"
    )


def format_vehicle_status(trip_id: str, position: dict) -> str:
    """Render a vehicle position dict as a Discord-markdown status card."""
    stop = position.get("stop_id") or "unknown"
    ts = _fmt_time(position.get("timestamp", ""))
    speed = position.get("speed_kmh")
    bearing = position.get("bearing")
    speed_str = f"  •  {speed:.0f} km/h" if speed is not None else ""
    bearing_str = f"  •  heading {bearing:.0f}°" if bearing is not None else ""
    return (
        f"📍 **Vehicle Status** — Trip `{trip_id}`\n"
        f"> Last stop: `{stop}`  •  as of {ts}{speed_str}{bearing_str}"
    )


def format_reminder_list(reminders: list[dict]) -> str:
    """Render pending reminders as a Discord-markdown list."""
    if not reminders:
        return "You have no pending reminders."
    now = datetime.now(timezone.utc)
    lines = ["## ⏰ Your Reminders", ""]
    for r in reminders:
        fire_at = parse_iso(r["fire_at"])
        if fire_at:
            remaining = fire_at - now
            mins = int(remaining.total_seconds() / 60)
            time_str = f"in {mins}m" if mins >= 0 else "overdue"
        else:
            time_str = "?"
        lines.append(f"`#{r['id']}` **{r['message']}** — {time_str}")
    return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fmt_time(iso: str) -> str:
    """Return HH:MM (Sydney local) from an ISO-8601 string, or '?' on failure."""
    dt = parse_iso(iso)
    if dt is None:
        return "?" if not iso else iso
    return dt.astimezone(SYDNEY_TZ).strftime("%H:%M")
