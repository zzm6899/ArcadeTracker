"""
Shared utility functions used across all layers.
No imports from data_layer or discord_handler — pure helpers only.
"""

from __future__ import annotations

from datetime import datetime


_SEVERITY_ICONS = {
    "SEVERE":  "🔴",
    "WARNING": "🟡",
    "INFO":    "🔵",
}

_MODE_ICONS = {
    "Train":      "🚆",
    "Metro":      "🚇",
    "Light Rail": "🚃",
    "Bus":        "🚌",
    "Coach":      "🚌",
    "Ferry":      "⛴️",
}


def format_timestamp(timestamp: str) -> str:
    """Convert an ISO-8601 timestamp to a human-readable string."""
    return timestamp.replace("T", " ").replace("Z", " UTC")


def validate_stop_id(stop_id: str) -> bool:
    """Return True when *stop_id* is a non-empty string."""
    return bool(stop_id and stop_id.strip())


def calculate_delay_minutes(scheduled_iso: str, actual_iso: str) -> int:
    """
    Return the signed delay in whole minutes (positive = late, negative = early).
    Raises ValueError when either timestamp cannot be parsed.
    """
    scheduled = datetime.fromisoformat(scheduled_iso.replace("Z", "+00:00"))
    actual = datetime.fromisoformat(actual_iso.replace("Z", "+00:00"))
    delta = actual - scheduled
    return int(delta.total_seconds() / 60)


def format_trip_report(legs: list[dict], target_datetime: datetime | None = None) -> str:
    """
    Render a trip-plan *legs* list as a Discord-markdown "Scheduled Trip Report".

    Each leg must contain the keys produced by APIService.plan_trip().
    """
    if not legs:
        return "No journey options found for the requested time."

    anchor_str = (
        target_datetime.strftime("%A %d %b %Y at %H:%M")
        if target_datetime
        else "now"
    )
    lines: list[str] = [
        f"## 🗺️ Scheduled Trip Report",
        f"**Departing:** {anchor_str}",
        "",
    ]
    total_mins = sum(leg.get("duration_min", 0) for leg in legs)

    for i, leg in enumerate(legs, 1):
        icon = _MODE_ICONS.get(leg.get("mode", ""), "🚍")
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


def format_alert_card(alerts: list[dict]) -> str:
    """
    Render a list of service alert dicts as a Discord-markdown disruption card.

    Each alert must contain the keys produced by APIService.get_service_alerts().
    """
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
) -> str:
    """Return a formatted delay alert message for Discord."""
    direction = "late" if delay_minutes > 0 else "early"
    sched = _fmt_time(scheduled_iso)
    pred = _fmt_time(predicted_iso)
    return (
        f"⚠️ **Delay Alert** — Trip `{trip_id}`\n"
        f"> Service to **{stop_name}** is **{abs(delay_minutes)} min {direction}**\n"
        f"> Scheduled: {sched}  •  Predicted: {pred}"
    )


# ── internal helpers ──────────────────────────────────────────────────────────

def _fmt_time(iso: str) -> str:
    """Return HH:MM from an ISO-8601 string, or the original string on failure."""
    if not iso:
        return "?"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%H:%M")
    except ValueError:
        return iso
