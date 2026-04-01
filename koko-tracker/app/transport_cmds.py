"""
Transport NSW Discord commands.
Registers slash commands under the /transport group.

DB tables (transport_stops, transport_routes) share the same SQLite
database as the main bot (DB_PATH env var).
"""

import asyncio
import json
import re
import sqlite3
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from zoneinfo import ZoneInfo

import discord
from discord import app_commands

from transport_nsw import (
    find_stops,
    get_departures,
    plan_trip,
    get_alerts,
    get_vehicle_position,
    format_departure_line,
    format_stop_stats,
    MODE_ICONS,
    MODE_NAMES,
    _format_mins,
    _fmt_time,
    SYDNEY_TZ,
)
from reminder_cmds import db_add_reminder, parse_reminder_time, ReminderModal

DB_PATH = os.environ.get("DB_PATH", "/data/koko.db")


# ─── DB setup ─────────────────────────────────────────────────────────────────

def transport_db_init():
    """Create transport tables if they don't exist yet."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transport_routes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id  TEXT NOT NULL,
            label       TEXT NOT NULL,
            from_id     TEXT NOT NULL,
            from_name   TEXT NOT NULL,
            to_id       TEXT NOT NULL,
            to_name     TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transport_stops (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id  TEXT NOT NULL,
            label       TEXT NOT NULL,
            stop_id     TEXT NOT NULL,
            stop_name   TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transport_tracking (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id      TEXT NOT NULL,
            channel_id      TEXT,
            guild_id        TEXT,
            vehicle_id      TEXT,
            route           TEXT NOT NULL,
            destination     TEXT NOT NULL,
            from_id         TEXT NOT NULL,
            to_id           TEXT NOT NULL,
            from_name       TEXT NOT NULL,
            to_name         TEXT NOT NULL,
            alert_stop_name TEXT NOT NULL,
            alert_stop_idx  INTEGER NOT NULL,
            stop_sequence   TEXT NOT NULL,
            scheduled_dep   TEXT NOT NULL,
            notified        INTEGER DEFAULT 0,
            active          INTEGER DEFAULT 1,
            created_at      TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


# ─── DB helpers ───────────────────────────────────────────────────────────────

def db_save_route(discord_id, label, from_id, from_name, to_id, to_name):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO transport_routes (discord_id,label,from_id,from_name,to_id,to_name) VALUES (?,?,?,?,?,?)",
        (str(discord_id), label, from_id, from_name, to_id, to_name),
    )
    conn.commit()
    row = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return row


def db_get_routes(discord_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM transport_routes WHERE discord_id=? ORDER BY created_at ASC",
        (str(discord_id),),
    ).fetchall()
    conn.close()
    return rows


def db_get_route(discord_id, route_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM transport_routes WHERE id=? AND discord_id=?",
        (route_id, str(discord_id)),
    ).fetchone()
    conn.close()
    return row


def db_delete_route(discord_id, route_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "DELETE FROM transport_routes WHERE id=? AND discord_id=?",
        (route_id, str(discord_id)),
    )
    conn.commit()
    conn.close()


def db_save_stop(discord_id, label, stop_id, stop_name):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO transport_stops (discord_id,label,stop_id,stop_name) VALUES (?,?,?,?)",
        (str(discord_id), label, stop_id, stop_name),
    )
    conn.commit()
    row = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return row


def db_get_stops(discord_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM transport_stops WHERE discord_id=? ORDER BY created_at ASC",
        (str(discord_id),),
    ).fetchall()
    conn.close()
    return rows


def db_get_stop(discord_id, stop_id_pk):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM transport_stops WHERE id=? AND discord_id=?",
        (stop_id_pk, str(discord_id)),
    ).fetchone()
    conn.close()
    return row


def db_delete_stop(discord_id, stop_id_pk):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "DELETE FROM transport_stops WHERE id=? AND discord_id=?",
        (stop_id_pk, str(discord_id)),
    )
    conn.commit()
    conn.close()


def db_rename_route(discord_id, route_id, new_label: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE transport_routes SET label=? WHERE id=? AND discord_id=?",
        (new_label, route_id, str(discord_id)),
    )
    conn.commit()
    conn.close()


def db_rename_stop(discord_id, stop_id_pk, new_label: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE transport_stops SET label=? WHERE id=? AND discord_id=?",
        (new_label, stop_id_pk, str(discord_id)),
    )
    conn.commit()
    conn.close()


def db_route_exists(discord_id, from_id: str, to_id: str) -> bool:
    """Return True if the user already has a route saved with the same from/to stop IDs."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id FROM transport_routes WHERE discord_id=? AND from_id=? AND to_id=?",
        (str(discord_id), from_id, to_id),
    ).fetchone()
    conn.close()
    return row is not None


def db_stop_exists(discord_id, stop_id: str) -> bool:
    """Return True if the user already has this stop saved."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id FROM transport_stops WHERE discord_id=? AND stop_id=?",
        (str(discord_id), stop_id),
    ).fetchone()
    conn.close()
    return row is not None


# ─── Tracking DB helpers ───────────────────────────────────────────────────────

def db_save_tracking(
    discord_id, channel_id, guild_id,
    vehicle_id, route, destination,
    from_id, to_id, from_name, to_name,
    alert_stop_name, alert_stop_idx,
    stop_sequence_json, scheduled_dep,
) -> int:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO transport_tracking
           (discord_id, channel_id, guild_id,
            vehicle_id, route, destination,
            from_id, to_id, from_name, to_name,
            alert_stop_name, alert_stop_idx,
            stop_sequence, scheduled_dep)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            str(discord_id), channel_id, guild_id,
            vehicle_id, route, destination,
            from_id, to_id, from_name, to_name,
            alert_stop_name, alert_stop_idx,
            stop_sequence_json, scheduled_dep,
        ),
    )
    conn.commit()
    row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return row_id


def db_get_active_trackings(discord_id=None):
    """Return all active tracking rows as dicts. Pass discord_id to filter by user."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if discord_id is not None:
        rows = conn.execute(
            "SELECT * FROM transport_tracking WHERE discord_id=? AND active=1 ORDER BY created_at DESC",
            (str(discord_id),),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM transport_tracking WHERE active=1 ORDER BY created_at ASC",
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def db_get_tracking(tracking_id, discord_id=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if discord_id is not None:
        row = conn.execute(
            "SELECT * FROM transport_tracking WHERE id=? AND discord_id=?",
            (tracking_id, str(discord_id)),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM transport_tracking WHERE id=?",
            (tracking_id,),
        ).fetchone()
    conn.close()
    return row


def db_deactivate_tracking(tracking_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE transport_tracking SET active=0 WHERE id=?",
        (tracking_id,),
    )
    conn.commit()
    conn.close()


def db_mark_tracking_alerted(tracking_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE transport_tracking SET notified=1 WHERE id=?",
        (tracking_id,),
    )
    conn.commit()
    conn.close()


def db_mark_dest_alerted(tracking_id):
    """Mark that the destination-arrival notification has been sent (notified=2)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE transport_tracking SET notified=2 WHERE id=?",
        (tracking_id,),
    )
    conn.commit()
    conn.close()


# ─── Shared UI helpers ─────────────────────────────────────────────────────────

TRAIN_COLOR = 0xF15A22   # TfNSW orange
ERROR_COLOR = 0xE74C3C
_VID_MAX_LEN = 20        # Max chars shown for vehicle/service IDs


def _err_embed(msg: str) -> discord.Embed:
    return discord.Embed(description=f"❌ {msg}", color=ERROR_COLOR)


def _valid_transit_legs(trip: dict) -> list[tuple[int, dict]]:
    """Return transit legs that have at least 1 stop in their stop-sequence data."""
    return [
        (i, l)
        for i, l in enumerate(trip.get("legs", []))
        if l.get("mode") != "walk" and len(l.get("stop_sequence", [])) >= 1
    ]


def _auto_alert_stop_idx(stop_seq: list[dict], dest_name: str) -> int:
    """Return the index of the best alert stop for dest_name in stop_seq.

    Picks the first stop whose name contains (or is contained by) dest_name;
    falls back to the last stop in the sequence.
    """
    idx = len(stop_seq) - 1
    dest_lower = dest_name.lower()
    for i, s in enumerate(stop_seq):
        s_lower = s["name"].lower()
        if dest_lower in s_lower or s_lower in dest_lower:
            idx = i
            break
    return idx


def _alert_keywords(from_stop: dict, to_stop: dict, trips: list[dict] | None = None) -> list[str]:
    """
    Build the keyword list used to filter service alerts to only those relevant
    to the queried route.  Includes stop names and every route/line number that
    appears in the planned trip legs.
    """
    kws: set[str] = set()
    for stop in (from_stop, to_stop):
        name = (stop.get("short_name") or stop.get("name") or "").strip()
        main = re.split(r"[,(]", name)[0].strip()
        if len(main) > 2:
            kws.add(main)
    for trip in (trips or []):
        for leg in trip.get("legs", []):
            if leg.get("mode") == "walk":
                continue
            route = (leg.get("route") or "").strip()
            if route:
                kws.add(route)
            dest = (leg.get("destination") or "").split(",")[0].strip()
            if len(dest) > 2:
                kws.add(dest)
    return list(kws)


def _stop_select_label(s: dict) -> str:
    """Build a compact Select label for a stop — max 100 chars."""
    icons = "".join(MODE_ICONS.get(m, "") for m in s["modes"]) or "🚏"
    if s["platform_hint"]:
        label = f"{icons} {s['parent_name']} — {s['platform_hint']}"
    else:
        label = f"{icons} {s['short_name']}"
        if s["suburb"] and s["suburb"] not in label:
            label += f", {s['suburb']}"
    return label[:100]


def _stop_select_description(s: dict) -> str:
    """Secondary line shown under the label in the Select menu."""
    mode_names = ", ".join(MODE_NAMES.get(m, m) for m in s["modes"]) or "Stop"
    suburb = s["suburb"] or ""
    if suburb:
        return f"{mode_names} · {suburb}"[:100]
    return mode_names[:100]


async def _pick_stop_silent(query: str) -> dict | None:
    """
    Like _pick_stop but returns the best single match without any interaction,
    or None if ambiguous/not found. Used for the natural-language /transport go
    command where we want auto-resolution without a picker dialog.
    """
    stops = await find_stops(_clean_stop_query(query), limit=5)
    if not stops:
        return None
    if len(stops) == 1:
        return stops[0]
    # Prefer exact match on short_name or parent_name
    q_lower = query.strip().lower()
    exact = [s for s in stops if s["short_name"].lower() == q_lower
             or s["parent_name"].lower() == q_lower]
    if exact:
        return exact[0]
    # Return best (first/highest matchQuality) result
    return stops[0]


async def _pick_stop(
    interaction: discord.Interaction,
    query: str,
    role: str = "origin",
) -> dict | None:
    """
    'Did you mean?' stop picker.

    - Single result or exact name match → return immediately, no prompt.
    - Multiple results → ephemeral embed + Select dropdown.

    IMPORTANT: caller must have already called interaction.response.defer()
    before calling this. All messages here use followup.send(ephemeral=True).
    Returns None on no match or timeout.
    """
    stops = await find_stops(_clean_stop_query(query), limit=8)
    if not stops:
        await interaction.followup.send(
            embed=_err_embed(
                f"No stops found matching **{query}**.\n"
                "Try the suburb name alone (e.g. *Parramatta*, *Strathfield*, *Chatswood*)."
            ),
            ephemeral=True,
        )
        return None

    # Auto-confirm: single result or exact name match
    if len(stops) == 1:
        return stops[0]
    q_lower = query.strip().lower()
    exact = [s for s in stops if s["short_name"].lower() == q_lower
             or s["parent_name"].lower() == q_lower]
    if len(exact) == 1:
        return exact[0]

    # ── Build "Did you mean?" picker ──────────────────────────────────────────
    groups: dict[str, list[dict]] = defaultdict(list)
    ungrouped = []
    for s in stops:
        if s["platform_hint"] and s["parent_name"]:
            groups[s["parent_name"]].append(s)
        else:
            ungrouped.append(s)

    lines = []
    option_list: list[dict] = []

    for station, platform_stops in groups.items():
        mode_icons = "".join(
            MODE_ICONS.get(m, "")
            for m in sorted({m for s in platform_stops for m in s["modes"]})
        ) or "🚏"
        lines.append(f"**{mode_icons} {station}**")
        for s in platform_stops:
            lines.append(f"  › {s['platform_hint']}")
            option_list.append(s)

    for s in ungrouped:
        icons = "".join(MODE_ICONS.get(m, "") for m in s["modes"]) or "🚏"
        suburb = f", {s['suburb']}" if s["suburb"] and s["suburb"] not in s["short_name"] else ""
        lines.append(f"**{icons} {s['short_name']}{suburb}**")
        option_list.append(s)

    # Safety: Discord requires at least 1 option
    if not option_list:
        return stops[0]

    embed = discord.Embed(
        title=f"Did you mean…? ({role})",
        description="\n".join(lines) or "Multiple stops found — please select one.",
        color=TRAIN_COLOR,
    )
    embed.set_footer(text="Select a stop below · times out in 30s")

    options = [
        discord.SelectOption(
            label=_stop_select_label(s),
            value=str(i),
            description=_stop_select_description(s),
        )
        for i, s in enumerate(option_list[:25])  # Discord max 25
    ]

    select = discord.ui.Select(placeholder=f"Choose {role} stop…", options=options)
    chosen: list[dict] = []

    async def on_select(select_interaction: discord.Interaction):
        chosen.append(option_list[int(select.values[0])])
        await select_interaction.response.defer()
        view.stop()

    select.callback = on_select
    view = discord.ui.View(timeout=30)
    view.add_item(select)

    picker_msg = await interaction.followup.send(embed=embed, view=view, ephemeral=True)
    await view.wait()

    if not chosen:
        # Timeout — disable the dropdown and update the picker message
        for item in view.children:
            item.disabled = True
        timeout_embed = _err_embed(f"Selection timed out for **{role}** stop.")
        try:
            await picker_msg.edit(embed=timeout_embed, view=view)
        except Exception:
            pass
        return None
    return chosen[0]


# Words that users append for context but that aren't part of a stop name.
# Strip these (case-insensitive, whole-word) from query parts before stop lookup.
_NOISE_WORDS = re.compile(
    r"\b(timezone|koko|arcade|casino|shopping\s+centre|shopping\s+center|"
    r"shopping|mall|westfield|centre|center|plaza|square|park|reserve|"
    r"hospital|university|uni|tafe|school|college|hotel|station|"
    r"bus|train|ferry|tram|metro|coach|light\s+rail)\b\s*$",
    re.IGNORECASE,
)


def _clean_stop_query(q: str) -> str:
    """Strip trailing noise words that aren't part of a stop name."""
    cleaned = _NOISE_WORDS.sub("", q).strip()
    return cleaned if cleaned else q  # don't return empty string


async def _stop_autocomplete(
    interaction: discord.Interaction,
    current: str,
) -> list[app_commands.Choice[str]]:
    """
    Autocomplete callback for stop-name parameters.
    Returns up to 8 matching stops as Discord choices.
    """
    if len(current) < 2:
        return []
    try:
        stops = await find_stops(_clean_stop_query(current), limit=8)
        return [
            app_commands.Choice(
                name=s["name"][:100],
                value=s["short_name"][:100],
            )
            for s in stops
        ]
    except Exception:
        return []


# ─── Time parser ──────────────────────────────────────────────────────────────

# Matches: "4pm", "4:30pm", "4:30 pm", "at 4pm", "@16:00", "at 16:00"
# Requires am/pm OR two-digit 24h hour (HH:MM).
_TIME_RE = re.compile(
    r"""
    \b(?:(?:at|@)\s*)?          # optional "at " / "@" prefix
    (?:
        (\d{1,2}):(\d{2})        # HH:MM  (group 1=hour, 2=min)
        \s*(am|pm)?              # optional am/pm
      |
        (\d{1,2})                # H or HH  (group 4=hour)
        \s*(am|pm)               # am/pm required when no colon (group 5)
    )
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _parse_time_from_query(text: str) -> tuple[str, "datetime | None"]:
    """
    Extract a departure time from a natural-language query string.

    Handles: "4pm", "4:30pm", "16:00", "at 4pm", "@9:30am", "at 16:30"
    The matched time fragment is stripped from the text.

    Returns (cleaned_text, sydney_datetime | None).
    Midnight-next-day rollover: if the parsed time has already passed by more
    than 5 minutes it is treated as the same time tomorrow.
    """
    m = _TIME_RE.search(text)
    if not m:
        return text, None

    if m.group(1) is not None:
        # HH:MM form
        hour, minute = int(m.group(1)), int(m.group(2))
        meridiem = (m.group(3) or "").lower()
    else:
        # H am/pm form
        hour, minute = int(m.group(4)), 0
        meridiem = (m.group(5) or "").lower()

    if meridiem == "pm" and hour < 12:
        hour += 12
    elif meridiem == "am" and hour == 12:
        hour = 0

    if hour > 23 or minute > 59:
        return text, None

    now_syd = datetime.now(SYDNEY_TZ)
    try:
        dep_time = now_syd.replace(hour=hour, minute=minute, second=0, microsecond=0)
    except ValueError:
        return text, None

    # If more than 5 minutes in the past, assume tomorrow
    if (dep_time - now_syd).total_seconds() < -300:
        dep_time += timedelta(days=1)

    # Strip the matched segment (and any surrounding whitespace / stray "at")
    cleaned = (text[: m.start()] + text[m.end() :]).strip()
    cleaned = re.sub(r"^\s*(?:at|@)\s+", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"\s+(?:at|@)\s*$", "", cleaned, flags=re.IGNORECASE).strip()
    if not cleaned:
        cleaned = text  # Safety: don't return empty

    return cleaned, dep_time


def _fmt_at_time(at_time: "datetime | None") -> str:
    """Return a short human label for an at_time, e.g. '(from 4:00 PM)'."""
    if not at_time:
        return ""
    return f" (from {at_time.astimezone(SYDNEY_TZ).strftime('%-I:%M %p')})"


# ─── Route-number prefix parser ───────────────────────────────────────────────
# Matches a Sydney transport line/route code at the very start of the query:
#   T1-T9, M1-M4, L1-L3, F1-F9, B1/B2, X-routes, NX routes, numeric bus routes
# Examples: "t1 central to strathfield" → ("central to strathfield", "T1")
#           "410 rhodes to macquarie park" → ("rhodes to macquarie park", "410")
_ROUTE_RE = re.compile(
    r"""
    ^
    (
        [A-Za-z]{1,3}\d{1,3}   # T1, M2, NX1, X85, B1, L1, F3
      | \d{2,4}[A-Za-z]{0,2}   # 410, 333, 700, 70X, 10X
    )
    \s+                         # must be followed by whitespace
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _parse_route_from_query(text: str) -> tuple[str, "str | None"]:
    """
    Strip an optional route/line number from the start of the query.

    Returns ``(cleaned_text, route_code)`` where ``route_code`` is upper-cased
    (e.g. ``"T1"``, ``"410"``) or ``None`` if no prefix was found.
    """
    m = _ROUTE_RE.match(text.strip())
    if m:
        route = m.group(1).upper()
        rest = text[m.end():].strip()
        # Sanity-check: there must still be something left for stop parsing
        if rest:
            return rest, route
    return text, None


def _filter_trips_by_route(trips: list, route: "str | None") -> list:
    """
    Return the subset of ``trips`` whose first transit leg matches ``route``.
    Falls back to the full list if nothing matches (so callers always get trips).
    """
    if not route or not trips:
        return trips
    matched = [
        t for t in trips
        if any(
            l.get("route", "").upper() == route
            for l in t.get("legs", [])
            if l.get("mode") != "walk"
        )
    ]
    return matched if matched else trips


# ─── Natural-language query parser ────────────────────────────────────────────

def _parse_go_query(text: str) -> tuple[str, str] | None:
    """
    Parse a natural-language trip query into (from_query, to_query).

    Handles:
      "rhodes to strathfield"
      "from rhodes to central"     → strips leading "from "
      "rhodes → central"
      "rhodes bus A to top ryde"   → from="rhodes bus A", to="top ryde"
      "central station to parramatta"

    Returns (from_part, to_part) or None if no separator found.
    """
    # Normalise arrows and various separators to " to "
    text = text.strip()
    # Strip a leading "from " if present so "from rhodes to central" works
    text = re.sub(r"^from\s+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*[-–—→=>]+\s*", " to ", text, flags=re.IGNORECASE)
    # Now split on " to " (case-insensitive, surrounded by word chars)
    # Use the LAST occurrence of " to " as the split point if multiple exist
    # (e.g. "top ryde to central" — "top" shouldn't split)
    pattern = re.compile(r"\bto\b", re.IGNORECASE)
    matches = list(pattern.finditer(text))
    if not matches:
        return None

    # Try each match from last to first; use the first one that yields
    # non-empty from/to parts
    for m in reversed(matches):
        from_part = text[:m.start()].strip()
        to_part = text[m.end():].strip()
        if from_part and to_part:
            return from_part, to_part

    return None


# ─── Trip result embed builder ────────────────────────────────────────────────

def _trip_summary_line(trip: dict, index: int) -> str:
    """One-line summary for a trip option — used in the compact list."""
    dep = trip["departs"]
    arr = trip["arrives"]
    mins = trip["mins_until"]
    dur = trip["duration_mins"]
    dep_str = _fmt_time(dep) if dep else "?"
    arr_str = _fmt_time(arr) if arr else "?"
    mins_str = _format_mins(mins) if mins is not None else "?"

    # Build compact leg icons: 🚆T9 → 🚌370
    leg_parts = []
    for leg in trip["legs"]:
        if leg["mode"] == "walk":
            leg_parts.append("🚶")
        else:
            leg_parts.append(f"{leg['icon']}**{leg.get('route','')}**")
    legs_str = " → ".join(leg_parts)

    changes = trip["num_legs"] - 1
    change_str = f"· {changes} change{'s' if changes != 1 else ''}" if changes > 0 else "· direct"
    rt = " 🔴" if trip.get("is_realtime") else ""

    return f"`{index}.` {legs_str}  —  **{dep_str}** ({mins_str}) → **{arr_str}** · {dur}m {change_str}{rt}"


def _trip_detail_field(trip: dict) -> str:
    """
    Expanded leg-by-leg detail for a single selected trip.
    For multi-leg trips, shows a transfer line between legs:
      ↳ Change at <stop> — catch <icon><route> at <time>
    """
    lines = []
    legs = trip["legs"]
    for i, leg in enumerate(legs):
        if leg["mode"] == "walk":
            lines.append(f"🚶 *{leg['summary']}*")
        else:
            dep_t = leg.get("departs")
            dep_t_str = _fmt_time(dep_t) if dep_t else ""
            from_n = leg.get("from", "")
            to_n = leg.get("to", "")
            route = leg.get("route", "")
            dest = leg.get("destination", "")
            icon = leg["icon"]

            # Build "from" with optional platform and suburb
            platform_from = leg.get("platform_from", "")
            suburb_from = leg.get("suburb_from", "")
            from_parts = [from_n]
            if platform_from:
                from_parts.append(platform_from)
            if suburb_from and suburb_from not in from_n:
                from_parts.append(suburb_from)
            from_detail = ", ".join(from_parts)

            # Build "arrives" with optional platform and suburb
            platform_to = leg.get("platform_to", "")
            suburb_to = leg.get("suburb_to", "")
            to_parts = [to_n]
            if platform_to:
                to_parts.append(platform_to)
            if suburb_to and suburb_to not in to_n:
                to_parts.append(suburb_to)
            to_detail = ", ".join(to_parts)

            # Board line
            board_line = f"{icon} **{route}**"
            if dest:
                board_line += f" towards {dest}"
            if dep_t_str:
                board_line += f" — departs **{dep_t_str}**"
            board_line += f"\n\u3000from **{from_detail}**"
            lines.append(board_line)

            # Transfer hint to next transit leg
            next_transit = [l for l in legs[i + 1:] if l["mode"] != "walk"]
            if next_transit:
                nl = next_transit[0]
                nl_dep = nl.get("departs")
                nl_dep_str = _fmt_time(nl_dep) if nl_dep else ""
                nl_from = nl.get("from", "")
                nl_icon = nl["icon"]
                nl_route = nl.get("route", "")
                transfer = f"\u3000\u2192 arrives **{to_detail}**"
                transfer += f"\n\u3000🔀 catch {nl_icon} **{nl_route}**"
                if nl_dep_str:
                    transfer += f" at **{nl_dep_str}**"
                if nl_from and nl_from != to_n:
                    transfer += f" from **{nl_from}**"
                lines.append(transfer)
            else:
                lines.append(f"\u3000\u2192 arrives **{to_detail}**")

            # Live position indicator — only shown when the vehicle has
            # departed at least one stop (i.e. the trip is currently in progress)
            current_stop = leg.get("current_stop")
            if current_stop:
                leg_arrives = leg.get("arrives")
                if leg_arrives:
                    now_utc = datetime.now(timezone.utc)
                    eta_mins = max(0, int(
                        (leg_arrives.astimezone(timezone.utc) - now_utc).total_seconds() / 60
                    ))
                    lines.append(
                        f"\u3000📍 Currently at **{current_stop}** · ETA {eta_mins}m"
                    )
                else:
                    lines.append(f"\u3000📍 Currently at **{current_stop}**")

    return "\n".join(lines)


def _build_alerts_fields(alerts: list[dict]) -> list[tuple[str, str]]:
    """Convert alert list to (name, value) tuples for embed fields."""
    fields = []
    for a in alerts:
        icon = "🚨" if a["is_replacement"] else ("⚠️" if a["priority"] in ("high", "veryHigh") else "ℹ️")
        title = f"{icon} {a['title']}"[:256]
        body = a["body"][:300] if a["body"] else ""
        url = a["url"]
        value = body
        if url:
            value = (value + f"\n[More info]({url})").strip()
        if not value:
            value = "\u200b"  # zero-width space — Discord requires non-empty field value
        fields.append((title, value[:1024]))
    return fields


def _build_trip_overview_embed(
    trips: list[dict],
    from_stop: dict,
    to_stop: dict,
    alerts: list[dict],
) -> discord.Embed:
    """
    Compact overview embed: one line per trip option, sorted by departure time.
    Alerts shown at bottom. User selects an option to expand detail.
    """
    embed = discord.Embed(
        title=f"🚆 {from_stop['short_name']} → {to_stop['short_name']}",
        color=TRAIN_COLOR,
    )

    lines = [_trip_summary_line(t, i) for i, t in enumerate(trips, 1)]
    embed.description = "\n".join(lines)

    embed.set_footer(text="Select an option below for details · 🔴 = real-time")
    return embed


# ─── Command registration ──────────────────────────────────────────────────────

def register_transport_commands(tree: app_commands.CommandTree):
    """Call this with the bot's command tree to register all transport commands."""

    transport_group = app_commands.Group(
        name="transport",
        description="NSW Transport — check trains, buses, ferries",
    )

    # ── /transport go  (natural-language shortcut) ────────────────────────────

    @transport_group.command(
        name="go",
        description='Natural-language trip planner: "rhodes to central" or "from central to parramatta"',
    )
    @app_commands.describe(
        query='Trip query — e.g. "rhodes to central", "t1 central to strathfield", "4pm rhodes to central"'
    )
    @app_commands.autocomplete(query=_stop_autocomplete)
    async def cmd_go(interaction: discord.Interaction, query: str):
        await interaction.response.defer(ephemeral=False)

        # Extract optional departure time and route prefix, then parse origin/destination
        cleaned_query, at_time = _parse_time_from_query(query)
        cleaned_query, route_filter = _parse_route_from_query(cleaned_query)
        parsed = _parse_go_query(cleaned_query)
        if not parsed:
            await interaction.followup.send(
                embed=_err_embed(
                    f'Could not parse **"{query}"**.\n'
                    'Use the format `origin to destination`, e.g. `rhodes to central`, '
                    '`t1 central to strathfield`, or `4pm rhodes to central`.'
                ),
                ephemeral=True,
            )
            return

        from_query, to_query = parsed

        try:
            from_result = await _pick_stop_silent(from_query)
            to_result = await _pick_stop_silent(to_query)

            if not from_result:
                from_result = await _pick_stop(interaction, from_query, "origin")
                if not from_result:
                    return
            if not to_result:
                to_result = await _pick_stop(interaction, to_query, "destination")
                if not to_result:
                    return

            trips = await plan_trip(from_result["id"], to_result["id"], limit=10, at_time=at_time)
            trips = _filter_trips_by_route(trips, route_filter)
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        if not trips:
            route_note = f" on **{route_filter}**" if route_filter else ""
            await interaction.followup.send(
                embed=_err_embed(
                    f"No trips found from **{from_result['short_name']}** to **{to_result['short_name']}**"
                    f"{route_note}{_fmt_at_time(at_time)}.\n"
                    f"Resolved: `{from_result['name']}` → `{to_result['name']}`"
                ),
                ephemeral=True,
            )
            return

        embed = _build_trip_overview_embed(trips, from_result, to_result, [])
        if at_time:
            embed.set_footer(
                text=f"Trips from {_fmt_time(at_time)} · Select an option below for details · 🔴 = real-time"
            )
        view = _TripSelectorView(
            interaction.user.id, trips, from_result, to_result, []
        )
        msg = await interaction.followup.send(embed=embed, view=view)
        view.message = msg

    # ── /transport train ──────────────────────────────────────────────────────

    @transport_group.command(name="train", description="Plan a trip between two stations/stops")
    @app_commands.describe(
        from_stop="Origin station or stop name (e.g. Central, Strathfield)",
        to_stop="Destination station or stop name (e.g. Rhodes, Parramatta)",
        time='Optional departure time, e.g. "4pm", "16:30", "9:30am"',
    )
    @app_commands.autocomplete(from_stop=_stop_autocomplete, to_stop=_stop_autocomplete)
    async def cmd_train(
        interaction: discord.Interaction,
        from_stop: str,
        to_stop: str,
        time: str = "",
    ):
        await interaction.response.defer(ephemeral=False)

        _, at_time = _parse_time_from_query(time) if time.strip() else (time, None)

        try:
            from_result = await _pick_stop(interaction, from_stop, "origin")
            if not from_result:
                return
            to_result = await _pick_stop(interaction, to_stop, "destination")
            if not to_result:
                return
            trips = await plan_trip(from_result["id"], to_result["id"], limit=5, at_time=at_time)
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        if not trips:
            await interaction.followup.send(
                embed=_err_embed(
                    f"No trips found from **{from_result['name']}** to **{to_result['name']}**"
                    f"{_fmt_at_time(at_time)}."
                ),
                ephemeral=True,
            )
            return

        embed = _build_trip_overview_embed(trips, from_result, to_result, [])
        if at_time:
            embed.set_footer(
                text=f"Trips from {_fmt_time(at_time)} · Select an option below for details · 🔴 = real-time"
            )
        view = _TripSelectorView(
            interaction.user.id, trips, from_result, to_result, []
        )
        msg = await interaction.followup.send(embed=embed, view=view)
        view.message = msg

    # ── /transport departures ─────────────────────────────────────────────────

    @transport_group.command(name="departures", description="Show upcoming departures from a stop")
    @app_commands.describe(
        stop="Stop or station name (e.g. Central, Chatswood)",
        mode="Filter by transport mode (optional)",
        time='Show departures from a specific time, e.g. "4pm", "16:30"',
    )
    @app_commands.choices(mode=[
        app_commands.Choice(name="All", value="all"),
        app_commands.Choice(name="🚆 Train", value="1"),
        app_commands.Choice(name="🚇 Metro", value="2"),
        app_commands.Choice(name="🚌 Bus", value="5"),
        app_commands.Choice(name="⛴️ Ferry", value="9"),
        app_commands.Choice(name="🚃 Light Rail", value="4"),
    ])
    @app_commands.autocomplete(stop=_stop_autocomplete)
    async def cmd_departures(
        interaction: discord.Interaction,
        stop: str,
        mode: str = "all",
        time: str = "",
    ):
        await interaction.response.defer(ephemeral=False)

        _, at_time = _parse_time_from_query(time) if time.strip() else (time, None)

        try:
            stop_result = await _pick_stop(interaction, stop, "stop")
            if not stop_result:
                return
            mode_filter = None if mode == "all" else mode
            deps = await get_departures(
                stop_result["id"], limit=8, mode_filter=mode_filter, at_time=at_time
            )
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        if not deps:
            mode_label = MODE_NAMES.get(mode, mode) if mode != "all" else ""
            time_note = f" from **{_fmt_time(at_time)}**" if at_time else ""
            no_deps_msg = (
                f"No upcoming {mode_label + ' ' if mode_label else ''}departures"
                f" from **{stop_result['short_name']}**{time_note}."
            )
            await interaction.followup.send(embed=_err_embed(no_deps_msg), ephemeral=True)
            return

        dep_window_str = _fmt_time(at_time) if at_time else datetime.now(SYDNEY_TZ).strftime("%H:%M")
        mode_label = "All modes" if mode == "all" else MODE_NAMES.get(mode, mode)
        embed = discord.Embed(
            title=f"🚏 {stop_result['short_name']}",
            description=f"Departures from **{dep_window_str}** · {mode_label}",
            color=TRAIN_COLOR,
        )
        lines = [format_departure_line(dep, i) for i, dep in enumerate(deps, 1)]
        embed.description += "\n\n" + "\n".join(lines)
        stats = format_stop_stats(deps)
        embed.set_footer(text=f"🔴 = real-time · ⚠️ = delayed{' · ' + stats if stats else ''}")

        view = _SaveStopView(
            interaction.user.id, stop_result["id"], stop_result["name"], mode_filter, deps
        )
        msg = await interaction.followup.send(embed=embed, view=view)
        view.message = msg

    # ── /transport next ───────────────────────────────────────────────────────

    @transport_group.command(name="next", description="Next departure from your saved station or route")
    @app_commands.describe(name='Saved trip/stop name or slot number — e.g. "morning commute" or "1"')
    async def cmd_next(interaction: discord.Interaction, name: str = "1"):
        await interaction.response.defer(ephemeral=False)

        routes = await asyncio.to_thread(db_get_routes, interaction.user.id)
        stops = await asyncio.to_thread(db_get_stops, interaction.user.id)

        all_items = list(routes) + list(stops)
        if not all_items:
            await interaction.followup.send(
                embed=discord.Embed(
                    description=(
                        "You have no saved trips or stops yet.\n\n"
                        "Use `/transport train` or `/transport departures` "
                        "and press **Save** to add one."
                    ),
                    color=TRAIN_COLOR,
                ),
                ephemeral=True,
            )
            return

        query = name.strip()
        slot_display = query

        if query.isdigit():
            idx = int(query) - 1
            if not (0 <= idx < len(all_items)):
                await interaction.followup.send(
                    embed=_err_embed(
                        f"Slot {query} doesn't exist. You have {len(all_items)} saved item(s)."
                    ),
                    ephemeral=True,
                )
                return
            item = all_items[idx]
        else:
            q_lower = query.lower()
            matches = [it for it in all_items if q_lower in it["label"].lower()]
            if not matches:
                labels = ", ".join(f"**{it['label']}**" for it in all_items)
                await interaction.followup.send(
                    embed=_err_embed(
                        f'No saved trip/stop matching "{query}".\n\nYour saved items: {labels}'
                    ),
                    ephemeral=True,
                )
                return
            item = matches[0]
            slot_display = item["label"]

        try:
            if "from_id" in item:
                from_stop = {"short_name": item["from_name"], "id": item["from_id"]}
                to_stop = {"short_name": item["to_name"], "id": item["to_id"]}
                trips = await plan_trip(item["from_id"], item["to_id"], limit=5)
                if not trips:
                    await interaction.followup.send(
                        embed=_err_embed(f"No trips found for **{item['label']}**."),
                        ephemeral=True,
                    )
                    return
                embed = _build_trip_overview_embed(trips, from_stop, to_stop, [])
                embed.title = f"🚆 {item['label']}"
                embed.set_footer(text=f"🔴 = real-time · {slot_display}")
                view = _TripSelectorView(
                    interaction.user.id, trips, from_stop, to_stop, []
                )
                msg = await interaction.followup.send(embed=embed, view=view)
                view.message = msg
                return
            else:
                deps = await get_departures(item["stop_id"], limit=6)
                if not deps:
                    await interaction.followup.send(
                        embed=_err_embed(f"No departures from **{item['label']}**."),
                        ephemeral=True,
                    )
                    return
                now_str = datetime.now(SYDNEY_TZ).strftime("%H:%M")
                embed = discord.Embed(
                    title=f"🚏 {item['label']}",
                    description=f"Departures as of **{now_str}**",
                    color=TRAIN_COLOR,
                )
                lines = [format_departure_line(dep, i) for i, dep in enumerate(deps, 1)]
                embed.description += "\n\n" + "\n".join(lines)
                stats = format_stop_stats(deps)
                embed.set_footer(
                    text=f"🔴 = real-time · {slot_display}{' · ' + stats if stats else ''}"
                )
                view = _SaveStopView(
                    interaction.user.id, item["stop_id"], item["stop_name"], None, deps
                )
                msg = await interaction.followup.send(embed=embed, view=view)
                view.message = msg
                return

        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

    # ── /transport find-stop ──────────────────────────────────────────────────

    @transport_group.command(name="find-stop", description="Search for a stop/station ID by name")
    @app_commands.describe(query="Stop or station name to search for")
    @app_commands.autocomplete(query=_stop_autocomplete)
    async def cmd_find_stop(interaction: discord.Interaction, query: str):
        await interaction.response.defer(ephemeral=True)

        try:
            stops = await find_stops(query, limit=8)
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        if not stops:
            await interaction.followup.send(
                embed=_err_embed(f"No stops found for **{query}**."), ephemeral=True
            )
            return

        embed = discord.Embed(
            title=f'\U0001f50d Stop search: "{query}"',
            color=TRAIN_COLOR,
        )
        for s in stops:
            modes = ", ".join(MODE_NAMES.get(m, m) for m in s["modes"]) or "Unknown"
            embed.add_field(
                name=s["name"],
                value=f"ID: `{s['id']}` · {modes}",
                inline=False,
            )
        embed.set_footer(text="Use these IDs with /transport departures or /transport train")
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── /transport my-trips ───────────────────────────────────────────────────

    @transport_group.command(name="my-trips", description="View your saved trips and stations")
    async def cmd_my_trips(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)

        routes = await asyncio.to_thread(db_get_routes, interaction.user.id)
        stops = await asyncio.to_thread(db_get_stops, interaction.user.id)

        if not routes and not stops:
            await interaction.followup.send(
                embed=discord.Embed(
                    description=(
                        "You have no saved trips or stops yet.\n\n"
                        "Use `/transport train` or `/transport departures` "
                        "then press **Save** to add one."
                    ),
                    color=TRAIN_COLOR,
                ),
                ephemeral=True,
            )
            return

        embed = discord.Embed(title="🗺️ Your saved trips & stops", color=TRAIN_COLOR)
        slot = 1

        for r in routes:
            embed.add_field(
                name=f"Slot {slot} · 🚆 {r['label']}",
                value=(
                    f"{r['from_name']} → {r['to_name']}\n"
                    f"`/transport next {slot}`  or  `/transport next {r['label']}`"
                ),
                inline=False,
            )
            slot += 1

        for s in stops:
            embed.add_field(
                name=f"Slot {slot} · 🚏 {s['label']}",
                value=(
                    f"Stop: {s['stop_name']}\n"
                    f"`/transport next {slot}`  or  `/transport next {s['label']}`"
                ),
                inline=False,
            )
            slot += 1

        embed.set_footer(text="/transport delete-trip or /transport delete-stop to remove · /transport rename to rename")
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── /transport save-trip ──────────────────────────────────────────────────

    @transport_group.command(
        name="save-trip",
        description="Save a route by stop IDs (use /transport find-stop to get IDs)",
    )
    @app_commands.describe(
        label="Nickname for this trip (e.g. Morning Commute)",
        from_id="Origin stop ID",
        from_name="Origin stop name",
        to_id="Destination stop ID",
        to_name="Destination stop name",
    )
    async def cmd_save_trip(
        interaction: discord.Interaction,
        label: str,
        from_id: str,
        from_name: str,
        to_id: str,
        to_name: str,
    ):
        await interaction.response.defer(ephemeral=True)
        already = await asyncio.to_thread(db_route_exists, interaction.user.id, from_id, to_id)
        if already:
            await interaction.followup.send(
                embed=_err_embed(
                    f"You already have a saved route from **{from_name}** to **{to_name}**.\n"
                    "Use `/transport my-trips` to view it."
                ),
                ephemeral=True,
            )
            return
        row_id = await asyncio.to_thread(
            db_save_route, interaction.user.id, label, from_id, from_name, to_id, to_name
        )
        routes = await asyncio.to_thread(db_get_routes, interaction.user.id)
        slot = next((i + 1 for i, r in enumerate(routes) if r["id"] == row_id), "?")
        await interaction.followup.send(
            embed=discord.Embed(
                description=(
                    f"✅ Saved **{label}** ({from_name} → {to_name}) as slot **{slot}**.\n"
                    f"Use `/transport next {slot}` to check it quickly."
                ),
                color=TRAIN_COLOR,
            ),
            ephemeral=True,
        )

    # ── /transport save-stop ──────────────────────────────────────────────────

    @transport_group.command(
        name="save-stop",
        description="Save a stop/station by ID (use /transport find-stop to get IDs)",
    )
    @app_commands.describe(
        label="Nickname for this stop (e.g. Home Station)",
        stop_id="Stop ID from /transport find-stop",
        stop_name="Stop name",
    )
    async def cmd_save_stop(
        interaction: discord.Interaction,
        label: str,
        stop_id: str,
        stop_name: str,
    ):
        await interaction.response.defer(ephemeral=True)
        already = await asyncio.to_thread(db_stop_exists, interaction.user.id, stop_id)
        if already:
            await interaction.followup.send(
                embed=_err_embed(
                    f"You already have **{stop_name}** saved.\n"
                    "Use `/transport my-trips` to view it."
                ),
                ephemeral=True,
            )
            return
        row_id = await asyncio.to_thread(
            db_save_stop, interaction.user.id, label, stop_id, stop_name
        )
        routes = await asyncio.to_thread(db_get_routes, interaction.user.id)
        stops = await asyncio.to_thread(db_get_stops, interaction.user.id)
        slot = len(routes) + next((i + 1 for i, s in enumerate(stops) if s["id"] == row_id), 1)
        await interaction.followup.send(
            embed=discord.Embed(
                description=(
                    f"✅ Saved **{label}** ({stop_name}) as slot **{slot}**.\n"
                    f"Use `/transport next {slot}` to check departures."
                ),
                color=TRAIN_COLOR,
            ),
            ephemeral=True,
        )

    # ── /transport delete-trip ────────────────────────────────────────────────

    @transport_group.command(name="delete-trip", description="Remove a saved route by its ID")
    @app_commands.describe(route_id="Route ID shown in /transport my-trips")
    async def cmd_delete_trip(interaction: discord.Interaction, route_id: int):
        await interaction.response.defer(ephemeral=True)
        row = await asyncio.to_thread(db_get_route, interaction.user.id, route_id)
        if not row:
            await interaction.followup.send(
                embed=_err_embed(f"No saved route with ID {route_id} found."), ephemeral=True
            )
            return
        await asyncio.to_thread(db_delete_route, interaction.user.id, route_id)
        await interaction.followup.send(
            embed=discord.Embed(
                description=f"🗑️ Removed **{row['label']}**.", color=TRAIN_COLOR
            ),
            ephemeral=True,
        )

    # ── /transport delete-stop ────────────────────────────────────────────────

    @transport_group.command(name="delete-stop", description="Remove a saved stop by its ID")
    @app_commands.describe(stop_id="Stop ID shown in /transport my-trips")
    async def cmd_delete_stop(interaction: discord.Interaction, stop_id: int):
        await interaction.response.defer(ephemeral=True)
        row = await asyncio.to_thread(db_get_stop, interaction.user.id, stop_id)
        if not row:
            await interaction.followup.send(
                embed=_err_embed(f"No saved stop with ID {stop_id} found."), ephemeral=True
            )
            return
        await asyncio.to_thread(db_delete_stop, interaction.user.id, stop_id)
        await interaction.followup.send(
            embed=discord.Embed(
                description=f"🗑️ Removed **{row['label']}**.", color=TRAIN_COLOR
            ),
            ephemeral=True,
        )

    # ── /transport status ─────────────────────────────────────────────────────

    @transport_group.command(
        name="status",
        description="Check current service notices for a specific line or route",
    )
    @app_commands.describe(line='Line or route identifier, e.g. "T9", "370", "F1", "L2"')
    async def cmd_status(interaction: discord.Interaction, line: str):
        await interaction.response.defer(ephemeral=False)
        line = line.strip()
        try:
            alerts = await get_alerts([line])
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        now_str = datetime.now(SYDNEY_TZ).strftime("%H:%M")
        embed = discord.Embed(
            title=f"🚦 Service Status — {line.upper()}",
            color=TRAIN_COLOR,
        )
        if not alerts:
            embed.description = (
                f"✅ No current service notices for **{line.upper()}**.\n"
                "Service appears to be running normally."
            )
        else:
            for name, value in _build_alerts_fields(alerts):
                embed.add_field(name=name, value=value, inline=False)
        embed.set_footer(text=f"Checked at {now_str} · Data from Transport for NSW")
        await interaction.followup.send(embed=embed)

    # ── /transport rename ─────────────────────────────────────────────────────

    @transport_group.command(
        name="rename",
        description="Rename a saved trip or stop",
    )
    @app_commands.describe(
        slot="Slot number or current label of the saved item (from /transport my-trips)",
        new_label="New name for this item",
    )
    async def cmd_rename(interaction: discord.Interaction, slot: str, new_label: str):
        await interaction.response.defer(ephemeral=True)

        new_label = new_label.strip()
        if not new_label:
            await interaction.followup.send(
                embed=_err_embed("New label cannot be empty."), ephemeral=True
            )
            return

        routes = await asyncio.to_thread(db_get_routes, interaction.user.id)
        stops = await asyncio.to_thread(db_get_stops, interaction.user.id)
        all_items = list(routes) + list(stops)

        if not all_items:
            await interaction.followup.send(
                embed=_err_embed("You have no saved trips or stops to rename."),
                ephemeral=True,
            )
            return

        query = slot.strip()
        if query.isdigit():
            idx = int(query) - 1
            if not (0 <= idx < len(all_items)):
                await interaction.followup.send(
                    embed=_err_embed(
                        f"Slot {query} doesn't exist. You have {len(all_items)} saved item(s)."
                    ),
                    ephemeral=True,
                )
                return
            item = all_items[idx]
        else:
            q_lower = query.lower()
            matches = [it for it in all_items if q_lower in it["label"].lower()]
            if not matches:
                labels = ", ".join(f"**{it['label']}**" for it in all_items)
                await interaction.followup.send(
                    embed=_err_embed(
                        f'No saved item matching "{query}".\n\nYour saved items: {labels}'
                    ),
                    ephemeral=True,
                )
                return
            item = matches[0]

        old_label = item["label"]
        is_route = "from_id" in item
        if is_route:
            await asyncio.to_thread(db_rename_route, interaction.user.id, item["id"], new_label)
        else:
            await asyncio.to_thread(db_rename_stop, interaction.user.id, item["id"], new_label)

        await interaction.followup.send(
            embed=discord.Embed(
                description=f"✏️ Renamed **{old_label}** → **{new_label}**.",
                color=TRAIN_COLOR,
            ),
            ephemeral=True,
        )

    # ── /transport track  (quick one-shot tracking) ──────────────────────────

    @transport_group.command(
        name="track",
        description='Instantly track the next trip: "central to parramatta" or "4pm central to parramatta"',
    )
    @app_commands.describe(
        query='Trip to track — e.g. "central to parramatta", "t1 central to strathfield", "4pm rhodes to central"'
    )
    @app_commands.autocomplete(query=_stop_autocomplete)
    async def cmd_track(interaction: discord.Interaction, query: str):
        await interaction.response.defer(ephemeral=True)

        # Extract optional time and route prefix, then parse origin → destination
        cleaned_query, at_time = _parse_time_from_query(query)
        cleaned_query, route_filter = _parse_route_from_query(cleaned_query)
        parsed = _parse_go_query(cleaned_query)
        if not parsed:
            await interaction.followup.send(
                embed=_err_embed(
                    f'Could not parse **"{query}"**.\n'
                    'Use the format `origin to destination`, e.g. `central to parramatta`, '
                    '`t1 central to strathfield`, or `4pm rhodes to central`.'
                ),
                ephemeral=True,
            )
            return

        from_query, to_query = parsed

        try:
            from_result = await _pick_stop_silent(from_query)
            to_result = await _pick_stop_silent(to_query)

            if not from_result:
                from_result = await _pick_stop(interaction, from_query, "origin")
                if not from_result:
                    return
            if not to_result:
                to_result = await _pick_stop(interaction, to_query, "destination")
                if not to_result:
                    return

            trips = await plan_trip(from_result["id"], to_result["id"], limit=10, at_time=at_time)
            trips = _filter_trips_by_route(trips, route_filter)
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        if not trips:
            time_note = _fmt_at_time(at_time)
            await interaction.followup.send(
                embed=_err_embed(
                    f"No trips found from **{from_result['short_name']}** to "
                    f"**{to_result['short_name']}**{time_note}."
                ),
                ephemeral=True,
            )
            return

        # Auto-select the first (soonest) trip
        trip = trips[0]
        valid_legs = _valid_transit_legs(trip)
        if not valid_legs:
            # Check if any transit legs exist at all
            any_transit = any(l.get("mode") != "walk" for l in trip.get("legs", []))
            if not any_transit:
                await interaction.followup.send(
                    embed=_err_embed("No trackable legs found in the first trip option."),
                    ephemeral=True,
                )
            else:
                await interaction.followup.send(
                    embed=_err_embed(
                        "No real-time stop data available to set up tracking.\n"
                        "Try again when the trip shows a 🔴 real-time indicator."
                    ),
                    ephemeral=True,
                )
            return

        dep_str = _fmt_time(trip["departs"]) if trip.get("departs") else "?"
        arr_str = _fmt_time(trip["arrives"]) if trip.get("arrives") else "?"
        time_label = _fmt_at_time(at_time)

        tracking_ids: list[int] = []
        leg_summaries: list[str] = []
        leg_alert_names: list[str] = []
        skipped_legs: int = 0

        for leg_i, (_, leg) in enumerate(valid_legs):
            stop_seq = leg.get("stop_sequence", [])
            dest_name = to_result["short_name"]
            alert_stop_idx = _auto_alert_stop_idx(stop_seq, dest_name)
            alert_stop_name = stop_seq[alert_stop_idx]["name"]

            planned_dep = leg.get("departs")
            scheduled_dep = planned_dep.isoformat() if planned_dep else ""

            stop_seq_json = json.dumps([
                {
                    "name": s["name"],
                    "departure": s["departure"].isoformat() if s.get("departure") else None,
                }
                for s in stop_seq
            ])

            # Use the leg's own boarding stop ID for subsequent legs so
            # get_vehicle_position can re-plan from the correct origin.
            if leg_i == 0:
                leg_from_id = from_result["id"]
                leg_from_name = from_result["short_name"]
            else:
                leg_from_id = leg.get("from_id", "")
                leg_from_name = leg.get("from", from_result["short_name"])
                if not leg_from_id:
                    skipped_legs += 1
                    continue  # skip if no stop ID available for this leg

            tid = await asyncio.to_thread(
                db_save_tracking,
                str(interaction.user.id),
                str(interaction.channel_id) if interaction.channel_id else None,
                str(interaction.guild_id) if interaction.guild_id else None,
                leg.get("vehicle_id", ""),
                leg.get("route", "?"),
                leg.get("destination", "?"),
                leg_from_id,
                to_result["id"],
                leg_from_name,
                to_result["short_name"],
                alert_stop_name,
                alert_stop_idx,
                stop_seq_json,
                scheduled_dep,
            )
            tracking_ids.append(tid)
            leg_alert_names.append(alert_stop_name)

            icon = leg.get("icon", "🚆")
            route = leg.get("route", "?")
            dest = leg.get("destination", "?")
            leg_summaries.append(f"{icon} **{route}** → {dest} · alert at **{alert_stop_name}**")

        if not tracking_ids:
            await interaction.followup.send(
                embed=_err_embed("Could not create tracking sessions — missing stop data."),
                ephemeral=True,
            )
            return

        first_leg = valid_legs[0][1]
        icon = first_leg.get("icon", "🚆")
        route = first_leg.get("route", "?")
        dest = first_leg.get("destination", "?")
        planned_dep = first_leg.get("departs")
        dep_str_leg = _fmt_time(planned_dep) if planned_dep else dep_str
        first_alert = leg_alert_names[0] if leg_alert_names else "?"

        if len(tracking_ids) == 1:
            description = (
                f"Tracking **{icon} {route}** → {dest}.\n\n"
                f"You'll get an alert as the service approaches **{first_alert}** "
                f"and again when it arrives."
            )
        else:
            description = "\n".join(f"• {s}" for s in leg_summaries)
            if skipped_legs:
                description += f"\n\n⚠️ {skipped_legs} leg(s) could not be tracked (no stop ID)."

        embed = discord.Embed(
            title=f"✅ Tracking started{time_label}",
            description=description,
            color=TRAIN_COLOR,
        )
        embed.add_field(name="🚉 From", value=from_result["short_name"], inline=True)
        embed.add_field(name="🏁 To", value=to_result["short_name"], inline=True)
        embed.add_field(name="🕐 Departs", value=dep_str_leg, inline=True)
        embed.add_field(name="🕑 Arrives", value=arr_str, inline=True)
        if len(tracking_ids) == 1:
            embed.add_field(name="📍 Alert stop", value=first_alert, inline=True)
        id_str = ", ".join(f"#{t}" for t in tracking_ids)
        embed.set_footer(
            text=f"Tracking ID(s): {id_str} · /transport stop-tracking <id> to cancel"
        )
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── /transport track-status ───────────────────────────────────────────────

    @transport_group.command(
        name="track-status",
        description="List your active vehicle tracking sessions",
    )
    async def cmd_track_status(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        sessions = await asyncio.to_thread(db_get_active_trackings, interaction.user.id)

        if not sessions:
            await interaction.followup.send(
                embed=discord.Embed(
                    description=(
                        "You have no active tracking sessions.\n\n"
                        "Use `/transport go` or `/transport train`, select a trip option, "
                        "then click **🚂 Track this train** to start tracking."
                    ),
                    color=TRAIN_COLOR,
                ),
                ephemeral=True,
            )
            return

        embed = discord.Embed(title="🚂 Your active tracking sessions", color=TRAIN_COLOR)
        for s in sessions:
            # Determine a meaningful status string and format departure time
            dep_str = "?"
            try:
                sched = datetime.fromisoformat(s['scheduled_dep'])
                if sched.tzinfo is None:
                    sched = sched.replace(tzinfo=timezone.utc)
                dep_str = _fmt_time(sched)

                # Try to find the alert stop's own departure time from the stored
                # stop sequence so we can distinguish "on route (not there yet)"
                # from "service may have already passed the alert stop".
                alert_dep: datetime | None = None
                last_dep: datetime | None = None
                try:
                    stored_seq = json.loads(s.get("stop_sequence") or "[]")
                    alert_name = (s.get("alert_stop_name") or "").lower()
                    for stop in stored_seq:
                        if alert_name in (stop.get("name") or "").lower():
                            raw = stop.get("departure")
                            if raw:
                                alert_dep = datetime.fromisoformat(raw)
                                if alert_dep.tzinfo is None:
                                    alert_dep = alert_dep.replace(tzinfo=timezone.utc)
                            break
                    if stored_seq:
                        raw_last = stored_seq[-1].get("departure")
                        if raw_last:
                            last_dep = datetime.fromisoformat(raw_last)
                            if last_dep.tzinfo is None:
                                last_dep = last_dep.replace(tzinfo=timezone.utc)
                except Exception:
                    pass

                now = datetime.now(timezone.utc)
                if s['notified']:
                    status = "✅ Alerted"
                elif last_dep is not None and now > last_dep:
                    status = "🏁 Service has finished its route"
                elif alert_dep is not None and now > alert_dep:
                    status = "⚠️ Service may have passed"
                elif now > sched:
                    status = "🚂 On Route"
                else:
                    status = "⏳ Waiting"
            except Exception:
                status = "✅ Alerted" if s['notified'] else "⏳ Waiting"
            embed.add_field(
                name=f"#{s['id']} — {s['route']} → {s['destination']}",
                value=(
                    f"🕐 Departs: **{dep_str}**\n"
                    f"Alert at: **{s['alert_stop_name']}**\n"
                    f"Route: {s['from_name']} → {s['to_name']}\n"
                    f"Status: {status}"
                ),
                inline=False,
            )
        embed.set_footer(text="Use /transport stop-tracking <id> to cancel a session")
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── /transport stop-tracking ──────────────────────────────────────────────

    @transport_group.command(
        name="stop-tracking",
        description="Cancel an active vehicle tracking session",
    )
    @app_commands.describe(tracking_id="Tracking session ID shown in /transport track-status")
    async def cmd_stop_tracking(interaction: discord.Interaction, tracking_id: int):
        await interaction.response.defer(ephemeral=True)
        row = await asyncio.to_thread(db_get_tracking, tracking_id, interaction.user.id)
        if not row:
            await interaction.followup.send(
                embed=_err_embed(f"No active tracking session #{tracking_id} found."),
                ephemeral=True,
            )
            return
        await asyncio.to_thread(db_deactivate_tracking, tracking_id)
        await interaction.followup.send(
            embed=discord.Embed(
                description=(
                    f"🛑 Stopped tracking **{row['route']}** → {row['destination']} "
                    f"(alert at **{row['alert_stop_name']}**)."
                ),
                color=TRAIN_COLOR,
            ),
            ephemeral=True,
        )

    tree.add_command(transport_group)


# ─── UI Views ─────────────────────────────────────────────────────────────────

class _SaveRouteView(discord.ui.View):
    """Attached to trip results — one-click save."""

    def __init__(self, discord_id, from_id, from_name, to_id, to_name):
        super().__init__(timeout=120)
        self.discord_id = discord_id
        self.from_id = from_id
        self.from_name = from_name
        self.to_id = to_id
        self.to_name = to_name

    @discord.ui.button(label="⭐ Save this route", style=discord.ButtonStyle.primary)
    async def save_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return
        modal = _LabelModal(
            title="Name this route",
            placeholder=f"{self.from_name[:20]} → {self.to_name[:20]}",
            callback=self._do_save,
        )
        await interaction.response.send_modal(modal)

    async def _do_save(self, interaction: discord.Interaction, label: str):
        row_id = await asyncio.to_thread(
            db_save_route,
            self.discord_id, label,
            self.from_id, self.from_name,
            self.to_id, self.to_name,
        )
        routes = await asyncio.to_thread(db_get_routes, self.discord_id)
        slot = next((i + 1 for i, r in enumerate(routes) if r["id"] == row_id), "?")
        # Modal submit already consumed the response — use followup
        await interaction.followup.send(
            embed=discord.Embed(
                description=(
                    f"✅ Saved as **{label}** (slot {slot}).\n"
                    f"Use `/transport next {slot}` for a quick check."
                ),
                color=TRAIN_COLOR,
            ),
            ephemeral=True,
        )
        self.stop()


class _SaveStopView(discord.ui.View):
    """Attached to departure board results — one-click save, refresh, and remind me."""

    def __init__(
        self,
        discord_id,
        stop_id,
        stop_name,
        mode_filter: str | None = None,
        deps: list | None = None,
    ):
        super().__init__(timeout=120)
        self.discord_id = discord_id
        self.stop_id = stop_id
        self.stop_name = stop_name
        self.mode_filter = mode_filter
        # Keep the first departure for a sensible reminder default
        self._first_dep = deps[0] if deps else None
        # Keep non-cancelled departures for the track picker
        self._trackable_deps = [d for d in (deps or []) if not d.get("cancelled")]
        # Set by the caller after sending so on_timeout can disable buttons
        self.message: discord.Message | None = None

        refresh_btn = discord.ui.Button(
            label="🔄 Refresh",
            style=discord.ButtonStyle.secondary,
        )
        refresh_btn.callback = self._on_refresh
        self.add_item(refresh_btn)

        remind_btn = discord.ui.Button(
            label="🔔 Remind me",
            style=discord.ButtonStyle.secondary,
        )
        remind_btn.callback = self._on_remind
        self.add_item(remind_btn)

        save_btn = discord.ui.Button(
            label="⭐ Save this stop",
            style=discord.ButtonStyle.primary,
        )
        save_btn.callback = self._on_save
        self.add_item(save_btn)

        if self._trackable_deps:
            track_btn = discord.ui.Button(
                label="🚂 Track a train",
                style=discord.ButtonStyle.success,
            )
            track_btn.callback = self._on_track_departure
            self.add_item(track_btn)

    async def _on_track_departure(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return
        if not self._trackable_deps:
            await interaction.response.send_message(
                "No trackable departures available.", ephemeral=True
            )
            return
        view = _TrackDepartureView(
            discord_id=interaction.user.id,
            stop_id=self.stop_id,
            stop_name=self.stop_name,
            deps=self._trackable_deps,
            channel_id=interaction.channel_id,
            guild_id=interaction.guild_id,
        )
        await interaction.response.send_message(
            embed=discord.Embed(
                title="🚂 Track a departure",
                description="Select the service you want to track from the dropdown below.",
                color=TRAIN_COLOR,
            ),
            view=view,
            ephemeral=True,
        )
        view.interaction = interaction

    async def _on_remind(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return
        # Build a helpful context message
        dep = self._first_dep
        if dep and not dep.get("cancelled"):
            icon = MODE_ICONS.get(dep["mode"], "🚌")
            context = (
                f"{icon} {dep['route']} → {dep['destination']} "
                f"from {self.stop_name} (departs {_fmt_time(dep['display_time'])})"
            )
        else:
            context = f"Departure from {self.stop_name}"
        modal = ReminderModal(
            context_message=context,
            channel_id=interaction.channel_id,
            guild_id=interaction.guild_id,
        )
        await interaction.response.send_modal(modal)

    async def _on_save(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return
        modal = _LabelModal(
            title="Name this stop",
            placeholder=self.stop_name[:45],
            callback=self._do_save,
        )
        await interaction.response.send_modal(modal)

    async def _on_refresh(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        await interaction.response.defer()
        try:
            deps = await get_departures(self.stop_id, limit=8, mode_filter=self.mode_filter)
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"Refresh failed: {e}"), ephemeral=True)
            return

        if not deps:
            mode_label = MODE_NAMES.get(self.mode_filter, self.mode_filter) if self.mode_filter else ""
            await interaction.followup.send(
                embed=_err_embed(
                    f"No upcoming {mode_label + ' ' if mode_label else ''}departures from **{self.stop_name}**."
                ),
                ephemeral=True,
            )
            return

        now_str = datetime.now(SYDNEY_TZ).strftime("%H:%M")
        mode_label = "All modes" if not self.mode_filter else MODE_NAMES.get(self.mode_filter, self.mode_filter)
        embed = discord.Embed(
            title=f"🚏 {self.stop_name}",
            description=f"Departures as of **{now_str}** · {mode_label}",
            color=TRAIN_COLOR,
        )
        lines = [format_departure_line(dep, i) for i, dep in enumerate(deps, 1)]
        embed.description += "\n\n" + "\n".join(lines)
        stats = format_stop_stats(deps)
        embed.set_footer(text=f"🔴 = real-time · ⚠️ = delayed{' · ' + stats if stats else ''}")

        new_view = _SaveStopView(self.discord_id, self.stop_id, self.stop_name, self.mode_filter, deps)
        self.stop()
        await interaction.edit_original_response(embed=embed, view=new_view)
        new_view.message = await interaction.original_response()

    async def _do_save(self, interaction: discord.Interaction, label: str):
        already = await asyncio.to_thread(db_stop_exists, self.discord_id, self.stop_id)
        if already:
            await interaction.followup.send(
                embed=_err_embed(
                    f"You already have **{self.stop_name}** saved.\n"
                    "Use `/transport my-trips` to view it."
                ),
                ephemeral=True,
            )
            return
        row_id = await asyncio.to_thread(
            db_save_stop,
            self.discord_id, label,
            self.stop_id, self.stop_name,
        )
        routes = await asyncio.to_thread(db_get_routes, self.discord_id)
        stops = await asyncio.to_thread(db_get_stops, self.discord_id)
        slot = len(routes) + next((i + 1 for i, s in enumerate(stops) if s["id"] == row_id), 1)
        # Modal submit already consumed the response — use followup
        await interaction.followup.send(
            embed=discord.Embed(
                description=(
                    f"✅ Saved as **{label}** (slot {slot}).\n"
                    f"Use `/transport next {slot}` for quick departures."
                ),
                color=TRAIN_COLOR,
            ),
            ephemeral=True,
        )
        self.stop()

    async def on_timeout(self):
        """Disable all buttons when the view expires."""
        for item in self.children:
            item.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except Exception:
                pass


class _LabelModal(discord.ui.Modal):
    def __init__(self, title: str, placeholder: str, callback):
        super().__init__(title=title)
        self._cb = callback
        self.label_input = discord.ui.TextInput(
            label="Label / nickname",
            placeholder=placeholder,
            max_length=50,
        )
        self.add_item(self.label_input)

    async def on_submit(self, interaction: discord.Interaction):
        # Must respond to the modal interaction before doing anything else.
        # We defer it so _cb can use followup.send.
        await interaction.response.defer(ephemeral=True)
        value = self.label_input.value.strip()
        await self._cb(interaction, value or str(self.label_input.placeholder))


class _TripSelectorView(discord.ui.View):
    """
    Attached to the trip overview embed.

    Lets the user:
      1. Select an option (1–5) from a dropdown to see full leg-by-leg detail.
      2. Press ⭐ Save to name and persist that specific route.
      3. Press 🔄 Refresh to re-fetch live trip data.
      4. Press ⬅️ Back to return to the compact overview after viewing a detail.

    The view is rebuilt each time an option is selected so the embed is
    edited in-place rather than sending new messages.
    """

    def __init__(
        self,
        discord_id: int,
        trips: list[dict],
        from_stop: dict,
        to_stop: dict,
        alerts: list[dict],
        selected_index: int | None = None,
    ):
        super().__init__(timeout=120)
        self.discord_id = discord_id
        self.trips = trips
        self.from_stop = from_stop
        self.to_stop = to_stop
        self.alerts = alerts
        self.selected_index = selected_index  # 0-based; None = overview
        # Set by the caller after sending so on_timeout can disable buttons
        self.message: discord.Message | None = None

        # ── Trip selector dropdown ─────────────────────────────────────────────
        options = [
            discord.SelectOption(
                label=f"Option {i + 1}",
                value=str(i),
                description=self._short_desc(t),
                default=(i == selected_index),
            )
            for i, t in enumerate(trips[:5])
        ]
        self.trip_select = discord.ui.Select(
            placeholder="Select a trip option to expand…",
            options=options,
        )
        self.trip_select.callback = self._on_select
        self.add_item(self.trip_select)

        # ── Action buttons row ─────────────────────────────────────────────────
        if selected_index is not None:
            back_btn = discord.ui.Button(
                label="⬅️ Back to Overview",
                style=discord.ButtonStyle.secondary,
            )
            back_btn.callback = self._on_overview
            self.add_item(back_btn)

        refresh_btn = discord.ui.Button(
            label="🔄 Refresh",
            style=discord.ButtonStyle.secondary,
        )
        refresh_btn.callback = self._on_refresh
        self.add_item(refresh_btn)

        if selected_index is not None:
            remind_btn = discord.ui.Button(
                label="🔔 Remind me",
                style=discord.ButtonStyle.secondary,
            )
            remind_btn.callback = self._on_remind
            self.add_item(remind_btn)

            self.save_btn = discord.ui.Button(
                label="⭐ Save this route",
                style=discord.ButtonStyle.primary,
            )
            self.save_btn.callback = self._on_save
            self.add_item(self.save_btn)

            track_btn = discord.ui.Button(
                label="🚂 Track this train",
                style=discord.ButtonStyle.success,
            )
            track_btn.callback = self._on_track
            self.add_item(track_btn)

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _short_desc(trip: dict) -> str:
        """One-liner for the Select option description (max 100 chars)."""
        dep = trip["departs"]
        arr = trip["arrives"]
        dep_s = _fmt_time(dep) if dep else "?"
        arr_s = _fmt_time(arr) if arr else "?"
        dur = trip["duration_mins"]
        changes = trip["num_legs"] - 1
        change_s = f"{changes} change{'s' if changes != 1 else ''}" if changes > 0 else "direct"
        rt = " · live" if trip.get("is_realtime") else ""
        return f"{dep_s} → {arr_s} · {dur}m · {change_s}{rt}"[:100]

    def _build_detail_embed(self, index: int) -> discord.Embed:
        """Full leg-by-leg embed for a selected trip option."""
        trip = self.trips[index]
        dep = trip["departs"]
        arr = trip["arrives"]
        dep_s = _fmt_time(dep) if dep else "?"
        arr_s = _fmt_time(arr) if arr else "?"
        mins = trip["mins_until"]
        mins_s = _format_mins(mins) if mins is not None else ""

        changes = trip["num_legs"] - 1
        change_s = f"{changes} change{'s' if changes != 1 else ''}" if changes > 0 else "direct"
        rt_note = "  🔴 real-time" if trip.get("is_realtime") else ""

        embed = discord.Embed(
            title=(
                f"Option {index + 1} — "
                f"{self.from_stop['short_name']} → {self.to_stop['short_name']}"
            ),
            description=(
                f"**{dep_s}** ({mins_s}) → **{arr_s}** · {trip['duration_mins']}m · {change_s}{rt_note}"
            ),
            color=TRAIN_COLOR,
        )

        # Vehicle / service IDs for each transit leg
        transit_legs = [l for l in trip.get("legs", []) if l.get("mode") != "walk"]
        id_parts = []
        for leg in transit_legs:
            vid = leg.get("vehicle_id", "")
            route = leg.get("route", "?")
            dest = leg.get("destination", "")
            if vid:
                short_vid = vid[:_VID_MAX_LEN] + ("…" if len(vid) > _VID_MAX_LEN else "")
                id_parts.append(f"{leg.get('icon','🚌')} **{route}** → {dest}  `{short_vid}`")
            else:
                id_parts.append(f"{leg.get('icon','🚌')} **{route}** → {dest}")
        if id_parts:
            embed.add_field(
                name="🆔 Service ID",
                value="\n".join(id_parts),
                inline=False,
            )

        # Leg-by-leg breakdown
        legs_text = _trip_detail_field(trip)
        embed.add_field(name="Journey detail", value=legs_text or "\u200b", inline=False)

        embed.set_footer(text="⭐ Press Save to add this route · 🚂 Track to get stop alerts · 🔴 = real-time")
        return embed

    # ── callbacks ──────────────────────────────────────────────────────────────

    async def _on_select(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        idx = int(self.trip_select.values[0])
        embed = self._build_detail_embed(idx)

        new_view = _TripSelectorView(
            self.discord_id, self.trips, self.from_stop, self.to_stop, self.alerts,
            selected_index=idx,
        )
        self.stop()
        await interaction.response.edit_message(embed=embed, view=new_view)
        new_view.message = await interaction.original_response()

    async def _on_overview(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        embed = _build_trip_overview_embed(self.trips, self.from_stop, self.to_stop, self.alerts)
        new_view = _TripSelectorView(
            self.discord_id, self.trips, self.from_stop, self.to_stop, self.alerts,
        )
        self.stop()
        await interaction.response.edit_message(embed=embed, view=new_view)
        new_view.message = await interaction.original_response()

    async def _on_refresh(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        await interaction.response.defer()
        try:
            trips = await plan_trip(self.from_stop["id"], self.to_stop["id"], limit=5)
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"Refresh failed: {e}"), ephemeral=True)
            return

        if not trips:
            await interaction.followup.send(
                embed=_err_embed("No trips found after refresh."), ephemeral=True
            )
            return

        embed = _build_trip_overview_embed(trips, self.from_stop, self.to_stop, [])
        new_view = _TripSelectorView(
            self.discord_id, trips, self.from_stop, self.to_stop, [],
        )
        self.stop()
        await interaction.edit_original_response(embed=embed, view=new_view)
        new_view.message = await interaction.original_response()

    async def _on_remind(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return
        if self.selected_index is None:
            await interaction.response.send_message(
                "Select a trip option first, then press Remind me.", ephemeral=True
            )
            return
        trip = self.trips[self.selected_index]
        dep = trip.get("departs")
        dep_str = _fmt_time(dep) if dep else "?"
        # Build legs summary e.g. "🚆T9 → 🚌370"
        leg_parts = []
        for leg in trip.get("legs", []):
            if leg["mode"] == "walk":
                continue
            leg_parts.append(f"{leg['icon']} {leg.get('route', '')}")
        legs_str = " → ".join(leg_parts) or "service"
        context = (
            f"{legs_str} from {self.from_stop['short_name']} "
            f"→ {self.to_stop['short_name']} (departs {dep_str})"
        )
        modal = ReminderModal(
            context_message=context,
            channel_id=interaction.channel_id,
            guild_id=interaction.guild_id,
        )
        await interaction.response.send_modal(modal)

    async def _on_save(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        if self.selected_index is None:
            await interaction.response.send_message(
                "Select a trip option first!", ephemeral=True
            )
            return

        modal = _LabelModal(
            title="Save this route",
            placeholder=f"{self.from_stop['short_name'][:20]} \u2192 {self.to_stop['short_name'][:20]}",
            callback=self._do_save,
        )
        await interaction.response.send_modal(modal)

    async def _do_save(self, interaction: discord.Interaction, label: str):
        already = await asyncio.to_thread(
            db_route_exists,
            self.discord_id,
            self.from_stop["id"],
            self.to_stop["id"],
        )
        if already:
            await interaction.followup.send(
                embed=_err_embed(
                    f"You already have a saved route from **{self.from_stop['short_name']}** "
                    f"to **{self.to_stop['short_name']}**.\n"
                    "Use `/transport my-trips` to view it."
                ),
                ephemeral=True,
            )
            return
        row_id = await asyncio.to_thread(
            db_save_route,
            self.discord_id, label,
            self.from_stop["id"], self.from_stop["short_name"],
            self.to_stop["id"], self.to_stop["short_name"],
        )
        routes = await asyncio.to_thread(db_get_routes, self.discord_id)
        slot = next((i + 1 for i, r in enumerate(routes) if r["id"] == row_id), "?")
        await interaction.followup.send(
            embed=discord.Embed(
                description=(
                    f"\u2705 Saved as **{label}** (slot {slot}).\n"
                    f"Use `/transport next {slot}` for a quick check."
                ),
                color=TRAIN_COLOR,
            ),
            ephemeral=True,
        )
        self.stop()

    async def _on_track(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return
        if self.selected_index is None:
            await interaction.response.send_message(
                "Select a trip option first!", ephemeral=True
            )
            return

        trip = self.trips[self.selected_index]
        valid_legs = _valid_transit_legs(trip)
        if not valid_legs:
            any_transit = any(l.get("mode") != "walk" for l in trip.get("legs", []))
            if not any_transit:
                await interaction.response.send_message(
                    "No trackable legs found in this trip.", ephemeral=True
                )
            else:
                await interaction.response.send_message(
                    "No real-time stop data available to set up tracking. "
                    "Try again on a live trip (🔴 indicator).",
                    ephemeral=True,
                )
            return

        _, leg = valid_legs[0]
        route = leg.get("route", "?")
        dest = leg.get("destination", "?")
        icon = leg.get("icon", "🚆")
        vid = leg.get("vehicle_id", "")
        vid_str = (f"`{vid[:_VID_MAX_LEN]}{'…' if len(vid) > _VID_MAX_LEN else ''}`") if vid else "*not available*"

        extra_count = len(valid_legs) - 1
        footer = "Select an alert stop from the dropdown below"
        if extra_count > 0:
            footer += f" · {extra_count} further leg(s) will be tracked automatically"

        embed = discord.Embed(
            title=f"🚂 Track {icon} {route} → {dest}",
            description=(
                "Select the stop where you want to receive an alert.\n"
                "You'll be notified when the service is **about to arrive**."
            ),
            color=TRAIN_COLOR,
        )
        embed.add_field(name="🆔 Service ID", value=vid_str, inline=True)
        embed.add_field(name="🚉 Route", value=f"{icon} **{route}** → {dest}", inline=True)
        embed.set_footer(text=footer)

        view = _TrackVehicleView(
            discord_id=interaction.user.id,
            trip=trip,
            from_stop=self.from_stop,
            to_stop=self.to_stop,
            channel_id=interaction.channel_id,
            guild_id=interaction.guild_id,
        )
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

    async def on_timeout(self):
        """Disable all items after 2 minutes so stale buttons don't clutter chat."""
        for item in self.children:
            item.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except Exception:
                pass


# ─── Departure tracking picker ─────────────────────────────────────────────────

class _TrackDepartureView(discord.ui.View):
    """
    Departure selector shown when the user clicks "🚂 Track a train" on a
    departure board (_SaveStopView).

    Presents a dropdown of non-cancelled departures.  When one is selected the
    bot resolves the destination stop, plans the full trip to get a stop
    sequence, and hands off to _TrackVehicleView so the user can pick an alert
    stop.
    """

    def __init__(self, discord_id, stop_id, stop_name, deps, channel_id, guild_id):
        super().__init__(timeout=60)
        self.discord_id = discord_id
        self.stop_id = stop_id
        self.stop_name = stop_name
        self.deps = deps
        self.channel_id = str(channel_id) if channel_id else None
        self.guild_id = str(guild_id) if guild_id else None
        # Set by the caller after sending so on_timeout can disable the dropdown
        self.interaction: discord.Interaction | None = None

        options = []
        for i, dep in enumerate(deps[:25]):
            icon = MODE_ICONS.get(dep["mode"], "🚌")
            label = f"{icon} {dep['route']} → {dep['destination']}"[:100]
            dep_time = _fmt_time(dep["display_time"]) if dep.get("display_time") else "?"
            desc = f"Departs {dep_time}"
            if dep.get("mins") is not None:
                desc += f" ({_format_mins(dep['mins'])})"
            options.append(discord.SelectOption(label=label, value=str(i), description=desc[:100]))

        select = discord.ui.Select(placeholder="Select a departure to track…", options=options)
        select.callback = self._on_dep_select
        self.add_item(select)

    async def _on_dep_select(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        idx = int(interaction.data["values"][0])
        dep = self.deps[idx]
        dest_name = dep["destination"]

        await interaction.response.defer(ephemeral=True)

        try:
            dest_stop = await _pick_stop_silent(dest_name)
            if not dest_stop:
                await interaction.followup.send(
                    embed=_err_embed(
                        f"Could not resolve destination **{dest_name}**.\n"
                        "Try `/transport train` to set up tracking manually."
                    ),
                    ephemeral=True,
                )
                return

            trips = await plan_trip(self.stop_id, dest_stop["id"], limit=5)
            if not trips:
                await interaction.followup.send(
                    embed=_err_embed(
                        f"Could not plan a trip to **{dest_name}**.\n"
                        "Try `/transport train` to set up tracking manually."
                    ),
                    ephemeral=True,
                )
                return

            # Match the trip whose first transit leg departure is closest to
            # the selected departure time (within 10 minutes).
            target_dep = dep.get("display_time") or dep.get("planned")
            best_trip = trips[0]
            if target_dep is not None:
                best_diff = None
                for trip in trips:
                    trip_dep = trip.get("departs") or trip.get("planned_departs")
                    if trip_dep is None:
                        continue
                    diff = abs(
                        (trip_dep.astimezone(timezone.utc) - target_dep.astimezone(timezone.utc)).total_seconds()
                    )
                    if best_diff is None or diff < best_diff:
                        best_diff = diff
                        best_trip = trip

            valid_legs = _valid_transit_legs(best_trip)
            if not valid_legs:
                any_transit = any(l.get("mode") != "walk" for l in best_trip.get("legs", []))
                if not any_transit:
                    await interaction.followup.send(
                        embed=_err_embed("No trackable legs found for this service."),
                        ephemeral=True,
                    )
                else:
                    await interaction.followup.send(
                        embed=_err_embed(
                            "No real-time stop data available to track this service.\n"
                            "Try again on a live trip (🔴 indicator)."
                        ),
                        ephemeral=True,
                    )
                return

            from_stop_dict = {"id": self.stop_id, "short_name": self.stop_name}
            to_stop_dict = {"id": dest_stop["id"], "short_name": dest_stop["short_name"]}

            _, leg = valid_legs[0]
            route = leg.get("route", "?")
            dest = leg.get("destination", "?")
            icon = leg.get("icon", "🚆")
            vid = leg.get("vehicle_id", "")
            vid_str = (
                f"`{vid[:_VID_MAX_LEN]}{'…' if len(vid) > _VID_MAX_LEN else ''}`"
                if vid else "*not available*"
            )

            extra_count = len(valid_legs) - 1
            footer = "Select an alert stop from the dropdown below"
            if extra_count > 0:
                footer += f" · {extra_count} further leg(s) will be tracked automatically"

            embed = discord.Embed(
                title=f"🚂 Track {icon} {route} → {dest}",
                description=(
                    "Select the stop where you want to receive an alert.\n"
                    "You'll be notified when the service is **about to arrive**."
                ),
                color=TRAIN_COLOR,
            )
            embed.add_field(name="🆔 Service ID", value=vid_str, inline=True)
            embed.add_field(name="🚉 Route", value=f"{icon} **{route}** → {dest}", inline=True)
            embed.set_footer(text=footer)

            view = _TrackVehicleView(
                discord_id=interaction.user.id,
                trip=best_trip,
                from_stop=from_stop_dict,
                to_stop=to_stop_dict,
                channel_id=self.channel_id,
                guild_id=self.guild_id,
            )
            await interaction.followup.send(embed=embed, view=view, ephemeral=True)
            self.stop()

        except Exception as e:
            await interaction.followup.send(
                embed=_err_embed(f"Error setting up tracking: {e}"),
                ephemeral=True,
            )

    async def on_timeout(self):
        """Disable the dropdown so any lingering interaction doesn't fire."""
        for item in self.children:
            item.disabled = True
        if self.interaction:
            try:
                await self.interaction.edit_original_response(view=self)
            except Exception:
                pass


# ─── Vehicle Tracking View ─────────────────────────────────────────────────────

class _TrackVehicleView(discord.ui.View):
    """
    Stop-picker for setting up live vehicle tracking.

    Shows all stops in the selected leg's stop sequence (excluding the first
    boarding stop) so the user can choose where they want to be alerted.
    After selection a tracking session is persisted to the DB and the
    background tracking_loop in bot.py will poll for the vehicle and send
    an alert when it approaches the chosen stop.
    """

    def __init__(
        self,
        discord_id: int,
        trip: dict,
        from_stop: dict,
        to_stop: dict,
        channel_id,
        guild_id,
    ):
        super().__init__(timeout=60)
        self.discord_id = discord_id
        self.trip = trip
        self.from_stop = from_stop
        self.to_stop = to_stop
        self.channel_id = str(channel_id) if channel_id else None
        self.guild_id = str(guild_id) if guild_id else None
        # Set by caller after sending so on_timeout can disable the dropdown
        self.message = None
        self.interaction: discord.Interaction | None = None
        self._extra_legs: list[tuple[int, dict]] = []

        # Find first valid transit leg (with enough stop data for tracking)
        valid_legs = _valid_transit_legs(trip)
        if not valid_legs:
            return
        self._leg_idx, self._leg = valid_legs[0]
        # Remaining valid legs will be auto-tracked when the user picks their alert stop
        self._extra_legs = valid_legs[1:]
        stop_seq = self._leg.get("stop_sequence", [])

        # Build stop selector.
        # Normally skip first stop (that's where the user boards).
        # When there is only 1 stop in the sequence, include it as the sole alert stop.
        options: list[discord.SelectOption] = []
        for i, s in enumerate(stop_seq):
            if i == 0 and len(stop_seq) > 1:
                continue
            dep = s.get("departure")
            desc = f"Stop {i + 1}/{len(stop_seq)}"
            if dep:
                desc += f" · {_fmt_time(dep)}"
            if len(stop_seq) == 1:
                desc += " (only stop)"
            options.append(
                discord.SelectOption(
                    label=s["name"][:100],
                    value=str(i),
                    description=desc[:100],
                )
            )

        if not options:
            return

        select = discord.ui.Select(
            placeholder="Select your alert stop…",
            options=options[:25],  # Discord max 25
        )
        select.callback = self._on_stop_select
        self.add_item(select)

    async def _on_stop_select(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        alert_stop_idx = int(interaction.data["values"][0])
        stop_seq = self._leg.get("stop_sequence", [])
        alert_stop_name = stop_seq[alert_stop_idx]["name"]

        planned_dep = self._leg.get("departs")
        scheduled_dep = planned_dep.isoformat() if planned_dep else ""

        # Serialise stop sequence for storage (datetimes → ISO strings)
        stop_seq_json = json.dumps([
            {
                "name": s["name"],
                "departure": s["departure"].isoformat() if s.get("departure") else None,
            }
            for s in stop_seq
        ])

        tracking_id = await asyncio.to_thread(
            db_save_tracking,
            str(interaction.user.id),
            self.channel_id,
            self.guild_id,
            self._leg.get("vehicle_id", ""),
            self._leg.get("route", "?"),
            self._leg.get("destination", "?"),
            self.from_stop.get("id", ""),
            self.to_stop.get("id", ""),
            self.from_stop.get("short_name", ""),
            self.to_stop.get("short_name", ""),
            alert_stop_name,
            alert_stop_idx,
            stop_seq_json,
            scheduled_dep,
        )

        # Auto-create tracking entries for any remaining valid legs
        extra_ids: list[int] = []
        dest_name = self.to_stop.get("short_name", "")
        for _, extra_leg in self._extra_legs:
            extra_seq = extra_leg.get("stop_sequence", [])
            extra_from_id = extra_leg.get("from_id", "")
            if not extra_from_id or not extra_seq:
                continue
            extra_alert_idx = _auto_alert_stop_idx(extra_seq, dest_name)
            extra_alert_name = extra_seq[extra_alert_idx]["name"]
            extra_dep = extra_leg.get("departs")
            extra_scheduled = extra_dep.isoformat() if extra_dep else ""
            extra_seq_json = json.dumps([
                {
                    "name": s["name"],
                    "departure": s["departure"].isoformat() if s.get("departure") else None,
                }
                for s in extra_seq
            ])
            tid = await asyncio.to_thread(
                db_save_tracking,
                str(interaction.user.id),
                self.channel_id,
                self.guild_id,
                extra_leg.get("vehicle_id", ""),
                extra_leg.get("route", "?"),
                extra_leg.get("destination", "?"),
                extra_from_id,
                self.to_stop.get("id", ""),
                extra_leg.get("from", self.from_stop.get("short_name", "")),
                dest_name,
                extra_alert_name,
                extra_alert_idx,
                extra_seq_json,
                extra_scheduled,
            )
            extra_ids.append(tid)

        dep_time = _fmt_time(planned_dep) if planned_dep else "?"
        route = self._leg.get("route", "?")
        dest = self._leg.get("destination", "?")
        icon = self._leg.get("icon", "🚆")

        description = (
            f"Now tracking **{icon} {route}** → {dest}.\n\n"
            f"You'll be alerted when the service is approaching **{alert_stop_name}**."
        )
        if extra_ids:
            extra_legs_info = [
                f"{l.get('icon','🚌')} **{l.get('route','?')}**"
                for _, l in self._extra_legs
                if l.get("from_id")
            ]
            if extra_legs_info:
                description += (
                    f"\n\nAlso auto-tracking {', '.join(extra_legs_info)} "
                    f"for the remaining leg(s) of your journey."
                )

        all_ids = [tracking_id] + extra_ids
        id_str = ", ".join(f"#{t}" for t in all_ids)

        embed = discord.Embed(
            title="✅ Tracking started!",
            description=description,
            color=TRAIN_COLOR,
        )
        embed.add_field(name="📍 Alert stop", value=alert_stop_name, inline=True)
        embed.add_field(name="🕐 Service departs", value=dep_time, inline=True)
        embed.set_footer(
            text=f"Tracking ID(s): {id_str} · Use /transport stop-tracking <id> to cancel"
        )

        await interaction.response.edit_message(embed=embed, view=None)
        self.stop()

    async def on_timeout(self):
        """Disable the dropdown when the selection window expires."""
        for item in self.children:
            item.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except Exception:
                pass
        elif self.interaction:
            try:
                await self.interaction.edit_original_response(view=self)
            except Exception:
                pass
