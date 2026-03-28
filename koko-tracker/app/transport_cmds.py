"""
Transport NSW Discord commands.
Registers slash commands under the /transport group.

DB tables (transport_stops, transport_routes) share the same SQLite
database as the main bot (DB_PATH env var).
"""

import asyncio
import re
import sqlite3
import os
from collections import defaultdict
from datetime import datetime

import discord
from discord import app_commands

from transport_nsw import (
    find_stops,
    get_departures,
    plan_trip,
    get_alerts,
    format_departure_line,
    MODE_ICONS,
    MODE_NAMES,
    _format_mins,
    _fmt_time,
    SYDNEY_TZ,
)

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


# ─── Shared UI helpers ─────────────────────────────────────────────────────────

TRAIN_COLOR = 0xF15A22   # TfNSW orange
ERROR_COLOR = 0xE74C3C


def _err_embed(msg: str) -> discord.Embed:
    return discord.Embed(description=f"❌ {msg}", color=ERROR_COLOR)


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

    await interaction.followup.send(embed=embed, view=view, ephemeral=True)
    await view.wait()

    if not chosen:
        # Timeout — edit the picker message rather than sending another followup
        await interaction.followup.send(
            embed=_err_embed(f"Selection timed out for **{role}** stop."),
            ephemeral=True,
        )
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


# ─── Natural-language query parser ────────────────────────────────────────────

def _parse_go_query(text: str) -> tuple[str, str] | None:
    """
    Parse a natural-language trip query into (from_query, to_query).

    Handles:
      "rhodes to strathfield"
      "rhodes → central"
      "rhodes bus A to top ryde"   → from="rhodes bus A", to="top ryde"
      "central station to parramatta"

    Returns (from_part, to_part) or None if no separator found.
    """
    # Normalise arrows and various separators to " to "
    text = text.strip()
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

            # Board line
            board_line = f"{icon} **{route}**"
            if dest:
                board_line += f" towards {dest}"
            if dep_t_str:
                board_line += f" — departs **{dep_t_str}**"
            board_line += f"\n\u3000from **{from_n}**"
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
                transfer = f"\u3000\u2192 arrives **{to_n}**"
                transfer += f"\n\u3000🔀 catch {nl_icon} **{nl_route}**"
                if nl_dep_str:
                    transfer += f" at **{nl_dep_str}**"
                if nl_from and nl_from != to_n:
                    transfer += f" from **{nl_from}**"
                lines.append(transfer)
            else:
                lines.append(f"\u3000\u2192 arrives **{to_n}**")

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

    if alerts:
        embed.add_field(
            name="📢 Service notices",
            value="\n".join(
                f"{'🚨' if a['is_replacement'] else '⚠️' if a['priority'] in ('high','veryHigh') else 'ℹ️'} "
                f"{a['title'][:100]}"
                + (f" — [details]({a['url']})" if a["url"] else "")
                for a in alerts
            )[:1024],
            inline=False,
        )

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
        description='Natural-language trip planner: "rhodes to central station" or "rhodes bus A to top ryde"',
    )
    @app_commands.describe(query='Where to and from, e.g. "rhodes to strathfield" or "central station to parramatta"')
    async def cmd_go(interaction: discord.Interaction, query: str):
        await interaction.response.defer(ephemeral=False)

        parsed = _parse_go_query(query)
        if not parsed:
            await interaction.followup.send(
                embed=_err_embed(
                    f'Could not parse **"{query}"**.\n'
                    'Use the format **from** `to` **destination**, e.g. `rhodes to central station` '
                    'or `rhodes bus A to top ryde`.'
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

            trips, alerts = await asyncio.gather(
                plan_trip(from_result["id"], to_result["id"], limit=5),
                get_alerts(),
            )
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        if not trips:
            await interaction.followup.send(
                embed=_err_embed(
                    f"No trips found from **{from_result['short_name']}** to **{to_result['short_name']}**.\n"
                    f"Resolved: `{from_result['name']}` → `{to_result['name']}`"
                ),
                ephemeral=True,
            )
            return

        embed = _build_trip_overview_embed(trips, from_result, to_result, alerts)
        view = _TripSelectorView(
            interaction.user.id, trips, from_result, to_result, alerts
        )
        await interaction.followup.send(embed=embed, view=view)

    # ── /transport train ──────────────────────────────────────────────────────

    @transport_group.command(name="train", description="Plan a trip between two stations/stops")
    @app_commands.describe(
        from_stop="Origin station or stop name (e.g. Central, Strathfield)",
        to_stop="Destination station or stop name (e.g. Rhodes, Parramatta)",
    )
    async def cmd_train(interaction: discord.Interaction, from_stop: str, to_stop: str):
        await interaction.response.defer(ephemeral=False)

        try:
            from_result = await _pick_stop(interaction, from_stop, "origin")
            if not from_result:
                return
            to_result = await _pick_stop(interaction, to_stop, "destination")
            if not to_result:
                return
            trips, alerts = await asyncio.gather(
                plan_trip(from_result["id"], to_result["id"], limit=5),
                get_alerts(),
            )
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        if not trips:
            await interaction.followup.send(
                embed=_err_embed(
                    f"No trips found from **{from_result['name']}** to **{to_result['name']}**."
                ),
                ephemeral=True,
            )
            return

        embed = _build_trip_overview_embed(trips, from_result, to_result, alerts)
        view = _TripSelectorView(
            interaction.user.id, trips, from_result, to_result, alerts
        )
        await interaction.followup.send(embed=embed, view=view)

    # ── /transport departures ─────────────────────────────────────────────────

    @transport_group.command(name="departures", description="Show upcoming departures from a stop")
    @app_commands.describe(
        stop="Stop or station name (e.g. Central, Chatswood)",
        mode="Filter by transport mode (optional)",
    )
    @app_commands.choices(mode=[
        app_commands.Choice(name="All", value="all"),
        app_commands.Choice(name="🚆 Train", value="1"),
        app_commands.Choice(name="🚇 Metro", value="2"),
        app_commands.Choice(name="🚌 Bus", value="5"),
        app_commands.Choice(name="⛴️ Ferry", value="9"),
        app_commands.Choice(name="🚃 Light Rail", value="4"),
    ])
    async def cmd_departures(interaction: discord.Interaction, stop: str, mode: str = "all"):
        await interaction.response.defer(ephemeral=False)

        try:
            stop_result = await _pick_stop(interaction, stop, "stop")
            if not stop_result:
                return
            mode_filter = None if mode == "all" else mode
            deps = await get_departures(stop_result["id"], limit=8, mode_filter=mode_filter)
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        if not deps:
            mode_label = MODE_NAMES.get(mode, mode) if mode != "all" else ""
            no_deps_msg = f"No upcoming {mode_label + ' ' if mode_label else ''}departures from **{stop_result['short_name']}**."
            await interaction.followup.send(embed=_err_embed(no_deps_msg), ephemeral=True)
            return

        now_str = datetime.now(SYDNEY_TZ).strftime("%H:%M")
        mode_label = "All modes" if mode == "all" else MODE_NAMES.get(mode, mode)
        embed = discord.Embed(
            title=f"🚏 {stop_result['short_name']}",
            description=f"Departures as of **{now_str}** · {mode_label}",
            color=TRAIN_COLOR,
        )
        embed.set_footer(text="🔴 = real-time · ⚠️ = delayed")

        lines = [format_departure_line(dep, i) for i, dep in enumerate(deps, 1)]
        embed.description += "\n\n" + "\n".join(lines)

        view = _SaveStopView(interaction.user.id, stop_result["id"], stop_result["name"], mode_filter)
        await interaction.followup.send(embed=embed, view=view)

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
            if "from_id" in item.keys():
                trips, alerts = await asyncio.gather(
                    plan_trip(item["from_id"], item["to_id"], limit=5),
                    get_alerts(),
                )
                if not trips:
                    await interaction.followup.send(
                        embed=_err_embed(f"No trips found for **{item['label']}**."),
                        ephemeral=True,
                    )
                    return
                from_stop = {"short_name": item["from_name"], "id": item["from_id"]}
                to_stop = {"short_name": item["to_name"], "id": item["to_id"]}
                embed = _build_trip_overview_embed(trips, from_stop, to_stop, alerts)
                embed.title = f"🚆 {item['label']}"
                embed.set_footer(text=f"🔴 = real-time · {slot_display}")
                view = _TripSelectorView(
                    interaction.user.id, trips, from_stop, to_stop, alerts
                )
                await interaction.followup.send(embed=embed, view=view)
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
                embed.set_footer(text=f"🔴 = real-time · {slot_display}")

        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"API error: {e}"), ephemeral=True)
            return

        await interaction.followup.send(embed=embed)

    # ── /transport find-stop ──────────────────────────────────────────────────

    @transport_group.command(name="find-stop", description="Search for a stop/station ID by name")
    @app_commands.describe(query="Stop or station name to search for")
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

        embed.set_footer(text="/transport delete-trip or /transport delete-stop to remove")
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
    """Attached to departure board results — one-click save and refresh."""

    def __init__(self, discord_id, stop_id, stop_name, mode_filter: str | None = None):
        super().__init__(timeout=120)
        self.discord_id = discord_id
        self.stop_id = stop_id
        self.stop_name = stop_name
        self.mode_filter = mode_filter

        refresh_btn = discord.ui.Button(
            label="🔄 Refresh",
            style=discord.ButtonStyle.secondary,
        )
        refresh_btn.callback = self._on_refresh
        self.add_item(refresh_btn)

        save_btn = discord.ui.Button(
            label="⭐ Save this stop",
            style=discord.ButtonStyle.primary,
        )
        save_btn.callback = self._on_save
        self.add_item(save_btn)

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
        embed.set_footer(text="🔴 = real-time · ⚠️ = delayed")
        lines = [format_departure_line(dep, i) for i, dep in enumerate(deps, 1)]
        embed.description += "\n\n" + "\n".join(lines)

        new_view = _SaveStopView(self.discord_id, self.stop_id, self.stop_name, self.mode_filter)
        self.stop()
        await interaction.edit_original_response(embed=embed, view=new_view)

    async def _do_save(self, interaction: discord.Interaction, label: str):
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
            self.save_btn = discord.ui.Button(
                label="⭐ Save this route",
                style=discord.ButtonStyle.primary,
            )
            self.save_btn.callback = self._on_save
            self.add_item(self.save_btn)

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

        # Leg-by-leg breakdown
        legs_text = _trip_detail_field(trip)
        embed.add_field(name="Journey detail", value=legs_text or "\u200b", inline=False)

        # Alerts (if any)
        if self.alerts:
            alert_lines = []
            for a in self.alerts:
                icon = "🚨" if a["is_replacement"] else (
                    "⚠️" if a["priority"] in ("high", "veryHigh") else "ℹ️"
                )
                line = f"{icon} {a['title'][:100]}"
                if a["url"]:
                    line += f" — [details]({a['url']})"
                alert_lines.append(line)
            embed.add_field(
                name="📢 Service notices",
                value="\n".join(alert_lines)[:1024],
                inline=False,
            )

        embed.set_footer(text="⭐ Press Save to add this route · 🔴 = real-time data")
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

    async def _on_refresh(self, interaction: discord.Interaction):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        await interaction.response.defer()
        try:
            trips, alerts = await asyncio.gather(
                plan_trip(self.from_stop["id"], self.to_stop["id"], limit=5),
                get_alerts(),
            )
        except Exception as e:
            await interaction.followup.send(embed=_err_embed(f"Refresh failed: {e}"), ephemeral=True)
            return

        if not trips:
            await interaction.followup.send(
                embed=_err_embed("No trips found after refresh."), ephemeral=True
            )
            return

        embed = _build_trip_overview_embed(trips, self.from_stop, self.to_stop, alerts)
        new_view = _TripSelectorView(
            self.discord_id, trips, self.from_stop, self.to_stop, alerts,
        )
        self.stop()
        await interaction.edit_original_response(embed=embed, view=new_view)

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

    async def on_timeout(self):
        """Disable all items after 2 minutes so stale buttons don't clutter chat."""
        for item in self.children:
            item.disabled = True
        # We can't edit the message here without a stored message reference,
        # so we just stop the view — Discord will ignore interactions after timeout.
