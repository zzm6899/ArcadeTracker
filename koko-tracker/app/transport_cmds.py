"""
Transport NSW Discord commands — appended to bot.py via import.
Registers slash commands: /train /next /find-stop /save-trip /my-trips /delete-trip

DB tables created here (transport_stops, transport_routes) share the same
SQLite database as the main bot (DB_PATH env var).
"""

import asyncio
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
    format_departure_line,
    format_trip_summary,
    MODE_ICONS,
    MODE_NAMES,
    _format_mins,
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
        # e.g. "🚌 Rhodes Station — Stop B"
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
    if s["platform_hint"] and suburb:
        return f"{mode_names} · {suburb}"[:100]
    elif s["platform_hint"]:
        return mode_names[:100]
    elif suburb:
        return f"{mode_names} · {suburb}"[:100]
    return mode_names[:100]


async def _pick_stop(
    interaction: discord.Interaction,
    query: str,
    role: str = "origin",
) -> dict | None:
    """
    'Did you mean?' stop picker.

    - Single result → return immediately, no prompt.
    - Exact name match → return immediately.
    - Multiple results → ephemeral embed with a Select dropdown showing
      mode icons, suburb, and platform hint (Stop A/B/C etc.).
    Returns None on failure/timeout.
    """
    stops = await find_stops(query, limit=8)
    if not stops:
        await interaction.followup.send(
            embed=_err_embed(
                f"No stops found matching **{query}**.\n"
                "Try a suburb or full station name (e.g. *Rhodes Station*, *Central*)."
            ),
            ephemeral=True,
        )
        return None

    # Auto-confirm: single result OR an exact case-insensitive name match
    if len(stops) == 1:
        return stops[0]
    q_lower = query.strip().lower()
    exact = [s for s in stops if s["short_name"].lower() == q_lower
             or s["parent_name"].lower() == q_lower]
    if len(exact) == 1:
        return exact[0]

    # ── Build "Did you mean?" picker ──────────────────────────────────────────
    # Group by parent station to make bus stop lists readable
    # e.g. "Rhodes Station" → [Stop A, Stop B, Stop C]
    groups: dict[str, list[dict]] = defaultdict(list)
    ungrouped = []
    for s in stops:
        if s["platform_hint"] and s["parent_name"]:
            groups[s["parent_name"]].append(s)
        else:
            ungrouped.append(s)

    # Build embed description
    lines = []
    option_list: list[dict] = []  # ordered list that matches Select option values

    for station, platform_stops in groups.items():
        mode_icons = "".join(
            MODE_ICONS.get(m, "")
            for m in sorted({m for s in platform_stops for m in s["modes"]})
        ) or "🚏"
        lines.append(f"**{mode_icons} {station}**")
        for s in platform_stops:
            idx = len(option_list)
            lines.append(f"  › {s['platform_hint']}")
            option_list.append(s)

    for s in ungrouped:
        idx = len(option_list)
        icons = "".join(MODE_ICONS.get(m, "") for m in s["modes"]) or "🚏"
        suburb = f", {s['suburb']}" if s["suburb"] and s["suburb"] not in s["short_name"] else ""
        lines.append(f"**{icons} {s['short_name']}{suburb}**")
        option_list.append(s)

    embed = discord.Embed(
        title=f"Did you mean…? ({role})",
        description="\n".join(lines),
        color=TRAIN_COLOR,
    )
    embed.set_footer(text="Select a stop below · times out in 30s")

    options = [
        discord.SelectOption(
            label=_stop_select_label(s),
            value=str(i),
            description=_stop_select_description(s),
        )
        for i, s in enumerate(option_list)
    ]

    select = discord.ui.Select(
        placeholder=f"Choose {role} stop…",
        options=options[:25],  # Discord limit
    )
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
        await interaction.followup.send(embed=_err_embed("Selection timed out."), ephemeral=True)
        return None
    return chosen[0]


# ─── /train ───────────────────────────────────────────────────────────────────

def register_transport_commands(tree: app_commands.CommandTree):
    """Call this with the bot's command tree to register all transport commands."""

    transport_group = app_commands.Group(
        name="transport",
        description="NSW Transport — check trains, buses, ferries",
    )

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

            trips = await plan_trip(from_result["id"], to_result["id"], limit=3)
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

        embed = discord.Embed(
            title=f"🚆 {from_result['short_name']} → {to_result['short_name']}",
            color=TRAIN_COLOR,
        )
        embed.set_footer(text="🔴 = real-time · Times in Sydney local time")

        for i, trip in enumerate(trips, 1):
            dep = trip["departs"]
            arr = trip["arrives"]
            mins = trip["mins_until"]
            dur = trip["duration_mins"]

            dep_str = dep.strftime("%H:%M") if dep else "?"
            arr_str = arr.strftime("%H:%M") if arr else "?"
            mins_str = _format_mins(mins) if mins is not None else "?"

            # Build leg description
            leg_lines = []
            for leg in trip["legs"]:
                if leg["mode"] == "walk":
                    leg_lines.append(f"  🚶 {leg['summary']}")
                else:
                    dep_t = leg.get("departs")
                    dep_t_str = dep_t.strftime("%H:%M") if dep_t else ""
                    from_n = leg.get("from", "")
                    to_n = leg.get("to", "")
                    route = leg.get("route", "")
                    icon = leg["icon"]
                    leg_lines.append(f"  {icon} **{route}** from {from_n} → {to_n}" + (f" at {dep_t_str}" if dep_t_str else ""))

            field_val = (
                f"Departs **{dep_str}** ({mins_str})  →  Arrives **{arr_str}**\n"
                f"Duration: **{dur} min**\n"
            ) + "\n".join(leg_lines)

            embed.add_field(
                name=f"Option {i}",
                value=field_val,
                inline=False,
            )

        # Save shortcut button
        view = _SaveRouteView(
            interaction.user.id,
            from_result["id"], from_result["name"],
            to_result["id"], to_result["name"],
        )
        await interaction.followup.send(embed=embed, view=view)

    # ── /transport departures ─────────────────────────────────────────────────

    @transport_group.command(name="departures", description="Show upcoming departures from a stop")
    @app_commands.describe(
        stop="Stop or station name (e.g. Central, Chatswood)",
        mode="Filter by mode (optional)",
    )
    @app_commands.choices(mode=[
        app_commands.Choice(name="All", value="all"),
        app_commands.Choice(name="Train", value="4"),
        app_commands.Choice(name="Bus", value="1"),
        app_commands.Choice(name="Ferry", value="2"),
        app_commands.Choice(name="Light Rail", value="5"),
        app_commands.Choice(name="Metro", value="11"),
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
            await interaction.followup.send(
                embed=_err_embed(f"No upcoming departures found from **{stop_result['name']}**."),
                ephemeral=True,
            )
            return

        now_str = datetime.now(SYDNEY_TZ).strftime("%H:%M")
        mode_label = MODE_NAMES.get(mode, "All modes") if mode != "all" else "All modes"
        embed = discord.Embed(
            title=f"🚏 Departures — {stop_result['short_name']}",
            description=f"As of **{now_str}** · {mode_label}",
            color=TRAIN_COLOR,
        )
        embed.set_footer(text="🔴 = real-time data · ⚠️ = delayed")

        lines = [format_departure_line(dep, i) for i, dep in enumerate(deps, 1)]
        embed.description += "\n\n" + "\n".join(lines)

        view = _SaveStopView(interaction.user.id, stop_result["id"], stop_result["name"])
        await interaction.followup.send(embed=embed, view=view)

    # ── /transport next ───────────────────────────────────────────────────────

    @transport_group.command(name="next", description="Show next departure from your saved station or route")
    @app_commands.describe(name="Saved trip/stop name or slot number (e.g. 'morning commute' or '1')")
    async def cmd_next(interaction: discord.Interaction, name: str = "1"):
        await interaction.response.defer(ephemeral=False)

        routes = await asyncio.to_thread(db_get_routes, interaction.user.id)
        stops = await asyncio.to_thread(db_get_stops, interaction.user.id)

        # Combine routes + stops, routes first (slot 1 = first saved route, then stops)
        all_items = list(routes) + list(stops)
        if not all_items:
            embed = discord.Embed(
                description=(
                    "You have no saved trips or stops yet.\n\n"
                    "Use `/transport train` or `/transport departures` and press **Save** to add one."
                ),
                color=TRAIN_COLOR,
            )
            await interaction.followup.send(embed=embed, ephemeral=True)
            return

        # Try numeric slot first, then fuzzy label match
        item = None
        slot_display = name
        query = name.strip()

        if query.isdigit():
            idx = int(query) - 1
            if 0 <= idx < len(all_items):
                item = all_items[idx]
                slot_display = query
            else:
                await interaction.followup.send(
                    embed=_err_embed(f"Slot {query} doesn't exist. You have {len(all_items)} saved item(s)."),
                    ephemeral=True,
                )
                return
        else:
            # Case-insensitive substring match on label
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
            item = matches[0]  # best match = first (earliest saved)
            slot_display = item["label"]

        try:
            if "from_id" in item.keys():
                # It's a route
                trips = await plan_trip(item["from_id"], item["to_id"], limit=3)
                if not trips:
                    await interaction.followup.send(
                        embed=_err_embed(f"No trips found for **{item['label']}**."), ephemeral=True
                    )
                    return
                embed = discord.Embed(
                    title=f"🚆 {item['label']}",
                    description=f"{item['from_name']} → {item['to_name']}",
                    color=TRAIN_COLOR,
                )
                for i, trip in enumerate(trips, 1):
                    dep = trip["departs"]
                    arr = trip["arrives"]
                    mins = trip["mins_until"]
                    dur = trip["duration_mins"]
                    dep_str = dep.strftime("%H:%M") if dep else "?"
                    arr_str = arr.strftime("%H:%M") if arr else "?"
                    mins_str = _format_mins(mins) if mins is not None else "?"
                    leg_icons = " → ".join(
                        l["icon"] if l["mode"] == "walk"
                        else f"{l['icon']}**{l.get('route','')}**"
                        for l in trip["legs"]
                    )
                    changes = trip["num_legs"] - 1
                    change_str = f", {changes} change{'s' if changes != 1 else ''}" if changes > 0 else ", direct"
                    embed.add_field(
                        name=f"Option {i} — departs {dep_str} ({mins_str})",
                        value=f"{leg_icons}\nArrives {arr_str} · {dur}m{change_str}",
                        inline=False,
                    )
                embed.set_footer(text=f"🔴 = real-time · {slot_display}")
            else:
                # It's a saved stop
                deps = await get_departures(item["stop_id"], limit=6)
                if not deps:
                    await interaction.followup.send(
                        embed=_err_embed(f"No departures found from **{item['label']}**."),
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
                        "Use `/transport train` or `/transport departures` then press **Save** to add one."
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
                value=f"{r['from_name']} → {r['to_name']}\n`/transport next {slot}`  or  `/transport next {r['label']}`  ·  ID: {r['id']}",
                inline=False,
            )
            slot += 1

        for s in stops:
            embed.add_field(
                name=f"Slot {slot} · 🚏 {s['label']}",
                value=f"Stop: {s['stop_name']}\n`/transport next {slot}`  or  `/transport next {s['label']}`  ·  ID: {s['id']}",
                inline=False,
            )
            slot += 1

        embed.set_footer(text="Use /transport delete-trip or /transport delete-stop to remove saved items")
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── /transport save-trip ──────────────────────────────────────────────────

    @transport_group.command(name="save-trip", description="Save a route by stop IDs (use /find-stop to get IDs)")
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
        embed = discord.Embed(
            description=f"✅ Saved **{label}** ({from_name} → {to_name}) as slot **{slot}**.\nUse `/transport next {slot}` to check it quickly.",
            color=TRAIN_COLOR,
        )
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── /transport save-stop ──────────────────────────────────────────────────

    @transport_group.command(name="save-stop", description="Save a stop/station by ID (use /find-stop to get IDs)")
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
        embed = discord.Embed(
            description=f"✅ Saved **{label}** ({stop_name}) as slot **{slot}**.\nUse `/transport next {slot}` to check departures.",
            color=TRAIN_COLOR,
        )
        await interaction.followup.send(embed=embed, ephemeral=True)

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
            embed=discord.Embed(description=f"🗑️ Removed **{row['label']}**.", color=TRAIN_COLOR),
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
            embed=discord.Embed(description=f"🗑️ Removed **{row['label']}**.", color=TRAIN_COLOR),
            ephemeral=True,
        )

    tree.add_command(transport_group)


# ─── UI Views ─────────────────────────────────────────────────────────────────

class _SaveRouteView(discord.ui.View):
    """Attached to /transport train results — lets users save the route in one click."""

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
        await interaction.response.send_message(
            embed=discord.Embed(
                description=f"✅ Saved as **{label}** (slot {slot}). Use `/transport next {slot}` for a quick check.",
                color=TRAIN_COLOR,
            ),
            ephemeral=True,
        )
        self.stop()


class _SaveStopView(discord.ui.View):
    """Attached to /transport departures results."""

    def __init__(self, discord_id, stop_id, stop_name):
        super().__init__(timeout=120)
        self.discord_id = discord_id
        self.stop_id = stop_id
        self.stop_name = stop_name

    @discord.ui.button(label="⭐ Save this stop", style=discord.ButtonStyle.primary)
    async def save_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.discord_id:
            await interaction.response.send_message("This isn't your result!", ephemeral=True)
            return

        modal = _LabelModal(
            title="Name this stop",
            placeholder=self.stop_name[:45],
            callback=self._do_save,
        )
        await interaction.response.send_modal(modal)

    async def _do_save(self, interaction: discord.Interaction, label: str):
        row_id = await asyncio.to_thread(
            db_save_stop,
            self.discord_id, label,
            self.stop_id, self.stop_name,
        )
        routes = await asyncio.to_thread(db_get_routes, self.discord_id)
        stops = await asyncio.to_thread(db_get_stops, self.discord_id)
        slot = len(routes) + next((i + 1 for i, s in enumerate(stops) if s["id"] == row_id), 1)
        await interaction.response.send_message(
            embed=discord.Embed(
                description=f"✅ Saved as **{label}** (slot {slot}). Use `/transport next {slot}` for quick departures.",
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
        await self._cb(interaction, self.label_input.value.strip() or self.label_input.placeholder)
