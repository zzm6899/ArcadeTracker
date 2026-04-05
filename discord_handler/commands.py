"""
Discord slash command registrations.

This module is the only place that imports discord / app_commands.
It glues Discord interactions → BotHandler methods → formatted responses.

All command logic lives in BotHandler / service_manager; this file
only handles Discord-specific concerns: defer, followup, ephemeral,
autocomplete, and wiring to the service objects.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import discord
from discord import app_commands

from utils.utilities import parse_duration, validate_stop_id

if TYPE_CHECKING:
    from discord_handler.bot import BotHandler
    from service_manager import DelayMonitor, LocationAlertStateMachine, ReminderScheduler

logger = logging.getLogger(__name__)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _err(msg: str) -> str:
    return f"❌ {msg}"


def _channel_id(interaction: discord.Interaction) -> str:
    return str(interaction.channel_id)


async def _stop_autocomplete(
    interaction: discord.Interaction,
    current: str,
) -> list[app_commands.Choice[str]]:
    """Autocomplete for stop name/ID parameters."""
    if not current or len(current) < 2:
        return []
    try:
        from app import _api_service  # injected at startup
        results = _api_service.find_stops(current, limit=10)
        return [
            app_commands.Choice(name=r["name"], value=r["id"])
            for r in results
        ]
    except Exception:
        return []


# ── Command registration ───────────────────────────────────────────────────────

def register_commands(
    tree: app_commands.CommandTree,
    bot: BotHandler,
    location_sm: LocationAlertStateMachine,
    delay_monitor: DelayMonitor,
    scheduler: ReminderScheduler,
) -> None:
    """
    Register all ArcadeTracker slash commands on *tree*.

    Call this once inside Client.setup_hook() before tree.sync().
    """

    # ── /alert ────────────────────────────────────────────────────────────────

    @tree.command(name="alert", description="Get notified when a vehicle reaches a stop")
    @app_commands.describe(
        trip_id="The trip / run ID to track (e.g. TRIP-001)",
        stop_id="The stop ID to watch for (e.g. 200060)",
    )
    @app_commands.autocomplete(stop_id=_stop_autocomplete)
    async def cmd_alert(
        interaction: discord.Interaction,
        trip_id: str,
        stop_id: str,
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        channel_id = _channel_id(interaction)
        if not validate_stop_id(stop_id):
            await interaction.followup.send(_err(f"Invalid stop ID `{stop_id}`."), ephemeral=True)
            return
        location_sm.register(
            trip_id=trip_id,
            target_stop_id=stop_id,
            channel_id=channel_id,
            notify_fn=bot.send_message,
        )
        await interaction.followup.send(
            f"🔔 Alert set for trip `{trip_id}` at stop `{stop_id}`. "
            "I'll post here when the vehicle arrives. Expires in 2 hours.",
            ephemeral=True,
        )

    # ── /trip ─────────────────────────────────────────────────────────────────

    @tree.command(
        name="trip",
        description="Plan a trip between two stops, optionally at a specific time",
    )
    @app_commands.describe(
        origin="Origin stop name or ID",
        destination="Destination stop name or ID",
        at_time="Departure time — e.g. '14:30' or '2026-04-07 14:30' (optional)",
        track="Auto-register a location alert for the first leg of this trip",
    )
    @app_commands.autocomplete(origin=_stop_autocomplete, destination=_stop_autocomplete)
    async def cmd_trip(
        interaction: discord.Interaction,
        origin: str,
        destination: str,
        at_time: str | None = None,
        track: bool = False,
    ) -> None:
        await interaction.response.defer()
        channel_id = _channel_id(interaction)

        target_dt: datetime | None = None
        if at_time:
            target_dt = _parse_time_str(at_time)
            if target_dt is None:
                await interaction.followup.send(
                    _err(f"Could not parse time `{at_time}`. Try `14:30` or `2026-04-07 14:30`."),
                    ephemeral=True,
                )
                return

        from utils.utilities import format_trip_report
        legs = bot.api_service.plan_trip(
            from_id=origin,
            to_id=destination,
            target_datetime=target_dt,
        )
        report = format_trip_report(legs, target_dt)
        await interaction.followup.send(report)

        # Auto-tracking: register an alert for the departure stop of the first leg.
        if track and legs:
            first_leg = legs[0]
            trip_id = first_leg.get("trip_id") or f"{origin}->{destination}"
            dep_stop = first_leg.get("dep_stop", origin)
            location_sm.register(
                trip_id=trip_id,
                target_stop_id=dep_stop,
                channel_id=channel_id,
                notify_fn=bot.send_message,
            )
            await interaction.followup.send(
                f"🔔 Tracking enabled — I'll notify you when your service departs **{dep_stop}**.",
                ephemeral=True,
            )

    # ── /delay ────────────────────────────────────────────────────────────────

    @tree.command(name="delay", description="Check if a service is running on time")
    @app_commands.describe(
        trip_id="Trip / run ID",
        stop_id="Stop ID to check arrival time at",
        threshold="Alert only if delay exceeds this many minutes (default 5)",
    )
    @app_commands.autocomplete(stop_id=_stop_autocomplete)
    async def cmd_delay(
        interaction: discord.Interaction,
        trip_id: str,
        stop_id: str,
        threshold: int = 5,
    ) -> None:
        await interaction.response.defer()
        await bot.handle_delay_check_command(
            channel_id=_channel_id(interaction),
            trip_id=trip_id,
            stop_id=stop_id,
            threshold_minutes=threshold,
        )
        # Swap the print-based send for a real followup by using a one-shot override.
        # (handle_delay_check_command calls bot.send_message which now uses the client.)

    # ── /disruptions ──────────────────────────────────────────────────────────

    @tree.command(name="disruptions", description="Show all active service disruptions")
    async def cmd_disruptions(interaction: discord.Interaction) -> None:
        await interaction.response.defer()
        from utils.utilities import format_alert_card
        alerts = bot.api_service.get_service_alerts()
        await interaction.followup.send(format_alert_card(alerts))

    # ── /departures ───────────────────────────────────────────────────────────

    @tree.command(name="departures", description="Show next departures from a stop")
    @app_commands.describe(
        stop="Stop name or ID",
        limit="Number of services to show (1-15, default 8)",
        track="Auto-register a location alert for the next departure",
    )
    @app_commands.autocomplete(stop=_stop_autocomplete)
    async def cmd_departures(
        interaction: discord.Interaction,
        stop: str,
        limit: int = 8,
        track: bool = False,
    ) -> None:
        await interaction.response.defer()
        channel_id = _channel_id(interaction)
        limit = max(1, min(limit, 15))

        departures = bot.api_service.get_departures(stop, limit=limit)
        stops = bot.api_service.find_stops(stop, limit=1)
        stop_name = stops[0]["name"] if stops else stop

        from utils.utilities import format_departures_board
        await interaction.followup.send(format_departures_board(stop_name, departures))

        # Auto-tracking: register an alert for the very next departure.
        if track and departures:
            next_dep = departures[0]
            trip_id = next_dep.get("trip_id") or f"{next_dep.get('line', 'SVC')}-{stop}"
            location_sm.register(
                trip_id=trip_id,
                target_stop_id=stop,
                channel_id=channel_id,
                notify_fn=bot.send_message,
            )
            await interaction.followup.send(
                f"🔔 Tracking **{next_dep.get('line', '')} {next_dep.get('headsign', '')}** "
                f"— I'll notify you when it arrives at **{stop_name}**.",
                ephemeral=True,
            )

    # ── /stops ────────────────────────────────────────────────────────────────

    @tree.command(name="stops", description="Search for a stop by name")
    @app_commands.describe(query="Stop name to search for")
    async def cmd_stops(interaction: discord.Interaction, query: str) -> None:
        await interaction.response.defer(ephemeral=True)
        results = bot.api_service.find_stops(query)
        if not results:
            await interaction.followup.send(
                f"No stops found matching **{query}**.", ephemeral=True
            )
            return
        lines = [f"## 🔍 Stop Search — \"{query}\"", ""]
        for r in results:
            modes = ", ".join(r.get("modes", []))
            lines.append(f"`{r['id']}` **{r['name']}**  _{r.get('type', '')}_ ({modes})")
        await interaction.followup.send("\n".join(lines), ephemeral=True)

    # ── /status ───────────────────────────────────────────────────────────────

    @tree.command(name="status", description="Show live vehicle position for a trip")
    @app_commands.describe(trip_id="Trip / run ID to look up")
    async def cmd_status(interaction: discord.Interaction, trip_id: str) -> None:
        await interaction.response.defer()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        position = bot.api_service.get_vehicle_position(trip_id, now_iso)
        if position is None:
            await interaction.followup.send(
                _err(f"No live position data for trip `{trip_id}`."), ephemeral=True
            )
            return
        from utils.utilities import format_vehicle_status
        await interaction.followup.send(format_vehicle_status(trip_id, position))

    # ── /remind ───────────────────────────────────────────────────────────────

    @tree.command(
        name="remind",
        description="Set a reminder — e.g. /remind Check T1 delays 30m",
    )
    @app_commands.describe(
        message="What to remind you about",
        duration="When to fire — e.g. 30m, 1h, 2h30m, in 45 minutes",
    )
    async def cmd_remind(
        interaction: discord.Interaction,
        message: str,
        duration: str,
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        delay = parse_duration(duration)
        if delay is None:
            await interaction.followup.send(
                _err("Could not parse duration. Try `30m`, `1h`, `2h30m`, or `in 45 minutes`."),
                ephemeral=True,
            )
            return
        channel_id = _channel_id(interaction)
        reminder = scheduler.add(
            channel_id=channel_id,
            message=message,
            delay=delay,
            notify_fn=bot.send_message,
        )
        mins = int(delay.total_seconds() / 60)
        await interaction.followup.send(
            f"⏰ Reminder `#{reminder.id}` set — I'll remind you in **{mins} min**:\n> {message}",
            ephemeral=True,
        )

    # ── /reminders ────────────────────────────────────────────────────────────

    @tree.command(name="reminders", description="List your pending reminders")
    async def cmd_reminders(interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        from utils.utilities import format_reminder_list
        pending = scheduler.pending_for(_channel_id(interaction))
        await interaction.followup.send(format_reminder_list(pending), ephemeral=True)

    # ── /cancel-reminder ──────────────────────────────────────────────────────

    @tree.command(name="cancel-reminder", description="Cancel a pending reminder by ID")
    @app_commands.describe(reminder_id="Reminder ID shown by /reminders (e.g. A1B2C3)")
    async def cmd_cancel_reminder(
        interaction: discord.Interaction,
        reminder_id: str,
    ) -> None:
        await interaction.response.defer(ephemeral=True)
        if scheduler.cancel(reminder_id.upper()):
            await interaction.followup.send(
                f"✅ Reminder `#{reminder_id.upper()}` cancelled.", ephemeral=True
            )
        else:
            await interaction.followup.send(
                _err(f"No pending reminder `#{reminder_id.upper()}`."), ephemeral=True
            )

    logger.info("All slash commands registered on command tree.")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_time_str(text: str) -> datetime | None:
    """
    Parse a user-supplied time string into a timezone-aware datetime.
    Accepts "HH:MM" (today, Sydney) or "YYYY-MM-DD HH:MM".
    """
    from utils.utilities import SYDNEY_TZ
    text = text.strip()
    today = datetime.now(SYDNEY_TZ).date()
    for fmt, use_today in (
        ("%H:%M", True),
        ("%I:%M%p", True),
        ("%Y-%m-%d %H:%M", False),
    ):
        try:
            parsed = datetime.strptime(text, fmt)
            if use_today:
                parsed = parsed.replace(year=today.year, month=today.month, day=today.day)
            return parsed.replace(tzinfo=SYDNEY_TZ)
        except ValueError:
            continue
    return None
