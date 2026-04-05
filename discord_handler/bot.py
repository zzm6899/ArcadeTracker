"""
Presentation Layer — Discord communication only.
All formatting helpers live in utils/utilities.py.
All business/scheduling logic lives in service_manager.py.
This file must NOT contain API calls or scheduling state.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from data_layer.api_service import APIService
from utils.utilities import (
    calculate_delay_minutes,
    format_alert_card,
    format_delay_alert,
    format_departures_board,
    format_reminder_list,
    format_trip_report,
    format_vehicle_status,
    parse_duration,
    validate_stop_id,
)

if TYPE_CHECKING:
    from service_manager import LocationAlertStateMachine, ReminderScheduler

logger = logging.getLogger(__name__)

_DEFAULT_CHANNEL = "default_channel"


class BotHandler:
    """Manages all Discord interactions and command dispatching."""

    def __init__(self, api_service: APIService, discord_client: Any = None):
        self.api_service = api_service
        self._client = discord_client  # discord.Client — set via set_client() after login
        logger.info("BotHandler initialized.")

    def set_client(self, client: Any) -> None:
        """Attach the live discord.Client so background sends reach real channels."""
        self._client = client

    # ── Core send primitive ───────────────────────────────────────────────────

    async def send_message(self, channel_id: str, content: str) -> None:
        """
        Send *content* to a Discord channel.

        When a discord.Client is attached (production), fetches the channel and
        sends via the real API.  Falls back to stdout for smoke-testing / mock mode.
        """
        if self._client is not None:
            try:
                channel = self._client.get_channel(int(channel_id))
                if channel is None:
                    channel = await self._client.fetch_channel(int(channel_id))
                await channel.send(content)
            except Exception:
                logger.exception("Failed to send message to channel %s", channel_id)
        else:
            print(f"[Discord -> #{channel_id}]\n{content}\n")

    # ── Unit 1: location alert ────────────────────────────────────────────────

    async def handle_location_alert_command(
        self,
        channel_id: str,
        trip_id: str,
        stop_id: str,
        state_machine: LocationAlertStateMachine,
    ) -> None:
        """
        Register a one-shot location alert.
        `/alert <trip_id> <stop_id>`
        """
        if not validate_stop_id(stop_id):
            await self.send_message(
                channel_id,
                f"❌ Invalid stop ID `{stop_id}`. Please provide a valid stop identifier.",
            )
            return

        state_machine.register(
            trip_id=trip_id,
            target_stop_id=stop_id,
            channel_id=channel_id,
            notify_fn=self.send_message,
        )
        await self.send_message(
            channel_id,
            f"🔔 Alert registered for trip `{trip_id}` at stop `{stop_id}`. "
            "You'll be notified when the vehicle arrives. Expires in 2 hours.",
        )

    # ── Unit 2: scheduled trip report ────────────────────────────────────────

    async def handle_scheduled_trip_command(
        self,
        channel_id: str,
        from_id: str,
        to_id: str,
        target_datetime: datetime | None = None,
    ) -> None:
        """
        Return a formatted trip report.
        `/trip <from> <to> [datetime]`
        """
        legs = self.api_service.plan_trip(
            from_id=from_id,
            to_id=to_id,
            target_datetime=target_datetime,
        )
        await self.send_message(channel_id, format_trip_report(legs, target_datetime))

    # ── Unit 3: on-demand delay check ────────────────────────────────────────

    async def handle_delay_check_command(
        self,
        channel_id: str,
        trip_id: str,
        stop_id: str,
        threshold_minutes: int = 5,
    ) -> None:
        """
        Check live vs scheduled arrival and report.
        `/delay <trip_id> <stop_id> [threshold]`
        """
        scheduled = self.api_service.get_scheduled_stop_time(trip_id, stop_id)
        live = self.api_service.get_live_arrival(trip_id, stop_id)

        if not scheduled or not live:
            await self.send_message(
                channel_id,
                f"⚠️ Could not retrieve timing data for trip `{trip_id}` "
                f"at stop `{stop_id}`.",
            )
            return

        delay_min = calculate_delay_minutes(
            scheduled["scheduled_arrival"],
            live["predicted_arrival"],
        )

        if abs(delay_min) < threshold_minutes:
            await self.send_message(
                channel_id,
                f"✅ Trip `{trip_id}` to **{scheduled.get('stop_name', stop_id)}** "
                "is running **on time**.",
            )
            return

        await self.send_message(
            channel_id,
            format_delay_alert(
                trip_id=trip_id,
                stop_name=scheduled.get("stop_name", stop_id),
                delay_minutes=delay_min,
                scheduled_iso=scheduled["scheduled_arrival"],
                predicted_iso=live["predicted_arrival"],
            ),
        )

    # ── Unit 4: service disruption dashboard ─────────────────────────────────

    async def handle_disruptions_command(self, channel_id: str) -> None:
        """
        Post a formatted disruption dashboard.
        `/disruptions`
        """
        await self.send_message(
            channel_id,
            format_alert_card(self.api_service.get_service_alerts()),
        )

    # ── Departures board ──────────────────────────────────────────────────────

    async def handle_departures_command(
        self,
        channel_id: str,
        stop_id: str,
        limit: int = 8,
    ) -> None:
        """
        Show the next departures for a stop.
        `/departures <stop_id> [limit]`
        """
        if not validate_stop_id(stop_id):
            await self.send_message(
                channel_id,
                f"❌ Invalid stop ID `{stop_id}`.",
            )
            return

        departures = self.api_service.get_departures(stop_id, limit=limit)
        # Try to resolve a friendly stop name from the first departure.
        stop_name = stop_id
        stops = self.api_service.find_stops(stop_id, limit=1)
        if stops:
            stop_name = stops[0]["name"]

        await self.send_message(
            channel_id,
            format_departures_board(stop_name, departures),
        )

    # ── Stop search ───────────────────────────────────────────────────────────

    async def handle_stop_search_command(
        self,
        channel_id: str,
        query: str,
    ) -> None:
        """
        Search for stops matching a name query.
        `/stops <query>`
        """
        if not query or not query.strip():
            await self.send_message(channel_id, "❌ Please provide a search query.")
            return

        results = self.api_service.find_stops(query)
        if not results:
            await self.send_message(
                channel_id,
                f"No stops found matching **{query}**.",
            )
            return

        lines = [f"## 🔍 Stop Search — \"{query}\"", ""]
        for r in results:
            modes = ", ".join(r.get("modes", []))
            lines.append(
                f"`{r['id']}` **{r['name']}**  _{r.get('type', '')}_ "
                f"({modes})"
            )
        await self.send_message(channel_id, "\n".join(lines))

    # ── Vehicle status ────────────────────────────────────────────────────────

    async def handle_vehicle_status_command(
        self,
        channel_id: str,
        trip_id: str,
    ) -> None:
        """
        Show the current live position of a vehicle.
        `/status <trip_id>`
        """
        from datetime import timezone
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        position = self.api_service.get_vehicle_position(trip_id, now_iso)

        if position is None:
            await self.send_message(
                channel_id,
                f"⚠️ No live position data available for trip `{trip_id}`.",
            )
            return

        await self.send_message(channel_id, format_vehicle_status(trip_id, position))

    # ── Reminder commands ─────────────────────────────────────────────────────

    async def handle_add_reminder_command(
        self,
        channel_id: str,
        message: str,
        duration_str: str,
        scheduler: ReminderScheduler,
    ) -> None:
        """
        Schedule a reminder.
        `/remind <message> <duration>` e.g. `/remind check T1 delays 30m`
        """
        delay = parse_duration(duration_str)
        if delay is None:
            await self.send_message(
                channel_id,
                "❌ Could not parse duration. Try `30m`, `1h`, `2h30m`, or `in 45 minutes`.",
            )
            return

        reminder = scheduler.add(
            channel_id=channel_id,
            message=message,
            delay=delay,
            notify_fn=self.send_message,
        )
        mins = int(delay.total_seconds() / 60)
        await self.send_message(
            channel_id,
            f"⏰ Reminder `#{reminder.id}` set — I'll remind you in **{mins} min**:\n"
            f"> {message}",
        )

    async def handle_list_reminders_command(
        self,
        channel_id: str,
        scheduler: ReminderScheduler,
    ) -> None:
        """
        List pending reminders for this channel.
        `/reminders`
        """
        pending = scheduler.pending_for(channel_id)
        await self.send_message(channel_id, format_reminder_list(pending))

    async def handle_cancel_reminder_command(
        self,
        channel_id: str,
        reminder_id: str,
        scheduler: ReminderScheduler,
    ) -> None:
        """
        Cancel a pending reminder by ID.
        `/cancel-reminder <id>`
        """
        if scheduler.cancel(reminder_id):
            await self.send_message(
                channel_id,
                f"✅ Reminder `#{reminder_id}` cancelled.",
            )
        else:
            await self.send_message(
                channel_id,
                f"❌ No pending reminder with ID `#{reminder_id}`.",
            )

    # ── Legacy helper ─────────────────────────────────────────────────────────

    async def handle_alert_trigger(self, trip_id: str, stop_id: str) -> None:
        """Direct alert for *trip_id* reaching *stop_id* — for test use."""
        await self.send_message(
            _DEFAULT_CHANNEL,
            f"✅ **Alert Triggered** — Trip `{trip_id}` has arrived at stop `{stop_id}`!",
        )
