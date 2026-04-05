"""
Presentation Layer — Discord communication only.
All formatting helpers live in utils/utilities.py.
All business logic lives in service_manager.py.
This file must NOT contain API calls or scheduling state.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Awaitable, Callable

from data_layer.api_service import APIService
from utils.utilities import (
    calculate_delay_minutes,
    format_alert_card,
    format_delay_alert,
    format_trip_report,
    validate_stop_id,
)

_DEFAULT_CHANNEL = "default_channel"

logger = logging.getLogger(__name__)


class BotHandler:
    """Manages all Discord interactions and command dispatching."""

    def __init__(self, api_service: APIService):
        self.api_service = api_service
        logger.info("BotHandler initialized.")

    # ── Core send primitive ───────────────────────────────────────────────────

    async def send_message(self, channel_id: str, content: str) -> None:
        """Send *content* to *channel_id*.  Replace body with real discord.py call."""
        print(f"[Discord -> #{channel_id}]\n{content}\n")

    # ── Unit 1: register a location alert (wires into service_manager) ────────

    async def handle_location_alert_command(
        self,
        channel_id: str,
        trip_id: str,
        stop_id: str,
        state_machine,  # LocationAlertStateMachine — avoids circular import type hint
    ) -> None:
        """
        Register a one-shot location alert.

        Called when a user invokes e.g. `/alert T1234 200060`.
        The state_machine.run() loop (started in app.py) will fire
        send_message() when the vehicle reaches the stop.
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
            f"You'll be notified when the vehicle arrives.",
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
        Handle `/trip <from> <to> [datetime]` — returns a formatted trip report.

        *target_datetime* should be a timezone-aware datetime; when None the
        API defaults to the current time.
        """
        legs = self.api_service.plan_trip(
            from_id=from_id,
            to_id=to_id,
            target_datetime=target_datetime,
        )
        report = format_trip_report(legs, target_datetime)
        await self.send_message(channel_id, report)

    # ── Unit 3: on-demand delay check ────────────────────────────────────────

    async def handle_delay_check_command(
        self,
        channel_id: str,
        trip_id: str,
        stop_id: str,
        threshold_minutes: int = 5,
    ) -> None:
        """
        Handle `/delay <trip_id> <stop_id> [threshold]`.

        Fetches live vs scheduled arrival, sends a Delay Alert if the service
        is running more than *threshold_minutes* off schedule, or an "on time"
        confirmation otherwise.
        """
        scheduled = self.api_service.get_scheduled_stop_time(trip_id, stop_id)
        live = self.api_service.get_live_arrival(trip_id, stop_id)

        if not scheduled or not live:
            await self.send_message(
                channel_id,
                f"⚠️ Could not retrieve timing data for trip `{trip_id}` at stop `{stop_id}`.",
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
                f"is running **on time**.",
            )
            return

        msg = format_delay_alert(
            trip_id=trip_id,
            stop_name=scheduled.get("stop_name", stop_id),
            delay_minutes=delay_min,
            scheduled_iso=scheduled["scheduled_arrival"],
            predicted_iso=live["predicted_arrival"],
        )
        await self.send_message(channel_id, msg)

    # ── Unit 4: service disruption dashboard ─────────────────────────────────

    async def handle_disruptions_command(self, channel_id: str) -> None:
        """
        Handle `/disruptions` — posts a formatted disruption dashboard card.
        """
        alerts = self.api_service.get_service_alerts()
        card = format_alert_card(alerts)
        await self.send_message(channel_id, card)

    # ── Legacy / internal helpers (kept for backward compatibility) ───────────

    async def handle_alert_trigger(self, trip_id: str, stop_id: str) -> None:
        """
        Internal helper: directly send an alert for *trip_id* reaching *stop_id*.
        Prefer registering via LocationAlertStateMachine for live tracking;
        this exists for direct/test invocations.
        """
        msg = (
            f"✅ **Alert Triggered** — Trip `{trip_id}` has arrived at stop `{stop_id}`!"
        )
        await self.send_message(_DEFAULT_CHANNEL, msg)
