"""
Service Layer — business logic, scheduling, and state machines.
Sits between data_layer (API calls) and discord_handler (presentation).
Does NOT import from discord_handler; communicates via callbacks.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Awaitable, Callable

from data_layer.api_service import APIService
from utils.utilities import calculate_delay_minutes, format_delay_alert

logger = logging.getLogger(__name__)


# ── Unit 1: Location Alert State Machine ─────────────────────────────────────

@dataclass
class AlertSubscription:
    """One user's request to be notified when a vehicle reaches a stop."""
    trip_id: str
    target_stop_id: str
    channel_id: str
    # Callback: (channel_id, message) -> awaitable
    notify_fn: Callable[[str, str], Awaitable[None]]
    # Internal state
    fired: bool = field(default=False, init=False)


class LocationAlertStateMachine:
    """
    Polls live vehicle positions and fires a one-shot notification the moment
    a tracked vehicle reaches (or departs) its target stop.

    Usage:
        sm = LocationAlertStateMachine(api_service)
        sm.register(trip_id, stop_id, channel_id, bot.send_message)
        asyncio.create_task(sm.run(poll_interval=30))
    """

    def __init__(self, api_service: APIService, poll_interval: int = 30):
        self._api = api_service
        self._poll_interval = poll_interval
        self._subscriptions: list[AlertSubscription] = []
        self._running = False

    def register(
        self,
        trip_id: str,
        target_stop_id: str,
        channel_id: str,
        notify_fn: Callable[[str, str], Awaitable[None]],
    ) -> None:
        """Add a new location alert subscription."""
        sub = AlertSubscription(
            trip_id=trip_id,
            target_stop_id=target_stop_id,
            channel_id=channel_id,
            notify_fn=notify_fn,
        )
        self._subscriptions.append(sub)
        logger.info(
            "LocationAlert registered: trip=%s stop=%s channel=%s",
            trip_id, target_stop_id, channel_id,
        )

    async def run(self) -> None:
        """Poll loop. Runs until stopped or all subscriptions have fired."""
        self._running = True
        logger.info("LocationAlertStateMachine started (poll=%ds)", self._poll_interval)
        while self._running and self._subscriptions:
            await self.poll_once()
            await asyncio.sleep(self._poll_interval)
        self._running = False
        logger.info("LocationAlertStateMachine stopped.")

    async def poll_once(self) -> None:
        """Run a single poll cycle — checks all pending subscriptions."""
        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        pending = [s for s in self._subscriptions if not s.fired]
        for sub in pending:
            await self._check_subscription(sub, now_iso)
        if any(s.fired for s in pending):
            self._subscriptions = [s for s in pending if not s.fired]

    def stop(self) -> None:
        self._running = False

    async def _check_subscription(self, sub: AlertSubscription, now_iso: str) -> None:
        position = self._api.get_vehicle_position(sub.trip_id, now_iso)
        if position is None:
            logger.warning("No position data for trip %s — skipping cycle.", sub.trip_id)
            return

        current_stop = position.get("stop_id")
        if current_stop != sub.target_stop_id:
            return

        # Confirmed stop passage — fire the alert exactly once.
        sub.fired = True
        msg = (
            f"✅ **Location Alert** — Trip `{sub.trip_id}`\n"
            f"> Vehicle has reached stop `{sub.target_stop_id}` "
            f"at {position.get('timestamp', now_iso)}"
        )
        try:
            await sub.notify_fn(sub.channel_id, msg)
            logger.info(
                "Alert fired: trip=%s stop=%s channel=%s",
                sub.trip_id, sub.target_stop_id, sub.channel_id,
            )
        except Exception:
            logger.exception(
                "Failed to deliver alert for trip=%s stop=%s",
                sub.trip_id, sub.target_stop_id,
            )


# ── Unit 3: Delay / Congestion Monitor ───────────────────────────────────────

class DelayMonitor:
    """
    Compares live arrival predictions against scheduled times and fires a
    "Delay Alert" when the deviation exceeds a user-configurable threshold.

    Each call to check_and_alert() is stateless — the caller decides
    how often to invoke it (e.g., from a polling loop or a Discord command).
    """

    DEFAULT_THRESHOLD_MINUTES = 5

    def __init__(self, api_service: APIService):
        self._api = api_service

    async def check_and_alert(
        self,
        trip_id: str,
        stop_id: str,
        channel_id: str,
        notify_fn: Callable[[str, str], Awaitable[None]],
        threshold_minutes: int = DEFAULT_THRESHOLD_MINUTES,
    ) -> bool:
        """
        Fetch live and scheduled arrival times for *trip_id* at *stop_id*.
        If the delay exceeds *threshold_minutes*, call *notify_fn* and return True.
        Returns False when the service is on time or data is unavailable.
        """
        scheduled = self._api.get_scheduled_stop_time(trip_id, stop_id)
        live = self._api.get_live_arrival(trip_id, stop_id)

        if not scheduled or not live:
            logger.warning(
                "DelayMonitor: missing data for trip=%s stop=%s", trip_id, stop_id
            )
            return False

        delay_min = calculate_delay_minutes(
            scheduled["scheduled_arrival"],
            live["predicted_arrival"],
        )

        if abs(delay_min) < threshold_minutes:
            return False

        msg = format_delay_alert(
            trip_id=trip_id,
            stop_name=scheduled.get("stop_name", stop_id),
            delay_minutes=delay_min,
            scheduled_iso=scheduled["scheduled_arrival"],
            predicted_iso=live["predicted_arrival"],
        )
        await notify_fn(channel_id, msg)
        logger.info(
            "Delay alert sent: trip=%s stop=%s delay=%dmin", trip_id, stop_id, delay_min
        )
        return True
