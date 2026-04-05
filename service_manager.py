"""
Service Layer — business logic, scheduling, and state machines.
Sits between data_layer (API calls) and discord_handler (presentation).
Does NOT import from discord_handler; communicates via callbacks.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Awaitable, Callable

from data_layer.api_service import APIService
from utils.utilities import (
    calculate_delay_minutes,
    format_delay_alert,
    format_reminder_list,
    is_quiet_hours,
    parse_iso,
)

if TYPE_CHECKING:
    pass  # future cross-layer type hints go here

logger = logging.getLogger(__name__)

# Maximum lifetime for an unresolved location alert.
_ALERT_TTL = timedelta(hours=2)
# Minimum gap between duplicate delay alerts for the same (trip, stop).
_DELAY_ALERT_COOLDOWN = timedelta(minutes=15)


# ── Unit 1: Location Alert State Machine ─────────────────────────────────────

@dataclass
class AlertSubscription:
    """One user's request to be notified when a vehicle reaches a stop."""
    trip_id: str
    target_stop_id: str
    channel_id: str
    notify_fn: Callable[[str, str], Awaitable[None]]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    fired: bool = field(default=False, init=False)

    @property
    def expired(self) -> bool:
        """True when the alert has been waiting longer than _ALERT_TTL."""
        return (datetime.now(timezone.utc) - self.created_at) > _ALERT_TTL


class LocationAlertStateMachine:
    """
    Polls live vehicle positions and fires a one-shot notification the moment
    a tracked vehicle reaches its target stop.

    Usage:
        sm = LocationAlertStateMachine(api_service)
        sm.register(trip_id, stop_id, channel_id, bot.send_message)
        asyncio.create_task(sm.run())
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
        """Poll loop — runs until stopped or all subscriptions resolve."""
        self._running = True
        logger.info("LocationAlertStateMachine started (poll=%ds)", self._poll_interval)
        while self._running and self._subscriptions:
            await self.poll_once()
            await asyncio.sleep(self._poll_interval)
        self._running = False
        logger.info("LocationAlertStateMachine stopped.")

    async def poll_once(self) -> None:
        """Run a single poll cycle across all pending, non-expired subscriptions."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        active = [s for s in self._subscriptions if not s.fired and not s.expired]
        expired = [s for s in self._subscriptions if not s.fired and s.expired]

        # Notify users whose alerts timed out without firing.
        for sub in expired:
            sub.fired = True
            try:
                await sub.notify_fn(
                    sub.channel_id,
                    f"⏰ Location alert for trip `{sub.trip_id}` at stop "
                    f"`{sub.target_stop_id}` expired after 2 hours without a match.",
                )
            except Exception:
                logger.exception("Failed to send expiry notice for trip=%s", sub.trip_id)

        for sub in active:
            await self._check_subscription(sub, now_iso)

        # Remove all resolved (fired or expired) subscriptions in one pass.
        if any(s.fired for s in self._subscriptions):
            self._subscriptions = [s for s in self._subscriptions if not s.fired]

    def stop(self) -> None:
        self._running = False

    async def _check_subscription(self, sub: AlertSubscription, now_iso: str) -> None:
        position = self._api.get_vehicle_position(sub.trip_id, now_iso)
        if position is None:
            logger.warning("No position data for trip %s — skipping cycle.", sub.trip_id)
            return

        if position.get("stop_id") != sub.target_stop_id:
            return

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
    Delay Alert when the deviation exceeds a configurable threshold.

    Includes per-(trip, stop) cooldown to prevent duplicate alerts.
    """

    DEFAULT_THRESHOLD_MINUTES = 5

    def __init__(self, api_service: APIService):
        self._api = api_service
        # Maps (trip_id, stop_id) -> datetime of last alert sent.
        self._last_alerted: dict[tuple[str, str], datetime] = {}

    async def check_and_alert(
        self,
        trip_id: str,
        stop_id: str,
        channel_id: str,
        notify_fn: Callable[[str, str], Awaitable[None]],
        threshold_minutes: int = DEFAULT_THRESHOLD_MINUTES,
        respect_quiet_hours: bool = True,
    ) -> bool:
        """
        Fetch live and scheduled arrival for *trip_id* at *stop_id*.
        If delay exceeds *threshold_minutes* (and cooldown allows), send an alert.
        Returns True when an alert was sent.
        """
        if respect_quiet_hours and is_quiet_hours():
            logger.debug("Quiet hours — suppressing delay check for trip=%s", trip_id)
            return False

        key = (trip_id, stop_id)
        last = self._last_alerted.get(key)
        if last and (datetime.now(timezone.utc) - last) < _DELAY_ALERT_COOLDOWN:
            logger.debug("Cooldown active for trip=%s stop=%s", trip_id, stop_id)
            return False

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
        self._last_alerted[key] = datetime.now(timezone.utc)
        logger.info(
            "Delay alert sent: trip=%s stop=%s delay=%dmin", trip_id, stop_id, delay_min
        )
        return True


# ── Reminder Scheduler ────────────────────────────────────────────────────────

@dataclass
class Reminder:
    """A scheduled one-shot reminder for a Discord channel."""
    id: str
    channel_id: str
    message: str
    fire_at: datetime
    fired: bool = field(default=False, init=False)


class ReminderScheduler:
    """
    In-memory reminder system.  Fires reminders at their scheduled time by
    calling the provided notify_fn.

    Usage:
        scheduler = ReminderScheduler()
        scheduler.add("channel-id", "Check T1 delays", timedelta(minutes=30), bot.send_message)
        asyncio.create_task(scheduler.run())
    """

    def __init__(self, poll_interval: int = 10):
        self._reminders: list[Reminder] = []
        self._poll_interval = poll_interval
        self._running = False

    def add(
        self,
        channel_id: str,
        message: str,
        delay: timedelta,
        notify_fn: Callable[[str, str], Awaitable[None]],
    ) -> Reminder:
        """Schedule a reminder and return it."""
        reminder = Reminder(
            id=uuid.uuid4().hex[:6].upper(),
            channel_id=channel_id,
            message=message,
            fire_at=datetime.now(timezone.utc) + delay,
        )
        # Store notify_fn alongside the reminder for delivery.
        reminder._notify_fn = notify_fn  # type: ignore[attr-defined]
        self._reminders.append(reminder)
        logger.info(
            "Reminder #%s scheduled in %.0f min: %s",
            reminder.id,
            delay.total_seconds() / 60,
            message,
        )
        return reminder

    def cancel(self, reminder_id: str) -> bool:
        """Cancel a pending reminder by ID.  Returns True when found."""
        for r in self._reminders:
            if r.id == reminder_id and not r.fired:
                r.fired = True
                logger.info("Reminder #%s cancelled.", reminder_id)
                return True
        return False

    def pending_for(self, channel_id: str) -> list[dict]:
        """Return serialised pending reminders for *channel_id*."""
        return [
            {"id": r.id, "message": r.message, "fire_at": r.fire_at.isoformat()}
            for r in self._reminders
            if r.channel_id == channel_id and not r.fired
        ]

    async def run(self) -> None:
        """Background loop — checks for due reminders every *poll_interval* seconds."""
        self._running = True
        logger.info("ReminderScheduler started.")
        while self._running:
            await self._deliver_due()
            await asyncio.sleep(self._poll_interval)
        self._running = False

    def stop(self) -> None:
        self._running = False

    async def _deliver_due(self) -> None:
        now = datetime.now(timezone.utc)
        due = [r for r in self._reminders if not r.fired and r.fire_at <= now]
        for reminder in due:
            reminder.fired = True
            try:
                notify_fn = reminder._notify_fn  # type: ignore[attr-defined]
                await notify_fn(
                    reminder.channel_id,
                    f"⏰ **Reminder** — {reminder.message}",
                )
                logger.info("Reminder #%s delivered.", reminder.id)
            except Exception:
                logger.exception("Failed to deliver reminder #%s.", reminder.id)
        if due:
            self._reminders = [r for r in self._reminders if not r.fired]
