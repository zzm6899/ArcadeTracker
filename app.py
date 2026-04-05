"""
Application entry point.

Responsibility: initialise all layers and wire them together.
  - data_layer/api_service.py  -> APIService          (data)
  - service_manager.py         -> LocationAlertStateMachine,
                                  DelayMonitor,
                                  ReminderScheduler   (logic)
  - discord_handler/bot.py     -> BotHandler          (presentation)

No business logic lives here — this file only bootstraps and starts
the async event loop.

Environment variables (read at startup):
  TFNSW_API_KEY    — TfNSW Open Data API key
  DISCORD_BOT_TOKEN — Discord bot token (unused in mock mode)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

# Ensure emoji/Unicode in mock print() calls render on all platforms.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from data_layer.api_service import APIService
from discord_handler.bot import BotHandler
from service_manager import DelayMonitor, LocationAlertStateMachine, ReminderScheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def build_services() -> tuple[APIService, BotHandler, LocationAlertStateMachine, DelayMonitor, ReminderScheduler]:
    """Initialise and return all core service objects."""
    api_service = APIService(api_key=os.environ.get("TFNSW_API_KEY"))
    bot = BotHandler(api_service)
    location_sm = LocationAlertStateMachine(api_service, poll_interval=30)
    delay_monitor = DelayMonitor(api_service)
    reminder_scheduler = ReminderScheduler(poll_interval=10)
    return api_service, bot, location_sm, delay_monitor, reminder_scheduler


async def demo() -> None:
    """
    Smoke-test all features.
    In production this is replaced by the Discord gateway event loop.
    """
    _, bot, location_sm, delay_monitor, scheduler = build_services()

    CH = "test-channel"

    # ── Unit 1: location alert ────────────────────────────────────────────────
    logger.info("=== Unit 1: Location Alert ===")
    await bot.handle_location_alert_command(
        channel_id=CH, trip_id="TRIP-001", stop_id="200060",
        state_machine=location_sm,
    )
    await location_sm.poll_once()

    # ── Unit 2: scheduled trip report ────────────────────────────────────────
    logger.info("=== Unit 2: Scheduled Trip Report ===")
    target = datetime(2026, 4, 7, 14, 30, tzinfo=timezone.utc)
    await bot.handle_scheduled_trip_command(
        channel_id=CH, from_id="Central", to_id="Bondi Beach",
        target_datetime=target,
    )

    # ── Unit 3: delay check ───────────────────────────────────────────────────
    logger.info("=== Unit 3: Delay Check ===")
    await bot.handle_delay_check_command(
        channel_id=CH, trip_id="TRIP-001", stop_id="200060",
        threshold_minutes=3,
    )

    # ── Unit 3 via DelayMonitor (with deduplication) ──────────────────────────
    # First call: delay (5 min) below threshold (10 min) — no alert.
    triggered = await delay_monitor.check_and_alert(
        trip_id="TRIP-001", stop_id="200060", channel_id=CH,
        notify_fn=bot.send_message,
        threshold_minutes=10,
        respect_quiet_hours=False,
    )
    logger.info("DelayMonitor below threshold (should be False): %s", triggered)

    # Second call: delay (5 min) exceeds threshold (3 min) — alert fires, cooldown set.
    triggered2 = await delay_monitor.check_and_alert(
        trip_id="TRIP-001", stop_id="200060", channel_id=CH,
        notify_fn=bot.send_message,
        threshold_minutes=3,
        respect_quiet_hours=False,
    )
    logger.info("DelayMonitor alert fires (should be True): %s", triggered2)

    # Third call: cooldown is active — alert suppressed.
    triggered3 = await delay_monitor.check_and_alert(
        trip_id="TRIP-001", stop_id="200060", channel_id=CH,
        notify_fn=bot.send_message,
        threshold_minutes=3,
        respect_quiet_hours=False,
    )
    logger.info("DelayMonitor cooldown suppresses (should be False): %s", triggered3)

    # ── Unit 4: service disruption dashboard ─────────────────────────────────
    logger.info("=== Unit 4: Service Disruptions ===")
    await bot.handle_disruptions_command(channel_id=CH)

    # ── Departures board ──────────────────────────────────────────────────────
    logger.info("=== Departures Board ===")
    await bot.handle_departures_command(channel_id=CH, stop_id="200060", limit=5)

    # ── Stop search ───────────────────────────────────────────────────────────
    logger.info("=== Stop Search ===")
    await bot.handle_stop_search_command(channel_id=CH, query="central")

    # ── Vehicle status ────────────────────────────────────────────────────────
    logger.info("=== Vehicle Status ===")
    await bot.handle_vehicle_status_command(channel_id=CH, trip_id="TRIP-001")

    # ── Reminders ────────────────────────────────────────────────────────────
    logger.info("=== Reminders ===")
    await bot.handle_add_reminder_command(
        channel_id=CH,
        message="Check T1 delays before leaving",
        duration_str="30m",
        scheduler=scheduler,
    )
    await bot.handle_add_reminder_command(
        channel_id=CH,
        message="Platform change alert",
        duration_str="1h",
        scheduler=scheduler,
    )
    await bot.handle_list_reminders_command(channel_id=CH, scheduler=scheduler)

    # Simulate one reminder firing immediately by backdating its fire_at.
    r = scheduler._reminders[0]
    r.fire_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await scheduler._deliver_due()

    await bot.handle_list_reminders_command(channel_id=CH, scheduler=scheduler)

    # Cancel the remaining reminder.
    remaining = scheduler._reminders[0] if scheduler._reminders else None
    if remaining:
        await bot.handle_cancel_reminder_command(
            channel_id=CH, reminder_id=remaining.id, scheduler=scheduler,
        )

    # Test bad duration parsing.
    await bot.handle_add_reminder_command(
        channel_id=CH,
        message="Bad reminder",
        duration_str="never",
        scheduler=scheduler,
    )


if __name__ == "__main__":
    asyncio.run(demo())
