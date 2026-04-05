"""
Application entry point.

Responsibility: initialise the three layers and wire them together.
  - data_layer/api_service.py  → APIService  (data)
  - service_manager.py         → LocationAlertStateMachine, DelayMonitor  (logic)
  - discord_handler/bot.py     → BotHandler  (presentation)

No business logic lives here — this file only bootstraps and starts the
async event loop.
"""

from __future__ import annotations

import asyncio
import logging
import sys

# Ensure emoji/Unicode in mock print() calls render correctly on all platforms.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from data_layer.api_service import APIService
from discord_handler.bot import BotHandler
from service_manager import DelayMonitor, LocationAlertStateMachine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def build_services(api_key: str = "MOCK_API_KEY"):
    """Initialise and return the three core service objects."""
    api_service = APIService(api_key)
    bot = BotHandler(api_service)
    location_sm = LocationAlertStateMachine(api_service, poll_interval=30)
    delay_monitor = DelayMonitor(api_service)
    return api_service, bot, location_sm, delay_monitor


async def demo() -> None:
    """
    Smoke-test all five implemented units.
    In production this would be replaced by the Discord gateway event loop.
    """
    _, bot, location_sm, delay_monitor = build_services()

    # ── Unit 1: register a location alert and simulate one poll cycle ─────────
    logger.info("=== Unit 1: Location Alert ===")
    await bot.handle_location_alert_command(
        channel_id="test-channel",
        trip_id="TRIP-001",
        stop_id="200060",          # mock vehicle will report this stop_id
        state_machine=location_sm,
    )
    await location_sm.poll_once()

    # ── Unit 2: scheduled trip report ─────────────────────────────────────────
    logger.info("=== Unit 2: Scheduled Trip Report ===")
    from datetime import datetime, timezone
    target = datetime(2026, 4, 7, 14, 30, tzinfo=timezone.utc)
    await bot.handle_scheduled_trip_command(
        channel_id="test-channel",
        from_id="Central",
        to_id="Bondi Beach",
        target_datetime=target,
    )

    # ── Unit 3: delay check ───────────────────────────────────────────────────
    logger.info("=== Unit 3: Delay Check ===")
    await bot.handle_delay_check_command(
        channel_id="test-channel",
        trip_id="TRIP-001",
        stop_id="200060",
        threshold_minutes=3,       # mock returns 5 min delay → should alert
    )

    # ── Unit 3 (via DelayMonitor): threshold not exceeded ─────────────────────
    triggered = await delay_monitor.check_and_alert(
        trip_id="TRIP-001",
        stop_id="200060",
        channel_id="test-channel",
        notify_fn=bot.send_message,
        threshold_minutes=10,      # mock delay is 5 min → should NOT alert
    )
    logger.info("DelayMonitor triggered (should be False): %s", triggered)

    # ── Unit 4: service disruption dashboard ─────────────────────────────────
    logger.info("=== Unit 4: Service Disruptions ===")
    await bot.handle_disruptions_command(channel_id="test-channel")


if __name__ == "__main__":
    asyncio.run(demo())
