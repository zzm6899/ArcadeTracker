"""
Discord bot entry point.

Run this file directly to start the live bot:
    python bot_main.py

Required environment variables:
    DISCORD_BOT_TOKEN  — your bot token from discord.com/developers
    TFNSW_API_KEY      — TfNSW Open Data API key
    DISCORD_GUILD_ID   — (optional) guild ID for instant command sync during dev

The bot registers slash commands, starts background polling loops
(location alerts, delay monitor, reminder delivery), and forwards
all user interactions to BotHandler.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

# Ensure emoji/Unicode renders correctly on all platforms.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import discord
from discord import app_commands
from discord.ext import tasks

from app import build_services
from discord_handler.commands import register_commands

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")

if not BOT_TOKEN:
    logger.error(
        "DISCORD_BOT_TOKEN is not set. "
        "Export it in your environment or docker-compose.yml and restart."
    )
    sys.exit(1)

# ── Build services ─────────────────────────────────────────────────────────────
api_service, bot_handler, location_sm, delay_monitor, reminder_scheduler = build_services()

# Expose api_service for autocomplete in commands.py
import app as _app_module
_app_module._api_service = api_service


# ── Discord client ─────────────────────────────────────────────────────────────

intents = discord.Intents.default()
intents.message_content = False


class TransportBot(discord.Client):
    def __init__(self) -> None:
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self) -> None:
        # Allow the bot to be used in guilds, DMs, and group DMs.
        self.tree.allowed_installs = app_commands.AppInstallationType(
            guild=True, user=True
        )
        self.tree.allowed_contexts = app_commands.AppCommandContext(
            guild=True, dm_channel=True, private_channel=True
        )

        # Register all slash commands.
        register_commands(
            tree=self.tree,
            bot=bot_handler,
            location_sm=location_sm,
            delay_monitor=delay_monitor,
            scheduler=reminder_scheduler,
        )

        # Sync commands — guild-scoped sync is instant; global sync takes ~1 hour.
        guild = discord.Object(id=int(GUILD_ID)) if GUILD_ID else None
        if guild:
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()
        logger.info("Commands synced. Guild: %s", GUILD_ID or "global")

    async def on_ready(self) -> None:
        logger.info("Logged in as %s (id=%s)", self.user, self.user.id)

        # Give BotHandler a reference to this client so background sends work.
        bot_handler.set_client(self)

        # Start background loops.
        if not location_alert_loop.is_running():
            location_alert_loop.start()
        if not reminder_loop.is_running():
            reminder_loop.start()
        if not status_loop.is_running():
            status_loop.start()

        logger.info("All background loops started.")

    async def on_app_command_error(
        self,
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ) -> None:
        msg = f"❌ An error occurred: {error}"
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)
        logger.exception("App command error: %s", error)


client = TransportBot()


# ── Background loops ───────────────────────────────────────────────────────────

@tasks.loop(seconds=30)
async def location_alert_loop() -> None:
    """Poll vehicle positions and fire any pending location alerts."""
    try:
        await location_sm.poll_once()
    except Exception:
        logger.exception("location_alert_loop error")


@tasks.loop(seconds=10)
async def reminder_loop() -> None:
    """Deliver reminders that are now due."""
    try:
        await reminder_scheduler._deliver_due()
    except Exception:
        logger.exception("reminder_loop error")


@tasks.loop(seconds=60)
async def status_loop() -> None:
    """Update the bot's Discord status with a transport fact."""
    _statuses = [
        discord.Activity(
            type=discord.ActivityType.watching, name="Sydney transport"
        ),
        discord.Activity(type=discord.ActivityType.listening, name="/trip help"),
        discord.Activity(type=discord.ActivityType.watching, name="live departures"),
    ]
    try:
        idx = status_loop.current_loop % len(_statuses)
        await client.change_presence(activity=_statuses[idx])
    except Exception:
        logger.exception("status_loop error")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    client.run(BOT_TOKEN, log_handler=None)
