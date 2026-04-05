"""
Reminder feature for the Discord bot.

* Standalone /reminder slash commands (set, list, delete).
* Shared DB helpers used by transport_cmds.py for the transport "Remind me" button.
* The delivery loop lives in bot.py (needs the discord.Client instance).

DB table: reminders  (same SQLite DB as the rest of the bot)
"""

import asyncio
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands
from zoneinfo import ZoneInfo

DB_PATH = os.environ.get("DB_PATH", "/data/koko.db")
SYDNEY_TZ = ZoneInfo("Australia/Sydney")

REMINDER_COLOR = 0x6366F1


# ─── DB setup ─────────────────────────────────────────────────────────────────

def reminder_db_init():
    """Create the reminders table if it doesn't exist yet."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reminders (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id  TEXT NOT NULL,
            channel_id  TEXT,
            guild_id    TEXT,
            message     TEXT NOT NULL,
            remind_at   TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now')),
            delivered   INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


# ─── DB helpers ───────────────────────────────────────────────────────────────

def db_add_reminder(
    discord_id,
    channel_id,
    guild_id,
    message: str,
    remind_at: datetime,
) -> int:
    """Insert a reminder and return its new row id."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO reminders (discord_id, channel_id, guild_id, message, remind_at) "
        "VALUES (?,?,?,?,?)",
        (
            str(discord_id),
            str(channel_id) if channel_id else None,
            str(guild_id) if guild_id else None,
            message,
            remind_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return row_id


def db_get_due_reminders() -> list:
    """Return all undelivered reminders whose remind_at is now or in the past."""
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM reminders WHERE delivered=0 AND remind_at <= ?",
        (now_utc,),
    ).fetchall()
    conn.close()
    return rows


def db_mark_delivered(reminder_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE reminders SET delivered=1 WHERE id=?", (reminder_id,))
    conn.commit()
    conn.close()


def db_get_reminders(discord_id) -> list:
    """Return all pending (undelivered) reminders for a user, soonest first."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM reminders WHERE discord_id=? AND delivered=0 ORDER BY remind_at ASC",
        (str(discord_id),),
    ).fetchall()
    conn.close()
    return rows


def db_delete_reminder(discord_id, reminder_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "DELETE FROM reminders WHERE id=? AND discord_id=?",
        (reminder_id, str(discord_id)),
    )
    conn.commit()
    conn.close()


# ─── Time parser ──────────────────────────────────────────────────────────────

def parse_reminder_time(text: str) -> datetime | None:
    """
    Parse a natural-language offset into an absolute datetime (Sydney tz).

    Accepts:
      "in 10 minutes" / "10 minutes" / "10m" / "10"
      "in 2 hours" / "2h"
      "in 1h30m" / "in 1 hour 30 minutes"
      "in 30 seconds" / "30s"
      "in 1h30m20s"
    Returns None if the input cannot be parsed.
    """
    text = text.strip().lower()
    now = datetime.now(SYDNEY_TZ)

    # "in NhMmSs" — full combined form (hours + minutes + seconds)
    m = re.fullmatch(
        r"(?:in\s+)?(\d+)\s*(?:hours?|hrs?|h)\s*(\d+)\s*(?:minutes?|mins?|m)\s*(\d+)\s*(?:seconds?|secs?|s)",
        text,
    )
    if m:
        return now + timedelta(hours=int(m.group(1)), minutes=int(m.group(2)), seconds=int(m.group(3)))

    # "in NhMm" / "in N hours M minutes"
    m = re.fullmatch(
        r"(?:in\s+)?(\d+)\s*(?:hours?|hrs?|h)\s*(\d+)\s*(?:minutes?|mins?|m)?", text
    )
    if m:
        return now + timedelta(hours=int(m.group(1)), minutes=int(m.group(2)))

    # "in N hours" variants
    m = re.fullmatch(r"(?:in\s+)?(\d+)\s*(?:hours?|hrs?|h)", text)
    if m:
        return now + timedelta(hours=int(m.group(1)))

    # "in N minutes" variants
    m = re.fullmatch(r"(?:in\s+)?(\d+)\s*(?:minutes?|mins?|m)", text)
    if m:
        return now + timedelta(minutes=int(m.group(1)))

    # "in N seconds" variants
    m = re.fullmatch(r"(?:in\s+)?(\d+)\s*(?:seconds?|secs?|s)", text)
    if m:
        return now + timedelta(seconds=int(m.group(1)))

    # Plain number → treat as minutes
    m = re.fullmatch(r"(\d+)", text)
    if m:
        return now + timedelta(minutes=int(m.group(1)))

    return None


# ─── Shared reminder modal (used by transport_cmds) ───────────────────────────

class ReminderModal(discord.ui.Modal, title="🔔 Set a Reminder"):
    """
    Modal that captures a 'remind me in X' string.

    ``context_message`` is the reminder text pre-filled for the user.
    ``channel_id`` and ``guild_id`` are stored with the reminder so the
    delivery loop can fall back to the channel if a DM fails.
    """

    when_input = discord.ui.TextInput(
        label="Remind me in…",
        placeholder='e.g. "10 minutes", "2 hours", "30"',
        max_length=40,
    )

    def __init__(
        self,
        context_message: str,
        channel_id: int | None,
        guild_id: int | None,
    ):
        super().__init__()
        self._context = context_message
        self._channel_id = channel_id
        self._guild_id = guild_id

    async def on_submit(self, interaction: discord.Interaction):
        remind_at = parse_reminder_time(self.when_input.value)
        if not remind_at:
            await interaction.response.send_message(
                '❌ Could not parse that time.\n'
                'Try `"10 minutes"`, `"2 hours"`, `"1h30m"` or just `"30"` for 30 mins.',
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True)
        await asyncio.to_thread(
            db_add_reminder,
            interaction.user.id,
            self._channel_id,
            self._guild_id,
            self._context,
            remind_at,
        )

        mins = max(1, int((remind_at - datetime.now(SYDNEY_TZ)).total_seconds() / 60))
        time_str = remind_at.strftime("%H:%M")
        await interaction.followup.send(
            embed=discord.Embed(
                description=(
                    f"🔔 Reminder set for **{time_str}** "
                    f"(in **{mins} min{'s' if mins != 1 else ''}**)!\n\n"
                    f"> {self._context[:200]}"
                ),
                color=REMINDER_COLOR,
            ),
            ephemeral=True,
        )


# ─── /reminder command group ──────────────────────────────────────────────────

def register_reminder_commands(tree: app_commands.CommandTree):
    """Register the /reminder slash command group."""

    reminder_group = app_commands.Group(
        name="reminder",
        description="Set personal timed reminders",
    )

    # ── /reminder set ─────────────────────────────────────────────────────────

    @reminder_group.command(
        name="set",
        description='Set a reminder — e.g. "in 10 minutes", "in 2 hours"',
    )
    @app_commands.describe(
        when='When to remind — "in 10 minutes", "in 2 hours", "30" (= 30 mins)',
        note="What to remind you about",
    )
    async def cmd_reminder_set(
        interaction: discord.Interaction, when: str, note: str
    ):
        remind_at = parse_reminder_time(when)
        if not remind_at:
            await interaction.response.send_message(
                '❌ Could not parse that time.\n'
                'Try `"in 10 minutes"`, `"in 2 hours"`, `"1h30m"` or just `"30"`.',
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True)
        channel_id = interaction.channel_id
        guild_id = interaction.guild_id
        await asyncio.to_thread(
            db_add_reminder, interaction.user.id, channel_id, guild_id, note, remind_at
        )

        mins = max(1, int((remind_at - datetime.now(SYDNEY_TZ)).total_seconds() / 60))
        time_str = remind_at.strftime("%H:%M")
        await interaction.followup.send(
            embed=discord.Embed(
                description=(
                    f"🔔 Reminder set for **{time_str}** "
                    f"(in **{mins} min{'s' if mins != 1 else ''}**)!\n\n"
                    f"> {note[:200]}"
                ),
                color=REMINDER_COLOR,
            ),
            ephemeral=True,
        )

    # ── /reminder list ────────────────────────────────────────────────────────

    @reminder_group.command(name="list", description="List your pending reminders")
    async def cmd_reminder_list(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        rows = await asyncio.to_thread(db_get_reminders, interaction.user.id)
        if not rows:
            await interaction.followup.send(
                embed=discord.Embed(
                    description="You have no pending reminders.",
                    color=REMINDER_COLOR,
                ),
                ephemeral=True,
            )
            return

        embed = discord.Embed(title="🔔 Your Pending Reminders", color=REMINDER_COLOR)
        for r in rows:
            remind_dt = datetime.strptime(r["remind_at"], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
            time_str = remind_dt.astimezone(SYDNEY_TZ).strftime("%a %d %b %H:%M")
            mins_left = max(0, int((remind_dt - datetime.now(timezone.utc)).total_seconds() / 60))
            embed.add_field(
                name=(
                    f"#{r['id']} — {time_str} "
                    f"({mins_left} min{'s' if mins_left != 1 else ''} left)"
                ),
                value=r["message"][:200],
                inline=False,
            )
        embed.set_footer(text="/reminder delete <id> to cancel")
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── /reminder delete ──────────────────────────────────────────────────────

    @reminder_group.command(name="delete", description="Cancel a pending reminder by its ID")
    @app_commands.describe(reminder_id="Reminder ID shown in /reminder list")
    async def cmd_reminder_delete(interaction: discord.Interaction, reminder_id: int):
        await interaction.response.defer(ephemeral=True)
        await asyncio.to_thread(db_delete_reminder, interaction.user.id, reminder_id)
        await interaction.followup.send(
            embed=discord.Embed(
                description=f"🗑️ Reminder **#{reminder_id}** cancelled.",
                color=REMINDER_COLOR,
            ),
            ephemeral=True,
        )

    tree.add_command(reminder_group)
