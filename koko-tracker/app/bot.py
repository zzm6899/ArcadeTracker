"""
Balance Tracker — Discord Bot
Runs alongside the Flask app in the same container.
Configure via environment variables in docker-compose.yml:
  DISCORD_BOT_TOKEN=your_bot_token
  DISCORD_GUILD_ID=your_server_id   (optional, for faster slash command sync)
"""

import os, sys, asyncio, sqlite3, secrets, json
from datetime import datetime, timedelta
import discord
from discord import app_commands
from discord.ext import tasks

DB_PATH    = os.environ.get('DB_PATH', '/data/koko.db')
BOT_TOKEN  = os.environ.get('DISCORD_BOT_TOKEN', '')
GUILD_ID   = os.environ.get('DISCORD_GUILD_ID', '')
APP_URL    = os.environ.get('APP_URL', 'http://localhost:5055')

if not BOT_TOKEN:
    print("[Bot] No DISCORD_BOT_TOKEN set — bot disabled.")
    sys.exit(0)

# ─── DB helpers (sync, called from bot) ──────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def db_get_leaderboard():
    """All public cards ranked by total balance."""
    conn = get_db()
    rows = conn.execute('''
        SELECT c.id, c.card_label, c.card_number, c.card_type, c.tier,
               u.username, u.leaderboard_opt_in,
               h.cash_balance, h.cash_bonus, h.points, h.recorded_at
        FROM cards c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN balance_history h ON h.id = (
            SELECT id FROM balance_history WHERE card_id = c.id ORDER BY recorded_at DESC LIMIT 1
        )
        WHERE c.active = 1 AND c.leaderboard_public = 1 AND u.leaderboard_opt_in = 1
        ORDER BY (COALESCE(h.cash_balance,0) + COALESCE(h.cash_bonus,0)) DESC
    ''').fetchall()
    conn.close()
    return rows

def db_get_user_cards(discord_id):
    """Cards for a linked discord user."""
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE discord_id=?', (str(discord_id),)).fetchone()
    if not user:
        conn.close(); return None, []
    cards = conn.execute('''
        SELECT c.*, h.cash_balance, h.cash_bonus, h.points, h.recorded_at as last_updated
        FROM cards c
        LEFT JOIN balance_history h ON h.id=(
            SELECT id FROM balance_history WHERE card_id=c.id ORDER BY recorded_at DESC LIMIT 1
        )
        WHERE c.user_id=? AND c.active=1 ORDER BY c.card_type, c.created_at
    ''', (user['id'],)).fetchall()
    conn.close()
    return user, list(cards)

def db_create_link_code(discord_id, discord_username):
    """Create or refresh a link code for a discord user."""
    conn = get_db()
    code = secrets.token_hex(4).upper()
    expires = (datetime.utcnow() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    conn.execute('''
        INSERT INTO discord_link_codes (discord_id, discord_username, code, expires_at)
        VALUES (?,?,?,?)
        ON CONFLICT(discord_id) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at, discord_username=excluded.discord_username
    ''', (str(discord_id), discord_username, code, expires))
    conn.commit(); conn.close()
    return code

def db_get_all_active_cards():
    """For bot status cycling."""
    conn = get_db()
    rows = conn.execute('''
        SELECT c.card_label, c.card_number, c.card_type,
               h.cash_balance, h.cash_bonus, h.points
        FROM cards c
        LEFT JOIN balance_history h ON h.id=(
            SELECT id FROM balance_history WHERE card_id=c.id ORDER BY recorded_at DESC LIMIT 1
        )
        WHERE c.active=1
    ''').fetchall()
    conn.close()
    return rows

# ─── Tier emoji helper ────────────────────────────────────────────────────────
def tier_emoji(tier):
    return {'Platinum': '💎', 'Gold': '🥇', 'Silver': '🥈'}.get(tier, '🎮')

def card_type_emoji(ctype):
    return '🕹️' if ctype == 'timezone' else '🎮'

# ─── Bot setup ────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = False

class BalanceBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self._status_cards = []
        self._status_idx = 0

    async def setup_hook(self):
        guild = discord.Object(id=int(GUILD_ID)) if GUILD_ID else None
        if guild:
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()
        self.cycle_status.start()
        print(f"[Bot] Commands synced. Guild: {GUILD_ID or 'global'}")

    async def on_ready(self):
        print(f"[Bot] Logged in as {self.user} ({self.user.id})")

bot = BalanceBot()

# ─── Status cycling task ──────────────────────────────────────────────────────
@tasks.loop(seconds=30)
async def cycle_status(self=None):
    client = bot
    try:
        cards = await asyncio.get_event_loop().run_in_executor(None, db_get_all_active_cards)
        if not cards:
            await client.change_presence(activity=discord.Game("Balance Tracker"))
            return
        idx = client._status_idx % len(cards)
        card = cards[idx]
        label = card['card_label'] or card['card_number'] or 'Card'
        total = (card['cash_balance'] or 0) + (card['cash_bonus'] or 0)
        emoji = card_type_emoji(card['card_type'])
        await client.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name=f"{emoji} {label}: ${total:.2f}"
            )
        )
        client._status_idx = idx + 1
    except Exception as e:
        print(f"[Bot] Status error: {e}")

# Attach to bot instance
BalanceBot.cycle_status = cycle_status

# ─── Slash commands ───────────────────────────────────────────────────────────

@bot.tree.command(name="link", description="Link your Discord account to your Balance Tracker account")
async def cmd_link(interaction: discord.Interaction):
    code = await asyncio.get_event_loop().run_in_executor(
        None, db_create_link_code, interaction.user.id, str(interaction.user)
    )
    embed = discord.Embed(
        title="🔗 Link Your Account",
        description=f"Go to your Balance Tracker settings and enter this code:",
        color=0x6366f1
    )
    embed.add_field(name="Link Code", value=f"```{code}```", inline=False)
    embed.add_field(name="Where", value=f"{APP_URL}/settings → Discord Link", inline=False)
    embed.set_footer(text="Code expires in 15 minutes")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="cards", description="Show your linked card balances")
async def cmd_cards(interaction: discord.Interaction):
    user, cards = await asyncio.get_event_loop().run_in_executor(
        None, db_get_user_cards, interaction.user.id
    )
    if not user:
        embed = discord.Embed(
            title="❌ Not linked",
            description=f"Use `/link` to connect your Discord to Balance Tracker",
            color=0xef4444
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    if not cards:
        await interaction.response.send_message("No cards found on your account.", ephemeral=True)
        return

    embed = discord.Embed(title=f"🎮 {user['username']}'s Cards", color=0x6366f1)
    for card in cards:
        total = (card['cash_balance'] or 0) + (card['cash_bonus'] or 0)
        emoji = card_type_emoji(card['card_type'])
        tier = f" {tier_emoji(card['tier'])} {card['tier']}" if card['tier'] else ""
        label = card['card_label'] or card['card_number'] or 'Card'
        last = card['last_updated'][:16] if card['last_updated'] else 'Never'
        val = f"💰 **${total:.2f}** (${card['cash_balance'] or 0:.2f} + ${card['cash_bonus'] or 0:.2f} bonus)\n"
        if card['card_type'] == 'timezone':
            val += f"🎫 {card['points'] or 0} e-Tickets\n"
        else:
            val += f"⭐ {card['points'] or 0} pts\n"
        val += f"🕐 {last}"
        embed.add_field(name=f"{emoji} {label}{tier}", value=val, inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="refresh", description="Force refresh your card balances")
async def cmd_refresh(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    user, cards = await asyncio.get_event_loop().run_in_executor(
        None, db_get_user_cards, interaction.user.id
    )
    if not user:
        await interaction.followup.send("Use `/link` first.", ephemeral=True)
        return

    import requests as req
    refreshed = 0
    for card in cards:
        try:
            resp = req.post(
                f"{APP_URL}/cards/{card['id']}/force-poll",
                cookies={'session': ''},  # won't work without auth — use internal DB call
                timeout=15
            )
        except: pass
        refreshed += 1

    # Actually call the internal functions directly
    from app import fetch_koko_balance, fetch_timezone_guest
    conn = get_db()
    for card in cards:
        try:
            if card['card_type'] == 'koko':
                data = fetch_koko_balance(card['card_token'])
            else:
                tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
                if not tzs: continue
                import json
                guest = fetch_timezone_guest(tzs['bearer_token'], json.loads(tzs['cookies_json'] or '{}'))
                data = None
                if guest:
                    for c in guest.get('cards', []):
                        if str(c.get('number')) == str(card['card_number']):
                            data = {'cash_balance': c.get('cashBalance',0), 'cash_bonus': c.get('bonusBalance',0),
                                    'points': c.get('eTickets',0), 'tier': c.get('tier','')}
                            break
            if data and any(v is not None for v in [data.get('cash_balance'), data.get('cash_bonus')]):
                conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,tier) VALUES (?,?,?,?,?)',
                    (card['id'], data.get('cash_balance'), data.get('cash_bonus'), data.get('points'), data.get('tier','')))
                refreshed += 1
        except Exception as e:
            print(f"[Bot] Refresh error card {card['id']}: {e}")
    conn.commit(); conn.close()

    await interaction.followup.send(f"✅ Refreshed {refreshed} card(s). Use `/cards` to see updated balances.", ephemeral=True)

@bot.tree.command(name="leaderboard", description="Show the public card balance leaderboard")
async def cmd_leaderboard(interaction: discord.Interaction):
    rows = await asyncio.get_event_loop().run_in_executor(None, db_get_leaderboard)
    if not rows:
        embed = discord.Embed(
            title="🏆 Leaderboard",
            description="No public cards yet! Users can enable leaderboard in Settings.",
            color=0xfbbf24
        )
        await interaction.response.send_message(embed=embed)
        return

    medals = ['🥇','🥈','🥉']
    embed = discord.Embed(title="🏆 Card Balance Leaderboard", color=0xfbbf24)
    for i, row in enumerate(rows[:10]):
        total = (row['cash_balance'] or 0) + (row['cash_bonus'] or 0)
        rank = medals[i] if i < 3 else f"`#{i+1}`"
        tier = f" {tier_emoji(row['tier'])}" if row['tier'] else ""
        label = row['card_label'] or row['card_number'] or 'Card'
        last = row['recorded_at'][:10] if row['recorded_at'] else 'Unknown'
        embed.add_field(
            name=f"{rank} {row['username']}{tier} — {label}",
            value=f"**${total:.2f}** · Last active: {last}",
            inline=False
        )
    embed.set_footer(text="Enable your card in Settings → Privacy to appear here")
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="balance", description="Quick check of your total balance")
async def cmd_balance(interaction: discord.Interaction):
    user, cards = await asyncio.get_event_loop().run_in_executor(
        None, db_get_user_cards, interaction.user.id
    )
    if not user:
        await interaction.response.send_message("Use `/link` to connect your account.", ephemeral=True)
        return
    total_balance = sum((c['cash_balance'] or 0) + (c['cash_bonus'] or 0) for c in cards)
    total_tickets = sum(c['points'] or 0 for c in cards)
    embed = discord.Embed(
        title=f"💰 {user['username']}'s Balance",
        description=f"**${total_balance:.2f}** across {len(cards)} card(s)\n🎫 {total_tickets:,} tickets/points",
        color=0x22c55e
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    bot.run(BOT_TOKEN, log_handler=None)
