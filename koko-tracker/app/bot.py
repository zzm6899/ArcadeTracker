"""
Balance Tracker — Discord Bot
Configure via docker-compose.yml environment variables:
  DISCORD_BOT_TOKEN=your_bot_token
  DISCORD_GUILD_ID=your_server_id  (optional, faster command sync)
"""

import os, sys, asyncio, sqlite3, secrets, random
from datetime import datetime, timedelta
import discord
from discord import app_commands
from discord.ext import tasks

DB_PATH   = os.environ.get('DB_PATH', '/data/koko.db')
BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN', '')
GUILD_ID  = os.environ.get('DISCORD_GUILD_ID', '')
APP_URL          = os.environ.get('APP_URL', 'http://localhost:5055')
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID', '')

def invite_url():
    cid = DISCORD_CLIENT_ID
    if cid:
        return f"https://discord.com/oauth2/authorize?client_id={cid}"
    return None

def bot_buttons():
    """Returns a View with a website button."""
    view = discord.ui.View()
    view.add_item(discord.ui.Button(label="🌐 Open Website", url=APP_URL, style=discord.ButtonStyle.link))
    return view

if not BOT_TOKEN:
    print("[Bot] No DISCORD_BOT_TOKEN set — bot disabled.")
    sys.exit(0)

# ─── DB helpers ───────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def db_get_user(discord_id):
    conn = get_db()
    u = conn.execute('SELECT * FROM users WHERE discord_id=?', (str(discord_id),)).fetchone()
    conn.close()
    return u

def db_get_user_cards(discord_id):
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

def db_get_leaderboard():
    conn = get_db()
    rows = conn.execute(
        'SELECT c.id, c.card_label, c.card_type, c.tier, u.username, '
        'h.cash_balance, h.cash_bonus, h.points, h.recorded_at '
        'FROM cards c JOIN users u ON c.user_id=u.id '
        'LEFT JOIN balance_history h ON h.id=(SELECT id FROM balance_history WHERE card_id=c.id ORDER BY recorded_at DESC LIMIT 1) '
        'WHERE c.active=1 AND c.leaderboard_public=1 AND u.leaderboard_opt_in=1 '
        'ORDER BY (COALESCE(h.cash_balance,0)+COALESCE(h.cash_bonus,0)) DESC LIMIT 10'
    ).fetchall()
    conn.close()
    return rows

def db_create_link_code(discord_id, discord_username):
    conn = get_db()
    code = secrets.token_hex(4).upper()
    expires = (datetime.utcnow() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    conn.execute('''
        INSERT INTO discord_link_codes (discord_id, discord_username, code, expires_at)
        VALUES (?,?,?,?)
        ON CONFLICT(discord_id) DO UPDATE SET code=excluded.code,
            expires_at=excluded.expires_at, discord_username=excluded.discord_username
    ''', (str(discord_id), discord_username, code, expires))
    conn.commit(); conn.close()
    return code

def db_get_command_privacy(user_id):
    """Return dict of command->ephemeral for a user."""
    conn = get_db()
    row = conn.execute('SELECT discord_cmd_privacy FROM users WHERE id=?', (user_id,)).fetchone()
    conn.close()
    if not row or not row['discord_cmd_privacy']:
        return {}
    try:
        import json
        return json.loads(row['discord_cmd_privacy'])
    except:
        return {}

def db_set_command_privacy(user_id, cmd, ephemeral):
    import json
    conn = get_db()
    row = conn.execute('SELECT discord_cmd_privacy FROM users WHERE id=?', (user_id,)).fetchone()
    priv = {}
    if row and row['discord_cmd_privacy']:
        try: priv = json.loads(row['discord_cmd_privacy'])
        except: pass
    priv[cmd] = ephemeral
    conn.execute('UPDATE users SET discord_cmd_privacy=? WHERE id=?', (json.dumps(priv), user_id))
    conn.commit(); conn.close()

def db_get_spent(user_id, days=1):
    """Get spending per card for the last N days."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    cards = conn.execute('SELECT id, card_label, card_number, card_type FROM cards WHERE user_id=? AND active=1', (user_id,)).fetchall()
    results = []
    for card in cards:
        rows = conn.execute(
            'SELECT cash_balance, cash_bonus, recorded_at FROM balance_history '
            'WHERE card_id=? AND recorded_at>=? ORDER BY recorded_at ASC',
            (card['id'], since)
        ).fetchall()
        if len(rows) < 2:
            # get latest before window for comparison
            before = conn.execute(
                'SELECT cash_balance, cash_bonus FROM balance_history WHERE card_id=? AND recorded_at<? ORDER BY recorded_at DESC LIMIT 1',
                (card['id'], since)
            ).fetchone()
            latest = conn.execute(
                'SELECT cash_balance, cash_bonus FROM balance_history WHERE card_id=? ORDER BY recorded_at DESC LIMIT 1',
                (card['id'],)
            ).fetchone()
            if before and latest:
                first_total = (before['cash_balance'] or 0) + (before['cash_bonus'] or 0)
                last_total  = (latest['cash_balance'] or 0) + (latest['cash_bonus'] or 0)
                spent = first_total - last_total
                results.append({'label': card['card_label'] or card['card_number'], 'card_type': card['card_type'], 'spent': spent})
            continue
        first_total = (rows[0]['cash_balance'] or 0) + (rows[0]['cash_bonus'] or 0)
        last_total  = (rows[-1]['cash_balance'] or 0) + (rows[-1]['cash_bonus'] or 0)
        spent = first_total - last_total
        results.append({'label': card['card_label'] or card['card_number'], 'card_type': card['card_type'], 'spent': spent})
    conn.close()
    return results

def db_get_stats_for_status():
    """Privacy-safe aggregate stats for bot status messages."""
    conn = get_db()
    total_cards = conn.execute('SELECT COUNT(*) FROM cards WHERE active=1').fetchone()[0]
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    # Sum of all public card balances only
    pub = conn.execute(
        'SELECT SUM(h.cash_balance + h.cash_bonus) as tot FROM cards c '
        'JOIN users u ON c.user_id=u.id '
        'LEFT JOIN balance_history h ON h.id=(SELECT id FROM balance_history WHERE card_id=c.id ORDER BY recorded_at DESC LIMIT 1) '
        'WHERE c.active=1 AND c.leaderboard_public=1 AND u.leaderboard_opt_in=1'
    ).fetchone()
    public_total = pub['tot'] or 0
    top = conn.execute(
        'SELECT c.tier, COUNT(*) as cnt FROM cards c WHERE c.active=1 AND c.tier!=\'\' AND c.tier IS NOT NULL GROUP BY c.tier ORDER BY cnt DESC LIMIT 1'
    ).fetchone()
    top_tier = top['tier'] if top else None
    conn.close()
    return {'cards': total_cards, 'users': total_users, 'public_total': public_total, 'top_tier': top_tier}

def is_ephemeral(user, cmd_name, default=True):
    """Check if a command should be ephemeral for this user."""
    if not user: return default
    priv = db_get_command_privacy(user['id'])
    return priv.get(cmd_name, default)

# ─── Helpers ──────────────────────────────────────────────────────────────────
def tier_emoji(tier):
    return {'Platinum': '💎', 'Gold': '🥇', 'Silver': '🥈'}.get(tier or '', '🎮')

def card_emoji(ctype):
    return '🕹️' if ctype == 'timezone' else '🎮'

def run_sync(fn, *args):
    return asyncio.get_event_loop().run_in_executor(None, fn, *args)

# ─── Bot ──────────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = False

class BalanceBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self._status_idx = 0

    async def setup_hook(self):
        # Allow bot to be used in DMs and group chats (user-installable app)
        self.tree.allowed_installs = discord.app_commands.AppInstallationType(guild=True, user=True)
        self.tree.allowed_contexts = discord.app_commands.AppCommandContext(
            guild=True, dm_channel=True, private_channel=True
        )
        guild = discord.Object(id=int(GUILD_ID)) if GUILD_ID else None
        if guild:
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()
        print(f"[Bot] Commands synced. Guild: {GUILD_ID or 'global'}")

    async def on_ready(self):
        print(f"[Bot] Logged in as {self.user}")
        if not self.status_task.is_running():
            self.status_task.start()

    @tasks.loop(seconds=45)
    async def status_task(self):
        STATUS_TEMPLATES = [
            lambda s: (discord.ActivityType.watching,  f"💰 ${s['public_total']:.0f} in public balances"),
            lambda s: (discord.ActivityType.watching,  f"🎮 {s['cards']} cards tracked"),
            lambda s: (discord.ActivityType.watching,  f"👥 {s['users']} players"),
            lambda s: (discord.ActivityType.playing,   "Balance Tracker"),
            lambda s: (discord.ActivityType.watching,  f"💎 {s['top_tier']} members active") if s['top_tier'] else (discord.ActivityType.watching, f"🎮 {s['cards']} cards tracked"),
        ]
        try:
            stats = await asyncio.get_event_loop().run_in_executor(None, db_get_stats_for_status)
            tmpl = STATUS_TEMPLATES[self._status_idx % len(STATUS_TEMPLATES)]
            atype, name = tmpl(stats)
            await self.change_presence(activity=discord.Activity(type=atype, name=name))
            self._status_idx += 1
            print(f"[Bot] Status: {name}")
        except Exception as e:
            print(f"[Bot] Status error: {e}")

bot = BalanceBot()

# ─── Commands ─────────────────────────────────────────────────────────────────

@bot.tree.command(name="link", description="Link your Discord account to Balance Tracker")
async def cmd_link(interaction: discord.Interaction):
    # Check if already linked
    user = await run_sync(db_get_user, interaction.user.id)
    if user:
        embed = discord.Embed(
            title="✅ Already Linked",
            description=f"Your Discord is linked to **{user['username']}** on Balance Tracker.",
            color=0x22c55e
        )
        embed.set_footer(text="To unlink, go to Settings on the website.")
        # Unlink button points to website settings
        view = discord.ui.View()
        view.add_item(discord.ui.Button(label="🌐 Manage on Website", url=f"{APP_URL}/settings", style=discord.ButtonStyle.link))
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
        return
    code = await run_sync(db_create_link_code, interaction.user.id, str(interaction.user))
    embed = discord.Embed(title="🔗 Link Your Account", color=0x6366f1,
        description="Enter this code in Balance Tracker Settings → Discord Link")
    embed.add_field(name="Code (expires 15min)", value=f"```{code}```", inline=False)
    embed.add_field(name="Where", value=f"{APP_URL}/settings", inline=False)
    await interaction.response.send_message(embed=embed, view=bot_buttons(), ephemeral=True)


@bot.tree.command(name="cards", description="Show your card balances")
async def cmd_cards(interaction: discord.Interaction):
    user, cards = await run_sync(db_get_user_cards, interaction.user.id)
    ephem = is_ephemeral(user, 'cards', default=True)
    if not user:
        await interaction.response.send_message("❌ Use `/link` to connect your account.", ephemeral=True); return
    if not cards:
        await interaction.response.send_message("No cards found.", ephemeral=ephem); return

    embed = discord.Embed(title=f"🎮 {user['username']}'s Cards", color=0x6366f1)
    for card in cards:
        total = (card['cash_balance'] or 0) + (card['cash_bonus'] or 0)
        tier  = f" {tier_emoji(card['tier'])} {card['tier']}" if card['tier'] else ""
        label = card['card_label'] or 'Card'
        last  = card['last_updated'][:16] if card['last_updated'] else 'Never'
        pts_label = 'e-Tickets' if card['card_type'] == 'timezone' else 'pts'
        val = (f"💰 **${total:.2f}** · ${card['cash_balance'] or 0:.2f} + ${card['cash_bonus'] or 0:.2f} bonus\n"
               f"🎫 {card['points'] or 0:,} {pts_label}\n"
               f"🕐 {last}")
        embed.add_field(name=f"{card_emoji(card['card_type'])} {label}{tier}", value=val, inline=False)
    await interaction.response.send_message(embed=embed, view=bot_buttons(), ephemeral=ephem)


@bot.tree.command(name="balance", description="Quick total balance summary")
async def cmd_balance(interaction: discord.Interaction):
    user, cards = await run_sync(db_get_user_cards, interaction.user.id)
    ephem = is_ephemeral(user, 'balance', default=True)
    if not user:
        await interaction.response.send_message("❌ Use `/link` first.", ephemeral=True); return
    total = sum((c['cash_balance'] or 0) + (c['cash_bonus'] or 0) for c in cards)
    tickets = sum(c['points'] or 0 for c in cards)
    embed = discord.Embed(
        title=f"💰 {user['username']}'s Balance",
        description=f"**${total:.2f}** across {len(cards)} card(s)\n🎫 {tickets:,} tickets/points",
        color=0x22c55e
    )
    await interaction.response.send_message(embed=embed, view=bot_buttons(), ephemeral=ephem)


@bot.tree.command(name="spent", description="How much you've spent in a timeframe")
@app_commands.describe(period="Timeframe: day, week, month (default: day)")
@app_commands.choices(period=[
    app_commands.Choice(name="Today (24h)", value="day"),
    app_commands.Choice(name="This week (7d)", value="week"),
    app_commands.Choice(name="This month (30d)", value="month"),
])
async def cmd_spent(interaction: discord.Interaction, period: str = "day"):
    user, _ = await run_sync(db_get_user_cards, interaction.user.id)
    ephem = is_ephemeral(user, 'spent', default=True)
    if not user:
        await interaction.response.send_message("❌ Use `/link` first.", ephemeral=True); return

    days_map = {'day': 1, 'week': 7, 'month': 30}
    days = days_map.get(period, 1)
    label_map = {'day': 'last 24h', 'week': 'last 7 days', 'month': 'last 30 days'}

    results = await asyncio.get_event_loop().run_in_executor(None, db_get_spent, user['id'], days)

    if not results:
        await interaction.response.send_message("No spending data available.", ephemeral=ephem); return

    total_spent = sum(r['spent'] for r in results)
    color = 0xef4444 if total_spent > 0 else 0x22c55e
    embed = discord.Embed(
        title=f"📊 Spending — {label_map[period]}",
        color=color
    )
    for r in results:
        spent = r['spent']
        sign = '-' if spent > 0 else '+'
        color_ind = '🔴' if spent > 0 else '🟢'
        embed.add_field(
            name=f"{card_emoji(r['card_type'])} {r['label']}",
            value=f"{color_ind} **{sign}${abs(spent):.2f}**",
            inline=True
        )
    summary = f"-${total_spent:.2f}" if total_spent > 0 else f"+${abs(total_spent):.2f}"
    embed.set_footer(text=f"Total: {summary} in {label_map[period]}")
    await interaction.response.send_message(embed=embed, ephemeral=ephem)


@bot.tree.command(name="refresh", description="Force refresh your card balances now")
async def cmd_refresh(interaction: discord.Interaction):
    user, cards = await run_sync(db_get_user_cards, interaction.user.id)
    ephem = is_ephemeral(user, 'refresh', default=True)
    if not user:
        await interaction.response.send_message("❌ Use `/link` first.", ephemeral=True); return
    await interaction.response.defer(ephemeral=ephem)

    sys.path.insert(0, os.path.dirname(__file__))
    from app import fetch_koko_balance, fetch_timezone_guest
    import json as _json

    conn = get_db()
    refreshed = 0
    for card in cards:
        try:
            data = None
            if card['card_type'] == 'koko':
                data = await asyncio.get_event_loop().run_in_executor(None, fetch_koko_balance, card['card_token'])
            else:
                tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
                if tzs:
                    guest = await asyncio.get_event_loop().run_in_executor(
                        None, fetch_timezone_guest, tzs['bearer_token'], _json.loads(tzs['cookies_json'] or '{}')
                    )
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
            print(f"[Bot] Refresh error {card['id']}: {e}")
    conn.commit(); conn.close()
    await interaction.followup.send(f"✅ Refreshed {refreshed}/{len(cards)} card(s). Use `/cards` to see updated balances.", ephemeral=ephem)


@bot.tree.command(name="leaderboard", description="Public card balance leaderboard (server only)")
async def cmd_leaderboard(interaction: discord.Interaction):
    # Leaderboard requires a guild context to be meaningful
    if interaction.guild is None:
        await interaction.response.send_message(
            "🏆 The leaderboard only works inside a server — invite me to a Discord server to use it!",
            ephemeral=True
        )
        return
    user = await asyncio.get_event_loop().run_in_executor(None, db_get_user, interaction.user.id)
    ephem = is_ephemeral(user, 'leaderboard', default=False)
    rows = await asyncio.get_event_loop().run_in_executor(None, db_get_leaderboard)
    if not rows:
        embed = discord.Embed(title="🏆 Leaderboard", color=0xfbbf24,
            description="No public cards yet.\nEnable leaderboard in Settings to appear here.")
        await interaction.response.send_message(embed=embed, view=bot_buttons(), ephemeral=ephem); return

    medals = ['🥇','🥈','🥉']
    embed = discord.Embed(title="🏆 Balance Leaderboard", color=0xfbbf24)
    for i, row in enumerate(rows):
        total = (row['cash_balance'] or 0) + (row['cash_bonus'] or 0)
        rank  = medals[i] if i < 3 else f"`#{i+1}`"
        tier  = f" {tier_emoji(row['tier'])}" if row['tier'] else ""
        last  = row['recorded_at'][:10] if row['recorded_at'] else '?'
        embed.add_field(
            name=f"{rank} {row['username']}{tier}",
            value=f"**${total:.2f}** · {row['card_label'] or 'Card'} · {last}",
            inline=False
        )
    embed.set_footer(text="Enable in Settings → Leaderboard to appear here")
    await interaction.response.send_message(embed=embed, view=bot_buttons(), ephemeral=ephem)


@bot.tree.command(name="privacy", description="Toggle whether each command response is public or private")
@app_commands.describe(command="Which command to configure", public="Show responses publicly in channel")
@app_commands.choices(command=[
    app_commands.Choice(name="/cards", value="cards"),
    app_commands.Choice(name="/balance", value="balance"),
    app_commands.Choice(name="/spent", value="spent"),
    app_commands.Choice(name="/refresh", value="refresh"),
    app_commands.Choice(name="/leaderboard", value="leaderboard"),
])
async def cmd_privacy(interaction: discord.Interaction, command: str, public: bool):
    user = await asyncio.get_event_loop().run_in_executor(None, db_get_user, interaction.user.id)
    if not user:
        await interaction.response.send_message("❌ Use `/link` first.", ephemeral=True); return
    ephemeral = not public
    await asyncio.get_event_loop().run_in_executor(None, db_set_command_privacy, user['id'], command, ephemeral)
    visibility = "**public** 📢" if public else "**private** 🔒"
    await interaction.response.send_message(
        f"✅ `/{command}` responses will now be {visibility} in this server.",
        ephemeral=True
    )




# ─── Add Card ─────────────────────────────────────────────────────────────────

def db_add_koko_card(user_id, token, label, cash_balance, cash_bonus, points, card_name):
    import sqlite3 as _sq
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id, active FROM cards WHERE user_id=? AND card_token=?", (user_id, token)
        ).fetchone()
        if existing:
            if existing['active']:
                conn.close()
                return False, "Card already tracked."
            conn.execute("UPDATE cards SET active=1, card_label=? WHERE id=?", (label or card_name or token, existing['id']))
            cid = existing['id']
        else:
            conn.execute(
                "INSERT INTO cards (user_id,card_type,card_token,card_label,card_number,poll_interval) VALUES (?,?,?,?,?,?)",
                (user_id, 'koko', token, label or card_name or token, card_name, 60)
            )
            cid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.execute(
            "INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name) VALUES (?,?,?,?,?)",
            (cid, cash_balance, cash_bonus, points, card_name)
        )
        conn.commit()
        return True, cid
    except _sq.IntegrityError as e:
        return False, str(e)
    finally:
        conn.close()


class AddKokoModal(discord.ui.Modal, title="Add Koko Card"):
    token = discord.ui.TextInput(
        label="Card Token",
        placeholder="e.g. 1ag9ukYM  (from the card QR URL)",
        min_length=4, max_length=64, required=True
    )
    nickname = discord.ui.TextInput(
        label="Nickname (optional)",
        placeholder="e.g. My Main Card",
        required=False, max_length=50
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        user = await asyncio.get_event_loop().run_in_executor(None, db_get_user, interaction.user.id)
        if not user:
            await interaction.followup.send("❌ Use `/link` first to connect your account.", ephemeral=True)
            return

        token_val = self.token.value.strip()
        label_val = self.nickname.value.strip()

        sys.path.insert(0, os.path.dirname(__file__))
        from app import fetch_koko_balance

        await interaction.followup.send("⏳ Fetching card data...", ephemeral=True)

        try:
            data = await asyncio.get_event_loop().run_in_executor(None, fetch_koko_balance, token_val)
        except Exception as e:
            await interaction.edit_original_response(content=f"❌ Error fetching card: {e}")
            return

        if not data or all(v is None for v in [data.get('cash_balance'), data.get('cash_bonus'), data.get('points')]):
            await interaction.edit_original_response(content="❌ Could not fetch data for that token. Check the token and try again.")
            return

        cash = data.get('cash_balance') or 0
        bonus = data.get('cash_bonus') or 0
        points = data.get('points') or 0
        card_name = data.get('card_name') or token_val
        total = cash + bonus

        ok, result = await asyncio.get_event_loop().run_in_executor(
            None, db_add_koko_card, user['id'], token_val, label_val, cash, bonus, points, card_name
        )

        if not ok:
            await interaction.edit_original_response(content=f"❌ {result}")
            return

        embed = discord.Embed(title="✅ Koko Card Added!", color=0x22c55e)
        embed.add_field(name="🎮 Card", value=label_val or card_name, inline=False)
        embed.add_field(name="💰 Balance", value=f"${cash:.2f}", inline=True)
        embed.add_field(name="🎁 Bonus", value=f"${bonus:.2f}", inline=True)
        embed.add_field(name="⭐ Points", value=f"{points:,}", inline=True)
        embed.add_field(name="💵 Total", value=f"**${total:.2f}**", inline=False)
        embed.set_footer(text="Card is now being tracked. Use /cards to view it.")
        await interaction.edit_original_response(content=None, embed=embed)


class TimezoneCardSelectView(discord.ui.View):
    """Shown after validating a Timezone session — lets user pick which card to track."""
    def __init__(self, user_id, cards_data, timeout=120):
        super().__init__(timeout=timeout)
        self.user_id = user_id
        self.cards_data = cards_data
        # Build select options
        options = []
        for c in cards_data[:25]:  # Discord max 25 options
            num = str(c.get('number', ''))
            tier = c.get('tier', '')
            balance = (c.get('cashBalance') or 0) + (c.get('bonusBalance') or 0)
            label = f"{tier+' · ' if tier else ''}${balance:.2f} credits"
            options.append(discord.SelectOption(label=f"Card {num[-8:]}", description=label, value=num))
        select = discord.ui.Select(placeholder="Choose a card to track…", options=options)
        select.callback = self.on_select
        self.add_item(select)

    async def on_select(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        chosen_num = interaction.data['values'][0]
        card_data = next((c for c in self.cards_data if str(c.get('number','')) == chosen_num), None)
        if not card_data:
            await interaction.followup.send("❌ Card not found.", ephemeral=True); return

        conn = get_db()
        token = f"tz_{chosen_num}"
        tier = card_data.get('tier', '')
        label = tier + ' ' + chosen_num[-6:] if tier else chosen_num[-6:]
        cash = card_data.get('cashBalance', 0)
        bonus = card_data.get('bonusBalance', 0)
        points = card_data.get('eTickets', card_data.get('tickets', 0))

        try:
            existing = conn.execute("SELECT id, active FROM cards WHERE user_id=? AND card_token=?", (self.user_id, token)).fetchone()
            if existing:
                if existing['active']:
                    await interaction.followup.send("⚠️ That card is already being tracked.", ephemeral=True)
                    conn.close(); return
                conn.execute("UPDATE cards SET active=1, card_label=?, tier=? WHERE id=?", (label, tier, existing['id']))
                cid = existing['id']
            else:
                conn.execute(
                    "INSERT INTO cards (user_id,card_type,card_token,card_label,card_number,tier,poll_interval) VALUES (?,'timezone',?,?,?,?,?)",
                    (self.user_id, token, label, chosen_num, tier, 900)
                )
                cid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
            conn.execute("INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,tier) VALUES (?,?,?,?,?)",
                (cid, cash, bonus, points, tier))
            conn.commit()
        finally:
            conn.close()

        embed = discord.Embed(title="✅ Timezone Card Added!", color=0xfbbf24)
        if tier:
            embed.add_field(name="🎖 Tier", value=f"{tier_emoji(tier)} {tier}", inline=True)
        embed.add_field(name="💳 Card", value=f"...{chosen_num[-6:]}", inline=True)
        embed.add_field(name="💰 Credits", value=f"${cash:.2f}", inline=True)
        embed.add_field(name="🎁 Bonus", value=f"${bonus:.2f}", inline=True)
        embed.add_field(name="🎫 e-Tickets", value=f"{points:,}", inline=True)
        embed.set_footer(text="Card is now being tracked. Use /cards to view it.")
        self.stop()
        await interaction.edit_original_response(content=None, embed=embed, view=None)


@bot.tree.command(name="addcard", description="Add a new card to track")
@app_commands.describe(card_type="Koko (QR token) or Timezone (uses your linked session)")
@app_commands.choices(card_type=[
    app_commands.Choice(name="🎮 Koko — enter card token", value="koko"),
    app_commands.Choice(name="🕹️ Timezone — pick from your account", value="timezone"),
])
async def cmd_addcard(interaction: discord.Interaction, card_type: str):
    user = await asyncio.get_event_loop().run_in_executor(None, db_get_user, interaction.user.id)
    if not user:
        await interaction.response.send_message("❌ Use `/link` first to connect your account.", ephemeral=True)
        return

    if card_type == "koko":
        await interaction.response.send_modal(AddKokoModal())

    elif card_type == "timezone":
        await interaction.response.defer(ephemeral=True)
        # Check for active Timezone session
        conn = get_db()
        tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
        conn.close()

        if not tzs or not tzs['bearer_token']:
            await interaction.followup.send(
                f"❌ No Timezone session found.\n\nConnect your Timezone account at {APP_URL}/timezone/start, then try again.",
                ephemeral=True
            )
            return

        sys.path.insert(0, os.path.dirname(__file__))
        from app import fetch_timezone_guest
        import json as _json

        await interaction.followup.send("⏳ Fetching your Timezone cards...", ephemeral=True)

        try:
            guest = await asyncio.get_event_loop().run_in_executor(
                None, fetch_timezone_guest, tzs['bearer_token'], _json.loads(tzs['cookies_json'] or '{}')
            )
        except Exception as e:
            await interaction.edit_original_response(content=f"❌ Error connecting to Timezone: {e}")
            return

        if not guest or not guest.get('cards'):
            await interaction.edit_original_response(
                content="❌ Could not fetch Timezone cards. Your session may have expired — reconnect at the website."
            )
            return

        tz_cards = guest.get('cards', [])
        # Filter out already-tracked active cards
        conn = get_db()
        tracked = {r['card_number'] for r in conn.execute(
            "SELECT card_number FROM cards WHERE user_id=? AND active=1 AND card_type='timezone'", (user['id'],)
        ).fetchall()}
        conn.close()

        untracked = [c for c in tz_cards if str(c.get('number','')) not in tracked]

        if not untracked:
            await interaction.edit_original_response(content="✅ All your Timezone cards are already being tracked!")
            return

        view = TimezoneCardSelectView(user['id'], untracked)
        await interaction.edit_original_response(
            content=f"Found **{len(untracked)}** untracked card(s). Select one to add:",
            view=view
        )



@bot.tree.command(name="help", description="Show all available commands")
async def cmd_help(interaction: discord.Interaction):
    user = await asyncio.get_event_loop().run_in_executor(None, db_get_user, interaction.user.id)
    linked = user is not None
    status = "Your account is linked." if linked else "Use /link to connect your account first."
    desc = "Track your Koko & Timezone arcade card balances. " + status
    embed = discord.Embed(title="Balance Tracker - Help", description=desc, color=0x6366f1)
    embed.add_field(name="Account", value="`/link` - Connect Discord\n`/addcard` - Add a card", inline=False)
    embed.add_field(name="Balances", value="`/cards` - All balances\n`/balance` - Quick total\n`/spent` - Spending history\n`/refresh` - Force refresh now", inline=False)
    embed.add_field(name="Leaderboard", value="`/leaderboard` - Public rankings (server only)\nEnable in Settings to appear", inline=False)
    embed.add_field(name="Settings", value="`/privacy command:X public:True/False` - Toggle visibility\n`/help` - This message", inline=False)
    if not linked:
        embed.add_field(name="Getting Started", value=f"1. Run /link\n2. Go to {APP_URL}/settings\n3. Enter the code\n4. Use /addcard!", inline=False)
    embed.set_footer(text="Balance Tracker - manage everything at the website")
    await interaction.response.send_message(embed=embed, view=bot_buttons(), ephemeral=True)


# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    bot.run(BOT_TOKEN, log_handler=None)
