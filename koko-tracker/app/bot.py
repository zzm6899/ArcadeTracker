"""
Balance Tracker — Discord Bot
Configure via docker-compose.yml environment variables:
  DISCORD_BOT_TOKEN=your_bot_token
  DISCORD_GUILD_ID=your_server_id  (optional, faster command sync)
"""

import os, sys, asyncio, sqlite3, secrets, random, json
from datetime import datetime, timedelta, timezone
import discord
from discord import app_commands
from discord.ext import tasks

# ─── Transport NSW ────────────────────────────────────────────────────────────
try:
    from transport_cmds import (
        register_transport_commands,
        transport_db_init,
        db_get_active_trackings,
        db_deactivate_tracking,
        db_mark_tracking_alerted,
        db_mark_dest_alerted,
        db_delete_inactive_trackings,
    )
    from transport_nsw import get_vehicle_position
    TRANSPORT_ENABLED = True
    print("[Bot] Transport NSW module loaded.")
except Exception as _transport_err:
    TRANSPORT_ENABLED = False
    print(f"[Bot] Transport NSW module not available: {_transport_err}")

# ─── Reminders ────────────────────────────────────────────────────────────────
try:
    from reminder_cmds import (
        register_reminder_commands,
        reminder_db_init,
        db_get_due_reminders,
        db_mark_delivered,
    )
    REMINDERS_ENABLED = True
    print("[Bot] Reminders module loaded.")
except Exception as _reminder_err:
    REMINDERS_ENABLED = False
    print(f"[Bot] Reminders module not available: {_reminder_err}")

DB_PATH   = os.environ.get('DB_PATH', '/data/koko.db')
BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN', '')
GUILD_ID  = os.environ.get('DISCORD_GUILD_ID', '')
APP_URL   = os.environ.get('APP_URL', 'http://localhost:5055')

# Delays within this many minutes of scheduled are considered "on time"
_ON_TIME_THRESHOLD_MINS = 1

if not BOT_TOKEN:
    print("[Bot] No DISCORD_BOT_TOKEN set — bot disabled.")
    sys.exit(0)

# ─── DB helpers ───────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def db_touch_last_seen(discord_id):
    """Update last_seen timestamp for a user (called on every command)."""
    try:
        conn = get_db()
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('UPDATE users SET last_seen=? WHERE discord_id=?', (now, str(discord_id)))
        conn.commit(); conn.close()
    except Exception:
        pass

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
        return json.loads(row['discord_cmd_privacy'])
    except:
        return {}

def db_set_command_privacy(user_id, cmd, ephemeral):
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

def db_get_spent_alltime(user_id):
    """Get all-time spending per card (first reading vs latest reading)."""
    conn = get_db()
    cards = conn.execute('SELECT id, card_label, card_number, card_type FROM cards WHERE user_id=? AND active=1', (user_id,)).fetchall()
    results = []
    for card in cards:
        first = conn.execute(
            'SELECT cash_balance, cash_bonus FROM balance_history WHERE card_id=? ORDER BY recorded_at ASC LIMIT 1',
            (card['id'],)
        ).fetchone()
        latest = conn.execute(
            'SELECT cash_balance, cash_bonus FROM balance_history WHERE card_id=? ORDER BY recorded_at DESC LIMIT 1',
            (card['id'],)
        ).fetchone()
        if first and latest:
            first_total = (first['cash_balance'] or 0) + (first['cash_bonus'] or 0)
            last_total  = (latest['cash_balance'] or 0) + (latest['cash_bonus'] or 0)
            spent = first_total - last_total
            results.append({'label': card['card_label'] or card['card_number'], 'card_type': card['card_type'], 'spent': spent})
    conn.close()
    return results

def db_get_stats_for_status():
    """Privacy-safe aggregate stats for bot status messages."""
    conn = get_db()
    total_cards = conn.execute('SELECT COUNT(*) FROM cards WHERE active=1').fetchone()[0]
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
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

# ─── Bot ──────────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = False

class BalanceBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self._status_idx = 0

    async def setup_hook(self):
        self.tree.allowed_installs = discord.app_commands.AppInstallationType(guild=True, user=True)
        self.tree.allowed_contexts = discord.app_commands.AppCommandContext(
            guild=True, dm_channel=True, private_channel=True
        )
        # Register Transport NSW commands if module is available
        if TRANSPORT_ENABLED:
            await asyncio.to_thread(transport_db_init)
            register_transport_commands(self.tree)
            print("[Bot] Transport NSW commands registered.")
        # Register Reminders commands
        if REMINDERS_ENABLED:
            await asyncio.to_thread(reminder_db_init)
            register_reminder_commands(self.tree)
            print("[Bot] Reminder commands registered.")
        guild = discord.Object(id=int(GUILD_ID)) if GUILD_ID else None
        if guild:
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()
        print(f"[Bot] Synced commands. Guild: {GUILD_ID or 'global'}")

    async def on_ready(self):
        print(f"[Bot] Logged in as {self.user}")
        if not self.status_loop.is_running():
            self.status_loop.start()
            print("[Bot] Status loop started.")
        if REMINDERS_ENABLED and not self.reminder_loop.is_running():
            self.reminder_loop.start()
            print("[Bot] Reminder loop started.")
        if TRANSPORT_ENABLED and not self.tracking_loop.is_running():
            self.tracking_loop.start()
            print("[Bot] Vehicle tracking loop started.")

    @tasks.loop(seconds=30)
    async def reminder_loop(self):
        """Fire any reminders that are now due — DM the user, or mention in channel."""
        if not REMINDERS_ENABLED:
            return
        try:
            due = await asyncio.to_thread(db_get_due_reminders)
        except Exception as e:
            print(f"[Bot] reminder_loop DB error: {e}")
            return
        for row in due:
            try:
                embed = discord.Embed(
                    title="🔔 Reminder",
                    description=row["message"],
                    color=0x6366F1,
                )
                embed.set_footer(text="This reminder was set by you via the bot.")
                sent = False
                # Try channel first (where the reminder was set)
                if row["channel_id"]:
                    try:
                        channel = self.get_channel(int(row["channel_id"]))
                        if channel is None:
                            channel = await self.fetch_channel(int(row["channel_id"]))
                        await channel.send(content=f"<@{row['discord_id']}>", embed=embed)
                        sent = True
                    except Exception as e:
                        print(f"[Bot] reminder channel send failed (reminder #{row['id']}): {e}")
                # Fallback: DM the user
                if not sent:
                    try:
                        user = await self.fetch_user(int(row["discord_id"]))
                        await user.send(embed=embed)
                        sent = True
                    except Exception as e:
                        print(f"[Bot] reminder DM failed (reminder #{row['id']}): {e}")
                if sent:
                    await asyncio.to_thread(db_mark_delivered, row["id"])
                    print(f"[Bot] Delivered reminder #{row['id']} to user {row['discord_id']}")
            except Exception as e:
                print(f"[Bot] reminder delivery error for #{row['id']}: {e}")

    @tasks.loop(seconds=45)
    async def status_loop(self):
        try:
            stats = await asyncio.to_thread(db_get_stats_for_status)
            templates = [
                (discord.ActivityType.watching,  f"💰 ${stats['public_total']:.0f} in public balances"),
                (discord.ActivityType.watching,  f"🎮 {stats['cards']} cards tracked"),
                (discord.ActivityType.watching,  f"👥 {stats['users']} players"),
                (discord.ActivityType.playing,   "Balance Tracker"),
            ]
            if stats['top_tier']:
                templates.append((discord.ActivityType.watching, f"💎 {stats['top_tier']} members active"))

            atype, name = templates[self._status_idx % len(templates)]
            await self.change_presence(activity=discord.Activity(type=atype, name=name))
            self._status_idx += 1
        except Exception as e:
            print(f"[Bot] Status error: {e}")

    @tasks.loop(seconds=60)
    async def tracking_loop(self):
        """Poll active vehicle tracking sessions and send alerts when approaching."""
        if not TRANSPORT_ENABLED:
            return
        try:
            sessions = await asyncio.to_thread(db_get_active_trackings)
        except Exception as e:
            print(f"[Bot] tracking_loop DB error: {e}")
            return

        for session in sessions:
            try:
                await self._process_tracking(session)
            except Exception as e:
                print(f"[Bot] tracking error #{session['id']}: {e}")

        # Hard-delete inactive tracking rows older than the configured TTL
        try:
            ttl = await asyncio.to_thread(self._get_tracking_ttl)
            deleted = await asyncio.to_thread(db_delete_inactive_trackings, ttl)
            if deleted:
                print(f"[Bot] tracking_loop: purged {deleted} inactive session(s) older than {ttl} min.")
        except Exception as e:
            print(f"[Bot] tracking_loop cleanup error: {e}")

    def _get_tracking_ttl(self) -> int:
        """Return the inactive-tracking TTL in minutes from app_config (default 30)."""
        try:
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute(
                "SELECT value FROM app_config WHERE key='tracking_completed_ttl_minutes'"
            ).fetchone()
            conn.close()
            return int(row[0]) if row else 30
        except Exception:
            return 30

    async def _process_tracking(self, session):
        """Check position of a tracked vehicle and alert user if approaching alert stop."""
        # Auto-expire sessions older than 3 hours
        try:
            created_str = session["created_at"]
            created = datetime.fromisoformat(created_str).replace(tzinfo=timezone.utc)
        except Exception:
            created = datetime.now(timezone.utc)
        if datetime.now(timezone.utc) - created > timedelta(hours=3):
            if session["notified"] == 0:
                await self._send_tracking_expired(session)
            await asyncio.to_thread(db_deactivate_tracking, session["id"])
            return

        # Re-fetch live vehicle position from the TfNSW API
        try:
            pos = await get_vehicle_position(
                session["from_id"],
                session["to_id"],
                session["scheduled_dep"],
            )
        except Exception:
            return  # API unavailable — skip silently

        if pos is None:
            # API returned nothing — the service may have already passed.
            # Use the alert stop's own scheduled departure time (from the stored
            # stop_sequence) as the trigger, falling back to the trip departure.
            # Fire immediately once that time has passed (no grace period needed —
            # if the API can't find the trip it's already gone).
            try:
                alert_dep: datetime | None = None
                try:
                    stored_seq = json.loads(session.get("stop_sequence") or "[]")
                    alert_name = session["alert_stop_name"].lower()
                    for s in stored_seq:
                        if alert_name in (s.get("name") or "").lower():
                            raw = s.get("departure")
                            if raw:
                                alert_dep = datetime.fromisoformat(raw)
                                if alert_dep.tzinfo is None:
                                    alert_dep = alert_dep.replace(tzinfo=timezone.utc)
                            break
                except Exception:
                    pass

                if alert_dep is None:
                    # Fallback: use the trip departure time
                    try:
                        alert_dep = datetime.fromisoformat(session["scheduled_dep"])
                        if alert_dep.tzinfo is None:
                            alert_dep = alert_dep.replace(tzinfo=timezone.utc)
                    except (ValueError, TypeError) as e:
                        print(f"[Bot] tracking scheduled_dep parse error #{session['id']}: {e}")

                if alert_dep is not None and datetime.now(timezone.utc) >= alert_dep:
                    if session["notified"] == 0:
                        # Alert stop departure time has passed and we never sent an
                        # alert — the train has almost certainly passed the stop.
                        dummy_pos = {
                            "current_stop": None,
                            "next_stop": None,
                            "final_stop": session.get("destination", ""),
                        }
                        await self._send_tracking_alert(
                            session, dummy_pos, session["alert_stop_name"], passed=True
                        )
                        await asyncio.to_thread(db_mark_tracking_alerted, session["id"])
                    await asyncio.to_thread(db_deactivate_tracking, session["id"])
            except Exception as e:
                print(f"[Bot] tracking pos-None error #{session['id']}: {e}")
            return

        alert_stop_name = session["alert_stop_name"]
        stored_alert_idx = session["alert_stop_idx"]

        # Locate alert stop in the fresh stop sequence (case-insensitive,
        # bidirectional substring match to handle platform-suffix differences).
        fresh_stop_seq = pos.get("stop_sequence", [])
        fresh_alert_idx: int | None = None
        alert_lower = alert_stop_name.lower()
        for i, s in enumerate(fresh_stop_seq):
            s_lower = s["name"].lower()
            if s_lower == alert_lower or alert_lower in s_lower or s_lower in alert_lower:
                fresh_alert_idx = i
                break
        effective_alert_idx = fresh_alert_idx if fresh_alert_idx is not None else stored_alert_idx

        # ── Real-time delay for the alert stop ──────────────────────────────────
        # Compare the fresh (real-time) departure of the alert stop against the
        # originally stored scheduled departure so we can surface delay info.
        alert_stop_delay: int | None = None
        alert_stop_realtime: bool = False
        check_idx = fresh_alert_idx if fresh_alert_idx is not None else (
            stored_alert_idx if stored_alert_idx < len(fresh_stop_seq) else None
        )
        if check_idx is not None:
            fresh_alert_stop = fresh_stop_seq[check_idx]
            alert_stop_realtime = fresh_alert_stop.get("is_realtime", False)
            fresh_dep = fresh_alert_stop.get("departure")
            if fresh_dep and alert_stop_realtime:
                try:
                    stored_seq = json.loads(session.get("stop_sequence") or "[]")
                    for s in stored_seq:
                        if alert_lower in (s.get("name") or "").lower():
                            raw = s.get("departure")
                            if raw:
                                sched_dep = datetime.fromisoformat(raw)
                                if sched_dep.tzinfo is None:
                                    sched_dep = sched_dep.replace(tzinfo=timezone.utc)
                                alert_stop_delay = int(
                                    (fresh_dep.astimezone(timezone.utc) - sched_dep).total_seconds() / 60
                                )
                            break
                except Exception:
                    pass

        current_idx = pos.get("current_idx")

        # ── Terminus safety net ──────────────────────────────────────────────────
        # If the vehicle has departed the last stop in the sequence the trip has
        # ended.  Send whichever alerts haven't fired yet, then deactivate.
        if current_idx is not None and fresh_stop_seq and current_idx >= len(fresh_stop_seq) - 1:
            if session["notified"] == 0:
                await self._send_tracking_alert(
                    session, pos, alert_stop_name, passed=True,
                    delay_mins=alert_stop_delay, is_realtime=alert_stop_realtime,
                )
                await asyncio.to_thread(db_mark_tracking_alerted, session["id"])
            if session["notified"] < 2:
                await self._send_dest_arrival_alert(session, pos)
            await asyncio.to_thread(db_deactivate_tracking, session["id"])
            return

        # ── Locate the destination (to_stop) in the fresh stop sequence ─────────
        to_name = session.get("to_name", "")
        dest_idx: int | None = None
        if to_name:
            for i, s in enumerate(fresh_stop_seq):
                s_name = s.get("name", "")
                if to_name.lower() in s_name.lower() or s_name.lower() in to_name.lower():
                    dest_idx = i
                    break

        # ── Destination arrival check ────────────────────────────────────────────
        # Vehicle has reached (or passed) the user's destination → send arrival
        # alert and deactivate.  Ensure the alert-stop notification fires first
        # if it was never sent (train skipped the loop iteration at that stop).
        if dest_idx is not None and current_idx is not None and current_idx >= dest_idx:
            if session["notified"] == 0:
                await self._send_tracking_alert(
                    session, pos, alert_stop_name, passed=True,
                    delay_mins=alert_stop_delay, is_realtime=alert_stop_realtime,
                )
                await asyncio.to_thread(db_mark_tracking_alerted, session["id"])
            if session["notified"] < 2:
                await self._send_dest_arrival_alert(session, pos)
            await asyncio.to_thread(db_deactivate_tracking, session["id"])
            return

        # ── Alert stop: passed check ─────────────────────────────────────────────
        # Vehicle has passed the chosen alert stop.  Send the alert (if not yet
        # done) but keep the session alive so we still watch for the destination.
        if current_idx is not None and current_idx >= effective_alert_idx:
            if session["notified"] == 0:
                await self._send_tracking_alert(
                    session, pos, alert_stop_name, passed=True,
                    delay_mins=alert_stop_delay, is_realtime=alert_stop_realtime,
                )
                await asyncio.to_thread(db_mark_tracking_alerted, session["id"])  # → notified=1
            # Do NOT deactivate here — wait for destination arrival check above
            return

        # ── Alert stop: approaching check ────────────────────────────────────────
        # Trigger if we're one stop away (index) OR within 10 minutes by schedule.
        # 10 min (up from 5) covers short-gap routes where stops are <2 min apart.
        approaching = current_idx is not None and current_idx >= effective_alert_idx - 1

        # Use stored_alert_idx as fallback for the time-based check when
        # fresh_alert_idx could not be matched (avoids silently skipping the check).
        if fresh_alert_idx is not None:
            time_check_idx = fresh_alert_idx
        elif stored_alert_idx < len(fresh_stop_seq):
            time_check_idx = stored_alert_idx
        else:
            time_check_idx = None
        if not approaching and time_check_idx is not None and time_check_idx < len(fresh_stop_seq):
            dep = fresh_stop_seq[time_check_idx].get("departure")
            approaching = (
                dep is not None
                and 0 <= (dep.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds() / 60 <= 10
            )

        if approaching and session["notified"] == 0:
            await self._send_tracking_alert(
                session, pos, alert_stop_name, passed=False,
                delay_mins=alert_stop_delay, is_realtime=alert_stop_realtime,
            )
            await asyncio.to_thread(db_mark_tracking_alerted, session["id"])  # → notified=1

    async def _send_tracking_alert(
        self,
        session,
        pos,
        alert_stop_name,
        *,
        passed: bool,
        delay_mins: int | None = None,
        is_realtime: bool = False,
    ):
        """DM or mention user about their tracked vehicle approaching/passing the alert stop."""
        route = session["route"]
        destination = session["destination"]
        current_stop = pos.get("current_stop") or "Unknown"
        next_stop = pos.get("next_stop") or alert_stop_name
        final_stop = pos.get("final_stop") or destination

        if passed:
            title = f"🚂 Train arrived at {alert_stop_name}"
            desc = (
                f"Your train (**{route}** → {destination}) has arrived at or "
                f"passed **{alert_stop_name}**."
            )
        else:
            title = f"🔔 Approaching {alert_stop_name}"
            desc = (
                f"Your train (**{route}** → {destination}) is approaching "
                f"**{alert_stop_name}** — get ready!"
            )

        # Build a real-time status string for the alert stop
        if is_realtime and delay_mins is not None:
            if delay_mins > _ON_TIME_THRESHOLD_MINS:
                rt_status = f"🔴 {delay_mins} min late"
            elif delay_mins < -_ON_TIME_THRESHOLD_MINS:
                rt_status = f"🟢 {abs(delay_mins)} min early"
            else:
                rt_status = "🟢 On time"
        elif is_realtime:
            rt_status = "🟢 On time"
        else:
            rt_status = "📅 Scheduled (no live data)"

        embed = discord.Embed(title=title, description=desc, color=0xF15A22)
        embed.add_field(name="📍 Last seen at", value=current_stop, inline=True)
        embed.add_field(name="➡️ Next stop", value=next_stop, inline=True)
        embed.add_field(name="🏁 Going to", value=final_stop, inline=True)
        embed.add_field(name="🕐 Real-time status", value=rt_status, inline=False)
        embed.set_footer(text="Transport for NSW · Live tracking")

        discord_id = session["discord_id"]
        channel_id = session.get("channel_id")

        sent = False
        if channel_id:
            try:
                channel = self.get_channel(int(channel_id))
                if channel is None:
                    channel = await self.fetch_channel(int(channel_id))
                await channel.send(content=f"<@{discord_id}>", embed=embed)
                sent = True
            except Exception as e:
                print(f"[Bot] tracking alert channel send failed (session #{session['id']}): {e}")

        if not sent:
            try:
                user = await self.fetch_user(int(discord_id))
                await user.send(embed=embed)
            except Exception as e:
                print(f"[Bot] tracking alert DM failed (session #{session['id']}): {e}")

    async def _send_tracking_expired(self, session):
        """Notify user that tracking ended because live position data is no longer available."""
        route = session["route"]
        destination = session["destination"]
        alert_stop_name = session["alert_stop_name"]

        embed = discord.Embed(
            title=f"⏰ Tracking ended — {alert_stop_name}",
            description=(
                f"Your tracked train (**{route}** → {destination}) can no longer be "
                f"located in real-time.\n\n"
                f"The service may have already **passed {alert_stop_name}** or has ended."
            ),
            color=0xF15A22,
        )
        embed.set_footer(text="Transport for NSW · Live tracking")

        discord_id = session["discord_id"]
        channel_id = session.get("channel_id")

        sent = False
        if channel_id:
            try:
                channel = self.get_channel(int(channel_id))
                if channel is None:
                    channel = await self.fetch_channel(int(channel_id))
                await channel.send(content=f"<@{discord_id}>", embed=embed)
                sent = True
            except Exception as e:
                print(f"[Bot] tracking expired channel send failed (session #{session['id']}): {e}")

        if not sent:
            try:
                user = await self.fetch_user(int(discord_id))
                await user.send(embed=embed)
            except Exception as e:
                print(f"[Bot] tracking expired DM failed (session #{session['id']}): {e}")

    async def _send_dest_arrival_alert(self, session, pos):
        """Send notification when vehicle arrives at the tracked destination stop."""
        route = session["route"]
        destination = session["destination"]
        to_name = session.get("to_name") or destination
        current_stop = pos.get("current_stop") or to_name

        embed = discord.Embed(
            title=f"🏁 Arrived at {to_name}",
            description=(
                f"Your train (**{route}** → {destination}) has arrived at your destination: "
                f"**{to_name}**."
            ),
            color=0x2ECC71,
        )
        embed.add_field(name="📍 Current stop", value=current_stop, inline=True)
        embed.add_field(name="🏁 Destination", value=to_name, inline=True)
        embed.set_footer(text="Transport for NSW · Live tracking")

        discord_id = session["discord_id"]
        channel_id = session.get("channel_id")

        sent = False
        if channel_id:
            try:
                channel = self.get_channel(int(channel_id))
                if channel is None:
                    channel = await self.fetch_channel(int(channel_id))
                await channel.send(content=f"<@{discord_id}>", embed=embed)
                sent = True
            except Exception as e:
                print(f"[Bot] dest arrival channel send failed (session #{session['id']}): {e}")

        if not sent:
            try:
                user = await self.fetch_user(int(discord_id))
                await user.send(embed=embed)
            except Exception as e:
                print(f"[Bot] dest arrival DM failed (session #{session['id']}): {e}")

        await asyncio.to_thread(db_mark_dest_alerted, session["id"])

bot = BalanceBot()

# ─── Commands ─────────────────────────────────────────────────────────────────

@bot.tree.command(name="help", description="Show all available commands")
async def cmd_help(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    embed = discord.Embed(
        title="📖 Balance Tracker — Commands",
        color=0x6366f1,
        description="Track your Koko & Timezone arcade card balances."
    )
    embed.add_field(name="🔗 /link", value="Link your Discord account", inline=True)
    embed.add_field(name="🎮 /cards", value="Show all card balances", inline=True)
    embed.add_field(name="💰 /balance", value="Quick total balance", inline=True)
    embed.add_field(name="📊 /spent", value="Spending over time", inline=True)
    embed.add_field(name="🔄 /refresh", value="Force poll all cards", inline=True)
    embed.add_field(name="🏆 /leaderboard", value="Public balance rankings", inline=True)
    embed.add_field(name="➕ /addcard", value="Add a Koko or Timezone card", inline=True)
    embed.add_field(name="🔒 /privacy", value="Toggle public/private per command", inline=True)
    embed.add_field(name="ℹ️ /info", value="Bot & account info", inline=True)
    embed.add_field(name="🛠 /setup", value="Quick start guide", inline=True)
    if REMINDERS_ENABLED:
        embed.add_field(name="\u200b", value="**🔔 Reminders**", inline=False)
        embed.add_field(
            name="🔔 /reminder set",
            value='Set a timed reminder — `"in 10 minutes"`, `"in 2 hours"`, `"30"`',
            inline=False,
        )
        embed.add_field(name="📋 /reminder list", value="List your pending reminders", inline=True)
        embed.add_field(name="🗑️ /reminder delete", value="Cancel a reminder by ID", inline=True)
    if TRANSPORT_ENABLED:
        embed.add_field(name="\u200b", value="**🚆 NSW Transport**", inline=False)
        embed.add_field(
            name="⚡ /transport go",
            value='Natural-language planner — `"rhodes to chatswood"`, `"central to parramatta bus"`',
            inline=False,
        )
        embed.add_field(name="🚆 /transport train", value="Plan a trip — pick stops interactively", inline=True)
        embed.add_field(name="🚏 /transport departures", value="Live departures + platform, origin & stats", inline=True)
        embed.add_field(name="📌 /transport next", value='Quick check saved route — `"1"` or `"morning commute"`', inline=False)
        embed.add_field(name="🔍 /transport find-stop", value="Search stop/station by name → get ID", inline=True)
        embed.add_field(name="🗺️ /transport my-trips", value="List all saved routes & stops with slot numbers", inline=True)
        embed.add_field(name="\u200b", value="**Saving & managing**", inline=False)
        embed.add_field(name="⭐ Save buttons", value="After any trip result — select option then press Save", inline=True)
        embed.add_field(name="🔔 Remind me buttons", value="On any departure board or trip detail — get a DM before it leaves", inline=True)
        embed.add_field(name="🚂 Track this train", value="On trip detail — pick a stop to be alerted when train approaches", inline=True)
        embed.add_field(name="🗑️ /transport delete-trip / delete-stop", value="Remove a saved route or stop by ID", inline=True)
        embed.add_field(name="📡 /transport track-status", value="List active vehicle tracking sessions", inline=True)
        embed.add_field(name="🛑 /transport stop-tracking", value="Cancel an active tracking session by ID", inline=True)
    embed.set_footer(text=f"Dashboard: {APP_URL}")
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="info", description="Bot info and your account status")
async def cmd_info(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    user = await asyncio.to_thread(db_get_user, interaction.user.id)

    embed = discord.Embed(title="ℹ️ Balance Tracker", color=0x6366f1)
    embed.add_field(name="🌐 Dashboard", value=f"[Open]({APP_URL})", inline=True)
    embed.add_field(name="⚙️ Settings", value=f"[Open]({APP_URL}/settings)", inline=True)

    if user:
        _, cards = await asyncio.to_thread(db_get_user_cards, interaction.user.id)
        koko_count = sum(1 for c in cards if c['card_type'] == 'koko')
        tz_count   = sum(1 for c in cards if c['card_type'] == 'timezone')
        total_bal  = sum((c['cash_balance'] or 0) + (c['cash_bonus'] or 0) for c in cards)

        embed.add_field(name="👤 Account", value=f"Linked as **{user['username']}**", inline=False)
        embed.add_field(name="🎮 Koko Cards", value=str(koko_count), inline=True)
        embed.add_field(name="🕹️ Timezone Cards", value=str(tz_count), inline=True)
        embed.add_field(name="💰 Total Balance", value=f"${total_bal:.2f}", inline=True)

        alltime = await asyncio.to_thread(db_get_spent_alltime, user['id'])
        total_alltime = sum(r['spent'] for r in alltime)
        if abs(total_alltime) >= 0.01:
            sign = '-' if total_alltime > 0 else '+'
            embed.add_field(name="📉 All-Time Spent", value=f"{sign}${abs(total_alltime):.2f}", inline=True)

        embed.add_field(name="🏆 Leaderboard", value="Opted In" if user['leaderboard_opt_in'] else "Opted Out", inline=True)
    else:
        embed.add_field(name="👤 Account", value="Not linked — use `/link` or `/setup`", inline=False)

    stats = await asyncio.to_thread(db_get_stats_for_status)
    embed.add_field(name="📊 Global Stats",
        value=f"{stats['cards']} cards · {stats['users']} players · ${stats['public_total']:.0f} public balance",
        inline=False)

    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="setup", description="Quick start guide to get tracking")
async def cmd_setup(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    user = await asyncio.to_thread(db_get_user, interaction.user.id)

    embed = discord.Embed(title="🛠 Quick Setup Guide", color=0x22c55e)

    if not user:
        embed.description = "Let's get you set up! Follow these steps:"
        embed.add_field(name="Step 1 — Create Account",
            value=f"Go to [{APP_URL}/register]({APP_URL}/register) and create your account.\n*Or use `/link` if you already have one.*",
            inline=False)
        embed.add_field(name="Step 2 — Link Discord",
            value="Run `/link` here to get a code, then enter it in Settings → Discord Link on the website.",
            inline=False)
        embed.add_field(name="Step 3 — Add Cards",
            value="**Koko:** Run `/addcard` → Koko, enter your card QR token.\n"
                  "**Timezone:** Connect your Timezone account on the website, then `/addcard` → Timezone.",
            inline=False)
        embed.add_field(name="Step 4 — Enjoy!",
            value="Use `/cards` to view balances, `/spent` to track spending, `/leaderboard` to compete!",
            inline=False)
    else:
        _, cards = await asyncio.to_thread(db_get_user_cards, interaction.user.id)
        koko_count = sum(1 for c in cards if c['card_type'] == 'koko')
        tz_count   = sum(1 for c in cards if c['card_type'] == 'timezone')

        embed.description = f"✅ You're linked as **{user['username']}**!"
        status_lines = []
        status_lines.append(f"{'✅' if koko_count else '⬜'} **Koko Cards:** {koko_count} tracked")
        status_lines.append(f"{'✅' if tz_count else '⬜'} **Timezone Cards:** {tz_count} tracked")
        status_lines.append(f"{'✅' if user['leaderboard_opt_in'] else '⬜'} **Leaderboard:** {'Opted in' if user['leaderboard_opt_in'] else 'Not opted in'}")
        embed.add_field(name="Your Status", value="\n".join(status_lines), inline=False)

        if not koko_count and not tz_count:
            embed.add_field(name="➡️ Next Step",
                value="Add a card with `/addcard`!",
                inline=False)
        else:
            embed.add_field(name="Useful Commands",
                value="`/cards` — View balances\n`/spent` — Track spending\n`/refresh` — Force update\n`/privacy` — Public/private toggle",
                inline=False)

    embed.set_footer(text=f"Dashboard: {APP_URL}")
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="link", description="Link your Discord account to Balance Tracker")
async def cmd_link(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    code = await asyncio.to_thread(db_create_link_code, interaction.user.id, str(interaction.user))
    embed = discord.Embed(title="🔗 Link Your Account", color=0x6366f1,
        description="Enter this code in Balance Tracker Settings → Discord Link")
    embed.add_field(name="Code (expires 15min)", value=f"```{code}```", inline=False)
    embed.add_field(name="Where", value=f"{APP_URL}/settings", inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="cards", description="Show your card balances")
async def cmd_cards(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    user, cards = await asyncio.to_thread(db_get_user_cards, interaction.user.id)
    ephem = is_ephemeral(user, 'cards', default=True)
    if not user:
        await interaction.followup.send("❌ Use `/link` to connect your account.", ephemeral=True); return
    if not cards:
        await interaction.followup.send("No cards found.", ephemeral=ephem); return

    alltime = await asyncio.to_thread(db_get_spent_alltime, user['id'])
    alltime_map = {r['label']: r['spent'] for r in alltime}

    embed = discord.Embed(title=f"🎮 {user['username']}'s Cards", color=0x6366f1)
    for card in cards:
        total = (card['cash_balance'] or 0) + (card['cash_bonus'] or 0)
        tier  = f" {tier_emoji(card['tier'])} {card['tier']}" if card['tier'] else ""
        label = card['card_label'] or 'Card'
        last  = card['last_updated'][:16] if card['last_updated'] else 'Never'
        pts_label = 'e-Tickets' if card['card_type'] == 'timezone' else 'pts'
        at_spent = alltime_map.get(label, 0)
        at_str = ''
        if abs(at_spent) >= 0.01:
            at_sign = '-' if at_spent > 0 else '+'
            at_str = f"\n📉 All-time: {at_sign}${abs(at_spent):.2f}"
        val = (f"💰 **${total:.2f}** · ${card['cash_balance'] or 0:.2f} + ${card['cash_bonus'] or 0:.2f} bonus\n"
               f"🎫 {card['points'] or 0:,} {pts_label}{at_str}\n"
               f"🕐 {last}")
        embed.add_field(name=f"{card_emoji(card['card_type'])} {label}{tier}", value=val, inline=False)
    await interaction.followup.send(embed=embed, ephemeral=ephem)


@bot.tree.command(name="balance", description="Quick total balance summary")
async def cmd_balance(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    user, cards = await asyncio.to_thread(db_get_user_cards, interaction.user.id)
    ephem = is_ephemeral(user, 'balance', default=True)
    if not user:
        await interaction.followup.send("❌ Use `/link` first.", ephemeral=True); return
    total = sum((c['cash_balance'] or 0) + (c['cash_bonus'] or 0) for c in cards)
    tickets = sum(c['points'] or 0 for c in cards)
    embed = discord.Embed(
        title=f"💰 {user['username']}'s Balance",
        description=f"**${total:.2f}** across {len(cards)} card(s)\n🎫 {tickets:,} tickets/points",
        color=0x22c55e
    )
    await interaction.followup.send(embed=embed, ephemeral=ephem)


@bot.tree.command(name="spent", description="How much you've spent in a timeframe")
@app_commands.describe(period="Timeframe: day, week, month, all time (default: day)")
@app_commands.choices(period=[
    app_commands.Choice(name="Today (24h)", value="day"),
    app_commands.Choice(name="This week (7d)", value="week"),
    app_commands.Choice(name="This month (30d)", value="month"),
    app_commands.Choice(name="All Time", value="all"),
])
async def cmd_spent(interaction: discord.Interaction, period: str = "day"):
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    user, _ = await asyncio.to_thread(db_get_user_cards, interaction.user.id)
    ephem = is_ephemeral(user, 'spent', default=True)
    if not user:
        await interaction.followup.send("❌ Use `/link` first.", ephemeral=True); return

    label_map = {'day': 'last 24h', 'week': 'last 7 days', 'month': 'last 30 days', 'all': 'all time'}

    if period == 'all':
        results = await asyncio.to_thread(db_get_spent_alltime, user['id'])
    else:
        days_map = {'day': 1, 'week': 7, 'month': 30}
        days = days_map.get(period, 1)
        results = await asyncio.to_thread(db_get_spent, user['id'], days)

    if not results:
        await interaction.followup.send("No spending data available.", ephemeral=ephem); return

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
    await interaction.followup.send(embed=embed, ephemeral=ephem)


@bot.tree.command(name="refresh", description="Force refresh your card balances now")
async def cmd_refresh(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    user, cards = await asyncio.to_thread(db_get_user_cards, interaction.user.id)
    ephem = is_ephemeral(user, 'refresh', default=True)
    if not user:
        await interaction.followup.send("❌ Use `/link` first.", ephemeral=True); return

    sys.path.insert(0, os.path.dirname(__file__))
    from app import fetch_koko_balance, fetch_timezone_guest

    conn = get_db()
    refreshed = 0
    for card in cards:
        try:
            data = None
            if card['card_type'] == 'koko':
                data = await asyncio.to_thread(fetch_koko_balance, card['card_token'])
            else:
                tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
                if tzs:
                    guest = await asyncio.to_thread(
                        fetch_timezone_guest, tzs['bearer_token'], json.loads(tzs['cookies_json'] or '{}')
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
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    if interaction.guild is None:
        await interaction.followup.send(
            "🏆 The leaderboard only works inside a server — invite me to a Discord server to use it!",
            ephemeral=True
        )
        return
    user = await asyncio.to_thread(db_get_user, interaction.user.id)
    ephem = is_ephemeral(user, 'leaderboard', default=False)
    rows = await asyncio.to_thread(db_get_leaderboard)
    if not rows:
        embed = discord.Embed(title="🏆 Leaderboard", color=0xfbbf24,
            description="No public cards yet.\nEnable leaderboard in Settings to appear here.")
        await interaction.followup.send(embed=embed, ephemeral=ephem); return

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
    await interaction.followup.send(embed=embed, ephemeral=ephem)


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
    await interaction.response.defer(ephemeral=True)
    await asyncio.to_thread(db_touch_last_seen, interaction.user.id)
    user = await asyncio.to_thread(db_get_user, interaction.user.id)
    if not user:
        await interaction.followup.send("❌ Use `/link` first.", ephemeral=True); return
    ephemeral = not public
    await asyncio.to_thread(db_set_command_privacy, user['id'], command, ephemeral)
    visibility = "**public** 📢" if public else "**private** 🔒"
    await interaction.followup.send(
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
                (user_id, 'koko', token, label or card_name or token, card_name, 300)
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
        user = await asyncio.to_thread(db_get_user, interaction.user.id)
        if not user:
            await interaction.followup.send("❌ Use `/link` first to connect your account.", ephemeral=True)
            return

        token_val = self.token.value.strip()
        label_val = self.nickname.value.strip()

        sys.path.insert(0, os.path.dirname(__file__))
        from app import fetch_koko_balance

        await interaction.followup.send("⏳ Fetching card data...", ephemeral=True)

        try:
            data = await asyncio.to_thread(fetch_koko_balance, token_val)
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

        ok, result = await asyncio.to_thread(
            db_add_koko_card, user['id'], token_val, label_val, cash, bonus, points, card_name
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
        options = []
        for c in cards_data[:25]:
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
    _, user = await asyncio.gather(
        asyncio.to_thread(db_touch_last_seen, interaction.user.id),
        asyncio.to_thread(db_get_user, interaction.user.id),
    )
    if not user:
        await interaction.response.send_message("❌ Use `/link` first to connect your account.", ephemeral=True)
        return

    if card_type == "koko":
        await interaction.response.send_modal(AddKokoModal())

    elif card_type == "timezone":
        await interaction.response.defer(ephemeral=True)
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

        await interaction.followup.send("⏳ Fetching your Timezone cards...", ephemeral=True)

        try:
            guest = await asyncio.to_thread(
                fetch_timezone_guest, tzs['bearer_token'], json.loads(tzs['cookies_json'] or '{}')
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

# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    bot.run(BOT_TOKEN, log_handler=None)
