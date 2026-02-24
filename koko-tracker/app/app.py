import os, sqlite3, threading, time, hashlib, secrets, json, base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__, template_folder='../templates', static_folder='../static')

@app.context_processor
def inject_discord():
    invite = f'https://discord.com/oauth2/authorize?client_id={DISCORD_CLIENT_ID}' if DISCORD_CLIENT_ID else None
    return dict(discord_invite=invite)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # requires HTTPS

DB_PATH = os.environ.get('DB_PATH', '/data/koko.db')
DEFAULT_POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 60))
TIMEZONE_POLL_INTERVAL = int(os.environ.get('TIMEZONE_POLL_INTERVAL', 900))
KOKO_BASE_URL = 'https://estore.kokoamusement.com.au/BalanceMobile/BalanceMobile.aspx'
TEEG_API = 'https://api.teeg.cloud'
ADMIN_USERNAME    = os.environ.get('ADMIN_USERNAME', '')
ADMIN_PASSWORD    = os.environ.get('ADMIN_PASSWORD', '')
DISCORD_CLIENT_ID     = os.environ.get('DISCORD_CLIENT_ID', '')
APP_URL               = os.environ.get('APP_URL', 'http://localhost:5055')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET', '')
MAIL_SERVER           = os.environ.get('MAIL_SERVER', '')
MAIL_PORT             = int(os.environ.get('MAIL_PORT', '587'))
MAIL_USERNAME         = os.environ.get('MAIL_USERNAME', '')
MAIL_PASSWORD         = os.environ.get('MAIL_PASSWORD', '')
MAIL_FROM             = os.environ.get('MAIL_FROM', MAIL_USERNAME)

# ─── Database ─────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            timezone_name TEXT DEFAULT 'Australia/Sydney',
            show_overview INTEGER DEFAULT 1,
            discord_webhook TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            card_type TEXT DEFAULT 'koko',
            card_token TEXT NOT NULL,
            card_label TEXT,
            card_number TEXT,
            tier TEXT,
            poll_interval INTEGER DEFAULT 60,  -- koko default; timezone cards use 900
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, card_token)
        );
        CREATE TABLE IF NOT EXISTS balance_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id INTEGER NOT NULL,
            cash_balance REAL,
            cash_bonus REAL,
            points INTEGER,
            card_name TEXT,
            tier TEXT,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (card_id) REFERENCES cards(id)
        );
        CREATE TABLE IF NOT EXISTS timezone_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            bearer_token TEXT,
            cookies_json TEXT,
            token_expires_at TEXT,
            session_expires_at TEXT,
            guest_id TEXT,
            last_poll_at TEXT,
            last_poll_status TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS poll_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id INTEGER NOT NULL,
            success INTEGER DEFAULT 1,
            message TEXT,
            logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_history_card_time ON balance_history(card_id, recorded_at);
        CREATE TABLE IF NOT EXISTS discord_link_codes (
            discord_id TEXT PRIMARY KEY,
            discord_username TEXT,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
    ''')
    # Migrations
    for sql in [
        'ALTER TABLE cards ADD COLUMN tier TEXT',
        'ALTER TABLE cards ADD COLUMN poll_interval INTEGER DEFAULT 60',
        'ALTER TABLE balance_history ADD COLUMN tier TEXT',
        'ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN timezone_name TEXT DEFAULT "Australia/Sydney"',
        'ALTER TABLE timezone_sessions ADD COLUMN last_poll_at TEXT',
        'ALTER TABLE timezone_sessions ADD COLUMN last_poll_status TEXT',
        'ALTER TABLE users ADD COLUMN show_overview INTEGER DEFAULT 1',
        'ALTER TABLE users ADD COLUMN discord_webhook TEXT',
        'ALTER TABLE users ADD COLUMN discord_id TEXT',
        'ALTER TABLE users ADD COLUMN leaderboard_opt_in INTEGER DEFAULT 0',
        'ALTER TABLE cards ADD COLUMN leaderboard_public INTEGER DEFAULT 0',
        'ALTER TABLE users ADD COLUMN discord_cmd_privacy TEXT',
        'ALTER TABLE balance_history ADD COLUMN description TEXT',
        'ALTER TABLE users ADD COLUMN email TEXT',
        'ALTER TABLE users ADD COLUMN reset_token TEXT',
        'ALTER TABLE users ADD COLUMN reset_expires TEXT',
        'ALTER TABLE timezone_sessions ADD COLUMN refresh_token TEXT',
        'ALTER TABLE timezone_sessions ADD COLUMN ms_client_id TEXT',
        'ALTER TABLE users ADD COLUMN discord_webhook TEXT',
    ]:
        try: conn.execute(sql)
        except: pass
    # Fix timezone cards that have the wrong default poll interval (60 instead of 900)
    try:
        conn.execute("UPDATE cards SET poll_interval=900 WHERE card_type='timezone' AND poll_interval=60")
    except: pass
    conn.commit()
    # Sync env-defined admin
    if ADMIN_USERNAME:
        try:
            conn.execute('UPDATE users SET is_admin=1 WHERE username=?', (ADMIN_USERNAME,))
        except: pass
    conn.commit()
    conn.close()

# ─── Auth ─────────────────────────────────────────────────────────────────────
def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()

def get_current_user():
    if 'user_id' not in session: return None
    conn = get_db()
    u = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    conn.close()
    return u

def login_required(f):
    from functools import wraps
    @wraps(f)
    def d(*a, **k):
        if not get_current_user(): return redirect(url_for('login'))
        return f(*a, **k)
    return d

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def d(*a, **k):
        u = get_current_user()
        if not u: return redirect(url_for('login'))
        if not u['is_admin']: return redirect(url_for('dashboard'))
        return f(*a, **k)
    return d

# ─── Koko scraper ─────────────────────────────────────────────────────────────
def fetch_koko_balance(token):
    try:
        resp = requests.get(f"{KOKO_BASE_URL}?i={token}", timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        soup = BeautifulSoup(resp.text, 'html.parser')
        data = {'card_name': None, 'cash_balance': None, 'cash_bonus': None, 'points': None}
        full_text = soup.get_text(separator='\n')
        m = re.search(r'Game Card:\s*(.+)', full_text, re.IGNORECASE)
        if m: data['card_name'] = m.group(1).strip()
        for row in soup.find_all('tr'):
            cells = row.find_all(['td','th'])
            if len(cells) >= 2:
                label = cells[0].get_text(strip=True).lower()
                value = cells[1].get_text(strip=True)
                if 'cash balance' in label:
                    m = re.search(r'[\d,.]+', value)
                    if m: data['cash_balance'] = float(m.group().replace(',',''))
                elif 'cash bonus' in label:
                    m = re.search(r'[\d,.]+', value)
                    if m: data['cash_bonus'] = float(m.group().replace(',',''))
                elif label == 'points':
                    m = re.search(r'[\d,]+', value)
                    if m: data['points'] = int(m.group().replace(',',''))
        lines = [l.strip() for l in full_text.splitlines() if l.strip()]
        for i, line in enumerate(lines):
            ll = line.lower(); nv = lines[i+1] if i+1 < len(lines) else ''
            if data['cash_balance'] is None and 'cash balance' in ll:
                m = re.search(r'\$?\s*([\d,.]+)', nv)
                if m: data['cash_balance'] = float(m.group(1).replace(',',''))
            if data['cash_bonus'] is None and 'cash bonus' in ll:
                m = re.search(r'\$?\s*([\d,.]+)', nv)
                if m: data['cash_bonus'] = float(m.group(1).replace(',',''))
            if data['points'] is None and ll == 'points':
                m = re.search(r'[\d,]+', nv)
                if m: data['points'] = int(m.group().replace(',',''))
        return data
    except Exception as e:
        print(f"[Koko] Error: {e}"); return None

# ─── Timezone API ─────────────────────────────────────────────────────────────
TZ_HEADERS = {
    'Accept': 'application/json',
    'Origin': 'https://portal.timezonegames.com',
    'Referer': 'https://portal.timezonegames.com/',
    'User-Agent': 'okhttp/4.12.0',
    'x-app-version': '20210722',
}

def tz_refresh_ms_token(refresh_token, ms_client_id=None):
    """Use Microsoft Identity refresh token to get a new access token for teeg.cloud."""
    # Timezone uses Microsoft B2C identity - refresh_token lets us get a new bearer
    cid = ms_client_id or 'ca0e4868-177b-49d2-8c63-f1044e3edc63'  # known Timezone clientId
    try:
        resp = requests.post(
            'https://identity.teeg.cloud/ca0e4868-177b-49d2-8c63-f1044e3edc63/B2C_1A_signupsignin/oauth2/v2.0/token',
            data={
                'grant_type': 'refresh_token',
                'client_id': cid,
                'refresh_token': refresh_token,
                'scope': f'openid profile offline_access https://identity.teeg.cloud/{cid}/guest.read',
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=15
        )
        print(f"[Timezone] MS token refresh: HTTP {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            new_token     = data.get('access_token') or data.get('id_token')
            new_refresh   = data.get('refresh_token', refresh_token)
            expires_in    = int(data.get('expires_in', 840))
            return new_token, new_refresh, expires_in
        print(f"[Timezone] MS refresh failed: {resp.text[:300]}")
        return None, None, None
    except Exception as e:
        print(f"[Timezone] MS refresh error: {e}"); return None, None, None

def tz_refresh_token(cookies_dict):
    """Use session cookies to get a fresh bearer token."""
    try:
        resp = requests.get(
            f'{TEEG_API}/guest?version=20210722',
            headers=TZ_HEADERS, cookies=cookies_dict or {}, timeout=15
        )
        print(f"[Timezone] Cookie token refresh: HTTP {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            new_token = data.get('token') or data.get('accessToken')
            return data, new_token, dict(resp.cookies)
        return None, None, None
    except Exception as e:
        print(f"[Timezone] Refresh error: {e}"); return None, None, None

def fetch_timezone_guest(bearer_token, cookies_dict=None, user_id=None):
    """Fetch guest data, auto-refreshing token if expired."""
    cookies = cookies_dict or {}
    headers = {**TZ_HEADERS, 'Authorization': f'Bearer {bearer_token}'}
    try:
        resp = requests.get(f'{TEEG_API}/guest?version=20210722', headers=headers,
                           cookies=cookies, timeout=15)
        print(f"[Timezone] guest API: HTTP {resp.status_code}")
        if resp.status_code == 200:
            return resp.json()
        # 401/403 = token expired — try MS refresh token first, then cookie refresh
        if resp.status_code in (401, 403, 400):
            print(f"[Timezone] Token expired (HTTP {resp.status_code}), attempting refresh...")
            new_token = None
            new_refresh = None

            # Try MS Identity refresh token first (most reliable)
            if user_id:
                try:
                    conn = get_db()
                    tzs = conn.execute('SELECT refresh_token, ms_client_id FROM timezone_sessions WHERE user_id=?', (user_id,)).fetchone()
                    conn.close()
                    if tzs and tzs['refresh_token']:
                        new_token, new_refresh, expires_in = tz_refresh_ms_token(tzs['refresh_token'], tzs['ms_client_id'])
                except Exception as e:
                    print(f"[Timezone] Could not get refresh token: {e}")

            # Fallback: cookie-based refresh
            if not new_token and cookies:
                data, new_token, new_cookies = tz_refresh_token(cookies)
                if data and not new_token:
                    # Cookie refresh returned guest data without a new token — use it directly
                    if user_id:
                        try:
                            conn = get_db()
                            conn.execute('UPDATE timezone_sessions SET last_poll_status=? WHERE user_id=?', ('ok', user_id))
                            conn.commit(); conn.close()
                        except: pass
                    return data

            if new_token:
                # Save refreshed token
                if user_id:
                    try:
                        now = datetime.utcnow()
                        tok_exp  = (now + timedelta(minutes=14)).strftime('%Y-%m-%d %H:%M:%S')
                        sess_exp = (now + timedelta(days=29)).strftime('%Y-%m-%d %H:%M:%S')
                        conn = get_db()
                        updates = 'bearer_token=?, token_expires_at=?, updated_at=CURRENT_TIMESTAMP'
                        params  = [new_token, tok_exp]
                        if new_refresh:
                            updates += ', refresh_token=?'
                            params.append(new_refresh)
                        params.append(user_id)
                        conn.execute(f'UPDATE timezone_sessions SET {updates} WHERE user_id=?', params)
                        conn.commit(); conn.close()
                        print(f"[Timezone] Token refreshed for user {user_id}")
                    except Exception as e:
                        print(f"[Timezone] Could not save refreshed token: {e}")

                # Retry with new token
                headers2 = {**TZ_HEADERS, 'Authorization': f'Bearer {new_token}'}
                try:
                    resp2 = requests.get(f'{TEEG_API}/guest?version=20210722', headers=headers2, cookies=cookies, timeout=15)
                    if resp2.status_code == 200:
                        return resp2.json()
                except Exception as e:
                    print(f"[Timezone] Retry after refresh failed: {e}")
        print(f"[Timezone] Error body: {resp.text[:300]}")
        return None
    except Exception as e:
        print(f"[Timezone] Error: {e}"); return None

def fetch_timezone_transactions(card_number, bearer_token, cookies_dict=None):
    """Fetch transaction history for a card — as many as available."""
    cookies = cookies_dict or {}
    headers = {**TZ_HEADERS, 'Authorization': f'Bearer {bearer_token}'}
    all_transactions = []
    try:
        # Try several URL patterns - we're not sure which the API uses
        url_attempts = [
            f'{TEEG_API}/guest/cards/AU/{card_number}/transactions',
            f'{TEEG_API}/guest/cards/{card_number}/transactions',
            f'{TEEG_API}/guest/transactions?cardNumber={card_number}',
        ]
        working_url = None
        for url in url_attempts:
            resp = requests.get(url, headers=headers, cookies=cookies, timeout=15)
            print(f"[Timezone] TX probe {url}: HTTP {resp.status_code} — {resp.text[:200]}")
            if resp.status_code == 200:
                working_url = url
                data = resp.json()
                if isinstance(data, list):
                    all_transactions.extend(data)
                else:
                    items = data.get('transactions') or data.get('items') or data.get('data') or []
                    all_transactions.extend(items)
                break

        if not working_url:
            print(f"[Timezone] No working transaction URL found for card {card_number}")
            return []

        # If first page worked, try paginated fetches
        if all_transactions and len(all_transactions) >= 20:
            for page in range(2, 11):
                url = f'{working_url}?page={page}&pageSize=50'
                resp = requests.get(url, headers=headers, cookies=cookies, timeout=15)
                if resp.status_code != 200:
                    break
                data = resp.json()
                items = data if isinstance(data, list) else (data.get('transactions') or data.get('items') or data.get('data') or [])
                if not items:
                    break
                all_transactions.extend(items)
                if len(items) < 50:
                    break

        print(f"[Timezone] Got {len(all_transactions)} transactions for card {card_number}")
        if all_transactions:
            print(f"[ImportTx] Sample keys: {list(all_transactions[0].keys())}")
            print(f"[ImportTx] Sample: {dict(all_transactions[0])}")
        return all_transactions
    except Exception as e:
        print(f"[Timezone] Transaction fetch error: {e}"); return []

def save_timezone_session(user_id, bearer_token, cookies_dict, token_exp, sess_exp, guest_id=None, refresh_token=None, ms_client_id=None):
    conn = get_db()
    conn.execute('''
        INSERT INTO timezone_sessions (user_id, bearer_token, cookies_json, token_expires_at, session_expires_at, guest_id, refresh_token, ms_client_id, last_poll_status, updated_at)
        VALUES (?,?,?,?,?,?,?,?,'ok',CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            bearer_token=excluded.bearer_token, cookies_json=excluded.cookies_json,
            token_expires_at=excluded.token_expires_at, session_expires_at=excluded.session_expires_at,
            guest_id=COALESCE(excluded.guest_id, timezone_sessions.guest_id),
            refresh_token=COALESCE(excluded.refresh_token, timezone_sessions.refresh_token),
            ms_client_id=COALESCE(excluded.ms_client_id, timezone_sessions.ms_client_id),
            last_poll_status='ok',
            updated_at=CURRENT_TIMESTAMP
    ''', (user_id, bearer_token, json.dumps(cookies_dict), token_exp, sess_exp, guest_id, refresh_token, ms_client_id))
    conn.commit(); conn.close()

def tz_session_status(tzs):
    """Return status string for a timezone session."""
    if not tzs or not tzs['bearer_token']:
        return 'disconnected'
    now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    now_dt  = datetime.utcnow()
    # Expired session cookie
    if tzs['session_expires_at'] and tzs['session_expires_at'] < now_str:
        return 'expired'
    # Check last poll
    if tzs['last_poll_at']:
        try:
            last = datetime.strptime(tzs['last_poll_at'], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            last = None
        if last:
            age = (now_dt - last).total_seconds()
            # Only call it 'error' if the LAST poll errored AND it happened recently
            # (i.e. not just an old stale error from before a reconnect)
            if tzs['last_poll_status'] == 'error' and age < TIMEZONE_POLL_INTERVAL * 2:
                return 'error'
            # Stale: no successful poll in 3x the poll interval
            if age > TIMEZONE_POLL_INTERVAL * 3:
                return 'stale'
    # No polls yet (freshly connected) or last poll was recent — show connected
    return 'connected'


# ─── Discord Webhook ──────────────────────────────────────────────────────────
def send_discord_webhook(webhook_url, card, data, prev_total, new_total):
    try:
        diff = new_total - prev_total
        sign = '+' if diff > 0 else ''
        color = 0x22c55e if diff > 0 else 0xef4444  # green if gained, red if spent
        label = card['card_label'] or card['card_number'] or 'Card'
        ctype = card['card_type'] or 'koko'
        emoji = '🕹️' if ctype == 'timezone' else '🎮'
        payload = {
            'embeds': [{
                'title': f'{emoji} {label}',
                'description': f'Balance updated',
                'color': color,
                'fields': [
                    {'name': 'Credits', 'value': f"${data.get('cash_balance', 0):.2f}", 'inline': True},
                    {'name': 'Bonus', 'value': f"${data.get('cash_bonus', 0):.2f}", 'inline': True},
                    {'name': 'Change', 'value': f"{sign}${diff:.2f}", 'inline': True},
                ],
                'footer': {'text': f'Total: ${new_total:.2f}'},
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }]
        }
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        print(f"[Discord] Webhook error: {e}")

# ─── Poller ───────────────────────────────────────────────────────────────────
def log_poll(card_id, success, message=''):
    try:
        conn = get_db()
        conn.execute('INSERT INTO poll_log (card_id, success, message) VALUES (?,?,?)',
                    (card_id, 1 if success else 0, message))
        # Keep only last 100 entries per card
        conn.execute('''DELETE FROM poll_log WHERE card_id=? AND id NOT IN 
                       (SELECT id FROM poll_log WHERE card_id=? ORDER BY logged_at DESC LIMIT 100)''',
                    (card_id, card_id))
        conn.commit(); conn.close()
    except: pass

def poll_cards():
    print(f"[Poller] Started. Default: {DEFAULT_POLL_INTERVAL}s Timezone: {TIMEZONE_POLL_INTERVAL}s")
    last_poll = {}  # card_id -> last poll timestamp

    while True:
        try:
            conn = get_db()
            cards = conn.execute('SELECT * FROM cards WHERE active=1').fetchall()
            conn.close()

            now = time.time()
            for card in cards:
                ctype = card['card_type'] or 'koko'
                default_interval = TIMEZONE_POLL_INTERVAL if ctype == 'timezone' else DEFAULT_POLL_INTERVAL
                interval = card['poll_interval'] if card['poll_interval'] and card['poll_interval'] > 0 else default_interval

                if now - last_poll.get(card['id'], 0) < interval:
                    continue
                last_poll[card['id']] = now

                data = None
                if ctype == 'koko':
                    data = fetch_koko_balance(card['card_token'])
                    if data and any(v is not None for v in [data.get('cash_balance'), data.get('cash_bonus'), data.get('points')]):
                        log_poll(card['id'], True, 'OK')
                    else:
                        log_poll(card['id'], False, 'No data returned')

                elif ctype == 'timezone':
                    conn = get_db()
                    tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (card['user_id'],)).fetchone()
                    conn.close()
                    if tzs and tzs['bearer_token']:
                        cookies = json.loads(tzs['cookies_json'] or '{}')
                        guest = fetch_timezone_guest(tzs['bearer_token'], cookies, user_id=card['user_id'])
                        if guest:
                            for c in guest.get('cards', []):
                                if str(c.get('number')) == str(card['card_number']):
                                    data = {
                                        'cash_balance': c.get('cashBalance', 0),
                                        'cash_bonus': c.get('bonusBalance', 0),
                                        'points': c.get('eTickets', c.get('tickets', 0)),
                                        'card_name': card['card_label'],
                                        'tier': c.get('tier', ''),
                                    }
                                    break
                            # Update poll status
                            conn = get_db()
                            status = 'ok' if data else 'card_not_found'
                            conn.execute('UPDATE timezone_sessions SET last_poll_at=?, last_poll_status=? WHERE user_id=?',
                                        (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), status, card['user_id']))
                            conn.commit(); conn.close()
                            log_poll(card['id'], bool(data), status)
                        else:
                            conn = get_db()
                            conn.execute('UPDATE timezone_sessions SET last_poll_status=? WHERE user_id=?',
                                        ('error', card['user_id']))
                            conn.commit(); conn.close()
                            log_poll(card['id'], False, 'API error - token may be expired')
                            print(f"[Poller] Timezone API error for user {card['user_id']} - token may be expired")
                    else:
                        log_poll(card['id'], False, 'No session token')

                if data and any(v is not None for v in [data.get('cash_balance'), data.get('cash_bonus'), data.get('points')]):
                    conn = get_db()
                    # Check previous balance to detect changes
                    prev = conn.execute('SELECT cash_balance,cash_bonus,points FROM balance_history WHERE card_id=? ORDER BY recorded_at DESC LIMIT 1', (card['id'],)).fetchone()
                    conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name,tier) VALUES (?,?,?,?,?,?)',
                        (card['id'], data.get('cash_balance'), data.get('cash_bonus'), data.get('points'), data.get('card_name'), data.get('tier','')))
                    if data.get('tier'):
                        conn.execute('UPDATE cards SET tier=? WHERE id=?', (data['tier'], card['id']))
                    conn.commit()
                    # Send discord webhook if balance changed
                    user_row = conn.execute('SELECT discord_webhook FROM users WHERE id=?', (card['user_id'],)).fetchone()
                    conn.close()
                    if user_row and user_row['discord_webhook'] and prev:
                        prev_total = (prev['cash_balance'] or 0) + (prev['cash_bonus'] or 0)
                        new_total = (data.get('cash_balance') or 0) + (data.get('cash_bonus') or 0)
                        if abs(new_total - prev_total) >= 0.01:
                            send_discord_webhook(user_row['discord_webhook'], card, data, prev_total, new_total)
                    print(f"[Poller] Card {card['id']} ({ctype}): {data.get('cash_balance')}/{data.get('cash_bonus')}/{data.get('points')}")

        except Exception as e:
            print(f"[Poller] Error: {e}")
        time.sleep(10)  # Check every 10s, each card polls at its own interval

# ─── Routes: Auth ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if get_current_user() else url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        c = request.form.get('confirm_password','')
        email = request.form.get('email','').strip() or None
        if not u or not p:
            flash('Username and password required.', 'error')
            return render_template('register.html')
        if len(p) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html')
        import re as _re
        if not _re.search(r'[A-Z]', p):
            flash('Password must contain at least one uppercase letter.', 'error')
            return render_template('register.html')
        if not _re.search(r'[0-9]', p):
            flash('Password must contain at least one number.', 'error')
            return render_template('register.html')
        if p != c:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        conn = get_db()
        try:
            count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            is_admin = 1 if (count == 0 or (ADMIN_USERNAME and u == ADMIN_USERNAME)) else 0
            conn.execute('INSERT INTO users (username,password_hash,email,is_admin) VALUES (?,?,?,?)',
                        (u, hash_password(p), email, is_admin))
            conn.commit(); flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError: flash('Username already taken.', 'error')
        finally: conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u, p = request.form['username'].strip(), request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=? AND password_hash=?', (u, hash_password(p))).fetchone()
        conn.close()
        if user:
            session.permanent = True
            session['user_id'] = user['id']; return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')


@app.route('/auth/discord')
def discord_oauth_start():
    """Redirect to Discord OAuth2 login."""
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        flash('Discord login not configured.', 'error')
        return redirect(url_for('login'))
    import secrets as _sec
    state = _sec.token_hex(16)
    session['discord_oauth_state'] = state
    # Use APP_URL to ensure https:// is used (url_for may produce http://)
    redirect_uri = APP_URL.rstrip('/') + '/auth/discord/callback'
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'identify email',
        'state': state
    }
    from urllib.parse import urlencode
    return redirect('https://discord.com/oauth2/authorize?' + urlencode(params))

@app.route('/auth/discord/callback')
def discord_oauth_callback():
    error = request.args.get('error')
    if error:
        flash('Discord login cancelled.', 'error')
        return redirect(url_for('login'))
    code  = request.args.get('code')
    state = request.args.get('state')
    if not code or state != session.pop('discord_oauth_state', None):
        flash('Invalid OAuth state.', 'error')
        return redirect(url_for('login'))

    redirect_uri = APP_URL.rstrip('/') + '/auth/discord/callback'
    # Exchange code for token
    token_resp = requests.post('https://discord.com/api/oauth2/token', data={
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
    }, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=10)
    if token_resp.status_code != 200:
        flash('Discord auth failed.', 'error'); return redirect(url_for('login'))

    access_token = token_resp.json().get('access_token')
    # Fetch Discord user info
    user_resp = requests.get('https://discord.com/api/users/@me',
        headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
    if user_resp.status_code != 200:
        flash('Could not fetch Discord profile.', 'error'); return redirect(url_for('login'))

    duser = user_resp.json()
    discord_id = str(duser['id'])
    discord_username = duser.get('username', '')
    discord_email = duser.get('email', '')

    conn = get_db()
    # Check if discord_id already linked to an account
    user = conn.execute('SELECT * FROM users WHERE discord_id=?', (discord_id,)).fetchone()
    if user:
        session.permanent = True
        session['user_id'] = user['id']
        conn.close()
        return redirect(url_for('dashboard'))

    # Check if email matches an existing account
    if discord_email:
        user = conn.execute('SELECT * FROM users WHERE email=?', (discord_email,)).fetchone()
        if user:
            conn.execute('UPDATE users SET discord_id=? WHERE id=?', (discord_id, user['id']))
            conn.commit()
            session['user_id'] = user['id']
            conn.close()
            flash(f'Discord linked to your account {user["username"]}.', 'success')
            return redirect(url_for('dashboard'))

    # Create new account from Discord profile
    count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    is_admin = 1 if count == 0 else 0
    username = discord_username
    # Ensure unique username
    base = username
    i = 1
    while conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
        username = f'{base}{i}'; i += 1
    conn.execute('INSERT INTO users (username, password_hash, email, discord_id, is_admin) VALUES (?,?,?,?,?)',
        (username, '', discord_email, discord_id, is_admin))
    conn.commit()
    user = conn.execute('SELECT * FROM users WHERE discord_id=?', (discord_id,)).fetchone()
    conn.close()
    session['user_id'] = user['id']
    flash(f'Welcome {username}! Account created via Discord.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('identifier','').strip()
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email=? OR username=?', (identifier, identifier)).fetchone()
        if user and user['email']:
            import secrets as _sec
            token = _sec.token_urlsafe(32)
            expires = (datetime.utcnow() + timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('UPDATE users SET reset_token=?, reset_expires=? WHERE id=?', (token, expires, user['id']))
            conn.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            # Send email
            if MAIL_SERVER:
                try:
                    import smtplib
                    from email.mime.text import MIMEText
                    msg = MIMEText(f'Reset your Balance Tracker password:\n\n{reset_url}\n\nExpires in 2 hours.')
                    msg['Subject'] = 'Balance Tracker — Password Reset'
                    msg['From'] = MAIL_FROM
                    msg['To'] = user['email']
                    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as s:
                        s.starttls()
                        if MAIL_USERNAME: s.login(MAIL_USERNAME, MAIL_PASSWORD)
                        s.send_message(msg)
                    flash('Password reset email sent. Check your inbox.', 'success')
                except Exception as e:
                    print(f'[Mail] Error: {e}')
                    flash(f'Reset link: {reset_url}', 'success')  # fallback — show link
            else:
                # No mail configured — show link directly (admin use case)
                flash(f'No email server configured. Reset link (share securely): {reset_url}', 'success')
        else:
            flash('If that account exists and has an email, a reset link was sent.', 'success')
        conn.close()
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE reset_token=?', (token,)).fetchone()
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    if not user or not user['reset_expires'] or user['reset_expires'] < now:
        conn.close()
        flash('Reset link is invalid or expired.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        pw = request.form.get('password','')
        if len(pw) < 6:
            return render_template('reset_password.html', token=token, error='Password must be at least 6 characters.')
        conn.execute('UPDATE users SET password_hash=?, reset_token=NULL, reset_expires=NULL WHERE id=?',
                    (hash_password(pw), user['id']))
        conn.commit(); conn.close()
        flash('Password updated. Please log in.', 'success')
        return redirect(url_for('login'))
    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

@app.route('/settings', methods=['GET','POST'])
@login_required
def settings():
    user = get_current_user()
    if request.method == 'POST':
        tz = request.form.get('timezone_name', 'Australia/Sydney')
        show_overview = 1 if request.form.get('show_overview') else 0
        discord_webhook = request.form.get('discord_webhook', '').strip()
        conn = get_db()
        leaderboard_opt = 1 if request.form.get('leaderboard_opt_in') else 0
        email = request.form.get('email', '').strip() or None
        conn.execute('UPDATE users SET timezone_name=?, show_overview=?, discord_webhook=?, leaderboard_opt_in=?, email=? WHERE id=?', 
                    (tz, show_overview, discord_webhook, leaderboard_opt, email, user['id']))
        conn.commit(); conn.close()
        flash('Settings saved.', 'success')
        return redirect(url_for('settings'))
    conn = get_db()
    cards = conn.execute('SELECT * FROM cards WHERE user_id=? AND active=1 ORDER BY card_type, created_at', (user['id'],)).fetchall()
    conn.close()
    return render_template('settings.html', user=user, cards=cards)

# ─── Routes: Dashboard ────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    conn = get_db()
    cards = conn.execute('''
        SELECT c.*, h.cash_balance, h.cash_bonus, h.points, h.recorded_at as last_updated
        FROM cards c
        LEFT JOIN balance_history h ON h.id=(SELECT id FROM balance_history WHERE card_id=c.id ORDER BY recorded_at DESC LIMIT 1)
        WHERE c.user_id=? AND c.active=1 ORDER BY c.card_type, c.created_at
    ''', (user['id'],)).fetchall()
    tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
    conn.close()
    tz_status = tz_session_status(tzs)
    return render_template('dashboard.html', user=user, cards=cards,
                          tz_connected=tz_status=='connected', tz_session=tzs,
                          tz_status=tz_status)

# ─── Routes: Cards ────────────────────────────────────────────────────────────
@app.route('/cards/add', methods=['POST'])
@login_required
def add_card():
    user = get_current_user()
    token = request.form.get('card_token','').strip()
    label = request.form.get('card_label','').strip()
    interval = int(request.form.get('poll_interval', DEFAULT_POLL_INTERVAL))
    if not token: flash('Card token is required.', 'error'); return redirect(url_for('dashboard'))
    data = fetch_koko_balance(token)
    if not data or all(v is None for v in [data['cash_balance'], data['cash_bonus'], data['points']]):
        flash('Could not fetch data for that card token.', 'error'); return redirect(url_for('dashboard'))
    conn = get_db()
    try:
        conn.execute('INSERT INTO cards (user_id,card_type,card_token,card_label,card_number,poll_interval) VALUES (?,?,?,?,?,?)',
            (user['id'],'koko',token, label or data.get('card_name',token), data.get('card_name'), interval))
        cid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name) VALUES (?,?,?,?,?)',
            (cid, data['cash_balance'], data['cash_bonus'], data['points'], data['card_name']))
        conn.commit(); flash(f'Koko card added!', 'success')
    except sqlite3.IntegrityError: flash('Card already added.', 'error')
    finally: conn.close()
    return redirect(url_for('dashboard'))

@app.route('/cards/<int:card_id>/delete', methods=['POST'])
@login_required
def delete_card(card_id):
    user = get_current_user()
    conn = get_db()
    conn.execute('UPDATE cards SET active=0 WHERE id=? AND user_id=?', (card_id, user['id']))
    conn.commit(); conn.close(); flash('Card removed.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/cards/<int:card_id>/poll-interval', methods=['POST'])
@login_required
def update_poll_interval(card_id):
    user = get_current_user()
    interval = int(request.form.get('poll_interval', DEFAULT_POLL_INTERVAL))
    conn = get_db()
    conn.execute('UPDATE cards SET poll_interval=? WHERE id=? AND user_id=?', (interval, card_id, user['id']))
    conn.commit(); conn.close()
    return jsonify({'success': True, 'interval': interval})

@app.route('/cards/<int:card_id>/force-poll', methods=['POST'])
@login_required
def force_poll(card_id):
    user = get_current_user()
    conn = get_db()
    card = conn.execute('SELECT * FROM cards WHERE id=? AND user_id=?', (card_id, user['id'])).fetchone()
    conn.close()
    if not card: return jsonify({'error': 'Not found'}), 404

    data = None
    error_msg = None
    if card['card_type'] == 'koko':
        try:
            data = fetch_koko_balance(card['card_token'])
        except Exception as e:
            error_msg = str(e)
    elif card['card_type'] == 'timezone':
        conn = get_db()
        tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
        conn.close()
        if not tzs:
            return jsonify({'success': False, 'error': 'No Timezone session — reconnect first'}), 400
        try:
            guest = fetch_timezone_guest(tzs['bearer_token'], json.loads(tzs['cookies_json'] or '{}'), user_id=user['id'])
            if guest and guest.get('cards'):
                card_num = str(card['card_number']).strip() if card['card_number'] else ''
                for c in guest.get('cards', []):
                    api_num = str(c.get('number', '')).strip()
                    if api_num == card_num or (card_num and card_num in api_num) or (api_num and api_num in card_num):
                        data = {
                            'cash_balance': float(c.get('cashBalance') or 0),
                            'cash_bonus':   float(c.get('bonusBalance') or 0),
                            'points':       int(c.get('eTickets') or c.get('tickets') or 0),
                            'card_name':    card['card_label'],
                            'tier':         c.get('tier', '')
                        }
                        break
                if not data:
                    error_msg = f"Card number {card_num!r} not found in Timezone session (found: {[str(c.get('number')) for c in guest.get('cards',[])]})"
            else:
                # No cards returned — try forcing a token refresh then retry once
                print(f"[ForcePoll] No cards from Timezone for user {user['id']}, forcing token refresh...")
                if tzs.get('refresh_token'):
                    new_tok, new_rt, _ = tz_refresh_ms_token(tzs['refresh_token'], tzs.get('ms_client_id'))
                    if new_tok:
                        guest2 = fetch_timezone_guest(new_tok, json.loads(tzs['cookies_json'] or '{}'), user_id=user['id'])
                        if guest2 and guest2.get('cards'):
                            card_num = str(card['card_number']).strip() if card['card_number'] else ''
                            for c in guest2.get('cards', []):
                                api_num = str(c.get('number', '')).strip()
                                if api_num == card_num or (card_num and card_num in api_num) or (api_num and api_num in card_num):
                                    data = {
                                        'cash_balance': float(c.get('cashBalance') or 0),
                                        'cash_bonus':   float(c.get('bonusBalance') or 0),
                                        'points':       int(c.get('eTickets') or c.get('tickets') or 0),
                                        'card_name':    card['card_label'],
                                        'tier':         c.get('tier', '')
                                    }
                                    break
                if not data:
                    error_msg = 'Timezone session returned no cards — please reconnect'
        except Exception as e:
            error_msg = str(e)

    now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    if data and any(v is not None for v in [data.get('cash_balance'), data.get('cash_bonus'), data.get('points')]):
        conn = get_db()
        conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name,tier) VALUES (?,?,?,?,?,?)',
            (card_id, data.get('cash_balance'), data.get('cash_bonus'), data.get('points'), data.get('card_name'), data.get('tier','')))
        if data.get('tier'):
            conn.execute('UPDATE cards SET tier=? WHERE id=?', (data['tier'], card_id))
        conn.commit()
        # Fetch updated poll logs
        logs = conn.execute(
            'SELECT * FROM poll_log WHERE card_id=? ORDER BY logged_at DESC LIMIT 20', (card_id,)
        ).fetchall()
        conn.close()
        log_poll(card_id, True, 'Manual poll')
        return jsonify({
            'success': True,
            'data': data,
            'last_updated': now_str[:16],
            'logs': [{'success': l['success'], 'message': l['message'] or 'OK', 'logged_at': l['logged_at'][:16]} for l in logs]
        })
    
    log_poll(card_id, False, error_msg or 'No data returned')
    print(f"[ForcePoll] Card {card_id} failed: {error_msg}")
    return jsonify({'success': False, 'error': error_msg or 'Could not fetch data'}), 400

@app.route('/cards/<int:card_id>/rename', methods=['POST'])
@login_required
def rename_card(card_id):
    user = get_current_user()
    new_label = request.form.get('card_label', '').strip()
    if not new_label:
        return jsonify({'error': 'Label cannot be empty'}), 400
    conn = get_db()
    conn.execute('UPDATE cards SET card_label=? WHERE id=? AND user_id=?', (new_label, card_id, user['id']))
    conn.commit(); conn.close()
    return jsonify({'success': True, 'label': new_label})

@app.route('/cards/<int:card_id>')
@login_required
def card_detail(card_id):
    user = get_current_user()
    conn = get_db()
    card = conn.execute('SELECT * FROM cards WHERE id=? AND user_id=? AND active=1', (card_id, user['id'])).fetchone()
    if not card: conn.close(); return redirect(url_for('dashboard'))
    logs = conn.execute('SELECT * FROM poll_log WHERE card_id=? ORDER BY logged_at DESC LIMIT 20', (card_id,)).fetchall()
    conn.close()
    return render_template('card_detail.html', user=user, card=card, poll_logs=logs)

# ─── Routes: Timezone ─────────────────────────────────────────────────────────
@app.route('/timezone/connect')
@login_required
def timezone_connect():
    return render_template('timezone_connect.html', user=get_current_user())

@app.route('/timezone/start')
@login_required
def timezone_start():
    return render_template('timezone_start.html', user=get_current_user(), app_url=APP_URL)

@app.route('/timezone/landing')
@login_required
def timezone_landing():
    return render_template('timezone_landing.html', user=get_current_user())

@app.route('/timezone/callback', methods=['POST'])
@login_required
def timezone_callback():
    user = get_current_user()
    data = request.get_json()
    bearer_token = data.get('bearer_token')
    cookies = data.get('cookies', {})
    if not bearer_token: return jsonify({'error': 'No token'}), 400
    try:
        payload = bearer_token.split('.')[1]
        payload += '=' * (4 - len(payload) % 4)
        claims = json.loads(base64.b64decode(payload))
        token_exp = datetime.utcfromtimestamp(claims['exp']).strftime('%Y-%m-%d %H:%M:%S')
    except:
        token_exp = (datetime.utcnow() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    sess_exp = (datetime.utcnow() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
    # Extract Microsoft refresh token from localStorage data if provided
    refresh_token = data.get('refresh_token') or data.get('refreshToken')
    ms_client_id  = data.get('ms_client_id') or data.get('clientId')
    save_timezone_session(user['id'], bearer_token, cookies, token_exp, sess_exp,
                          refresh_token=refresh_token, ms_client_id=ms_client_id)
    guest = fetch_timezone_guest(bearer_token, cookies)
    if not guest: return jsonify({'error': 'Could not fetch Timezone data'}), 400
    conn = get_db()
    conn.execute('UPDATE timezone_sessions SET guest_id=? WHERE user_id=?', (guest.get('id'), user['id']))
    conn.commit(); conn.close()
    cards = _format_tz_cards(guest)
    return jsonify({'success': True, 'cards': cards, 'name': guest.get('givenName','')})

@app.route('/timezone/extract-token', methods=['POST'])
@login_required
def timezone_extract_token():
    user = get_current_user()
    data = request.get_json() or {}
    bearer_token = data.get('bearer_token')
    cookies_from_browser = data.get('cookies', {})
    if bearer_token and bearer_token.startswith('eyJ'):
        guest = fetch_timezone_guest(bearer_token, cookies_from_browser)
        if guest:
            try:
                payload = bearer_token.split('.')[1]
                payload += '=' * (4 - len(payload) % 4)
                claims = json.loads(base64.b64decode(payload))
                token_exp = datetime.utcfromtimestamp(claims['exp']).strftime('%Y-%m-%d %H:%M:%S')
            except:
                token_exp = (datetime.utcnow() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
            sess_exp = (datetime.utcnow() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
            rt  = data.get('refresh_token') or data.get('refreshToken')
            cid = data.get('client_id') or data.get('clientId')
            save_timezone_session(user['id'], bearer_token, cookies_from_browser, token_exp, sess_exp, guest.get('id'), refresh_token=rt, ms_client_id=cid)
            return jsonify({'success': True, 'cards': _format_tz_cards(guest), 'name': guest.get('givenName','')})
    return jsonify({'success': False, 'error': 'Could not extract token'})

def _format_tz_cards(guest):
    return [{'number': str(c.get('number','')), 'cashBalance': c.get('cashBalance',0),
             'bonusBalance': c.get('bonusBalance',0), 'tickets': c.get('eTickets', c.get('tickets',0)),
             'paperTickets': c.get('paperTickets',0), 'cumulativeBalance': c.get('cumulativeBalance',0),
             'tier': c.get('tier',''), 'status': c.get('status','Active'),
             'fullCardNumber': c.get('fullCardNumber',''), 'country': c.get('country','')}
            for c in guest.get('cards',[])]

@app.route('/timezone/add-card', methods=['POST'])
@login_required
def timezone_add_card():
    user = get_current_user()
    card_number = request.form.get('card_number','').strip()
    card_label = request.form.get('card_label','').strip()
    cash_balance = float(request.form.get('cash_balance', 0))
    bonus_balance = float(request.form.get('bonus_balance', 0))
    tickets = int(float(request.form.get('tickets', 0)))
    tier = request.form.get('tier', '')
    interval = int(request.form.get('poll_interval', TIMEZONE_POLL_INTERVAL))
    if not card_number: flash('Card number required.', 'error'); return redirect(url_for('dashboard'))
    conn = get_db()
    try:
        existing = conn.execute("SELECT id FROM cards WHERE user_id=? AND card_token=?",
            (user['id'], f'tz_{card_number}')).fetchone()
        if existing:
            conn.execute("UPDATE cards SET active=1, card_label=?, tier=?, poll_interval=? WHERE id=?",
                (card_label or f'Timezone {card_number}', tier, interval, existing['id']))
            cid = existing['id']
        else:
            conn.execute("INSERT INTO cards (user_id,card_type,card_token,card_label,card_number,tier,poll_interval) VALUES (?,'timezone',?,?,?,?,?)",
                (user['id'], f'tz_{card_number}', card_label or f'Timezone {card_number}', card_number, tier, interval))
            cid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name,tier) VALUES (?,?,?,?,?,?)',
            (cid, cash_balance, bonus_balance, tickets, card_label or f'Timezone {card_number}', tier))
        conn.commit(); flash(f'Timezone card {card_number} added!', 'success')
    except sqlite3.IntegrityError: flash('Card already tracked.', 'error')
    finally: conn.close()
    return redirect(url_for('dashboard'))

@app.route('/timezone/disconnect', methods=['POST'])
@login_required
def timezone_disconnect():
    user = get_current_user()
    conn = get_db()
    conn.execute('DELETE FROM timezone_sessions WHERE user_id=?', (user['id'],))
    conn.execute("UPDATE cards SET active=0 WHERE user_id=? AND card_type='timezone'", (user['id'],))
    conn.commit(); conn.close(); flash('Timezone account disconnected.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/timezone/extractor')
@login_required
def timezone_extractor():
    return render_template('timezone_extractor.html')


@app.route('/settings/test-webhook', methods=['POST'])
@login_required
def test_webhook():
    user = get_current_user()
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL'}), 400
    try:
        payload = {
            'embeds': [{
                'title': '🎮 Balance Tracker — Test',
                'description': 'Webhook connected successfully!',
                'color': 0x6366f1,
                'footer': {'text': f'From: {user["username"]}'},
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }]
        }
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code in (200, 204):
            return jsonify({'success': True})
        return jsonify({'error': f'Discord returned {resp.status_code}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/discord/link', methods=['POST'])
@login_required
def discord_link():
    user = get_current_user()
    code = request.form.get('link_code','').strip().upper()
    if not code:
        flash('Enter a link code from Discord /link command.', 'error')
        return redirect(url_for('settings'))
    conn = get_db()
    row = conn.execute('SELECT * FROM discord_link_codes WHERE code=?', (code,)).fetchone()
    if not row:
        conn.close(); flash('Invalid code.', 'error'); return redirect(url_for('settings'))
    if row['expires_at'] < datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'):
        conn.close(); flash('Code expired - use /link in Discord again.', 'error'); return redirect(url_for('settings'))
    existing = conn.execute('SELECT id FROM users WHERE discord_id=?', (row['discord_id'],)).fetchone()
    if existing and existing['id'] != user['id']:
        conn.close(); flash('That Discord account is already linked.', 'error'); return redirect(url_for('settings'))
    conn.execute('UPDATE users SET discord_id=? WHERE id=?', (row['discord_id'], user['id']))
    conn.execute('DELETE FROM discord_link_codes WHERE discord_id=?', (row['discord_id'],))
    conn.commit(); conn.close()
    flash(f'Discord linked: {row["discord_username"]}', 'success')
    return redirect(url_for('settings'))

@app.route('/discord/unlink', methods=['POST'])
@login_required
def discord_unlink():
    user = get_current_user()
    conn = get_db()
    conn.execute('UPDATE users SET discord_id=NULL WHERE id=?', (user['id'],))
    conn.commit(); conn.close()
    flash('Discord account unlinked.', 'success')
    return redirect(url_for('settings'))

@app.route('/cards/<int:card_id>/leaderboard', methods=['POST'])
@login_required
def toggle_leaderboard(card_id):
    user = get_current_user()
    val = 1 if request.form.get('leaderboard_public') == '1' else 0
    conn = get_db()
    conn.execute('UPDATE cards SET leaderboard_public=? WHERE id=? AND user_id=?', (val, card_id, user['id']))
    conn.commit(); conn.close()
    return jsonify({'success': True, 'leaderboard_public': val})

@app.route('/api/leaderboard')
def api_leaderboard():
    conn = get_db()
    rows = conn.execute(
        'SELECT c.id, c.card_label, c.card_number, c.card_type, c.tier, u.username, '
        'h.cash_balance, h.cash_bonus, h.points, h.recorded_at '
        'FROM cards c JOIN users u ON c.user_id=u.id '
        'LEFT JOIN balance_history h ON h.id=(SELECT id FROM balance_history WHERE card_id=c.id ORDER BY recorded_at DESC LIMIT 1) '
        'WHERE c.active=1 AND c.leaderboard_public=1 AND u.leaderboard_opt_in=1 '
        'ORDER BY (COALESCE(h.cash_balance,0)+COALESCE(h.cash_bonus,0)) DESC LIMIT 20'
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/cards/<int:card_id>/import-transactions', methods=['POST'])
@login_required
def import_transactions(card_id):
    """Import historical transactions from Timezone API into balance_history."""
    user = get_current_user()
    conn = get_db()
    card = conn.execute('SELECT * FROM cards WHERE id=? AND user_id=? AND active=1', (card_id, user['id'])).fetchone()
    if not card or card['card_type'] != 'timezone':
        conn.close(); return jsonify({'error': 'Card not found or not a Timezone card'}), 404
    tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
    conn.close()
    if not tzs: return jsonify({'error': 'No Timezone session'}), 400

    cookies = json.loads(tzs['cookies_json'] or '{}')
    card_number = card['card_number']
    if not card_number: return jsonify({'error': 'Card has no card number'}), 400

    transactions = fetch_timezone_transactions(card_number, tzs['bearer_token'], cookies)
    if not transactions:
        return jsonify({'error': 'No transactions found or API unavailable'}), 400

    # Log first transaction so we can see the real field names
    if transactions:
        print(f"[ImportTx] Sample transaction keys: {list(transactions[0].keys())}")
        print(f"[ImportTx] Sample transaction: {dict(transactions[0])}")

    # Sort transactions oldest first so running balance builds in order
    transactions = sorted(transactions, key=lambda t: t.get('modified', ''))

    conn = get_db()
    imported = 0
    skipped = 0
    for tx in transactions:
        tx_time = tx.get('modified')
        if not tx_time:
            continue

        running_total = tx.get('runningCumulativeBalance')
        cash_delta    = float(tx.get('cashBalance') or 0)
        bonus_delta   = float(tx.get('bonusBalance') or 0)
        e_cash        = float(tx.get('eCash') or 0)
        p_cash        = float(tx.get('pCash') or 0)
        tickets       = int(tx.get('eTickets') or 0)
        description   = tx.get('description') or tx.get('reason') or None

        # runningCumulativeBalance = 0 means this field isn't set for this tx — skip it
        # to avoid false 0-balance data points corrupting the chart
        if running_total is None or float(running_total) == 0:
            # Only use delta-based calculation if it's a top-up (positive cash)
            if cash_delta <= 0 and e_cash <= 0 and p_cash <= 0:
                skipped += 1
                continue
            cash_balance = round(cash_delta + e_cash + p_cash, 2)
            cash_bonus   = 0.0
        else:
            running_total = float(running_total)
            # running total is cash+bonus combined
            # Use bonus_delta to separate: if bonus was spent (negative), that's bonus component
            if bonus_delta < 0:
                # bonus was spent this tx — running total already reflects spend
                cash_bonus = 0.0
                cash_balance = round(running_total, 2)
            elif bonus_delta > 0:
                # bonus was added — split it out
                cash_bonus = round(bonus_delta, 2)
                cash_balance = round(running_total - bonus_delta, 2)
            else:
                # Pure cash transaction
                cash_bonus = 0.0
                cash_balance = round(running_total, 2)

        # Normalise timestamp — "2026-02-23T05:04:27.0000000+00:00"
        try:
            ts = str(tx_time)[:19].replace('T', ' ')
            datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
        except:
            continue

        exists = conn.execute(
            'SELECT id FROM balance_history WHERE card_id=? AND recorded_at=?', (card_id, ts)
        ).fetchone()
        if not exists:
            conn.execute(
                'INSERT INTO balance_history (card_id, cash_balance, cash_bonus, points, description, recorded_at) VALUES (?,?,?,?,?,?)',
                (card_id, cash_balance, cash_bonus, tickets, description, ts)
            )
            imported += 1
    conn.commit(); conn.close()
    print(f"[ImportTx] Imported {imported}, skipped {skipped} zero-balance rows")
    return jsonify({'success': True, 'imported': imported, 'skipped': skipped, 'total': len(transactions)})


@app.route('/admin/timezone-debug')
@login_required
def timezone_debug():
    user = get_current_user()
    if not user or not user['is_admin']:
        return jsonify({'error': 'Admin only'}), 403
    conn = get_db()
    sessions = conn.execute('''
        SELECT ts.*, u.username FROM timezone_sessions ts
        JOIN users u ON u.id = ts.user_id
    ''').fetchall()
    conn.close()
    result = []
    for s in sessions:
        result.append({
            'username': s['username'],
            'user_id': s['user_id'],
            'has_bearer': bool(s['bearer_token']),
            'has_refresh_token': bool(s['refresh_token']),
            'has_ms_client_id': bool(s['ms_client_id']),
            'ms_client_id': s['ms_client_id'],
            'token_expires_at': s['token_expires_at'],
            'session_expires_at': s['session_expires_at'],
            'last_poll_at': s['last_poll_at'],
            'last_poll_status': s['last_poll_status'],
            'refresh_token_preview': s['refresh_token'][:20] + '...' if s['refresh_token'] else None,
        })
    return jsonify(result)

# ─── Routes: Admin ────────────────────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin():
    conn = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY created_at').fetchall()
    cards = conn.execute('''
        SELECT c.*, u.username,
               h.cash_balance, h.cash_bonus, h.points, h.recorded_at as last_updated
        FROM cards c
        JOIN users u ON c.user_id = u.id
        LEFT JOIN balance_history h ON h.id=(SELECT id FROM balance_history WHERE card_id=c.id ORDER BY recorded_at DESC LIMIT 1)
        WHERE c.active=1 ORDER BY u.username, c.card_type
    ''').fetchall()
    tz_sessions = conn.execute('''
        SELECT ts.*, u.username FROM timezone_sessions ts
        JOIN users u ON ts.user_id = u.id
    ''').fetchall()
    conn.close()
    tz_statuses = {ts['user_id']: tz_session_status(ts) for ts in tz_sessions}
    current = get_current_user()
    return render_template('admin.html', users=users, cards=cards,
                          tz_sessions=tz_sessions, tz_statuses=tz_statuses,
                          user=current, current_user=current, admin_username=ADMIN_USERNAME)

@app.route('/admin/make-admin/<int:user_id>', methods=['POST'])
@admin_required
def make_admin(user_id):
    conn = get_db()
    conn.execute('UPDATE users SET is_admin=1 WHERE id=?', (user_id,))
    conn.commit(); conn.close()
    flash('User promoted to admin.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/remove-admin/<int:user_id>', methods=['POST'])
@admin_required
def remove_admin(user_id):
    current = get_current_user()
    conn = get_db()
    target = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        conn.close(); flash('User not found.', 'error'); return redirect(url_for('admin'))
    is_root = (target['id'] == 1) or (ADMIN_USERNAME and target['username'] == ADMIN_USERNAME)
    if is_root:
        conn.close(); flash('Cannot remove admin from root user.', 'error'); return redirect(url_for('admin'))
    if target['id'] == current['id']:
        conn.close(); flash('Cannot demote yourself.', 'error'); return redirect(url_for('admin'))
    conn.execute('UPDATE users SET is_admin=0 WHERE id=?', (user_id,))
    conn.commit(); conn.close()
    flash(f'Admin removed from {target["username"]}.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/users/<int:user_id>/rename', methods=['POST'])
@admin_required
def admin_rename_user(user_id):
    new_username = request.form.get('new_username', '').strip()
    if not new_username:
        flash('Username cannot be empty.', 'error'); return redirect(url_for('admin'))
    conn = get_db()
    try:
        conn.execute('UPDATE users SET username=? WHERE id=?', (new_username, user_id))
        conn.commit(); flash(f'Username updated to {new_username}.', 'success')
    except sqlite3.IntegrityError:
        flash('Username already taken.', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    current = get_current_user()
    if user_id == current['id']:
        flash('Cannot delete your own account.', 'error'); return redirect(url_for('admin'))
    conn = get_db()
    target = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        conn.close(); flash('User not found.', 'error'); return redirect(url_for('admin'))
    is_root = (target['id'] == 1) or (ADMIN_USERNAME and target['username'] == ADMIN_USERNAME)
    if is_root:
        conn.close(); flash('Cannot delete root admin.', 'error'); return redirect(url_for('admin'))
    # Soft-delete all cards, delete sessions, then user
    conn.execute('UPDATE cards SET active=0 WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM timezone_sessions WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit(); conn.close()
    flash(f'User {target["username"]} deleted.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/users/<int:user_id>/leaderboard', methods=['POST'])
@admin_required
def admin_user_leaderboard(user_id):
    val = 1 if request.form.get('leaderboard_opt_in') == '1' else 0
    conn = get_db()
    conn.execute('UPDATE users SET leaderboard_opt_in=? WHERE id=?', (val, user_id))
    conn.commit(); conn.close()
    flash('Leaderboard opt-in updated.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/cards/<int:card_id>/leaderboard', methods=['POST'])
@admin_required
def admin_toggle_leaderboard(card_id):
    val = 1 if request.form.get('leaderboard_public') == '1' else 0
    conn = get_db()
    conn.execute('UPDATE cards SET leaderboard_public=? WHERE id=?', (val, card_id))
    conn.commit(); conn.close()
    flash('Card leaderboard visibility updated.', 'success')
    return redirect(url_for('admin'))

# ─── Routes: API ──────────────────────────────────────────────────────────────
@app.route('/api/cards/<int:card_id>/history')
@login_required
def api_history(card_id):
    user = get_current_user()
    period = request.args.get('period','day')
    since = datetime.utcnow() - ({'day': timedelta(hours=24), 'week': timedelta(days=7), 'month': timedelta(days=30)}.get(period, timedelta(hours=24)))
    conn = get_db()
    if not conn.execute('SELECT id FROM cards WHERE id=? AND user_id=?', (card_id, user['id'])).fetchone():
        conn.close(); return jsonify({'error': 'Not found'}), 404
    rows = conn.execute('SELECT cash_balance,cash_bonus,points,recorded_at,description FROM balance_history WHERE card_id=? AND recorded_at>=? AND cash_balance IS NOT NULL ORDER BY recorded_at ASC',
        (card_id, since.strftime('%Y-%m-%d %H:%M:%S'))).fetchall()
    conn.close()
    return jsonify({'labels':[r['recorded_at'] for r in rows], 'cash_balance':[r['cash_balance'] for r in rows],
                    'cash_bonus':[r['cash_bonus'] for r in rows], 'points':[r['points'] for r in rows],
                    'descriptions':[r['description'] for r in rows]})

@app.route('/api/cards/<int:card_id>/stats')
@login_required
def api_stats(card_id):
    user = get_current_user()
    conn = get_db()
    card = conn.execute('SELECT * FROM cards WHERE id=? AND user_id=?', (card_id, user['id'])).fetchone()
    if not card: conn.close(); return jsonify({'error': 'Not found'}), 404
    latest = conn.execute('SELECT * FROM balance_history WHERE card_id=? ORDER BY recorded_at DESC LIMIT 1', (card_id,)).fetchone()
    count = conn.execute('SELECT COUNT(*) as c FROM balance_history WHERE card_id=?', (card_id,)).fetchone()['c']
    since_24h = (datetime.utcnow()-timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    first_24h = conn.execute('SELECT cash_balance,cash_bonus FROM balance_history WHERE card_id=? AND recorded_at>=? ORDER BY recorded_at ASC LIMIT 1',
        (card_id, since_24h)).fetchone()
    conn.close()
    spent_24h = None
    if first_24h and latest:
        spent_24h = round(((first_24h['cash_balance'] or 0)+(first_24h['cash_bonus'] or 0))-((latest['cash_balance'] or 0)+(latest['cash_bonus'] or 0)), 2)
    return jsonify({'total_readings': count, 'latest': dict(latest) if latest else None, 'spent_24h': spent_24h, 'card_type': card['card_type']})

@app.route('/api/dashboard/overview')
@login_required
def api_dashboard_overview():
    """All cards combined history for the overview graph."""
    user = get_current_user()
    period = request.args.get('period', 'day')
    since = datetime.utcnow() - ({'day': timedelta(hours=24), 'week': timedelta(days=7), 'month': timedelta(days=30)}.get(period, timedelta(hours=24)))
    conn = get_db()
    cards = conn.execute('SELECT id, card_label, card_type, card_number FROM cards WHERE user_id=? AND active=1', (user['id'],)).fetchall()
    result = []
    for card in cards:
        rows = conn.execute('SELECT cash_balance, cash_bonus, points, recorded_at FROM balance_history WHERE card_id=? AND recorded_at>=? ORDER BY recorded_at ASC',
            (card['id'], since.strftime('%Y-%m-%d %H:%M:%S'))).fetchall()
        result.append({
            'card_id': card['id'],
            'label': card['card_label'] or card['card_number'] or 'Card',
            'card_type': card['card_type'],
            'data': [{'t': r['recorded_at'], 'total': (r['cash_balance'] or 0) + (r['cash_bonus'] or 0), 'points': r['points']} for r in rows]
        })
    conn.close()
    return jsonify(result)

@app.route('/api/cards/resolve-qr', methods=['POST'])
@login_required
def resolve_qr():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url: return jsonify({'error': 'No URL'}), 400
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        final_url = resp.url
        m = re.search(r'[?&]i=([^&]+)', final_url)
        if m:
            token = m.group(1)
            balance = fetch_koko_balance(token)
            if balance and any(v is not None for v in [balance.get('cash_balance'), balance.get('cash_bonus'), balance.get('points')]):
                return jsonify({'success': True, 'token': token, 'balance': balance})
            return jsonify({'error': 'Token found but could not fetch balance'}), 400
        return jsonify({'error': f'Could not extract token from: {final_url}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Keep old route for backward compat
@app.route('/cards/resolve-qr', methods=['POST'])
@login_required
def resolve_qr_old():
    return resolve_qr()

def start_discord_bot():
    bot_token = os.environ.get('DISCORD_BOT_TOKEN', '')
    if not bot_token:
        print("[Bot] DISCORD_BOT_TOKEN not set - Discord bot disabled.")
        return
    try:
        import subprocess, sys
        subprocess.Popen(
            [sys.executable, os.path.join(os.path.dirname(__file__), 'bot.py')],
            env=os.environ.copy()
        )
        print("[Bot] Discord bot process started.")
    except Exception as e:
        print(f"[Bot] Failed to start: {e}")

if __name__ == '__main__':
    init_db()
    threading.Thread(target=poll_cards, daemon=True).start()
    start_discord_bot()
    app.run(host='0.0.0.0', port=5000, debug=False)
