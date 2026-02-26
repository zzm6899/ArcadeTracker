import os, sqlite3, threading, time, hashlib, secrets, json, base64
import logging
from collections import deque

# ─── In-memory log buffer (last 500 lines) ────────────────────────────────────
_log_buffer = deque(maxlen=500)

class _BufferHandler(logging.Handler):
    def emit(self, record):
        _log_buffer.append({
            'ts': self.formatTime(record, '%Y-%m-%d %H:%M:%S'),
            'level': record.levelname,
            'msg': self.format(record),
        })

# Also capture print() output via a stream wrapper
import sys
class _PrintCapture:
    def __init__(self, original):
        self._orig = original
    def write(self, msg):
        if msg.strip():
            _log_buffer.append({
                'ts': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'INFO',
                'msg': msg.rstrip(),
            })
        self._orig.write(msg)
    def flush(self): self._orig.flush()
    def fileno(self): return self._orig.fileno()
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__, template_folder='../templates', static_folder='../static')
sys.stdout = _PrintCapture(sys.stdout)
sys.stderr = _PrintCapture(sys.stderr)

@app.context_processor
def inject_discord():
    invite = f'https://discord.com/oauth2/authorize?client_id={DISCORD_CLIENT_ID}' if DISCORD_CLIENT_ID else None
    user_tz = 'Australia/Sydney'
    if 'user_id' in session:
        try:
            conn = get_db()
            u = conn.execute('SELECT timezone_name FROM users WHERE id=?', (session['user_id'],)).fetchone()
            conn.close()
            if u and u['timezone_name']:
                user_tz = u['timezone_name']
        except: pass
    return dict(discord_invite=invite, user_timezone=user_tz)
def _get_persistent_secret():
    """Get or create a persistent secret key stored in the data directory."""
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    key_file = os.path.join(os.path.dirname(DB_PATH), '.flask_secret_key')
    try:
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                key = f.read().strip()
                if key:
                    return key
        # Generate and persist
        key = secrets.token_hex(32)
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, 'w') as f:
            f.write(key)
        print(f"[App] Generated new persistent secret key at {key_file}")
        return key
    except Exception as e:
        print(f"[App] Warning: Could not persist secret key ({e}), sessions will not survive restarts")
        return secrets.token_hex(32)

app.secret_key = _get_persistent_secret()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # requires HTTPS

DB_PATH = os.environ.get('DB_PATH', '/data/koko.db')
DEFAULT_POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 300))
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

# ─── Token Cache ──────────────────────────────────────────────────────────────
# In-memory cache: user_id -> {'token': str, 'refresh_token': str, 'expires_at': datetime, 'cookies': dict}
_token_cache = {}
_token_cache_lock = threading.Lock()

def cache_set_token(user_id, bearer_token, refresh_token=None, expires_at=None, cookies=None):
    """Store a bearer token in the in-memory cache."""
    with _token_cache_lock:
        _token_cache[user_id] = {
            'token': bearer_token,
            'refresh_token': refresh_token,
            'expires_at': expires_at or (datetime.utcnow() + timedelta(minutes=14)),
            'cookies': cookies or {},
            'cached_at': datetime.utcnow(),
        }

def cache_get_token(user_id):
    """Get cached token if not expired (with 60s buffer). Returns None if missing/expired."""
    with _token_cache_lock:
        entry = _token_cache.get(user_id)
        if not entry:
            return None
        # Treat as expired if within 60s of expiry
        if (entry['expires_at'] - datetime.utcnow()).total_seconds() < 60:
            return None
        return entry

def cache_invalidate_token(user_id):
    """Remove a user's token from cache."""
    with _token_cache_lock:
        _token_cache.pop(user_id, None)

def cache_get_or_load_token(user_id):
    """Get token from cache, falling back to DB load. Returns (bearer, refresh, cookies, expires_dt) or None."""
    cached = cache_get_token(user_id)
    if cached:
        return cached['token'], cached['refresh_token'], cached['cookies'], cached['expires_at']
    # Load from DB
    try:
        conn = get_db()
        tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user_id,)).fetchone()
        conn.close()
        if not tzs or not tzs['bearer_token']:
            if tzs and tzs['last_poll_status'] == 'needs_reconnect':
                print(f"[TokenCache] User {user_id} needs_reconnect — skipping token load")
            return None
        expires_dt = datetime.utcnow() + timedelta(minutes=14)
        if tzs['token_expires_at']:
            try:
                expires_dt = datetime.strptime(tzs['token_expires_at'], '%Y-%m-%d %H:%M:%S')
            except:
                pass
        cookies = json.loads(tzs['cookies_json'] or '{}')
        # Populate cache
        cache_set_token(user_id, tzs['bearer_token'], tzs['refresh_token'], expires_dt, cookies)
        return tzs['bearer_token'], tzs['refresh_token'], cookies, expires_dt
    except Exception as e:
        print(f"[TokenCache] DB load error for user {user_id}: {e}")
        return None

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
            last_seen TIMESTAMP,
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
        CREATE TABLE IF NOT EXISTS admin_webhook (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            webhook_url TEXT,
            enabled INTEGER DEFAULT 0,
            mode TEXT DEFAULT 'off',
            last_fired_at TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    ''')
    # Ensure admin_webhook singleton row exists
    conn.execute("INSERT OR IGNORE INTO admin_webhook (id, enabled, mode) VALUES (1, 0, 'off')")
    # Ensure default quiet hours config
    conn.execute("INSERT OR IGNORE INTO app_config (key, value) VALUES ('koko_quiet_start', '4')")
    conn.execute("INSERT OR IGNORE INTO app_config (key, value) VALUES ('koko_quiet_end', '10')")
    conn.execute("INSERT OR IGNORE INTO app_config (key, value) VALUES ('koko_quiet_enabled', '1')")
    conn.execute("INSERT OR IGNORE INTO app_config (key, value) VALUES ('koko_quiet_timezone', 'Australia/Sydney')")
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
        'ALTER TABLE users ADD COLUMN last_seen TIMESTAMP',
    ]:
        try: conn.execute(sql)
        except: pass
    # Fix timezone cards that have the wrong default poll interval (60 instead of 900)
    try:
        conn.execute("UPDATE cards SET poll_interval=900 WHERE card_type='timezone' AND poll_interval=60")
    except: pass
    # Migrate koko cards from old 1-min default to 5-min default
    try:
        conn.execute("UPDATE cards SET poll_interval=300 WHERE card_type='koko' AND poll_interval=60")
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

# Timezone B2C constants
# Web portal (bookmarklet captures tokens from this app registration)
TZ_TOKEN_URL       = 'https://identity.teeg.cloud/guests.teeg.cloud/b2c_1a_signupsignin/oauth2/v2.0/token'
TZ_CLIENT_ID       = 'ca0e4868-177b-49d2-8c63-f1044e3edc63'  # web portal azp
TZ_SCOPE           = 'https://guests.teeg.cloud/api/all-apis openid profile offline_access'

# Mobile app (longer-lived refresh tokens — extracted from APK)
TZ_MOBILE_TOKEN_URL = 'https://identity.teeg.cloud/guests.teeg.cloud/B2C_1_SignupSignin/oauth2/v2.0/token'
TZ_MOBILE_CLIENT_ID = '8791e440-a74b-482e-8089-9ccb16fd718b'  # mobile app azp

# Sentinel returned when the refresh token itself has expired — user must reconnect
TZ_REFRESH_TOKEN_EXPIRED = 'REFRESH_TOKEN_EXPIRED'

def tz_refresh_ms_token(refresh_token, ms_client_id=None):
    """
    Refresh Timezone bearer token.
    Tries the original client_id first, then attempts the mobile app's endpoint
    which may have a longer refresh token lifetime.
    Returns (new_access_token, new_refresh_token, expires_in) on success.
    Returns (TZ_REFRESH_TOKEN_EXPIRED, None, None) when the refresh token has DEFINITIVELY expired (AADB2C90080).
    Returns (None, None, None) on other/transient errors.
    """
    # Build list of (token_url, client_id, label) to try
    attempts = []
    effective_cid = ms_client_id or TZ_CLIENT_ID
    if effective_cid == TZ_MOBILE_CLIENT_ID:
        # Token was issued by mobile app — only try mobile endpoint
        attempts.append((TZ_MOBILE_TOKEN_URL, TZ_MOBILE_CLIENT_ID, 'mobile'))
    else:
        # Token from web portal — try web first, then mobile as fallback
        attempts.append((TZ_TOKEN_URL, effective_cid, 'web'))
        attempts.append((TZ_MOBILE_TOKEN_URL, TZ_MOBILE_CLIENT_ID, 'mobile-fallback'))

    last_error_desc = ''
    for token_url, client_id, label in attempts:
        try:
            resp = requests.post(token_url, data={
                'grant_type': 'refresh_token',
                'client_id': client_id,
                'scope': TZ_SCOPE,
                'refresh_token': refresh_token,
            }, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=15)
            print(f"[Timezone] MS refresh ({label}, cid={client_id[:8]}...): HTTP {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                new_token   = data.get('access_token')
                new_refresh = data.get('refresh_token') or refresh_token
                expires_in  = int(data.get('expires_in', 840))
                print(f"[Timezone] MS refresh SUCCESS ({label}) — expires {expires_in}s, new RT: {'yes' if data.get('refresh_token') else 'no'}")
                return new_token, new_refresh, expires_in
            else:
                try:
                    err = resp.json()
                except Exception:
                    err = {}
                error_code = err.get('error', '')
                error_desc = err.get('error_description', '')
                last_error_desc = error_desc
                print(f"[Timezone] MS refresh fail ({label}, {resp.status_code}): {error_code}: {error_desc[:200]}")
                # Definitively expired — don't try fallback
                if 'AADB2C90080' in error_desc:
                    print(f"[Timezone] Refresh token has definitively expired (AADB2C90080) — user must reconnect")
                    return TZ_REFRESH_TOKEN_EXPIRED, None, None
                # Wrong client_id for this token — try next
                if 'AADB2C90222' in error_desc or 'AADB2C90057' in error_desc:
                    print(f"[Timezone] Client mismatch ({label}), trying next...")
                    continue
                # Other error on first attempt — try fallback
                if label == 'web':
                    continue
                return None, None, None
        except Exception as e:
            print(f"[Timezone] MS refresh error ({label}): {e}")
            if label == 'web':
                continue
            return None, None, None
    # All attempts failed
    if 'AADB2C90080' in last_error_desc:
        return TZ_REFRESH_TOKEN_EXPIRED, None, None
    return None, None, None

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

def _save_refreshed_token_to_db(user_id, new_token, new_refresh, expires_in, cookies=None):
    """Save a refreshed token to DB and update cache."""
    now = datetime.utcnow()
    tok_exp = (now + timedelta(seconds=expires_in or 840)).strftime('%Y-%m-%d %H:%M:%S')
    expires_dt = now + timedelta(seconds=expires_in or 840)
    try:
        conn = get_db()
        upd = 'bearer_token=?, token_expires_at=?, last_poll_status=?, updated_at=CURRENT_TIMESTAMP'
        params = [new_token, tok_exp, 'ok']
        if new_refresh:
            upd += ', refresh_token=?'
            params.append(new_refresh)
        params.append(user_id)
        conn.execute(f'UPDATE timezone_sessions SET {upd} WHERE user_id=?', params)
        conn.commit(); conn.close()
        print(f"[Timezone] Token saved to DB for user {user_id}, expires {tok_exp}")
    except Exception as e:
        print(f"[Timezone] Could not save refreshed token to DB: {e}")
    # Always update cache regardless of DB success
    existing = cache_get_token(user_id)
    existing_cookies = (existing['cookies'] if existing else {}) or cookies or {}
    cache_set_token(user_id, new_token, new_refresh or (existing['refresh_token'] if existing else None),
                    expires_dt, existing_cookies)

def _mark_needs_reconnect(user_id):
    """
    Mark a Timezone session as needing full reconnect (refresh token expired — AADB2C90080).
    This is distinct from a transient 'error': the user must redo the bookmarklet.
    Clears bearer + refresh token so the poller stops hammering a dead session.
    """
    try:
        conn = get_db()
        conn.execute(
            "UPDATE timezone_sessions SET last_poll_status='needs_reconnect', "
            "bearer_token=NULL, refresh_token=NULL, updated_at=CURRENT_TIMESTAMP "
            "WHERE user_id=?",
            (user_id,)
        )
        conn.commit(); conn.close()
        print(f"[Timezone] User {user_id} marked needs_reconnect — refresh token expired (AADB2C90080)")
    except Exception as e:
        print(f"[Timezone] Could not mark needs_reconnect for user {user_id}: {e}")
    cache_invalidate_token(user_id)

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
            expires_in = None

            # Try MS Identity refresh token first (most reliable)
            # Check cache first, then DB
            if user_id:
                cached = cache_get_token(user_id)
                rt = (cached['refresh_token'] if cached else None)
                if not rt:
                    try:
                        conn = get_db()
                        tzs = conn.execute('SELECT refresh_token, ms_client_id FROM timezone_sessions WHERE user_id=?', (user_id,)).fetchone()
                        conn.close()
                        if tzs and tzs['refresh_token']:
                            rt = tzs['refresh_token']
                    except Exception as e:
                        print(f"[Timezone] Could not get refresh token from DB: {e}")
                if rt:
                    ms_client_id = None
                    if not cached:
                        try:
                            conn = get_db()
                            tzs = conn.execute('SELECT ms_client_id FROM timezone_sessions WHERE user_id=?', (user_id,)).fetchone()
                            conn.close()
                            ms_client_id = tzs['ms_client_id'] if tzs else None
                        except: pass
                    new_token, new_refresh, expires_in = tz_refresh_ms_token(rt, ms_client_id)
                    # Refresh token itself has expired — user must reconnect
                    if new_token is TZ_REFRESH_TOKEN_EXPIRED:
                        if user_id:
                            _mark_needs_reconnect(user_id)
                        return None

            # Fallback: cookie-based refresh
            if not new_token and cookies:
                data, new_token, new_cookies = tz_refresh_token(cookies)
                if data and not new_token:
                    if user_id:
                        try:
                            conn = get_db()
                            conn.execute('UPDATE timezone_sessions SET last_poll_status=? WHERE user_id=?', ('ok', user_id))
                            conn.commit(); conn.close()
                        except: pass
                    return data

            if new_token:
                if user_id:
                    _save_refreshed_token_to_db(user_id, new_token, new_refresh, expires_in or 840, cookies)

                # Retry with new token
                headers2 = {**TZ_HEADERS, 'Authorization': f'Bearer {new_token}'}
                try:
                    resp2 = requests.get(f'{TEEG_API}/guest?version=20210722', headers=headers2, cookies=cookies, timeout=15)
                    if resp2.status_code == 200:
                        return resp2.json()
                except Exception as e:
                    print(f"[Timezone] Retry after refresh failed: {e}")
            else:
                # Refresh failed — invalidate cache so next call reloads from DB
                if user_id:
                    cache_invalidate_token(user_id)
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

        # Paginate if needed
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

def _store_timezone_transactions(card_id, card_number, bearer_token, cookies_dict):
    """
    Fetch and store the latest Timezone transactions into balance_history.
    This runs on each poll to capture the rolling 20-transaction window before
    it scrolls out. Returns (imported, skipped) counts.
    """
    transactions = fetch_timezone_transactions(card_number, bearer_token, cookies_dict)
    if not transactions:
        return 0, 0

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

        if running_total is None or float(running_total) == 0:
            if cash_delta <= 0 and e_cash <= 0 and p_cash <= 0:
                skipped += 1
                continue
            cash_balance = round(cash_delta + e_cash + p_cash, 2)
            cash_bonus   = 0.0
        else:
            running_total = float(running_total)
            if bonus_delta < 0:
                cash_bonus = 0.0
                cash_balance = round(running_total, 2)
            elif bonus_delta > 0:
                cash_bonus = round(bonus_delta, 2)
                cash_balance = round(running_total - bonus_delta, 2)
            else:
                cash_bonus = 0.0
                cash_balance = round(running_total, 2)

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
    if imported:
        print(f"[TxStore] Card {card_id}: stored {imported} new transactions (skipped {skipped})")
    return imported, skipped

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
    # Populate cache
    try:
        exp_dt = datetime.strptime(token_exp, '%Y-%m-%d %H:%M:%S') if token_exp else datetime.utcnow() + timedelta(minutes=14)
    except:
        exp_dt = datetime.utcnow() + timedelta(minutes=14)
    cache_set_token(user_id, bearer_token, refresh_token, exp_dt, cookies_dict)

def tz_session_status(tzs):
    """Return status string for a timezone session."""
    if not tzs or not tzs['bearer_token']:
        if tzs and tzs['last_poll_status'] == 'needs_reconnect':
            return 'needs_reconnect'
        return 'disconnected'
    now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    now_dt  = datetime.utcnow()
    if tzs['session_expires_at'] and tzs['session_expires_at'] < now_str:
        return 'expired'
    # Explicit needs_reconnect always wins
    if tzs['last_poll_status'] == 'needs_reconnect':
        return 'needs_reconnect'
    # Expiring soon — session within 2 hours of absolute expiry
    if tzs['last_poll_status'] == 'expiring_soon':
        return 'expiring_soon'
    if tzs['session_expires_at']:
        try:
            sess_exp = datetime.strptime(tzs['session_expires_at'], '%Y-%m-%d %H:%M:%S')
            if (sess_exp - now_dt).total_seconds() < 7200:
                return 'expiring_soon'
        except: pass
    if tzs['last_poll_at']:
        try:
            last = datetime.strptime(tzs['last_poll_at'], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            last = None
        if last:
            age = (now_dt - last).total_seconds()
            if tzs['last_poll_status'] == 'error' and age < TIMEZONE_POLL_INTERVAL * 2:
                return 'error'
            if age > TIMEZONE_POLL_INTERVAL * 3:
                updated_at = None
                if tzs['updated_at']:
                    try:
                        updated_at = datetime.strptime(str(tzs['updated_at'])[:19], '%Y-%m-%d %H:%M:%S')
                    except: pass
                if updated_at:
                    updated_age = (now_dt - updated_at).total_seconds()
                    if updated_age < TIMEZONE_POLL_INTERVAL * 2:
                        return 'connected'
                return 'stale'
    return 'connected'

def tz_session_hours_remaining(tzs):
    """Return hours remaining on a Timezone session, or None if unknown."""
    if not tzs or not tzs['session_expires_at']:
        return None
    try:
        exp = datetime.strptime(tzs['session_expires_at'], '%Y-%m-%d %H:%M:%S')
        secs = (exp - datetime.utcnow()).total_seconds()
        return max(0, secs / 3600)
    except:
        return None


# ─── Discord Webhook ──────────────────────────────────────────────────────────
# ─── Admin Webhook ────────────────────────────────────────────────────────────
# In-memory: last time admin webhook was fired per mode (timer modes)
_admin_webhook_last = {}
_admin_webhook_lock = threading.Lock()

# Mode -> seconds interval (None = fire on every update)
ADMIN_WEBHOOK_INTERVALS = {
    'on':  None,   # fire on every card update
    '5m':  300,
    '10m': 600,
    '30m': 1800,
    '1h':  3600,
    '1d':  86400,
}

def get_admin_webhook_config():
    """Return (url, mode) or (None, 'off') if not configured."""
    try:
        conn = get_db()
        row = conn.execute('SELECT webhook_url, mode, enabled FROM admin_webhook WHERE id=1').fetchone()
        conn.close()
        if row and row['enabled'] and row['webhook_url'] and row['mode'] != 'off':
            return row['webhook_url'], row['mode']
    except Exception as e:
        print(f"[AdminWebhook] Config read error: {e}")
    return None, 'off'

def send_admin_webhook(card, data, prev, username):
    """
    Fire the admin-wide webhook with full card info.
    Respects mode: 'on' = every update, timer modes = throttled.
    card     — cards row (with card_type, card_label, card_number, user_id)
    data     — freshly polled balance dict
    prev     — previous balance_history row (or None)
    username — owner's username string
    """
    url, mode = get_admin_webhook_config()
    if not url or mode == 'off':
        return

    interval = ADMIN_WEBHOOK_INTERVALS.get(mode)
    if interval is not None:
        # Timer mode — only fire if enough time has passed since last fire
        with _admin_webhook_lock:
            last = _admin_webhook_last.get('fired')
            now  = datetime.utcnow()
            if last and (now - last).total_seconds() < interval:
                return
            _admin_webhook_lock_update = True
        # Update last fired (outside lock to avoid blocking)
        with _admin_webhook_lock:
            _admin_webhook_last['fired'] = datetime.utcnow()
        # Also persist to DB so it survives restarts
        try:
            conn = get_db()
            conn.execute("UPDATE admin_webhook SET last_fired_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
                         (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),))
            conn.commit(); conn.close()
        except: pass

    try:
        ctype     = card['card_type'] or 'koko'
        label     = card['card_label'] or card['card_number'] or 'Card'
        emoji     = '🕹️' if ctype == 'timezone' else '🎮'
        type_emoji = '🟡' if ctype == 'timezone' else '🟣'
        new_bal   = data.get('cash_balance') or 0
        new_bon   = data.get('cash_bonus') or 0
        new_pts   = data.get('points') or 0
        new_total = new_bal + new_bon

        # Build change fields if we have a previous reading
        fields = [
            {'name': 'User',    'value': f'`{username}`',       'inline': True},
            {'name': 'Type',    'value': f'{type_emoji} {ctype}','inline': True},
            {'name': 'Card',    'value': f'`{label}`',           'inline': True},
            {'name': 'Credits', 'value': f'${new_bal:.2f}',      'inline': True},
            {'name': 'Bonus',   'value': f'${new_bon:.2f}',      'inline': True},
            {'name': 'Points',  'value': str(new_pts),           'inline': True},
        ]
        if data.get('tier'):
            fields.append({'name': 'Tier', 'value': data['tier'], 'inline': True})

        color = 0x6366f1  # indigo default
        change_str = ''
        action = ''
        if prev:
            prev_total = (prev['cash_balance'] or 0) + (prev['cash_bonus'] or 0)
            diff = new_total - prev_total
            if abs(diff) >= 0.01:
                sign      = '+' if diff >= 0 else ''
                color     = 0x22c55e if diff > 0 else 0xef4444
                action    = '💳 Topup!' if diff > 0 else '🎮 Tapped!'
                change_str = f'{sign}${diff:.2f}'
                fields.append({'name': 'Change', 'value': f'{action}  {change_str}', 'inline': True})

        mode_label = {'on': 'Live', '5m': 'Every 5m', '10m': 'Every 10m',
                      '30m': 'Every 30m', '1h': 'Hourly', '1d': 'Daily'}.get(mode, mode)

        payload = {
            'embeds': [{
                'title': f'{emoji} {action or "Balance Update"} — {label}',
                'color': color,
                'fields': fields,
                'footer': {'text': f'Total: ${new_total:.2f}  ·  Admin Monitor ({mode_label})'},
                'timestamp': datetime.utcnow().isoformat() + 'Z',
            }]
        }
        resp = requests.post(url, json=payload, timeout=8)
        print(f"[AdminWebhook] Fired for card {card['id']} ({label}) — HTTP {resp.status_code}")
    except Exception as e:
        print(f"[AdminWebhook] Error firing webhook: {e}")

def send_discord_webhook(webhook_url, card, data, prev_total, new_total):
    try:
        diff   = new_total - prev_total
        sign   = '+' if diff > 0 else ''
        color  = 0x22c55e if diff > 0 else 0xef4444
        action = '💳 Topup!' if diff > 0 else '🎮 Tapped!'
        label  = card['card_label'] or card['card_number'] or 'Card'
        ctype  = card['card_type'] or 'koko'
        emoji  = '🕹️' if ctype == 'timezone' else '🎮'
        fields = [
            {'name': 'Credits', 'value': f"${data.get('cash_balance', 0):.2f}", 'inline': True},
            {'name': 'Bonus',   'value': f"${data.get('cash_bonus', 0):.2f}",   'inline': True},
            {'name': 'Change',  'value': f"{sign}${diff:.2f}",                  'inline': True},
        ]
        # Calculate all-time spending
        try:
            conn = get_db()
            first = conn.execute('SELECT cash_balance, cash_bonus FROM balance_history WHERE card_id=? ORDER BY recorded_at ASC LIMIT 1', (card['id'],)).fetchone()
            conn.close()
            if first:
                first_total = (first['cash_balance'] or 0) + (first['cash_bonus'] or 0)
                alltime_spent = first_total - new_total
                if abs(alltime_spent) >= 0.01:
                    fields.append({'name': 'All-Time Spent', 'value': f"${alltime_spent:.2f}", 'inline': True})
        except: pass
        payload = {
            'embeds': [{
                'title': f'{emoji} {label}',
                'description': action,
                'color': color,
                'fields': fields,
                'footer': {'text': f'Total: ${new_total:.2f}'},
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }]
        }
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        print(f"[Discord] Webhook error: {e}")

def fetch_timezone_history(bearer_token, card_no, cookies_dict=None):
    try:
        resp = requests.get(f'{TEEG_API}/guest/cards/AU/{card_no}/transactions', timeout=15, headers={
            'Authorization': f'Bearer {bearer_token}',
            'Accept': 'application/json',
            'Origin': 'https://portal.timezonegames.com',
            'Referer': 'https://portal.timezonegames.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }, cookies=cookies_dict or {})
        if resp.status_code == 200:
            print(f"[Timezone] History API: Fetched transaction history for card {card_no}")
            return resp.json()
        print(f"[Timezone] History API error: HTTP {resp.status_code} - {resp.text[:200]}")
    except Exception as e:
        print(f"[Timezone] History API error: {e}")
        return None

# ─── Poller ───────────────────────────────────────────────────────────────────
def get_quiet_hours():
    """Return (enabled, start_hour, end_hour, tz_name) for koko quiet hours."""
    try:
        conn = get_db()
        enabled = conn.execute("SELECT value FROM app_config WHERE key='koko_quiet_enabled'").fetchone()
        start = conn.execute("SELECT value FROM app_config WHERE key='koko_quiet_start'").fetchone()
        end = conn.execute("SELECT value FROM app_config WHERE key='koko_quiet_end'").fetchone()
        tz = conn.execute("SELECT value FROM app_config WHERE key='koko_quiet_timezone'").fetchone()
        conn.close()
        return (
            bool(int(enabled['value'])) if enabled else True,
            int(start['value']) if start else 4,
            int(end['value']) if end else 10,
            tz['value'] if tz else 'Australia/Sydney',
        )
    except:
        return True, 4, 10, 'Australia/Sydney'

def is_koko_quiet_hour():
    """Check if we're in the koko quiet hours window (in the configured timezone)."""
    enabled, start, end, tz_name = get_quiet_hours()
    if not enabled:
        return False
    try:
        from zoneinfo import ZoneInfo
        now_local = datetime.now(ZoneInfo(tz_name))
        hour = now_local.hour
    except Exception:
        hour = datetime.utcnow().hour  # fallback to UTC
    if start <= end:
        return start <= hour < end
    else:  # wraps around midnight
        return hour >= start or hour < end

def log_poll(card_id, success, message=''):
    try:
        conn = get_db()
        conn.execute('INSERT INTO poll_log (card_id, success, message) VALUES (?,?,?)',
                    (card_id, 1 if success else 0, message))
        conn.execute('''DELETE FROM poll_log WHERE card_id=? AND id NOT IN 
                       (SELECT id FROM poll_log WHERE card_id=? ORDER BY logged_at DESC LIMIT 100)''',
                    (card_id, card_id))
        conn.commit(); conn.close()
    except: pass

def _refresh_tz_tokens(label):
    """Refresh any Timezone tokens that are expired or expiring within 10 minutes.
    Also check session_expires_at (Azure B2C absolute refresh token lifetime ~24h)
    and warn when approaching expiry."""
    try:
        conn = get_db()
        # Exclude sessions already marked needs_reconnect — nothing we can do until user reconnects
        sessions = conn.execute(
            "SELECT ts.*, u.username, u.discord_webhook FROM timezone_sessions ts "
            "JOIN users u ON ts.user_id = u.id "
            "WHERE ts.refresh_token IS NOT NULL "
            "AND ts.last_poll_status != 'needs_reconnect'"
        ).fetchall()
        conn.close()
        now = datetime.utcnow()
        for tzs in sessions:
            # Check session absolute expiry (Azure B2C ~24h refresh token lifetime)
            if tzs['session_expires_at']:
                try:
                    sess_exp = datetime.strptime(tzs['session_expires_at'], '%Y-%m-%d %H:%M:%S')
                    secs_until_sess_exp = (sess_exp - now).total_seconds()

                    # Warn at 2 hours remaining (only once — set status to 'expiring_soon')
                    if 0 < secs_until_sess_exp < 7200 and tzs['last_poll_status'] not in ('expiring_soon', 'needs_reconnect'):
                        hrs_left = secs_until_sess_exp / 3600
                        print(f"[{label}] ⚠️ Session for user {tzs['user_id']} ({tzs['username']}) expires in {hrs_left:.1f}h")
                        try:
                            conn2 = get_db()
                            conn2.execute("UPDATE timezone_sessions SET last_poll_status='expiring_soon' WHERE user_id=?", (tzs['user_id'],))
                            conn2.commit(); conn2.close()
                        except: pass
                        # Fire user webhook warning if configured
                        if tzs['discord_webhook']:
                            try:
                                import requests as _req
                                _req.post(tzs['discord_webhook'], json={
                                    'embeds': [{'title': '⚠️ Timezone Session Expiring',
                                        'description': f'Your Timezone session expires in **{hrs_left:.1f} hours**.\n\nReconnect at the dashboard to keep tracking.',
                                        'color': 0xfbbf24}]
                                }, timeout=5)
                            except: pass

                    # Session has actually expired — don't wait for AADB2C90080
                    if secs_until_sess_exp <= 0 and tzs['last_poll_status'] != 'needs_reconnect':
                        print(f"[{label}] Session expired for user {tzs['user_id']} ({tzs['username']}) — marking needs_reconnect")
                        _mark_needs_reconnect(tzs['user_id'])
                        continue
                except:
                    pass

            # Check access token expiry
            needs_refresh = False
            if not tzs['token_expires_at']:
                needs_refresh = True
            else:
                try:
                    exp = datetime.strptime(tzs['token_expires_at'], '%Y-%m-%d %H:%M:%S')
                    if (exp - now).total_seconds() < 600:  # 10 min window
                        needs_refresh = True
                except:
                    needs_refresh = True
            if needs_refresh:
                print(f"[{label}] Refreshing token for user {tzs['user_id']}...")
                new_tok, new_rt, expires_in = tz_refresh_ms_token(tzs['refresh_token'], tzs['ms_client_id'])
                if new_tok is TZ_REFRESH_TOKEN_EXPIRED:
                    # Refresh token itself expired — user must redo bookmarklet
                    print(f"[{label}] Refresh token EXPIRED for user {tzs['user_id']} — marking needs_reconnect")
                    _mark_needs_reconnect(tzs['user_id'])
                elif new_tok:
                    _save_refreshed_token_to_db(tzs['user_id'], new_tok, new_rt, expires_in or 840,
                                                json.loads(tzs['cookies_json'] or '{}'))
                    print(f"[{label}] Token refreshed for user {tzs['user_id']}")
                else:
                    # Transient error — leave as error, will retry next cycle
                    print(f"[{label}] Could not refresh token for user {tzs['user_id']} - transient MS error")
                    cache_invalidate_token(tzs['user_id'])
                    try:
                        conn = get_db()
                        conn.execute("UPDATE timezone_sessions SET last_poll_status='error' WHERE user_id=?", (tzs['user_id'],))
                        conn.commit(); conn.close()
                    except: pass
    except Exception as e:
        print(f"[{label}] Error: {e}")

def startup_refresh_tz_tokens():
    _refresh_tz_tokens("Startup")

def token_watcher():
    """Background thread: check and refresh Timezone tokens every 5 minutes."""
    time.sleep(30)
    while True:
        _refresh_tz_tokens("Token watcher")
        time.sleep(300)

def poll_cards():
    startup_refresh_tz_tokens()
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
                    if is_koko_quiet_hour():
                        continue  # skip koko cards during quiet hours
                    data = fetch_koko_balance(card['card_token'])
                    if data and any(v is not None for v in [data.get('cash_balance'), data.get('cash_bonus'), data.get('points')]):
                        log_poll(card['id'], True, 'OK')
                    else:
                        log_poll(card['id'], False, 'No data returned')

                elif ctype == 'timezone':
                    # Use cache-aware token loading
                    token_info = cache_get_or_load_token(card['user_id'])
                    if token_info:
                        bearer, rt, cookies, expires_dt = token_info
                        secs_left = (expires_dt - datetime.utcnow()).total_seconds()

                        # Proactively refresh if expiring within 10 minutes
                        if secs_left < 600 and rt:
                            print(f"[Poller] Token expires in {secs_left:.0f}s for user {card['user_id']}, pre-refreshing...")
                            conn2 = get_db()
                            tzs_row = conn2.execute('SELECT ms_client_id FROM timezone_sessions WHERE user_id=?', (card['user_id'],)).fetchone()
                            conn2.close()
                            ms_cid = tzs_row['ms_client_id'] if tzs_row else None
                            new_tok, new_rt, new_exp = tz_refresh_ms_token(rt, ms_cid)
                            if new_tok is TZ_REFRESH_TOKEN_EXPIRED:
                                print(f"[Poller] Refresh token expired for user {card['user_id']} — marking needs_reconnect")
                                _mark_needs_reconnect(card['user_id'])
                                log_poll(card['id'], False, 'Refresh token expired — user must reconnect')
                                continue  # skip this card this cycle
                            elif new_tok:
                                _save_refreshed_token_to_db(card['user_id'], new_tok, new_rt, new_exp or 840, cookies)
                                bearer = new_tok
                                print(f"[Poller] Pre-refresh success for user {card['user_id']}")

                        guest = fetch_timezone_guest(bearer, cookies, user_id=card['user_id'])
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
                            conn = get_db()
                            status = 'ok' if data else 'card_not_found'
                            conn.execute('UPDATE timezone_sessions SET last_poll_at=?, last_poll_status=? WHERE user_id=?',
                                        (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), status, card['user_id']))
                            conn.commit(); conn.close()
                            log_poll(card['id'], bool(data), status)

                            # Store transaction history on each poll to preserve rolling 20-tx window
                            if data:
                                try:
                                    _store_timezone_transactions(card['id'], card['card_number'], bearer, cookies)
                                except Exception as tx_e:
                                    print(f"[Poller] Transaction store error for card {card['id']}: {tx_e}")
                        else:
                            conn = get_db()
                            conn.execute('UPDATE timezone_sessions SET last_poll_status=? WHERE user_id=?',
                                        ('error', card['user_id']))
                            conn.commit(); conn.close()
                            cache_invalidate_token(card['user_id'])
                            log_poll(card['id'], False, 'API error - token may be expired')
                            print(f"[Poller] Timezone API error for user {card['user_id']} - token may be expired")
                    else:
                        # Check why — needs_reconnect vs never connected
                        try:
                            conn2 = get_db()
                            tzs_check = conn2.execute(
                                'SELECT last_poll_status FROM timezone_sessions WHERE user_id=?',
                                (card['user_id'],)
                            ).fetchone()
                            conn2.close()
                            if tzs_check and tzs_check['last_poll_status'] == 'needs_reconnect':
                                log_poll(card['id'], False, 'needs_reconnect — user must redo bookmarklet')
                                print(f"[Poller] Card {card['id']} skipped — user {card['user_id']} needs_reconnect")
                            else:
                                log_poll(card['id'], False, 'No Timezone session')
                                print(f"[Poller] Card {card['id']} skipped — no Timezone session for user {card['user_id']}")
                        except:
                            log_poll(card['id'], False, 'No session token')

                if data and any(v is not None for v in [data.get('cash_balance'), data.get('cash_bonus'), data.get('points')]):
                    conn = get_db()
                    prev = conn.execute('SELECT cash_balance,cash_bonus,points FROM balance_history WHERE card_id=? ORDER BY recorded_at DESC LIMIT 1', (card['id'],)).fetchone()
                    conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name,tier) VALUES (?,?,?,?,?,?)',
                        (card['id'], data.get('cash_balance'), data.get('cash_bonus'), data.get('points'), data.get('card_name'), data.get('tier','')))
                    if data.get('tier'):
                        conn.execute('UPDATE cards SET tier=? WHERE id=?', (data['tier'], card['id']))
                    conn.commit()
                    user_row = conn.execute('SELECT discord_webhook, username FROM users WHERE id=?', (card['user_id'],)).fetchone()
                    conn.close()
                    if user_row and user_row['discord_webhook'] and prev:
                        prev_total = (prev['cash_balance'] or 0) + (prev['cash_bonus'] or 0)
                        new_total = (data.get('cash_balance') or 0) + (data.get('cash_bonus') or 0)
                        if abs(new_total - prev_total) >= 0.01:
                            send_discord_webhook(user_row['discord_webhook'], card, data, prev_total, new_total)
                    # Admin-wide webhook — only fire when balance actually changed
                    username = user_row['username'] if user_row else f'user_{card["user_id"]}'
                    if prev is not None:
                        new_total_adm  = (data.get('cash_balance') or 0) + (data.get('cash_bonus') or 0)
                        prev_total_adm = (prev['cash_balance'] or 0) + (prev['cash_bonus'] or 0)
                        if abs(new_total_adm - prev_total_adm) >= 0.01:
                            send_admin_webhook(card, data, prev, username)
                    print(f"[Poller] Card {card['id']} ({ctype}): {data.get('cash_balance')}/{data.get('cash_bonus')}/{data.get('points')}")

        except Exception as e:
            print(f"[Poller] Error: {e}")
        time.sleep(10)

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
            session['user_id'] = user['id']
            try:
                conn2 = get_db()
                conn2.execute('UPDATE users SET last_seen=? WHERE id=?', (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
                conn2.commit(); conn2.close()
            except: pass
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')


@app.route('/auth/discord')
def discord_oauth_start():
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        flash('Discord login not configured.', 'error')
        return redirect(url_for('login'))
    import secrets as _sec
    state = _sec.token_hex(16)
    session['discord_oauth_state'] = state
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
    user_resp = requests.get('https://discord.com/api/users/@me',
        headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
    if user_resp.status_code != 200:
        flash('Could not fetch Discord profile.', 'error'); return redirect(url_for('login'))

    duser = user_resp.json()
    discord_id = str(duser['id'])
    discord_username = duser.get('username', '')
    discord_email = duser.get('email', '')

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE discord_id=?', (discord_id,)).fetchone()
    if user:
        session.permanent = True
        session['user_id'] = user['id']
        conn.execute('UPDATE users SET last_seen=? WHERE id=?', (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
        conn.commit(); conn.close()
        return redirect(url_for('dashboard'))

    if discord_email:
        user = conn.execute('SELECT * FROM users WHERE email=?', (discord_email,)).fetchone()
        if user:
            conn.execute('UPDATE users SET discord_id=? WHERE id=?', (discord_id, user['id']))
            conn.commit()
            session.permanent = True
            session['user_id'] = user['id']
            conn.close()
            flash(f'Discord linked to your account {user["username"]}.', 'success')
            return redirect(url_for('dashboard'))

    count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    is_admin = 1 if count == 0 else 0
    username = discord_username
    base = username
    i = 1
    while conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
        username = f'{base}{i}'; i += 1
    conn.execute('INSERT INTO users (username, password_hash, email, discord_id, is_admin) VALUES (?,?,?,?,?)',
        (username, '', discord_email, discord_id, is_admin))
    conn.commit()
    user = conn.execute('SELECT * FROM users WHERE discord_id=?', (discord_id,)).fetchone()
    conn.close()
    session.permanent = True
    session['user_id'] = user['id']
    session['discord_new_user'] = True
    flash(f'Welcome {username}! Account created via Discord.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('identifier','').strip()
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email=? OR username=?', (identifier, identifier)).fetchone()
        if user and user['discord_id'] and not user['password_hash']:
            conn.close()
            flash('This account was created with Discord. Log in with Discord, then go to Settings to set a password.', 'error')
            return redirect(url_for('forgot_password'))
        if user and user['email']:
            import secrets as _sec
            token = _sec.token_urlsafe(32)
            expires = (datetime.utcnow() + timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('UPDATE users SET reset_token=?, reset_expires=? WHERE id=?', (token, expires, user['id']))
            conn.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
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
                    flash(f'Reset link: {reset_url}', 'success')
            else:
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


@app.route('/api/timezone/reauth', methods=['POST'])
@login_required
def timezone_reauth():
    user = get_current_user()
    data = request.get_json() or {}
    target_uid = data.get('user_id', user['id'])
    if target_uid != user['id'] and not user['is_admin']:
        return jsonify({'success': False, 'error': 'Admin only'}), 403

    conn = get_db()
    tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (target_uid,)).fetchone()
    conn.close()

    if not tzs:
        return jsonify({'success': False, 'error': 'No Timezone session found'})
    if not tzs['refresh_token']:
        return jsonify({'success': False, 'error': 'No refresh token stored — user must reconnect via bookmarklet'})

    print(f"[Reauth] Attempting token refresh for user {target_uid}...")
    new_tok, new_rt, expires_in = tz_refresh_ms_token(tzs['refresh_token'], tzs['ms_client_id'])

    if new_tok is TZ_REFRESH_TOKEN_EXPIRED:
        _mark_needs_reconnect(target_uid)
        return jsonify({
            'success': False,
            'needs_reconnect': True,
            'error': 'Refresh token has expired (AADB2C90080) — user must reconnect via bookmarklet'
        })

    if not new_tok:
        cache_invalidate_token(target_uid)
        return jsonify({'success': False, 'error': 'MS token refresh failed — transient error, try again shortly'})

    _save_refreshed_token_to_db(target_uid, new_tok, new_rt, expires_in or 840,
                                json.loads(tzs['cookies_json'] or '{}'))
    # Also reset last_poll_at so the stale detector doesn't immediately re-flag
    now = datetime.utcnow()
    tok_exp = (now + timedelta(seconds=expires_in or 840)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        conn = get_db()
        conn.execute(
            "UPDATE timezone_sessions SET last_poll_at=?, last_poll_status='ok' WHERE user_id=?",
            (now.strftime('%Y-%m-%d %H:%M:%S'), target_uid)
        )
        conn.commit(); conn.close()
    except Exception as e:
        print(f"[Reauth] Could not reset last_poll_at: {e}")
    print(f"[Reauth] Token refreshed for user {target_uid}, expires {tok_exp}")
    return jsonify({'success': True, 'expires': tok_exp, 'message': f'Token refreshed, expires {tok_exp}'})


@app.route('/set-password', methods=['GET', 'POST'])
@login_required
def set_password():
    user = get_current_user()
    if request.method == 'POST':
        pw  = request.form.get('password', '')
        pw2 = request.form.get('confirm_password', '')
        import re as _re
        if len(pw) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('set_password.html', user=user)
        if not _re.search(r'[A-Z]', pw):
            flash('Password must contain at least one uppercase letter.', 'error')
            return render_template('set_password.html', user=user)
        if not _re.search(r'[0-9]', pw):
            flash('Password must contain at least one number.', 'error')
            return render_template('set_password.html', user=user)
        if pw != pw2:
            flash('Passwords do not match.', 'error')
            return render_template('set_password.html', user=user)
        conn = get_db()
        conn.execute('UPDATE users SET password_hash=? WHERE id=?', (hash_password(pw), user['id']))
        conn.commit(); conn.close()
        session.pop('discord_new_user', None)
        flash('Password set! You can now log in with your username and password.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('set_password.html', user=user)

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
    # Update last_seen
    try: conn.execute('UPDATE users SET last_seen=? WHERE id=?', (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
    except: pass
    cards = conn.execute('''
        SELECT c.*, h.cash_balance, h.cash_bonus, h.points, h.recorded_at as last_updated
        FROM cards c
        LEFT JOIN balance_history h ON h.id=(SELECT id FROM balance_history WHERE card_id=c.id ORDER BY recorded_at DESC LIMIT 1)
        WHERE c.user_id=? AND c.active=1 ORDER BY c.card_type, c.created_at
    ''', (user['id'],)).fetchall()
    tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
    conn.close()
    tz_status = tz_session_status(tzs)
    tz_hours_left = tz_session_hours_remaining(tzs)
    return render_template('dashboard.html', user=user, cards=cards,
                          tz_connected=tz_status=='connected', tz_session=tzs,
                          tz_status=tz_status, tz_hours_left=tz_hours_left)

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
        token_info = cache_get_or_load_token(user['id'])
        if not token_info:
            return jsonify({'success': False, 'error': 'No Timezone session — reconnect first'}), 400
        bearer, rt, cookies, expires_dt = token_info
        try:
            guest = fetch_timezone_guest(bearer, cookies, user_id=user['id'])
            if guest and guest.get('cards'):
                card_num = str(card['card_number']).strip() if card['card_number'] else ''
                for c in guest.get('cards', []):
                    api_num = str(c.get('number', '')).strip()
                    history = fetch_timezone_history(bearer, api_num, cookies)
                    if api_num == card_num or (card_num and card_num in api_num) or (api_num and api_num in card_num):
                        data = {
                            'cash_balance': float(c.get('cashBalance') or 0),
                            'cash_bonus':   float(c.get('bonusBalance') or 0),
                            'points':       int(c.get('eTickets') or c.get('tickets') or 0),
                            'card_name':    card['card_label'],
                            'tier':         c.get('tier', ''),
                            'history':      history if history else []
                        }
                        break
                if not data:
                    error_msg = f"Card number {card_num!r} not found in Timezone session (found: {[str(c.get('number')) for c in guest.get('cards',[])]})"
            else:
                # No cards — force token refresh
                print(f"[ForcePoll] No cards from Timezone for user {user['id']}, forcing token refresh...")
                if rt:
                    conn2 = get_db()
                    tzs_row = conn2.execute('SELECT ms_client_id FROM timezone_sessions WHERE user_id=?', (user['id'],)).fetchone()
                    conn2.close()
                    new_tok, new_rt, new_exp = tz_refresh_ms_token(rt, tzs_row['ms_client_id'] if tzs_row else None)
                    if new_tok:
                        _save_refreshed_token_to_db(user['id'], new_tok, new_rt, new_exp or 840, cookies)
                        guest2 = fetch_timezone_guest(new_tok, cookies, user_id=user['id'])
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
    latest = conn.execute('SELECT recorded_at FROM balance_history WHERE card_id=? ORDER BY recorded_at DESC LIMIT 1', (card_id,)).fetchone()
    conn.close()
    last_updated = latest['recorded_at'][:16] if latest else None
    return render_template('card_detail.html', user=user, card=card, poll_logs=logs, last_updated=last_updated)

# ─── Routes: Timezone ─────────────────────────────────────────────────────────

# ─── Timezone: Direct OAuth Login (mobile client_id — long-lived tokens) ──────
# Uses Authorization Code + PKCE against the mobile app's B2C user flow.
# This gives refresh tokens with a much longer lifetime than the web portal.

TZ_B2C_AUTHORIZE  = 'https://identity.teeg.cloud/guests.teeg.cloud/B2C_1_SignupSignin/oauth2/v2.0/authorize'
TZ_B2C_TOKEN      = 'https://identity.teeg.cloud/guests.teeg.cloud/B2C_1_SignupSignin/oauth2/v2.0/token'
TZ_PKCE_CLIENT_ID = TZ_MOBILE_CLIENT_ID  # '8791e440-a74b-482e-8089-9ccb16fd718b'
# Azure B2C public clients accept this redirect for native apps
TZ_PKCE_REDIRECT  = 'https://login.microsoftonline.com/common/oauth2/nativeclient'

import hashlib as _hashlib

@app.route('/timezone/login')
@login_required
def timezone_oauth_start():
    """Redirect user to Azure B2C login using mobile app's client_id + PKCE."""
    # Generate PKCE code_verifier and code_challenge
    code_verifier = secrets.token_urlsafe(64)[:128]
    code_challenge = base64.urlsafe_b64encode(
        _hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')
    # Generate state for CSRF
    state = secrets.token_urlsafe(32)
    # Store in session
    session['tz_pkce_verifier'] = code_verifier
    session['tz_pkce_state'] = state

    params = {
        'client_id': TZ_PKCE_CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': f'{APP_URL}/timezone/oauth-callback',
        'scope': TZ_SCOPE,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'response_mode': 'query',
    }
    auth_url = TZ_B2C_AUTHORIZE + '?' + '&'.join(f'{k}={requests.utils.quote(str(v))}' for k, v in params.items())
    print(f"[Timezone OAuth] Redirecting user {session.get('user_id')} to B2C login")
    return redirect(auth_url)


@app.route('/timezone/oauth-callback')
@login_required
def timezone_oauth_callback():
    """Handle the OAuth2 callback from Azure B2C, exchange code for tokens."""
    user = get_current_user()
    error = request.args.get('error')
    error_desc = request.args.get('error_description', '')

    if error:
        print(f"[Timezone OAuth] Error from B2C: {error}: {error_desc[:200]}")
        flash(f'Timezone login failed: {error_desc[:100]}', 'error')
        return redirect(url_for('timezone_start'))

    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        flash('No authorization code received.', 'error')
        return redirect(url_for('timezone_start'))

    # Validate state
    expected_state = session.pop('tz_pkce_state', None)
    code_verifier = session.pop('tz_pkce_verifier', None)
    if not expected_state or state != expected_state:
        flash('Invalid state — possible CSRF. Please try again.', 'error')
        return redirect(url_for('timezone_start'))

    # Exchange code for tokens
    try:
        resp = requests.post(TZ_B2C_TOKEN, data={
            'client_id': TZ_PKCE_CLIENT_ID,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': f'{APP_URL}/timezone/oauth-callback',
            'code_verifier': code_verifier,
            'scope': TZ_SCOPE,
        }, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=15)

        print(f"[Timezone OAuth] Token exchange: HTTP {resp.status_code}")

        if resp.status_code != 200:
            err = resp.json() if resp.headers.get('content-type','').startswith('application/json') else {}
            print(f"[Timezone OAuth] Token exchange failed: {err.get('error','')}: {err.get('error_description','')[:200]}")
            flash(f'Token exchange failed: {err.get("error_description", "Unknown error")[:100]}', 'error')
            return redirect(url_for('timezone_start'))

        data = resp.json()
        access_token = data.get('access_token')
        refresh_token = data.get('refresh_token')
        expires_in = int(data.get('expires_in', 900))

        if not access_token:
            flash('No access token in response.', 'error')
            return redirect(url_for('timezone_start'))

        print(f"[Timezone OAuth] Got tokens! access={access_token[:20]}... refresh={'yes' if refresh_token else 'no'} expires={expires_in}s")

        # Calculate expiry
        token_exp = (datetime.utcnow() + timedelta(seconds=expires_in)).strftime('%Y-%m-%d %H:%M:%S')
        sess_exp = (datetime.utcnow() + timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')

        # Save session with mobile client_id
        save_timezone_session(user['id'], access_token, {}, token_exp, sess_exp,
                              refresh_token=refresh_token, ms_client_id=TZ_PKCE_CLIENT_ID)

        # Fetch guest data to get cards
        guest = fetch_timezone_guest(access_token, {}, user_id=user['id'])
        if guest:
            conn = get_db()
            conn.execute('UPDATE timezone_sessions SET guest_id=? WHERE user_id=?', (guest.get('id'), user['id']))
            conn.commit(); conn.close()
            cards = _format_tz_cards(guest)
            print(f"[Timezone OAuth] Success for user {user['id']}: {len(cards)} cards found")
            # Store card data in session for the landing page
            session['tz_oauth_cards'] = cards
            session['tz_oauth_name'] = guest.get('givenName', '')
            return redirect(url_for('timezone_oauth_success'))
        else:
            flash('Connected but could not fetch card data. Try refreshing the dashboard.', 'error')
            return redirect(url_for('dashboard'))

    except Exception as e:
        print(f"[Timezone OAuth] Token exchange error: {e}")
        flash(f'Connection error: {str(e)[:100]}', 'error')
        return redirect(url_for('timezone_start'))


@app.route('/timezone/oauth-success')
@login_required
def timezone_oauth_success():
    """Show success page after OAuth login."""
    cards = session.pop('tz_oauth_cards', [])
    name = session.pop('tz_oauth_name', '')
    return render_template('timezone_landing.html', user=get_current_user(),
                          oauth_success=True, oauth_cards=cards, oauth_name=name)


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
    sess_exp = (datetime.utcnow() + timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
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
            sess_exp = (datetime.utcnow() + timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
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

@app.route('/timezone/add-all-cards', methods=['POST'])
@login_required
def timezone_add_all_cards():
    """Add all timezone cards at once from a JSON payload."""
    user = get_current_user()
    data = request.get_json()
    cards_data = data.get('cards', [])
    if not cards_data:
        return jsonify({'error': 'No cards provided'}), 400
    added = 0
    conn = get_db()
    for c in cards_data:
        card_number = str(c.get('number', '')).strip()
        if not card_number:
            continue
        card_label = c.get('label', f'Timezone {card_number}')
        cash_balance = float(c.get('cashBalance', 0))
        bonus_balance = float(c.get('bonusBalance', 0))
        tickets = int(float(c.get('tickets', 0)))
        tier = c.get('tier', '')
        try:
            existing = conn.execute("SELECT id FROM cards WHERE user_id=? AND card_token=?",
                (user['id'], f'tz_{card_number}')).fetchone()
            if existing:
                conn.execute("UPDATE cards SET active=1, card_label=?, tier=?, poll_interval=? WHERE id=?",
                    (card_label, tier, TIMEZONE_POLL_INTERVAL, existing['id']))
                cid = existing['id']
            else:
                conn.execute("INSERT INTO cards (user_id,card_type,card_token,card_label,card_number,tier,poll_interval) VALUES (?,'timezone',?,?,?,?,?)",
                    (user['id'], f'tz_{card_number}', card_label, card_number, tier, TIMEZONE_POLL_INTERVAL))
                cid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
            conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name,tier) VALUES (?,?,?,?,?,?)',
                (cid, cash_balance, bonus_balance, tickets, card_label, tier))
            added += 1
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'added': added})

@app.route('/timezone/disconnect', methods=['POST'])
@login_required
def timezone_disconnect():
    user = get_current_user()
    cache_invalidate_token(user['id'])
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
    conn.close()

    token_info = cache_get_or_load_token(user['id'])
    if not token_info:
        return jsonify({'error': 'No Timezone session'}), 400

    bearer, rt, cookies, _ = token_info
    card_number = card['card_number']
    if not card_number: return jsonify({'error': 'Card has no card number'}), 400

    imported, skipped = _store_timezone_transactions(card_id, card_number, bearer, cookies)
    total_fetched = imported + skipped  # approximate
    if imported == 0 and skipped == 0:
        return jsonify({'error': 'No transactions found or API unavailable'}), 400

    return jsonify({'success': True, 'imported': imported, 'skipped': skipped, 'total': total_fetched})


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
        # Also show cache status
        cached = cache_get_token(s['user_id'])
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
            'cache_status': 'hit' if cached else 'miss',
            'cache_expires_in_seconds': round((cached['expires_at'] - datetime.utcnow()).total_seconds()) if cached else None,
        })
    return jsonify(result)

# ─── Routes: Admin ────────────────────────────────────────────────────────────

@app.route('/admin/logs')
@login_required
def admin_logs():
    user = get_current_user()
    if not user or not user['is_admin']:
        return jsonify({'error': 'Admin only'}), 403
    return jsonify({'lines': list(_log_buffer)})

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
    admin_wh = conn.execute('SELECT * FROM admin_webhook WHERE id=1').fetchone()
    # Get quiet hours config
    quiet_cfg = {}
    for key in ['koko_quiet_enabled', 'koko_quiet_start', 'koko_quiet_end', 'koko_quiet_timezone']:
        row = conn.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
        quiet_cfg[key] = row['value'] if row else ('1' if 'enabled' in key else '4' if 'start' in key else '10' if 'end' in key else 'Australia/Sydney')
    conn.close()
    tz_statuses = {ts['user_id']: tz_session_status(ts) for ts in tz_sessions}
    current = get_current_user()
    return render_template('admin.html', users=users, cards=cards,
                          tz_sessions=tz_sessions, tz_statuses=tz_statuses,
                          user=current, current_user=current, admin_username=ADMIN_USERNAME,
                          admin_webhook=admin_wh, quiet_cfg=quiet_cfg,
                          now_date=datetime.utcnow().strftime('%Y-%m-%d'))

@app.route('/admin/webhook', methods=['POST'])
@admin_required
def admin_webhook_save():
    """Save admin webhook config."""
    data = request.get_json()
    url  = (data.get('webhook_url') or '').strip()
    mode = data.get('mode', 'off')
    if mode not in ('off', 'on', '5m', '10m', '30m', '1h', '1d'):
        return jsonify({'success': False, 'error': 'Invalid mode'}), 400
    enabled = 0 if mode == 'off' else 1
    conn = get_db()
    conn.execute(
        "UPDATE admin_webhook SET webhook_url=?, enabled=?, mode=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
        (url or None, enabled, mode)
    )
    conn.commit(); conn.close()
    print(f"[AdminWebhook] Config updated: mode={mode}, url={'set' if url else 'cleared'}")
    return jsonify({'success': True, 'mode': mode, 'enabled': bool(enabled)})

@app.route('/admin/webhook/test', methods=['POST'])
@admin_required
def admin_webhook_test():
    """Fire a test embed to verify the webhook URL."""
    data = request.get_json()
    url  = (data.get('webhook_url') or '').strip()
    if not url:
        return jsonify({'success': False, 'error': 'No webhook URL provided'})
    try:
        payload = {
            'embeds': [{
                'title': '🔔 Admin Webhook Test',
                'description': 'Balance Tracker admin webhook is configured correctly.',
                'color': 0x6366f1,
                'fields': [
                    {'name': 'User',    'value': '`test_user`',    'inline': True},
                    {'name': 'Type',    'value': '🟣 koko',         'inline': True},
                    {'name': 'Card',    'value': '`Test Card`',     'inline': True},
                    {'name': 'Credits', 'value': '$42.00',          'inline': True},
                    {'name': 'Bonus',   'value': '$8.00',           'inline': True},
                    {'name': 'Points',  'value': '1337',            'inline': True},
                ],
                'footer': {'text': 'Admin Monitor — Test message'},
                'timestamp': datetime.utcnow().isoformat() + 'Z',
            }]
        }
        resp = requests.post(url, json=payload, timeout=8)
        if resp.status_code in (200, 204):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': f'Discord returned HTTP {resp.status_code}: {resp.text[:200]}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/quiet-hours', methods=['POST'])
@admin_required
def admin_quiet_hours():
    """Save koko quiet hours config."""
    data = request.get_json()
    enabled = '1' if data.get('enabled') else '0'
    start = str(int(data.get('start', 4)))
    end = str(int(data.get('end', 10)))
    tz_name = data.get('timezone', 'Australia/Sydney')
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO app_config (key, value) VALUES ('koko_quiet_enabled', ?)", (enabled,))
    conn.execute("INSERT OR REPLACE INTO app_config (key, value) VALUES ('koko_quiet_start', ?)", (start,))
    conn.execute("INSERT OR REPLACE INTO app_config (key, value) VALUES ('koko_quiet_end', ?)", (end,))
    conn.execute("INSERT OR REPLACE INTO app_config (key, value) VALUES ('koko_quiet_timezone', ?)", (tz_name,))
    conn.commit(); conn.close()
    print(f"[Admin] Quiet hours updated: enabled={enabled}, {start}:00-{end}:00 {tz_name}")
    return jsonify({'success': True})

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
    cache_invalidate_token(user_id)
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
    conn = get_db()
    if not conn.execute('SELECT id FROM cards WHERE id=? AND user_id=?', (card_id, user['id'])).fetchone():
        conn.close(); return jsonify({'error': 'Not found'}), 404
    if period == 'all':
        rows = conn.execute('SELECT cash_balance,cash_bonus,points,recorded_at,description FROM balance_history WHERE card_id=? AND cash_balance IS NOT NULL ORDER BY recorded_at ASC',
            (card_id,)).fetchall()
    else:
        since = datetime.utcnow() - ({'day': timedelta(hours=24), 'week': timedelta(days=7), 'month': timedelta(days=30)}.get(period, timedelta(hours=24)))
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

    history = None
    if card['card_type'] == 'timezone':
        token_info = cache_get_or_load_token(user['id'])
        if token_info:
            bearer, _, cookies, _ = token_info
            history = fetch_timezone_history(bearer, str(card['card_number']), cookies)

    spent_24h = None
    if first_24h and latest:
        spent_24h = round(((first_24h['cash_balance'] or 0)+(first_24h['cash_bonus'] or 0))-((latest['cash_balance'] or 0)+(latest['cash_bonus'] or 0)), 2)
    # All-time spending: difference between first ever reading and latest
    spent_alltime = None
    first_ever = conn2_first = None
    try:
        conn2 = get_db()
        first_ever = conn2.execute('SELECT cash_balance,cash_bonus FROM balance_history WHERE card_id=? ORDER BY recorded_at ASC LIMIT 1', (card_id,)).fetchone()
        conn2.close()
    except: pass
    if first_ever and latest:
        spent_alltime = round(((first_ever['cash_balance'] or 0)+(first_ever['cash_bonus'] or 0))-((latest['cash_balance'] or 0)+(latest['cash_bonus'] or 0)), 2)
    return jsonify({'total_readings': count, 'latest': dict(latest) if latest else None, 'spent_24h': spent_24h, 'spent_alltime': spent_alltime, 'card_type': card['card_type'], 'history': history or []})

@app.route('/api/dashboard/overview')
@login_required
def api_dashboard_overview():
    user = get_current_user()
    period = request.args.get('period', 'day')
    conn = get_db()
    cards = conn.execute('SELECT id, card_label, card_type, card_number FROM cards WHERE user_id=? AND active=1', (user['id'],)).fetchall()
    result = []
    for card in cards:
        if period == 'all':
            rows = conn.execute('SELECT cash_balance, cash_bonus, points, recorded_at FROM balance_history WHERE card_id=? ORDER BY recorded_at ASC',
                (card['id'],)).fetchall()
        else:
            since = datetime.utcnow() - ({'day': timedelta(hours=24), 'week': timedelta(days=7), 'month': timedelta(days=30)}.get(period, timedelta(hours=24)))
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
    threading.Thread(target=token_watcher, daemon=True).start()
    start_discord_bot()
    app.run(host='0.0.0.0', port=5000, debug=False)
