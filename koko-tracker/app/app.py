import os, sqlite3, threading, time, hashlib, secrets, json, base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DB_PATH = os.environ.get('DB_PATH', '/data/koko.db')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 60))
TIMEZONE_POLL_INTERVAL = int(os.environ.get('TIMEZONE_POLL_INTERVAL', 900))
KOKO_BASE_URL = 'https://estore.kokoamusement.com.au/BalanceMobile/BalanceMobile.aspx'
TEEG_API = 'https://api.teeg.cloud'

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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            card_type TEXT DEFAULT 'koko',
            card_token TEXT NOT NULL,
            card_label TEXT,
            card_number TEXT,
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
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_history_card_time ON balance_history(card_id, recorded_at);
    ''')
    conn.commit()
    conn.close()

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

# ── Koko scraper ──────────────────────────────────────────────────────────────
def fetch_koko_balance(token):
    try:
        resp = requests.get(f"{KOKO_BASE_URL}?i={token}", timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
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

# ── Timezone API ──────────────────────────────────────────────────────────────
def fetch_timezone_guest(bearer_token, cookies_dict=None):
    try:
        resp = requests.get(f'{TEEG_API}/guest?version=20210722', timeout=15, headers={
            'Authorization': f'Bearer {bearer_token}',
            'Accept': 'application/json',
            'Origin': 'https://portal.timezonegames.com',
            'Referer': 'https://portal.timezonegames.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
        }, cookies=cookies_dict or {})
        print(f"[Timezone] guest API: HTTP {resp.status_code}")
        return resp.json() if resp.status_code == 200 else None
    except Exception as e:
        print(f"[Timezone] Error: {e}"); return None

def save_timezone_session(user_id, bearer_token, cookies_dict, token_exp, sess_exp, guest_id=None):
    conn = get_db()
    conn.execute('''
        INSERT INTO timezone_sessions (user_id, bearer_token, cookies_json, token_expires_at, session_expires_at, guest_id, updated_at)
        VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            bearer_token=excluded.bearer_token, cookies_json=excluded.cookies_json,
            token_expires_at=excluded.token_expires_at, session_expires_at=excluded.session_expires_at,
            guest_id=COALESCE(excluded.guest_id, timezone_sessions.guest_id), updated_at=CURRENT_TIMESTAMP
    ''', (user_id, bearer_token, json.dumps(cookies_dict), token_exp, sess_exp, guest_id))
    conn.commit(); conn.close()

# ── Poller ────────────────────────────────────────────────────────────────────
def poll_cards():
    print(f"[Poller] Started. Koko:{POLL_INTERVAL}s Timezone:{TIMEZONE_POLL_INTERVAL}s")
    last_tz_poll = {}
    while True:
        try:
            conn = get_db()
            cards = conn.execute('SELECT * FROM cards WHERE active=1').fetchall()
            conn.close()
            for card in cards:
                data = None
                ctype = card['card_type'] or 'koko'
                if ctype == 'koko':
                    data = fetch_koko_balance(card['card_token'])
                elif ctype == 'timezone':
                    now = time.time()
                    if now - last_tz_poll.get(card['id'], 0) < TIMEZONE_POLL_INTERVAL:
                        continue
                    last_tz_poll[card['id']] = now
                    conn = get_db()
                    tzs = conn.execute('SELECT * FROM timezone_sessions WHERE user_id=?', (card['user_id'],)).fetchone()
                    conn.close()
                    if tzs and tzs['bearer_token']:
                        cookies = json.loads(tzs['cookies_json'] or '{}')
                        guest = fetch_timezone_guest(tzs['bearer_token'], cookies)
                        if guest:
                            for c in guest.get('cards', []):
                                if str(c.get('number')) == str(card['card_number']):
                                    data = {
                                        'cash_balance': c.get('cashBalance', 0),
                                        'cash_bonus': c.get('bonusBalance', 0),
                                        'points': c.get('tickets', c.get('eTickets', 0)),
                                        'card_name': card['card_label'],
                                    }
                                    break
                if data and any(v is not None for v in [data.get('cash_balance'), data.get('cash_bonus'), data.get('points')]):
                    conn = get_db()
                    conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name) VALUES (?,?,?,?,?)',
                        (card['id'], data.get('cash_balance'), data.get('cash_bonus'), data.get('points'), data.get('card_name')))
                    if data.get('card_name') and not card['card_number']:
                        conn.execute('UPDATE cards SET card_number=? WHERE id=?', (data['card_name'], card['id']))
                    conn.commit(); conn.close()
                    print(f"[Poller] Card {card['id']} ({ctype}): {data.get('cash_balance')}/{data.get('cash_bonus')}/{data.get('points')}")
        except Exception as e:
            print(f"[Poller] Error: {e}")
        time.sleep(POLL_INTERVAL)

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if get_current_user() else url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u, p = request.form['username'].strip(), request.form['password']
        if not u or not p:
            flash('Username and password required.', 'error')
            return render_template('register.html')
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username,password_hash) VALUES (?,?)', (u, hash_password(p)))
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
            session['user_id'] = user['id']; return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

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
    return render_template('dashboard.html', user=user, cards=cards, tz_connected=bool(tzs and tzs['bearer_token']), tz_session=tzs)

@app.route('/cards/add', methods=['POST'])
@login_required
def add_card():
    user = get_current_user()
    token = request.form.get('card_token','').strip()
    label = request.form.get('card_label','').strip()
    if not token: flash('Card token is required.', 'error'); return redirect(url_for('dashboard'))
    data = fetch_koko_balance(token)
    if not data or all(v is None for v in [data['cash_balance'], data['cash_bonus'], data['points']]):
        flash('Could not fetch data for that card token.', 'error'); return redirect(url_for('dashboard'))
    conn = get_db()
    try:
        conn.execute('INSERT INTO cards (user_id,card_type,card_token,card_label,card_number) VALUES (?,?,?,?,?)',
            (user['id'],'koko',token, label or data.get('card_name',token), data.get('card_name')))
        cid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name) VALUES (?,?,?,?,?)',
            (cid, data['cash_balance'], data['cash_bonus'], data['points'], data['card_name']))
        conn.commit(); flash(f'Koko card added! Balance: ${data["cash_balance"] or 0:.2f}', 'success')
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

@app.route('/cards/<int:card_id>')
@login_required
def card_detail(card_id):
    user = get_current_user()
    conn = get_db()
    card = conn.execute('SELECT * FROM cards WHERE id=? AND user_id=? AND active=1', (card_id, user['id'])).fetchone()
    conn.close()
    if not card: return redirect(url_for('dashboard'))
    return render_template('card_detail.html', user=user, card=card)

# ── Timezone routes ───────────────────────────────────────────────────────────
@app.route('/timezone/connect')
@login_required
def timezone_connect():
    return render_template('timezone_connect.html', user=get_current_user())

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
    save_timezone_session(user['id'], bearer_token, cookies, token_exp, sess_exp)
    guest = fetch_timezone_guest(bearer_token, cookies)
    if not guest: return jsonify({'error': 'Could not fetch Timezone data'}), 400
    conn = get_db()
    conn.execute('UPDATE timezone_sessions SET guest_id=? WHERE user_id=?', (guest.get('id'), user['id']))
    conn.commit(); conn.close()
    cards = [{'number': str(c.get('number','')), 'cashBalance': c.get('cashBalance',0),
               'bonusBalance': c.get('bonusBalance',0), 'tickets': c.get('tickets', c.get('eTickets',0)),
               'country': c.get('country','')} for c in guest.get('cards',[])]
    return jsonify({'success': True, 'cards': cards, 'name': guest.get('givenName','')})

@app.route('/timezone/add-card', methods=['POST'])
@login_required
def timezone_add_card():
    user = get_current_user()
    card_number = request.form.get('card_number','').strip()
    card_label = request.form.get('card_label','').strip()
    cash_balance = float(request.form.get('cash_balance', 0))
    bonus_balance = float(request.form.get('bonus_balance', 0))
    tickets = int(float(request.form.get('tickets', 0)))
    if not card_number: flash('Card number required.', 'error'); return redirect(url_for('dashboard'))
    conn = get_db()
    try:
        conn.execute("INSERT INTO cards (user_id,card_type,card_token,card_label,card_number) VALUES (?,'timezone',?,?,?)",
            (user['id'], f'tz_{card_number}', card_label or f'Timezone {card_number}', card_number))
        cid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.execute('INSERT INTO balance_history (card_id,cash_balance,cash_bonus,points,card_name) VALUES (?,?,?,?,?)',
            (cid, cash_balance, bonus_balance, tickets, card_label or f'Timezone {card_number}'))
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

@app.route('/api/cards/<int:card_id>/history')
@login_required
def api_history(card_id):
    user = get_current_user()
    period = request.args.get('period','day')
    since = datetime.utcnow() - ({'day': timedelta(hours=24), 'week': timedelta(days=7), 'month': timedelta(days=30)}.get(period, timedelta(hours=24)))
    conn = get_db()
    if not conn.execute('SELECT id FROM cards WHERE id=? AND user_id=?', (card_id, user['id'])).fetchone():
        conn.close(); return jsonify({'error': 'Not found'}), 404
    rows = conn.execute('SELECT cash_balance,cash_bonus,points,recorded_at FROM balance_history WHERE card_id=? AND recorded_at>=? ORDER BY recorded_at ASC',
        (card_id, since.strftime('%Y-%m-%d %H:%M:%S'))).fetchall()
    conn.close()
    return jsonify({'labels':[r['recorded_at'] for r in rows], 'cash_balance':[r['cash_balance'] for r in rows],
                    'cash_bonus':[r['cash_bonus'] for r in rows], 'points':[r['points'] for r in rows]})

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

@app.route('/timezone/extractor')
@login_required
def timezone_extractor():
    """
    Bridge page loaded inside the iframe after Timezone login.
    Runs on our domain so it can postMessage the parent freely.
    It also makes a server-side call to TEEG using the cookies
    passed from the browser to validate and extract the bearer token.
    """
    return render_template('timezone_extractor.html')

@app.route('/timezone/extract-token', methods=['POST'])
@login_required
def timezone_extract_token():
    """
    Called by the extractor page with whatever token/cookie data
    it could read from the portal's localStorage/sessionStorage.
    Falls back to server-side probe using browser-forwarded cookies.
    """
    user = get_current_user()
    data = request.get_json() or {}
    bearer_token = data.get('bearer_token')
    cookies_from_browser = data.get('cookies', {})

    # If the extractor found a token in storage, use it directly
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
            save_timezone_session(user['id'], bearer_token, cookies_from_browser, token_exp, sess_exp, guest.get('id'))
            cards = [{'number': str(c.get('number','')), 'cashBalance': c.get('cashBalance',0),
                      'bonusBalance': c.get('bonusBalance',0), 'tickets': c.get('tickets', c.get('eTickets',0)),
                      'country': c.get('country','')} for c in guest.get('cards',[])]
            return jsonify({'success': True, 'cards': cards, 'name': guest.get('givenName','')})

    return jsonify({'success': False, 'error': 'Could not extract token'})

@app.route('/timezone/landing')
@login_required
def timezone_landing():
    """
    Mobile-friendly landing page after Timezone login.
    User is redirected here from their browser after logging in.
    Page reads token from localStorage and sends it to the server.
    """
    return render_template('timezone_landing.html', user=get_current_user())

@app.route('/timezone/start')
@login_required  
def timezone_start():
    """Redirect user to Timezone portal, with our landing page as the return destination."""
    app_url = os.environ.get('APP_URL', request.host_url.rstrip('/'))
    return render_template('timezone_start.html', user=get_current_user(), app_url=app_url)

if __name__ == '__main__':
    init_db()
    threading.Thread(target=poll_cards, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False)
