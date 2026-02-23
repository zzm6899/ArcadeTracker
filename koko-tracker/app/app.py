import os
import sqlite3
import threading
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DB_PATH = os.environ.get('DB_PATH', '/data/koko.db')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 60))  # seconds
BASE_URL = 'https://estore.kokomusement.com.au/BalanceMobile/BalanceMobile.aspx'

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
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
        CREATE INDEX IF NOT EXISTS idx_history_card_time ON balance_history(card_id, recorded_at);
    ''')
    conn.commit()
    conn.close()

# ─── Auth helpers ─────────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_current_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return user

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ─── Scraper ──────────────────────────────────────────────────────────────────

def fetch_balance(token):
    """Fetch balance data from Koko website."""
    try:
        url = f"{BASE_URL}?i={token}"
        resp = requests.get(url, timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; KokoTracker/1.0)'
        })
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        data = {'card_name': None, 'cash_balance': None, 'cash_bonus': None, 'points': None}
        
        # Get card name
        title = soup.find('title')
        h_tags = soup.find_all(['h1', 'h2', 'h3', 'h4'])
        for tag in h_tags:
            text = tag.get_text(strip=True)
            if text:
                data['card_name'] = text
                break
        
        # Parse table rows
        text = resp.text
        
        # Cash Balance
        m = re.search(r'Cash Balance[^$]*\$\s*([\d,.]+)', text, re.IGNORECASE)
        if m:
            data['cash_balance'] = float(m.group(1).replace(',', ''))
        
        # Cash Bonus
        m = re.search(r'Cash Bonus[^$]*\$\s*([\d,.]+)', text, re.IGNORECASE)
        if m:
            data['cash_bonus'] = float(m.group(1).replace(',', ''))
        
        # Points
        m = re.search(r'Points[^\d]*([\d,]+)', text, re.IGNORECASE)
        if m:
            data['points'] = int(m.group(1).replace(',', ''))

        # Card name from page
        m = re.search(r'Game Card:\s*(.+?)(?:\n|<)', text)
        if m:
            data['card_name'] = m.group(1).strip()
            
        return data
    except Exception as e:
        print(f"[Scraper] Error fetching token {token}: {e}")
        return None

def poll_cards():
    """Background thread: poll all active cards every POLL_INTERVAL seconds."""
    print(f"[Poller] Started. Interval: {POLL_INTERVAL}s")
    while True:
        try:
            conn = get_db()
            cards = conn.execute('SELECT * FROM cards WHERE active = 1').fetchall()
            conn.close()
            
            for card in cards:
                data = fetch_balance(card['card_token'])
                if data and any(v is not None for v in [data['cash_balance'], data['cash_bonus'], data['points']]):
                    conn = get_db()
                    conn.execute('''
                        INSERT INTO balance_history (card_id, cash_balance, cash_bonus, points, card_name)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (card['id'], data['cash_balance'], data['cash_bonus'], data['points'], data['card_name']))
                    
                    # Update card number/label if we got a name
                    if data['card_name'] and not card['card_number']:
                        conn.execute('UPDATE cards SET card_number = ? WHERE id = ?', 
                                    (data['card_name'], card['id']))
                    conn.commit()
                    conn.close()
                    print(f"[Poller] Card {card['id']}: balance={data['cash_balance']}, bonus={data['cash_bonus']}, points={data['points']}")
        except Exception as e:
            print(f"[Poller] Error: {e}")
        
        time.sleep(POLL_INTERVAL)

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password required.', 'error')
            return render_template('register.html')
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                        (username, hash_password(password)))
            conn.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken.', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?',
                           (username, hash_password(password))).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    conn = get_db()
    cards = conn.execute('''
        SELECT c.*, 
               h.cash_balance, h.cash_bonus, h.points, h.recorded_at as last_updated
        FROM cards c
        LEFT JOIN balance_history h ON h.id = (
            SELECT id FROM balance_history WHERE card_id = c.id ORDER BY recorded_at DESC LIMIT 1
        )
        WHERE c.user_id = ? AND c.active = 1
        ORDER BY c.created_at
    ''', (user['id'],)).fetchall()
    conn.close()
    return render_template('dashboard.html', user=user, cards=cards)

@app.route('/cards/add', methods=['POST'])
@login_required
def add_card():
    user = get_current_user()
    token = request.form.get('card_token', '').strip()
    label = request.form.get('card_label', '').strip()
    
    if not token:
        flash('Card token is required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Validate by fetching
    data = fetch_balance(token)
    if data is None or all(v is None for v in [data['cash_balance'], data['cash_bonus'], data['points']]):
        flash('Could not fetch data for that card token. Please check it is correct.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    try:
        conn.execute('INSERT INTO cards (user_id, card_token, card_label, card_number) VALUES (?, ?, ?, ?)',
                    (user['id'], token, label or data.get('card_name', token), data.get('card_name')))
        card_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        # Save initial reading
        conn.execute('INSERT INTO balance_history (card_id, cash_balance, cash_bonus, points, card_name) VALUES (?,?,?,?,?)',
                    (card_id, data['cash_balance'], data['cash_bonus'], data['points'], data['card_name']))
        conn.commit()
        flash(f'Card added! Current balance: ${data["cash_balance"]:.2f}, Bonus: ${data["cash_bonus"]:.2f}', 'success')
    except sqlite3.IntegrityError:
        flash('That card is already added to your account.', 'error')
    finally:
        conn.close()
    return redirect(url_for('dashboard'))

@app.route('/cards/<int:card_id>/delete', methods=['POST'])
@login_required
def delete_card(card_id):
    user = get_current_user()
    conn = get_db()
    conn.execute('UPDATE cards SET active = 0 WHERE id = ? AND user_id = ?', (card_id, user['id']))
    conn.commit()
    conn.close()
    flash('Card removed.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/cards/<int:card_id>')
@login_required
def card_detail(card_id):
    user = get_current_user()
    conn = get_db()
    card = conn.execute('SELECT * FROM cards WHERE id = ? AND user_id = ? AND active = 1',
                       (card_id, user['id'])).fetchone()
    if not card:
        conn.close()
        return redirect(url_for('dashboard'))
    conn.close()
    return render_template('card_detail.html', user=user, card=card)

@app.route('/api/cards/<int:card_id>/history')
@login_required
def api_history(card_id):
    user = get_current_user()
    period = request.args.get('period', 'day')
    
    if period == 'day':
        since = datetime.utcnow() - timedelta(hours=24)
    elif period == 'week':
        since = datetime.utcnow() - timedelta(days=7)
    elif period == 'month':
        since = datetime.utcnow() - timedelta(days=30)
    else:
        since = datetime.utcnow() - timedelta(hours=24)
    
    conn = get_db()
    # Verify ownership
    card = conn.execute('SELECT * FROM cards WHERE id = ? AND user_id = ?', (card_id, user['id'])).fetchone()
    if not card:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    
    rows = conn.execute('''
        SELECT cash_balance, cash_bonus, points, recorded_at
        FROM balance_history
        WHERE card_id = ? AND recorded_at >= ?
        ORDER BY recorded_at ASC
    ''', (card_id, since.strftime('%Y-%m-%d %H:%M:%S'))).fetchall()
    conn.close()
    
    data = {
        'labels': [r['recorded_at'] for r in rows],
        'cash_balance': [r['cash_balance'] for r in rows],
        'cash_bonus': [r['cash_bonus'] for r in rows],
        'points': [r['points'] for r in rows],
    }
    return jsonify(data)

@app.route('/api/cards/<int:card_id>/stats')
@login_required
def api_stats(card_id):
    user = get_current_user()
    conn = get_db()
    card = conn.execute('SELECT * FROM cards WHERE id = ? AND user_id = ?', (card_id, user['id'])).fetchone()
    if not card:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    
    latest = conn.execute('''
        SELECT * FROM balance_history WHERE card_id = ? ORDER BY recorded_at DESC LIMIT 1
    ''', (card_id,)).fetchone()
    
    oldest = conn.execute('''
        SELECT * FROM balance_history WHERE card_id = ? ORDER BY recorded_at ASC LIMIT 1
    ''', (card_id,)).fetchone()

    count = conn.execute('SELECT COUNT(*) as c FROM balance_history WHERE card_id = ?', (card_id,)).fetchone()['c']
    
    # Spending in last 24h (drop in cash_balance + cash_bonus)
    since_24h = (datetime.utcnow() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    first_24h = conn.execute('''
        SELECT cash_balance, cash_bonus FROM balance_history 
        WHERE card_id = ? AND recorded_at >= ? ORDER BY recorded_at ASC LIMIT 1
    ''', (card_id, since_24h)).fetchone()
    
    conn.close()
    
    spent_24h = None
    if first_24h and latest:
        spent_24h = round(
            ((first_24h['cash_balance'] or 0) + (first_24h['cash_bonus'] or 0)) -
            ((latest['cash_balance'] or 0) + (latest['cash_bonus'] or 0)), 2
        )
    
    return jsonify({
        'total_readings': count,
        'latest': dict(latest) if latest else None,
        'oldest': dict(oldest) if oldest else None,
        'spent_24h': spent_24h,
    })

if __name__ == '__main__':
    init_db()
    # Start background poller
    t = threading.Thread(target=poll_cards, daemon=True)
    t.start()
    app.run(host='0.0.0.0', port=5000, debug=False)
