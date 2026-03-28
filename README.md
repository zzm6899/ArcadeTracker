# ArcadeTracker

Self-hosted balance tracker for **Koko Amusement** and **Timezone** arcade cards in Australia. Monitor your credits, bonus balance, points, and spending over time — with a web dashboard, Discord bot, and automated polling.

![Docker](https://img.shields.io/badge/docker-ready-blue?logo=docker)
![Python](https://img.shields.io/badge/python-3.10+-yellow?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

### 📊 Web Dashboard
- **Balance history charts** — view cash, bonus, and points over 24h / 7 days / 30 days / all time
- **Spending tracker** — see how much you've spent per card over any time period, dynamically synced with chart selection
- **All-time spending** — first-ever reading vs latest, always visible at a glance
- **Multi-card support** — track unlimited Koko and Timezone cards per account
- **Overview chart** — combined balance view across all your cards
- **Transaction history** — imported rolling transaction log for Timezone cards (descriptions, timestamps, deltas)
- **Mobile-friendly** — dark theme, responsive layout

### 🤖 Discord Bot
- **`/cards`** — show all card balances with all-time spending
- **`/balance`** — quick total balance summary
- **`/spent`** — spending breakdown by period (24h / 7d / 30d / all time)
- **`/refresh`** — force poll all cards immediately
- **`/addcard`** — add Koko (QR token) or Timezone (linked session) cards
- **`/leaderboard`** — public balance rankings (server only)
- **`/privacy`** — toggle public/private per command
- **`/help`** — command reference
- **`/info`** — account status and global stats
- **`/setup`** — context-aware onboarding guide
- **`/link`** — connect Discord to your web account
- Works in servers, DMs, and group chats (user-installable)

### 🔄 Automated Polling
- **Koko cards** — scrapes balance from the Koko eStore page every 5 minutes (configurable)
- **Timezone cards** — uses the TEEG API with automatic token refresh (Azure B2C OAuth)
- **Quiet hours** — configurable polling pause window (e.g. 11 PM – 6 AM) with timezone support
- **Transaction import** — captures Timezone's rolling 20-transaction window on each poll before it scrolls out

### 🛡️ Admin Panel
- User management — rename, delete, promote/demote admin, toggle leaderboard
- Card overview — all active cards with last balance and update time
- Timezone session status — connected / error / stale / needs reconnect
- Quiet hours config — enable/disable, set start/end hour, select timezone
- Admin webhook — Discord webhook with configurable fire modes (live / 5m / 10m / 30m / 1h / daily)
- Last seen tracking — see when each user last interacted (web or Discord)
- Live logs — in-memory log viewer for debugging

### 🔗 Integrations
- **Discord OAuth** — login and account creation via Discord
- **Discord webhooks** — per-user and admin-wide balance change notifications
- **Timezone portal** — one-click session capture via bookmarklet
- **Email** — password reset support (SMTP)

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- (Optional) A Discord bot token for the bot features
- (Optional) Discord OAuth app for Discord login

### 1. Clone

```bash
git clone https://github.com/zzm6899/ArcadeTracker.git
cd ArcadeTracker
```

### 2. Configure

Create a `.env` file or set environment variables in `docker-compose.yml`:

```env
# Required
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme

# Optional — Discord Bot
DISCORD_BOT_TOKEN=your_bot_token
DISCORD_GUILD_ID=your_server_id

# Optional — Discord OAuth (for "Login with Discord")
DISCORD_CLIENT_ID=your_client_id
DISCORD_CLIENT_SECRET=your_client_secret

# Optional — App URL (used in bot messages and OAuth redirects)
APP_URL=https://your-domain.com

# Optional — Email (password reset)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=you@gmail.com
MAIL_PASSWORD=app_password
MAIL_FROM=you@gmail.com

# Optional — Session persistence (auto-generated if not set)
SECRET_KEY=your_random_secret
```

### 3. Run

```bash
docker-compose up -d
```

The app will be available at `http://localhost:5055` (or your configured port).

### 4. Add Cards

**Koko cards:**
1. Find your card's QR code URL (usually `https://estore.kokoamusement.com.au/...?i=TOKEN`)
2. Go to Dashboard → Add Card → Koko, paste the token
3. Or use `/addcard` in Discord

**Timezone cards:**
1. Go to Dashboard → Timezone → Connect
2. Follow the bookmarklet instructions to capture your session
3. Select which cards to track
4. Or use `/addcard` → Timezone in Discord after connecting on the web

---

## Architecture

```
ArcadeTracker/
├── koko-tracker/
│   ├── src/
│   │   ├── app.py           # Flask app — web routes, API, polling engine
│   │   └── bot.py           # Discord bot — slash commands, status cycling
│   ├── templates/           # Jinja2 HTML templates
│   │   ├── dashboard.html
│   │   ├── card_detail.html
│   │   ├── admin.html
│   │   ├── settings.html
│   │   └── ...
│   ├── static/              # CSS, JS, images
│   ├── Dockerfile
│   └── docker-compose.yml
├── .github/workflows/       # CI/CD
└── README.md
```

### Stack
- **Backend:** Python 3.10+, Flask, SQLite
- **Frontend:** Jinja2 templates, Chart.js, Tailwind CSS (CDN)
- **Discord:** discord.py 2.x with app commands
- **Polling:** Background threads with configurable intervals
- **Auth:** Session-based (Flask), Discord OAuth2, SHA-256 password hashing
- **Data:** SQLite with auto-migrations on startup

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ADMIN_USERNAME` | Yes | — | Root admin username |
| `ADMIN_PASSWORD` | Yes | — | Root admin password |
| `DB_PATH` | No | `/data/koko.db` | SQLite database path |
| `SECRET_KEY` | No | Auto-generated | Flask session secret (persisted to `/data/.flask_secret_key` if not set) |
| `DISCORD_BOT_TOKEN` | No | — | Enables the Discord bot |
| `DISCORD_GUILD_ID` | No | — | Faster slash command sync to a specific server |
| `DISCORD_CLIENT_ID` | No | — | Enables "Login with Discord" |
| `DISCORD_CLIENT_SECRET` | No | — | Required with `DISCORD_CLIENT_ID` |
| `APP_URL` | No | `http://localhost:5055` | Public URL for bot messages and OAuth redirects |
| `POLL_INTERVAL` | No | `300` | Default Koko poll interval in seconds |
| `TIMEZONE_POLL_INTERVAL` | No | `900` | Default Timezone poll interval in seconds |
| `TFNSW_API_KEY` | No | — | TfNSW Open Data Hub API key for Transport NSW commands — obtain from [opendata.transport.nsw.gov.au](https://opendata.transport.nsw.gov.au) |
| `MAIL_SERVER` | No | — | SMTP server for password reset emails |
| `MAIL_PORT` | No | `587` | SMTP port |
| `MAIL_USERNAME` | No | — | SMTP username |
| `MAIL_PASSWORD` | No | — | SMTP password |
| `MAIL_FROM` | No | `MAIL_USERNAME` | From address for emails |

---

## Discord Bot Setup

1. Create a bot at [discord.com/developers](https://discord.com/developers/applications)
2. Enable the **applications.commands** scope
3. Set `DISCORD_BOT_TOKEN` and optionally `DISCORD_GUILD_ID`
4. Invite the bot to your server with the OAuth2 URL generator (scopes: `bot`, `applications.commands`)
5. The bot supports user-install — members can add it to their DMs too

For Discord OAuth login, also create an OAuth2 redirect URL pointing to `{APP_URL}/auth/discord/callback`.

---

## API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/cards/<id>/history?period=day\|week\|month\|all` | Session | Balance history data points |
| `GET /api/cards/<id>/stats` | Session | Latest balance, 24h spending, transaction history |
| `GET /api/dashboard/overview?period=day` | Session | Combined chart data for all cards |
| `POST /api/cards/resolve-qr` | Session | Resolve a Koko QR URL to a card token |
| `POST /api/cards/<id>/force-poll` | Session | Force immediate balance check |

---

## Contributing

Pull requests welcome. The codebase is a single Flask app (`app.py`) and Discord bot (`bot.py`) — no build step required.

```bash
# Local dev (no Docker)
pip install flask requests beautifulsoup4 discord.py
python koko-tracker/src/app.py
```

---

## License

MIT
