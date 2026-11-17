# ArcadeTracker

ArcadeTracker checks **Koko Amusement** and **Timezone** arcade cards in Australia. It records credits, bonus balances, points and spending over time. Host it yourself and check your cards from the web dashboard or Discord.

![Docker](https://img.shields.io/badge/docker-ready-blue?logo=docker)
![Python](https://img.shields.io/badge/python-3.10+-yellow?logo=python)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

### Web dashboard
- Chart cash, bonus balances and points over 24 hours, 7 days, 30 days or all time.
- See spending per card for the selected chart period. An all-time figure based on the first and latest readings stays visible.
- Add as many Koko and Timezone cards as you like. The overview chart combines their balances.
- Review imported Timezone transactions with descriptions, timestamps and balance changes.
- The dashboard has a dark theme and adapts to phone screens.

### Discord bot
- `/cards` shows each card's balance and all-time spending.
- `/balance` shows your total balance.
- `/spent` breaks down spending over 24 hours, 7 days, 30 days or all time.
- `/refresh` checks all your cards immediately.
- `/addcard` adds a Koko card with a QR token or a Timezone card from a linked session.
- `/leaderboard` shows public balance rankings in servers.
- `/privacy` switches individual commands between public and private responses.
- `/help` lists the commands.
- `/info` shows account status and global stats.
- `/setup` gives setup instructions based on your account.
- `/link` connects Discord to your web account.

Users can install the bot for servers, direct messages and group chats.

### Scheduled checks
- The tracker reads Koko balances from the Koko eStore every 5 minutes by default. You can change the interval.
- Timezone checks use the TEEG API and refresh Azure B2C OAuth tokens automatically. Each check saves Timezone's rolling window of 20 transactions before older entries drop out.
- Set quiet hours in your timezone to pause checks, for example from 11 PM to 6 AM.

### Admin panel
- Rename or delete users, grant or remove admin access, and toggle leaderboard participation.
- View active cards with their last balance and update time. See whether each Timezone session is connected, has an error, is stale, or needs to reconnect.
- Turn quiet hours on or off, set the start and end hours, and choose a timezone.
- Set the admin Discord webhook to send live, every 5, 10 or 30 minutes, hourly, or daily.
- See when users last interacted on the web or Discord. Use the live in-memory logs to debug problems.

### Integrations
- Sign in or create an account with Discord OAuth.
- Use Discord webhooks to send balance change notifications to individual users or admins.
- Capture a Timezone portal session in one click with the bookmarklet.
- Send password reset emails through SMTP.

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
1. Find your card's QR code URL (usually `https://customer.kokoamusement.com.au/BalanceMobile/BalanceMobile.aspx?i=TOKEN`)
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
| `TFNSW_API_KEY` | No | — | TfNSW Open Data Hub API key for Transport NSW commands. Get a key at [opendata.transport.nsw.gov.au](https://opendata.transport.nsw.gov.au). |
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
5. Members can install the bot in their DMs too.

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

Pull requests are welcome. You can run the Flask app (`app.py`) and Discord bot (`bot.py`) without a build step.

```bash
# Local dev (no Docker)
pip install flask requests beautifulsoup4 discord.py
python koko-tracker/src/app.py
```

---

## License

MIT
