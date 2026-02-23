# 🎮 Koko Tracker

Self-hosted app to track your **Koko Amusement** game card balance history over time, with graphs for day/week/month trends.

## Features

- 🔄 **Auto-polls** your card balance every 60 seconds (configurable)
- 📊 **Charts** — Cash Balance, Cash Bonus, and Points over 24h / 7 days / 30 days
- 👥 **Multi-user** — each person logs in and tracks their own cards
- 🃏 **Multi-card** — add multiple cards per account
- 💾 **SQLite** database — zero-config, data persists in a Docker volume
- 🐳 **Docker-ready** for TrueNAS (or any Linux host)

---

## Quick Start (TrueNAS / Any Docker Host)

### Option A: Docker Compose (Recommended)

```bash
# 1. Copy these files to your TrueNAS dataset, e.g. /mnt/tank/apps/koko-tracker/
# 2. Edit docker-compose.yml to set a proper SECRET_KEY
# 3. Run:

docker-compose up -d
```

Then open: **http://YOUR_TRUENAS_IP:5055**

### Option B: TrueNAS Apps UI (Custom App)

1. Go to **Apps → Discover Apps → Custom App**
2. Set image to your built image OR use docker-compose manually via SSH
3. Map port `5000` → any host port (e.g. `5055`)
4. Add a host path volume: `/mnt/tank/koko-data` → `/data`
5. Set environment variable `SECRET_KEY` to a random string

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | random | Flask session secret. Set this to something fixed so sessions survive restarts |
| `POLL_INTERVAL` | `60` | Seconds between balance polls |
| `DB_PATH` | `/data/koko.db` | SQLite database path |

---

## How to Find Your Card Token

Your card URL looks like:
```
https://estore.kokomusement.com.au/BalanceMobile/BalanceMobile.aspx?i=1ag9ukYM
```

The token is everything after `?i=` → in this case: **`1ag9ukYM`**

You can find this by:
- Scanning the QR code on your card and copying the URL
- Checking your Koko app/email for a balance link

---

## Building from Source

```bash
docker build -t koko-tracker .
docker run -d \
  -p 5055:5000 \
  -v koko-data:/data \
  -e SECRET_KEY=your_secret_here \
  --name koko-tracker \
  --restart unless-stopped \
  koko-tracker
```

---

## TrueNAS Dataset Setup (Recommended)

```bash
# Create a dataset for persistent data
# In TrueNAS UI: Storage → Add Dataset → "koko-tracker"

# Then in docker-compose.yml, replace the volume section with:
volumes:
  koko-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /mnt/tank/koko-tracker  # Your dataset path
```

---

## Updating

```bash
docker-compose pull   # if using registry
docker-compose up -d --build  # if building locally
```

Data in the `/data` volume is preserved across updates.

---

## Architecture

```
Browser ←→ Flask (port 5000)
              ├── Background thread polls Koko website every 60s
              ├── Stores readings in SQLite
              └── Serves charts via Chart.js + REST API
```
