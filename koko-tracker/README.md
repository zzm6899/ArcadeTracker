# Koko Tracker

Koko Tracker records the balance on your **Koko Amusement** game cards. It runs on your own server and charts how your balance changes by day, week or month.

## Features

- The app checks balances every 60 seconds by default. You can change the interval.
- Charts show cash balance, cash bonus and points over 24 hours, 7 days or 30 days.
- Each person signs in and can track multiple cards on their own account.
- SQLite needs no setup and keeps its data in a Docker volume.
- Run the Docker container on TrueNAS or another Linux host.

---

## Quick Start (TrueNAS / Any Docker Host)

### Option A: Docker Compose (Recommended)

```bash
# 1. Copy these files to your TrueNAS dataset, e.g. /mnt/tank/apps/koko-tracker/
# 2. Edit docker-compose.yml to set a proper SECRET_KEY
# 3. Run:

docker-compose up -d
```

Open **http://YOUR_TRUENAS_IP:5055** in your browser.

### Option B: TrueNAS Apps UI (Custom App)

1. Go to **Apps → Discover Apps → Custom App**
2. Select the image you built. You can also run Docker Compose over SSH.
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
https://customer.kokoamusement.com.au/BalanceMobile/BalanceMobile.aspx?i=TOKEN
```

The card token is the value of the `i` query parameter.

Scan the QR code on your card and copy the URL, or find a balance link in the Koko app or an email from Koko.

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
