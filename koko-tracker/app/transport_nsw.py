"""
Transport NSW API client for Discord bot.
Uses the TfNSW Trip Planner API v1 (departure_mon + stop_finder + trip endpoints).
API key is read from the TFNSW_API_KEY environment variable.
"""

import os
import asyncio
import aiohttp
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

TFNSW_API_KEY = os.environ.get("TFNSW_API_KEY", "")
BASE_URL = "https://api.transport.nsw.gov.au/v1/tp"
SYDNEY_TZ = ZoneInfo("Australia/Sydney")

# ─── Mode mappings ────────────────────────────────────────────────────────────
MODE_ICONS = {
    "1": "🚌",   # Bus
    "2": "🚢",   # Ferry
    "4": "🚆",   # Train
    "5": "🚃",   # Light Rail
    "7": "🚌",   # Coach
    "9": "🚌",   # Express Bus
    "11": "🚆",  # Metro
    "99": "🚌",  # On demand
}
MODE_NAMES = {
    "1": "Bus", "2": "Ferry", "4": "Train", "5": "Light Rail",
    "7": "Coach", "9": "Express Bus", "11": "Metro", "99": "On Demand",
}


def _headers():
    return {"Authorization": f"apikey {TFNSW_API_KEY}"}


def _sydney_now():
    return datetime.now(SYDNEY_TZ)


def _parse_tfnsw_time(ts: str) -> datetime | None:
    """Parse a TfNSW ISO timestamp like '2025-03-29T14:35:00+11:00'."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _minutes_until(dt: datetime) -> int:
    """Minutes from now (Sydney time) until dt."""
    now = datetime.now(timezone.utc)
    diff = dt.astimezone(timezone.utc) - now
    return max(0, int(diff.total_seconds() / 60))


def _format_mins(mins: int) -> str:
    if mins == 0:
        return "**Now**"
    if mins == 1:
        return "**1 min**"
    return f"**{mins} mins**"


# ─── Stop Finder ──────────────────────────────────────────────────────────────

async def find_stops(query: str, limit: int = 5) -> list[dict]:
    """
    Search for stops/stations by name.
    Returns list of dicts: {id, name, type, modes}
    """
    params = {
        "outputFormat": "rapidJSON",
        "type_sf": "stop",
        "name_sf": query,
        "coordOutputFormat": "EPSG:4326",
        "TfNSWSF": "true",
        "version": "10.2.1.42",
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{BASE_URL}/stop_finder",
            params=params,
            headers=_headers(),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()

    locations = data.get("locations", [])
    results = []
    for loc in locations[:limit]:
        stop_id = loc.get("id", "")
        name = loc.get("disassembledName") or loc.get("name", "Unknown")
        parent = loc.get("parent", {})
        parent_name = parent.get("name", "") if parent else ""
        if parent_name and parent_name not in name:
            display_name = f"{name}, {parent_name}"
        else:
            display_name = name
        # Determine transport modes available at this stop
        assigned_stops = loc.get("assignedStops", [])
        modes = set()
        for s in assigned_stops:
            for mode in s.get("modes", []):
                modes.add(str(mode))
        if not modes:
            # fallback: guess from stop id
            if stop_id.startswith("21"):
                modes.add("4")  # train
        results.append({
            "id": stop_id,
            "name": display_name,
            "short_name": name,
            "modes": sorted(modes),
        })
    return results


# ─── Departures ───────────────────────────────────────────────────────────────

async def get_departures(stop_id: str, limit: int = 5, mode_filter: str | None = None) -> list[dict]:
    """
    Get upcoming departures from a stop.
    Returns list of dicts with: route, destination, planned, realtime, mins, delay, stop_name, mode, line_name
    mode_filter: '4' = trains only, '1' = buses, etc.
    """
    now_syd = _sydney_now()
    params = {
        "outputFormat": "rapidJSON",
        "coordOutputFormat": "EPSG:4326",
        "mode": "direct",
        "type_dm": "stop",
        "name_dm": stop_id,
        "depArrMacro": "dep",
        "itdDate": now_syd.strftime("%Y%m%d"),
        "itdTime": now_syd.strftime("%H%M"),
        "TfNSWDM": "true",
        "version": "10.2.1.42",
    }
    if mode_filter:
        params["ptOptionsActive"] = "-1"
        params[f"inclMOT_{mode_filter}"] = "1"

    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{BASE_URL}/departure_mon",
            params=params,
            headers=_headers(),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"API error {resp.status}: {text[:200]}")
            data = await resp.json()

    stop_events = data.get("stopEvents", [])
    departures = []
    for ev in stop_events:
        transport = ev.get("transportation", {})
        route_num = transport.get("number", "?")
        line_name = transport.get("description", "") or transport.get("name", "")
        dest = (transport.get("destination") or {}).get("name", "Unknown")
        mode_id = str((transport.get("product") or {}).get("class", "?"))

        planned_str = ev.get("departureTimePlanned", "")
        rt_str = ev.get("departureTimeEstimated", "")

        planned_dt = _parse_tfnsw_time(planned_str)
        rt_dt = _parse_tfnsw_time(rt_str) if rt_str else None

        display_dt = rt_dt or planned_dt
        if not display_dt:
            continue

        mins = _minutes_until(display_dt)

        # Delay in minutes (positive = late)
        delay = 0
        if rt_dt and planned_dt:
            delay = int((rt_dt - planned_dt).total_seconds() / 60)

        # Stop location for the "nearest ping" feature
        location = ev.get("location", {})
        stop_name = location.get("name", "")

        # Is this running on time?
        on_time = abs(delay) <= 1

        departures.append({
            "route": route_num,
            "line_name": line_name,
            "destination": dest,
            "planned": planned_dt,
            "realtime": rt_dt,
            "display_time": display_dt,
            "mins": mins,
            "delay": delay,
            "on_time": on_time,
            "stop_name": stop_name,
            "mode": mode_id,
        })

        if len(departures) >= limit:
            break

    return departures


# ─── Trip Planner ─────────────────────────────────────────────────────────────

async def plan_trip(from_id: str, to_id: str, limit: int = 3) -> list[dict]:
    """
    Plan trips between two stop IDs.
    Returns list of trip dicts with legs, total duration, and departure time.
    """
    now_syd = _sydney_now()
    params = {
        "outputFormat": "rapidJSON",
        "coordOutputFormat": "EPSG:4326",
        "depArrMacro": "dep",
        "itdDate": now_syd.strftime("%Y%m%d"),
        "itdTime": now_syd.strftime("%H%M"),
        "type_origin": "stop",
        "name_origin": from_id,
        "type_destination": "stop",
        "name_destination": to_id,
        "calcNumberOfTrips": str(limit),
        "TfNSWTR": "true",
        "version": "10.2.1.42",
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{BASE_URL}/trip",
            params=params,
            headers=_headers(),
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"API error {resp.status}: {text[:200]}")
            data = await resp.json()

    journeys = data.get("journeys", [])
    trips = []
    for journey in journeys[:limit]:
        legs = journey.get("legs", [])
        if not legs:
            continue

        first_dep_str = legs[0].get("origin", {}).get("departureTimePlanned", "")
        last_arr_str = legs[-1].get("destination", {}).get("arrivalTimePlanned", "")
        first_dep = _parse_tfnsw_time(first_dep_str)
        last_arr = _parse_tfnsw_time(last_arr_str)

        # Real-time for first departure
        rt_dep_str = legs[0].get("origin", {}).get("departureTimeEstimated", "")
        rt_dep = _parse_tfnsw_time(rt_dep_str) if rt_dep_str else None
        display_dep = rt_dep or first_dep

        duration_mins = 0
        if first_dep and last_arr:
            duration_mins = int((last_arr - first_dep).total_seconds() / 60)

        parsed_legs = []
        for leg in legs:
            transport = leg.get("transportation", {})
            mode_id = str((transport.get("product") or {}).get("class", "?"))
            if mode_id == "100":
                # Walking leg
                walk_dur = leg.get("duration", 0)
                parsed_legs.append({
                    "mode": "walk",
                    "icon": "🚶",
                    "summary": f"Walk {walk_dur // 60}m",
                    "from": leg.get("origin", {}).get("name", ""),
                    "to": leg.get("destination", {}).get("name", ""),
                })
            else:
                route_num = transport.get("number", "")
                dest = (transport.get("destination") or {}).get("name", "")
                dep_str = leg.get("origin", {}).get("departureTimePlanned", "")
                dep_dt = _parse_tfnsw_time(dep_str)
                from_name = leg.get("origin", {}).get("name", "")
                to_name = leg.get("destination", {}).get("name", "")
                parsed_legs.append({
                    "mode": mode_id,
                    "icon": MODE_ICONS.get(mode_id, "🚌"),
                    "route": route_num,
                    "destination": dest,
                    "from": from_name,
                    "to": to_name,
                    "departs": dep_dt,
                    "summary": f"{MODE_ICONS.get(mode_id, '🚌')} {route_num} → {dest}",
                })

        trips.append({
            "departs": display_dep,
            "planned_departs": first_dep,
            "arrives": last_arr,
            "duration_mins": duration_mins,
            "mins_until": _minutes_until(display_dep) if display_dep else None,
            "legs": parsed_legs,
            "num_legs": len([l for l in parsed_legs if l["mode"] != "walk"]),
        })

    return trips


# ─── Formatting helpers ────────────────────────────────────────────────────────

def format_departure_line(dep: dict, index: int | None = None) -> str:
    """Format a single departure into a compact line."""
    icon = MODE_ICONS.get(dep["mode"], "🚌")
    route = dep["route"]
    dest = dep["destination"]
    mins_str = _format_mins(dep["mins"])
    delay_str = ""
    if not dep["on_time"]:
        sign = "+" if dep["delay"] > 0 else ""
        delay_str = f" ⚠️ {sign}{dep['delay']}m late"
    rt_indicator = " 🔴" if dep["realtime"] else ""
    prefix = f"`{index}.` " if index is not None else ""
    return f"{prefix}{icon} **{route}** → {dest} — {mins_str}{rt_indicator}{delay_str}"


def format_trip_summary(trip: dict, index: int) -> str:
    """Format a trip option into a short summary line."""
    dep = trip["departs"]
    mins = trip["mins_until"]
    dur = trip["duration_mins"]
    legs = trip["legs"]

    dep_str = dep.strftime("%H:%M") if dep else "?"
    mins_str = _format_mins(mins) if mins is not None else "?"

    # Build leg icons string
    leg_icons = " → ".join(
        l["icon"] if l["mode"] == "walk" else f"{l['icon']}**{l.get('route','')}**"
        for l in legs
    )

    changes = trip["num_legs"] - 1
    change_str = f", {changes} change{'s' if changes != 1 else ''}" if changes > 0 else ", direct"

    return f"`{index}.` {leg_icons}  —  departs **{dep_str}** ({mins_str}) · {dur}m{change_str}"
