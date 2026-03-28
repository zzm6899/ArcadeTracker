"""
Transport NSW API client for Discord bot.
Uses the TfNSW Trip Planner API v1 (departure_mon + stop_finder + trip endpoints).
API key is read from the TFNSW_API_KEY environment variable.
"""

import os
import asyncio
import aiohttp
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

TFNSW_API_KEY = os.environ.get("TFNSW_API_KEY", "")
BASE_URL = "https://api.transport.nsw.gov.au/v1/tp"
SYDNEY_TZ = ZoneInfo("Australia/Sydney")

# ─── Mode mappings ────────────────────────────────────────────────────────────
# These are the product.class values returned by departure_mon and trip APIs.
# (Different from the stop_finder modes[] array — that uses a separate numbering.)
MODE_ICONS = {
    "1": "🚆",   # Train
    "2": "🚇",   # Metro
    "4": "🚃",   # Light Rail
    "5": "🚌",   # Bus
    "7": "🚌",   # Coach / Express Bus
    "9": "⛴️",   # Ferry
    "11": "🚌",  # On-demand / Night bus
    "99": "🚌",  # Other bus
}
MODE_NAMES = {
    "1": "Train", "2": "Metro", "4": "Light Rail", "5": "Bus",
    "7": "Coach", "9": "Ferry", "11": "Bus", "99": "Bus",
}

# Map from stop_finder modes[] integers to departure product.class strings
# stop_finder uses: 1=Bus 2=Ferry 4=Train 5=LightRail 7=Coach 11=Metro 99=OnDemand
# departure_mon uses: 1=Train 2=Metro 4=LightRail 5=Bus 9=Ferry
STOPFINDER_TO_PRODUCT_CLASS = {
    "1": "5",    # Bus
    "2": "9",    # Ferry
    "4": "1",    # Train
    "5": "4",    # Light Rail
    "7": "7",    # Coach
    "11": "2",   # Metro
    "99": "11",  # On-demand
}


def _headers():
    return {"Authorization": f"apikey {TFNSW_API_KEY}"}


def _sydney_now():
    return datetime.now(SYDNEY_TZ)


def _parse_tfnsw_time(ts: str) -> datetime | None:
    """Parse a TfNSW ISO timestamp.
    Handles both offset form ('2025-03-29T14:35:00+11:00') and UTC Z form
    ('2026-03-28T14:54:00Z') — the Z suffix isn't supported by fromisoformat
    until Python 3.11, so we normalise it to +00:00 first.
    """
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _minutes_until(dt: datetime) -> int:
    """Minutes from now until dt."""
    now = datetime.now(timezone.utc)
    diff = dt.astimezone(timezone.utc) - now
    return max(0, int(diff.total_seconds() / 60))


def _fmt_time(dt: datetime) -> str:
    """Format a datetime as HH:MM in Sydney local time."""
    return dt.astimezone(SYDNEY_TZ).strftime("%H:%M")


def _format_mins(mins: int) -> str:
    if mins == 0:
        return "**Now**"
    if mins == 1:
        return "**1 min**"
    return f"**{mins} mins**"


# ─── Stop Finder ──────────────────────────────────────────────────────────────

def _normalise_query(query: str) -> str:
    """Capitalise the first letter of each word while preserving the rest.
    Unlike str.title(), this leaves acronyms like 'NSW' or 'CBD' intact,
    e.g. 'top ryde' → 'Top Ryde', 'NSW trains' → 'NSW Trains'.
    """
    return " ".join((w[0].upper() + w[1:]) for w in query.strip().split() if w)


async def _stop_finder_raw(query: str) -> list:
    """
    Hit the stop_finder endpoint and return filtered locations list.
    Shared by find_stops and its fuzzy-retry path.
    """
    params = {
        "outputFormat": "rapidJSON",
        "type_sf": "any",
        "name_sf": _normalise_query(query),
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

    all_locations = data.get("locations", [])
    return [
        l for l in all_locations
        if l.get("type") in ("stop", "platform")
        or (l.get("type") == "poi" and l.get("productClasses"))
    ]


# Common station/suburb names used for fuzzy correction
_KNOWN_PLACES = [
    "central", "rhodes", "chatswood", "parramatta", "strathfield", "burwood",
    "redfern", "newtown", "bondi", "circular quay", "wynyard", "town hall",
    "museum", "st james", "kings cross", "edgecliff", "bondi junction",
    "mascot", "green square", "sydenham", "tempe", "wolli creek", "arncliffe",
    "rockdale", "kogarah", "hurstville", "mortdale", "penshurst", "beverly hills",
    "narwee", "riverwood", "padstow", "revesby", "panania", "east hills",
    "liverpool", "cabramatta", "fairfield", "yennora", "guildford", "merrylands",
    "granville", "clyde", "auburn", "lidcombe", "olympic park", "homebush",
    "flemington", "north strathfield", "concord west", "rhodes", "meadowbank",
    "west ryde", "ryde", "top ryde", "epping", "cheltenham", "beecroft",
    "pennant hills", "thornleigh", "normanhurst", "hornsby", "asquith",
    "mount colah", "mount kuring-gai", "berowra", "cowan", "hawkesbury river",
    "brooklyn", "wondabyne", "gosford", "wyong", "tuggerah", "wyee",
    "morisset", "awaba", "booragul", "teralba", "cockle creek", "cardiff",
    "glendale", "broadmeadow", "hamilton", "newcastle", "newcastle interchange",
    "macquarie fields", "glenfield", "leppington", "campbelltown", "penrith",
    "blacktown", "seven hills", "toongabbie", "wentworthville", "westmead",
    "harris park", "northmead", "north parramatta", "carlingford",
    "macquarie university", "macquarie park", "lane cove", "artarmon",
    "st leonards", "waverton", "north sydney", "milsons point", "wynyard",
    "martin place", "central", "redfern", "macdonaldtown", "erskineville",
    "st peters", "sydenham", "marrickville", "dulwich hill", "hurlstone park",
    "canterbury", "campsie", "lakemba", "wiley park", "punchbowl", "bankstown",
    "yagoona", "birrong", "sefton", "chester hill", "leightonfield",
    "villawood", "carramar", "cabramatta", "warwick farm", "liverpool",
    "cronulla", "miranda", "sutherland", "jannali", "como", "oatley",
    "hurstville", "allawah", "carlton", "kogarah", "st george",
    "sydney airport", "domestic airport", "international airport",
]


def _fuzzy_correct(query: str) -> str | None:
    """
    Return a spelling-corrected version of query if a close match is found
    in our known places list, otherwise None.
    Uses difflib — no extra dependencies.
    """
    from difflib import get_close_matches
    q = query.strip().lower()
    # Try whole query first
    matches = get_close_matches(q, _KNOWN_PLACES, n=1, cutoff=0.72)
    if matches:
        return matches[0]
    # Try each word individually (handles "paramatta station" → "parramatta")
    words = q.split()
    if len(words) > 1:
        corrected = []
        changed = False
        for w in words:
            m = get_close_matches(w, _KNOWN_PLACES, n=1, cutoff=0.78)
            if m and m[0] != w:
                corrected.append(m[0])
                changed = True
            else:
                corrected.append(w)
        if changed:
            return " ".join(corrected)
    return None


async def find_stops(query: str, limit: int = 5) -> list[dict]:
    """
    Search for stops/stations by name.
    Returns list of dicts: {id, name, type, modes}
    """
    locations = await _stop_finder_raw(query)

    # Fallback 1: retry with " station" appended, but only when the initial query
    # returned no transit stops at all.
    # Handles queries like "rhodes" where the API returns only cafes/POIs that are
    # filtered out, leaving locations empty.
    # We intentionally skip this when locations is already non-empty — appending
    # "station" for suburb names like "top ryde" would redirect to a different stop
    # (e.g. "top ryde station" → Ryde Station) instead of the correct bus stops.
    q_lower = query.strip().lower()
    if not q_lower.endswith("station") and not locations:
        station_locs = await _stop_finder_raw(query + " station")
        if station_locs:
            locations = station_locs

    # Fallback 2: fuzzy spelling correction for clear misspellings.
    # Triggers when top result quality is low (< 500), meaning the API matched
    # something unrelated (e.g. "rodes" → Rodeo Dr, quality ~200).
    best_quality = max((l.get("matchQuality", 0) for l in locations), default=0)
    if best_quality < 500:
        corrected = _fuzzy_correct(query)
        if corrected and corrected.lower() != q_lower:
            fuzzy_locs = await _stop_finder_raw(corrected + " station")
            if not fuzzy_locs:
                fuzzy_locs = await _stop_finder_raw(corrected)
            fuzzy_quality = max((l.get("matchQuality", 0) for l in fuzzy_locs), default=0)
            if fuzzy_locs and fuzzy_quality > best_quality:
                locations = fuzzy_locs
    results = []
    for loc in locations[:limit]:
        stop_id = loc.get("id", "")

        # disassembledName splits the stop cleanly: e.g. "Stop A" vs "Rhodes Station"
        disassembled = loc.get("disassembledName", "") or ""
        full_name = loc.get("name", "Unknown")

        parent = loc.get("parent", {}) or {}
        parent_name = parent.get("name", "") or ""
        suburb = parent.get("name", "") or ""

        # platform_hint = the sub-stop identifier that distinguishes bus stops/stands
        # at the same station, e.g. "Stand A", "Stop B", "Platform 3".
        # We only set it when disassembledName looks like a platform label — NOT when
        # it is just the station name itself (e.g. "Rhodes Station" is NOT a hint).
        PLATFORM_KEYWORDS = ("stop", "stand", "platform", "bay", "wharf", "berth")
        platform_hint = ""
        if disassembled and parent_name and disassembled != parent_name:
            d_lower = disassembled.lower()
            # Is it a short platform label like "Stop B", "Stand A", "Platform 3"?
            if any(d_lower.startswith(kw) for kw in PLATFORM_KEYWORDS):
                platform_hint = disassembled

        # Human display name
        if platform_hint:
            display_name = f"{parent_name}, {platform_hint}" if parent_name else disassembled
        elif parent_name and parent_name not in full_name:
            display_name = f"{full_name}, {parent_name}"
        else:
            display_name = full_name

        # Determine transport modes available at this stop.
        # The API returns modes as integers directly on the location object — use that first.
        # TfNSW mode codes: 1=Bus, 2=Ferry, 4=Train, 5=LightRail, 7=Coach, 11=Metro, 99=OnDemand
        # stop_finder returns modes as its own numbering (1=Bus,2=Ferry,4=Train,5=LR,11=Metro).
        # Translate to departure product.class numbers for consistent display.
        raw_modes = loc.get("modes", [])
        sf_modes = {str(m) for m in raw_modes if m is not None}
        if not sf_modes:
            for s in loc.get("assignedStops", []):
                for mode in s.get("modes", []):
                    sf_modes.add(str(mode))
        if not sf_modes:
            # Last resort: infer from stop ID prefix
            if stop_id.startswith("21") or stop_id.startswith("20"):
                sf_modes.add("4")
            elif stop_id.startswith("3"):
                sf_modes.add("1")
            elif stop_id.startswith("4"):
                sf_modes.add("2")
            elif stop_id.startswith("6"):
                sf_modes.add("5")
        # Translate stop_finder mode numbers → product.class numbers for display
        modes = {STOPFINDER_TO_PRODUCT_CLASS.get(m, m) for m in sf_modes}

        # short_name = the station name for display (without suburb suffix)
        # Use disassembledName unless it's a platform label, then use full_name
        short_name = disassembled if disassembled and not platform_hint else full_name

        results.append({
            "id": stop_id,
            "name": display_name,
            "short_name": short_name,
            "parent_name": parent_name,
            "suburb": suburb,
            "platform_hint": platform_hint,
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
    # Fetch a larger buffer so client-side mode filtering still returns enough results
    fetch_limit = limit * 5 if mode_filter else limit * 2
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
        "maxResults": str(fetch_limit),
    }
    # Note: the TfNSW API ignores inclMOT_X / ptOptionsActive in this version.
    # We fetch a buffer and filter client-side instead.

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
        # Client-side mode filter (API ignores server-side inclMOT params)
        ev_mode = str((ev.get("transportation", {}).get("product") or {}).get("class", "?"))
        if mode_filter and ev_mode != mode_filter:
            continue
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


# ─── Service Alerts ───────────────────────────────────────────────────────────

async def get_alerts(stop_ids: list[str] | None = None, line_names: list[str] | None = None) -> list[dict]:
    """
    Fetch current service alerts from TfNSW.
    Optionally filter to alerts relevant to given stop IDs or line names.
    Returns list of dicts: {priority, title, content, url, is_replacement}
    """
    import re as _re
    params = {
        "outputFormat": "rapidJSON",
        "version": "10.2.1.42",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{BASE_URL}/add_info",
                params=params,
                headers=_headers(),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
    except Exception:
        return []

    current = data.get("infos", {}).get("current", [])
    results = []
    for alert in current:
        content_html = alert.get("content", "") or ""
        subtitle = alert.get("subtitle", "") or ""
        url = alert.get("url", "") or ""
        priority = alert.get("priority", "normal")

        # Strip HTML tags for plain text
        content_text = _re.sub(r"<[^>]+>", " ", content_html).strip()
        content_text = _re.sub(r"\s+", " ", content_text).strip()

        if not content_text and not subtitle:
            continue

        title = subtitle[:120] if subtitle else content_text[:80]
        body = content_text[:300] if content_text != title else ""

        is_replacement = any(
            kw in content_text.lower() or kw in subtitle.lower()
            for kw in ("bus replacement", "road coach", "replaced by", "coach replacement")
        )

        results.append({
            "priority": priority,
            "title": title,
            "body": body,
            "url": url,
            "is_replacement": is_replacement,
        })

    # If filters given, try to narrow down — best effort (API doesn't return structured stop/line refs)
    # We just return all current alerts if no reliable filter data available
    # Cap at 5 to avoid embed spam
    high_priority = [a for a in results if a["priority"] in ("high", "veryHigh")]
    normal = [a for a in results if a["priority"] not in ("high", "veryHigh")]
    return (high_priority + normal)[:5]


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
    rt_indicator = " 🔴" if dep["realtime"] is not None else ""
    prefix = f"`{index}.` " if index is not None else ""
    return f"{prefix}{icon} **{route}** → {dest} — {mins_str}{rt_indicator}{delay_str}"


def format_trip_summary(trip: dict, index: int) -> str:
    """Format a trip option into a short summary line."""
    dep = trip["departs"]
    mins = trip["mins_until"]
    dur = trip["duration_mins"]
    legs = trip["legs"]

    dep_str = _fmt_time(dep) if dep else "?"
    mins_str = _format_mins(mins) if mins is not None else "?"

    # Build leg icons string
    leg_icons = " → ".join(
        l["icon"] if l["mode"] == "walk" else f"{l['icon']}**{l.get('route','')}**"
        for l in legs
    )

    changes = trip["num_legs"] - 1
    change_str = f", {changes} change{'s' if changes != 1 else ''}" if changes > 0 else ", direct"

    return f"`{index}.` {leg_icons}  —  departs **{dep_str}** ({mins_str}) · {dur}m{change_str}"
