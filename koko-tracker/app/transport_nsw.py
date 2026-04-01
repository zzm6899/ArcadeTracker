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

BASE_URL = "https://api.transport.nsw.gov.au/v1/tp"
SYDNEY_TZ = ZoneInfo("Australia/Sydney")

# Platform label keywords — used to identify disassembledName as a platform hint
_PLATFORM_KEYWORDS = ("platform", "stop", "stand", "bay", "wharf", "berth")

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
    api_key = os.environ.get("TFNSW_API_KEY")
    if not api_key:
        raise RuntimeError(
            "TFNSW_API_KEY environment variable is not set. "
            "Obtain a key from https://opendata.transport.nsw.gov.au and set it."
        )
    return {"Authorization": f"apikey {api_key}"}


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


async def _stop_finder_raw(query: str, type_sf: str = "any") -> list:
    """
    Hit the stop_finder endpoint and return filtered locations list.
    Shared by find_stops and its fuzzy-retry path.

    type_sf controls the TfNSW server-side search scope:
      "any"  – search all location types (addresses, localities, stops, POIs).
               Can return locality/suburb results that our type filter strips out.
      "stop" – search only for transit stops/platforms, avoiding locality noise.
    """
    params = {
        "outputFormat": "rapidJSON",
        "type_sf": type_sf,
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
                text = await resp.text()
                preview = text[:200] + ("…" if len(text) > 200 else "")
                raise RuntimeError(f"TfNSW API error {resp.status}: {preview}")
            data = await resp.json()

    all_locations = data.get("locations") or []
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


# Station names that share their name with a suburb/locality, causing the API to
# return non-station results when the bare name is queried.  For these queries we
# search with " station" appended *first* so the correct station is returned even
# when the API would otherwise rank a suburb or unrelated stop higher.
_PREFER_STATION_SUFFIX = frozenset({"central"})


async def find_stops(query: str, limit: int = 5) -> list[dict]:
    """
    Search for stops/stations by name.
    Returns list of dicts: {id, name, type, modes}
    """
    q_lower = query.strip().lower()

    # Pre-emptive station search: for names that are ambiguous with suburb/locality
    # names (e.g. "central"), always try "<name> station" first so the main station
    # is returned instead of an unrelated stop or locality.
    if q_lower in _PREFER_STATION_SUFFIX:
        locations = await _stop_finder_raw(query + " station")
        if not locations:
            locations = await _stop_finder_raw(query)
    else:
        locations = await _stop_finder_raw(query)

    # Fallback 1: retry with " station" appended, but only when the initial query
    # returned no transit stops at all.
    # Handles queries like "rhodes" where the API returns only cafes/POIs that are
    # filtered out, leaving locations empty.
    # We intentionally skip this when locations is already non-empty — appending
    # "station" for suburb names like "top ryde" would redirect to a different stop
    # (e.g. "top ryde station" → Ryde Station) instead of the correct bus stops.
    if not q_lower.endswith("station") and not locations:
        station_locs = await _stop_finder_raw(query + " station")
        if station_locs:
            locations = station_locs

    # Fallback 2: explicit stop-type search.
    # The TfNSW type_sf=any search ranks suburb/locality results highly for
    # well-known suburb names (e.g. "Central", "Rhodes"). Those locality entries
    # are filtered out by our type check, leaving locations empty even though the
    # actual train station exists. Using type_sf=stop forces the API to return
    # only transit stops, so the station appears at the top of results.
    if not locations:
        stop_locs = await _stop_finder_raw(query, type_sf="stop")
        if stop_locs:
            locations = stop_locs
        elif not q_lower.endswith("station"):
            # Also retry with the station suffix and type_sf=stop (mirrors Fallback 1
            # but with the stop-specific scope, which can surface stations that the
            # any-type search missed entirely).
            stop_station_locs = await _stop_finder_raw(query + " station", type_sf="stop")
            if stop_station_locs:
                locations = stop_station_locs

    # Fallback 3: fuzzy spelling correction for clear misspellings.
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

async def get_departures(
    stop_id: str,
    limit: int = 5,
    mode_filter: str | None = None,
    at_time: "datetime | None" = None,
) -> list[dict]:
    """
    Get upcoming departures from a stop.
    Returns list of dicts with: route, destination, planned, realtime, mins, delay, stop_name, mode, line_name
    mode_filter: '4' = trains only, '1' = buses, etc.
    at_time: optional departure window start (defaults to now).
    """
    query_time = at_time.astimezone(SYDNEY_TZ) if at_time else _sydney_now()
    # Fetch a larger buffer so client-side mode filtering still returns enough results
    fetch_limit = limit * 5 if mode_filter else limit * 2
    params = {
        "outputFormat": "rapidJSON",
        "coordOutputFormat": "EPSG:4326",
        "mode": "direct",
        "type_dm": "stop",
        "name_dm": stop_id,
        "depArrMacro": "dep",
        "itdDate": query_time.strftime("%Y%m%d"),
        "itdTime": query_time.strftime("%H%M"),
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

        # Platform identifier at this stop (e.g. "Platform 3", "Stand A")
        platform = ""
        disassembled_loc = location.get("disassembledName", "") or ""
        if disassembled_loc and any(
            disassembled_loc.lower().startswith(kw) for kw in _PLATFORM_KEYWORDS
        ):
            platform = disassembled_loc

        # Service origin — where this vehicle started its journey
        origin_name = (transport.get("origin") or {}).get("name", "") or ""

        # Cancellation flag
        cancelled = bool(ev.get("cancelledDeparture") or ev.get("isCancelled"))

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
            "platform": platform,
            "origin_name": origin_name,
            "cancelled": cancelled,
        })

        if len(departures) >= limit:
            break

    return departures


# ─── Trip leg helpers ─────────────────────────────────────────────────────────

def _extract_leg_stop_info(loc: dict) -> tuple[str, str, str]:
    """
    Extract (name, platform, suburb) from a trip leg origin/destination dict.

    ``platform`` is a label like "Platform 1" when the disassembledName or
    properties contain one.  ``suburb`` is the parent locality name.
    """
    name = loc.get("name", "")

    # Platform label from disassembledName when it looks like a platform
    dname = (loc.get("disassembledName") or "").strip()
    platform = ""
    if dname and any(dname.lower().startswith(kw) for kw in _PLATFORM_KEYWORDS):
        platform = dname
    if not platform:
        props = loc.get("properties") or {}
        platform = (props.get("PlatformName") or "").strip()

    # Suburb from parent locality
    parent = loc.get("parent") or {}
    suburb = (parent.get("name") or "").strip()

    return name, platform, suburb


def _find_current_stop_in_leg(stop_seq: list[dict]) -> str | None:
    """
    Return the name of the most recently departed stop in a transit leg's
    stop sequence, or None if the vehicle has not yet departed from any stop.

    Stops are compared against UTC now using timezone-aware datetime comparison,
    which correctly handles times in any offset (e.g. +11:00 vs UTC).
    """
    now = datetime.now(timezone.utc)
    last_name: str | None = None
    for stop in stop_seq:
        dep = stop.get("departure")
        if dep and dep < now:
            last_name = stop["name"]
        else:
            break
    return last_name


# ─── Trip Planner ─────────────────────────────────────────────────────────────

async def plan_trip(
    from_id: str,
    to_id: str,
    limit: int = 3,
    at_time: "datetime | None" = None,
) -> list[dict]:
    """
    Plan trips between two stop IDs.
    Returns list of trip dicts with legs, total duration, and departure time.

    ``at_time`` sets the requested departure time (Sydney-aware datetime).
    Defaults to now when not provided.
    """
    query_time = at_time.astimezone(SYDNEY_TZ) if at_time else _sydney_now()
    params = {
        "outputFormat": "rapidJSON",
        "coordOutputFormat": "EPSG:4326",
        "depArrMacro": "dep",
        "itdDate": query_time.strftime("%Y%m%d"),
        "itdTime": query_time.strftime("%H%M"),
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

                # Platform and suburb for origin and destination
                _from_name, platform_from, suburb_from = _extract_leg_stop_info(
                    leg.get("origin", {})
                )
                _to_name, platform_to, suburb_to = _extract_leg_stop_info(
                    leg.get("destination", {})
                )

                # Destination arrival time (real-time preferred)
                arr_rt_str = leg.get("destination", {}).get("arrivalTimeEstimated", "")
                arr_pl_str = leg.get("destination", {}).get("arrivalTimePlanned", "")
                arr_rt = _parse_tfnsw_time(arr_rt_str) if arr_rt_str else None
                arr_pl = _parse_tfnsw_time(arr_pl_str) if arr_pl_str else None
                leg_arrives = arr_rt or arr_pl

                # Parse stop sequence for real-time vehicle position
                raw_stops = leg.get("stopSequence", [])
                stop_seq: list[dict] = []
                for s in raw_stops:
                    dep_rt_s = _parse_tfnsw_time(s.get("departureTimeEstimated", ""))
                    dep_pl_s = _parse_tfnsw_time(s.get("departureTimePlanned", ""))
                    dep_s = dep_rt_s or dep_pl_s
                    s_name = s.get("name", "")
                    if s_name and dep_s:
                        stop_seq.append({
                            "name": s_name,
                            "departure": dep_s,
                            "is_realtime": dep_rt_s is not None,
                        })

                current_stop = _find_current_stop_in_leg(stop_seq)

                parsed_legs.append({
                    "mode": mode_id,
                    "icon": MODE_ICONS.get(mode_id, "🚌"),
                    "route": route_num,
                    "destination": dest,
                    "from": from_name,
                    "to": to_name,
                    "platform_from": platform_from,
                    "platform_to": platform_to,
                    "suburb_from": suburb_from,
                    "suburb_to": suburb_to,
                    "arrives": leg_arrives,
                    "departs": dep_dt,
                    "summary": f"{MODE_ICONS.get(mode_id, '🚌')} {route_num} → {dest}",
                    "current_stop": current_stop,
                    "stop_sequence": stop_seq,
                    "vehicle_id": transport.get("id", ""),
                })

        trips.append({
            "departs": display_dep,
            "planned_departs": first_dep,
            "arrives": last_arr,
            "duration_mins": duration_mins,
            "mins_until": _minutes_until(display_dep) if display_dep else None,
            "legs": parsed_legs,
            "num_legs": len([l for l in parsed_legs if l["mode"] != "walk"]),
            "is_realtime": rt_dep is not None,
        })

    return trips


# ─── Service Alerts ───────────────────────────────────────────────────────────

async def get_alerts(keywords: list[str] | None = None) -> list[dict]:
    """
    Fetch current service alerts from TfNSW and return only those relevant to
    the queried route or stop.

    ``keywords`` should contain stop names and route/line numbers (e.g.
    ["Central", "Rhodes", "T9"]).  Alerts whose title or body do not mention
    at least one keyword are suppressed.  Passing an empty list or None
    suppresses *all* alerts so generic system-wide notices never leak into
    unrelated queries.

    Returns list of dicts: {priority, title, body, url, is_replacement}
    """
    # No keywords → caller explicitly wants no alerts shown
    if not keywords:
        return []

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

    # Keep only alerts that mention at least one of the requested keywords.
    # Match against both title and body (case-insensitive).
    kw_lower = {k.strip().lower() for k in keywords if k and k.strip()}
    if kw_lower:
        relevant = [
            a for a in results
            if any(kw in (a["title"] + " " + a["body"]).lower() for kw in kw_lower)
        ]
    else:
        relevant = []

    high_priority = [a for a in relevant if a["priority"] in ("high", "veryHigh")]
    normal = [a for a in relevant if a["priority"] not in ("high", "veryHigh")]
    return (high_priority + normal)[:5]


# ─── Formatting helpers ────────────────────────────────────────────────────────

def format_departure_line(dep: dict, index: int | None = None) -> str:
    """Format a single departure into a compact line."""
    icon = MODE_ICONS.get(dep["mode"], "🚌")
    route = dep["route"]
    dest = dep["destination"]
    prefix = f"`{index}.` " if index is not None else ""

    if dep.get("cancelled"):
        return f"{prefix}{icon} ~~**{route}** → {dest}~~ 🚫 Cancelled"

    mins_str = _format_mins(dep["mins"])
    delay_str = ""
    if not dep["on_time"]:
        sign = "+" if dep["delay"] > 0 else ""
        delay_str = f" ⚠️ {sign}{dep['delay']}m"
    rt_indicator = " 🔴" if dep["realtime"] is not None else ""

    extras = []
    platform = dep.get("platform", "")
    if platform:
        extras.append(platform)
    origin = dep.get("origin_name", "")
    if origin:
        # Shorten to the principal name before any comma / "Station" suffix
        short = origin.split(",")[0].strip()
        short = short.replace(" Station", "").replace(" station", "").strip()
        if short:
            extras.append(f"↑ {short[:18]}")

    extras_str = (" · " + " · ".join(extras)) if extras else ""
    return f"{prefix}{icon} **{route}** → {dest} — {mins_str}{rt_indicator}{delay_str}{extras_str}"


def format_stop_stats(deps: list[dict]) -> str:
    """Return a compact one-line statistics string for a departure list."""
    if not deps:
        return ""
    total = len(deps)
    cancelled = sum(1 for d in deps if d.get("cancelled"))
    running = total - cancelled
    on_time_count = sum(1 for d in deps if d.get("on_time") and not d.get("cancelled"))
    rt_count = sum(1 for d in deps if d.get("realtime") is not None and not d.get("cancelled"))
    delay_vals = [
        d["delay"] for d in deps
        if d.get("realtime") is not None and not d.get("cancelled") and d["delay"] != 0
    ]

    parts = []
    if cancelled:
        parts.append(f"🚫 {cancelled} cancelled")
    if running > 0:
        parts.append(f"✅ {on_time_count}/{running} on time")
    if rt_count:
        parts.append(f"🔴 {rt_count} live")
    if delay_vals:
        avg = sum(delay_vals) / len(delay_vals)
        sign = "+" if avg > 0 else ""
        parts.append(f"avg {sign}{avg:.0f}m")
    return " · ".join(parts)


async def get_vehicle_position(from_id: str, to_id: str, scheduled_dep: str) -> dict | None:
    """
    Re-fetch the live position of a vehicle currently operating on the route
    from ``from_id`` to ``to_id``.

    ``scheduled_dep`` is the ISO-formatted planned departure time of the first
    leg — used to identify the specific service among multiple trips returned
    by the trip planner.

    Returns a dict with:
      current_stop  – name of the most recently departed stop (or None)
      current_idx   – 0-based index of current_stop in stop_sequence (or None)
      next_stop     – name of the next upcoming stop (or None)
      next_idx      – 0-based index of next_stop (or None)
      final_stop    – name of the terminus stop
      vehicle_id    – service/journey identifier string
      route         – route number (e.g. "T9")
      destination   – final destination name
      stop_sequence – list of {name, departure (datetime | None), is_realtime} dicts
    Returns None if the journey cannot be found.
    """
    try:
        target = datetime.fromisoformat(scheduled_dep)
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None

    # Query around the scheduled departure time so the API returns the specific
    # service even when it is already mid-journey.  Querying from "now" only
    # returns future departures and misses an in-progress trip entirely.
    trips = await plan_trip(from_id, to_id, limit=10, at_time=target)

    best_trip = None
    best_diff = timedelta(minutes=60)

    for trip in trips:
        planned = trip.get("planned_departs")
        if planned is None:
            continue
        try:
            # Ensure both sides are timezone-aware before subtracting
            p = planned if planned.tzinfo else planned.replace(tzinfo=timezone.utc)
            diff = abs(p - target)
        except TypeError:
            continue
        if diff < best_diff:
            best_diff = diff
            best_trip = trip

    if best_trip is None:
        return None

    transit_legs = [l for l in best_trip.get("legs", []) if l.get("mode") != "walk"]
    if not transit_legs:
        return None

    leg = transit_legs[0]
    stop_seq = leg.get("stop_sequence", [])

    current_stop = leg.get("current_stop")
    current_idx: int | None = None
    if current_stop:
        for i, s in enumerate(stop_seq):
            if s["name"] == current_stop:
                current_idx = i
                break

    now_utc = datetime.now(timezone.utc)
    next_stop: str | None = None
    next_idx: int | None = None
    for i, s in enumerate(stop_seq):
        dep = s.get("departure")
        if dep and dep.astimezone(timezone.utc) > now_utc:
            next_stop = s["name"]
            next_idx = i
            break

    final_stop = stop_seq[-1]["name"] if stop_seq else None

    return {
        "current_stop": current_stop,
        "current_idx": current_idx,
        "next_stop": next_stop,
        "next_idx": next_idx,
        "final_stop": final_stop,
        "vehicle_id": leg.get("vehicle_id", ""),
        "route": leg.get("route", ""),
        "destination": leg.get("destination", ""),
        "stop_sequence": stop_seq,
    }


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
