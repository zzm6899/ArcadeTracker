"""
Data Layer — all external API interaction is contained here.
No business logic; callers receive structured dicts/lists and handle decisions.

Environment variables:
  TFNSW_API_KEY  — TfNSW Open Data API key (required in production)
"""

from __future__ import annotations

import os
from datetime import datetime


class APIService:
    """Handles all interaction with external transport APIs (TfNSW or mocks)."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("TFNSW_API_KEY", "")
        if not self.api_key:
            print("WARNING: No API key provided. Using mock responses only.")
        print("APIService initialized.")

    # ── Unit 1: live position ─────────────────────────────────────────────────

    def get_vehicle_position(self, trip_id: str, current_time: str) -> dict | None:
        """
        Fetch live vehicle location for *trip_id*.

        Returns a dict with keys:
          lat (float), lon (float), timestamp (str ISO-8601),
          stop_id (str | None), bearing (float | None), speed_kmh (float | None).
        Returns None when the trip is not found or the API is unreachable.
        """
        print(f"APIService.get_vehicle_position: trip={trip_id} at {current_time}")
        # Mock — replace with real GTFS-RT / TfNSW vehicle-position call.
        return {
            "lat": -33.8688,
            "lon": 151.2093,
            "timestamp": current_time,
            "stop_id": "200060",
            "bearing": 180.0,
            "speed_kmh": 40.0,
        }

    def get_scheduled_stop_time(self, trip_id: str, stop_id: str) -> dict | None:
        """
        Return the scheduled arrival/departure time for *stop_id* on *trip_id*.

        Returns a dict with keys:
          scheduled_arrival (str ISO-8601), scheduled_departure (str ISO-8601),
          stop_name (str), stop_sequence (int).
        Returns None when the stop is not part of this trip.
        """
        print(f"APIService.get_scheduled_stop_time: trip={trip_id} stop={stop_id}")
        return {
            "scheduled_arrival": "2026-04-06T14:30:00+10:00",
            "scheduled_departure": "2026-04-06T14:31:00+10:00",
            "stop_name": "Town Hall",
            "stop_sequence": 12,
        }

    # ── Unit 2: trip planning ─────────────────────────────────────────────────

    def plan_trip(
        self,
        from_id: str,
        to_id: str,
        target_datetime: datetime | None = None,
    ) -> list[dict]:
        """
        Plan a journey from *from_id* to *to_id*.

        *target_datetime* anchors the search; defaults to current time when None.

        Each leg dict contains:
          mode (str), line (str), headsign (str),
          dep_stop (str), dep_time (str ISO-8601),
          arr_stop (str), arr_time (str ISO-8601),
          duration_min (int), platform (str | None).
        """
        anchor = target_datetime.isoformat() if target_datetime else "now"
        print(f"APIService.plan_trip: {from_id} -> {to_id} anchored at {anchor}")
        return [
            {
                "mode": "Train",
                "line": "T1 North Shore",
                "headsign": "Berowra",
                "dep_stop": "Central",
                "dep_time": "2026-04-06T14:35:00+10:00",
                "arr_stop": "Town Hall",
                "arr_time": "2026-04-06T14:38:00+10:00",
                "duration_min": 3,
                "platform": "Platform 3",
            },
            {
                "mode": "Bus",
                "line": "333",
                "headsign": "Bondi Beach",
                "dep_stop": "Town Hall",
                "dep_time": "2026-04-06T14:45:00+10:00",
                "arr_stop": "Bondi Beach",
                "arr_time": "2026-04-06T15:10:00+10:00",
                "duration_min": 25,
                "platform": None,
            },
        ]

    # ── Unit 3: live delay ────────────────────────────────────────────────────

    def get_live_arrival(self, trip_id: str, stop_id: str) -> dict | None:
        """
        Return the real-time predicted arrival for *stop_id* on *trip_id*.

        Returns a dict with keys:
          predicted_arrival (str ISO-8601), predicted_departure (str ISO-8601),
          delay_seconds (int) — positive = late, negative = early.
        Returns None when no real-time data is available.
        """
        print(f"APIService.get_live_arrival: trip={trip_id} stop={stop_id}")
        return {
            "predicted_arrival": "2026-04-06T14:35:00+10:00",
            "predicted_departure": "2026-04-06T14:36:00+10:00",
            "delay_seconds": 300,
        }

    # ── Unit 4: service alerts ────────────────────────────────────────────────

    def get_service_alerts(self) -> list[dict]:
        """
        Fetch all active system-wide service alerts.

        Each alert dict contains:
          id (str), severity (str: INFO|WARNING|SEVERE),
          affected_lines (list[str]), header (str), description (str),
          start_time (str ISO-8601 | None), end_time (str ISO-8601 | None).
        """
        print("APIService.get_service_alerts")
        return [
            {
                "id": "ALT-001",
                "severity": "WARNING",
                "affected_lines": ["T1", "T2"],
                "header": "Signal fault at Central",
                "description": (
                    "All T1 and T2 services are subject to delays of up to 15 minutes "
                    "due to a signal fault near Central Station."
                ),
                "start_time": "2026-04-06T13:00:00+10:00",
                "end_time": None,
            },
            {
                "id": "ALT-002",
                "severity": "INFO",
                "affected_lines": ["333"],
                "header": "Route 333 diversion",
                "description": (
                    "Route 333 buses are diverting via Oxford St "
                    "due to a road closure on Anzac Parade."
                ),
                "start_time": "2026-04-06T08:00:00+10:00",
                "end_time": "2026-04-06T18:00:00+10:00",
            },
        ]

    # ── Departures board ──────────────────────────────────────────────────────

    def get_departures(self, stop_id: str, limit: int = 8) -> list[dict]:
        """
        Return the next *limit* departures for *stop_id*.

        Each departure dict contains:
          mode (str), line (str), headsign (str),
          dep_time (str ISO-8601), platform (str | None),
          delay_seconds (int).
        Returns an empty list when the stop is unknown or the API is unreachable.
        """
        print(f"APIService.get_departures: stop={stop_id} limit={limit}")
        # Mock — replace with TfNSW departure_mon endpoint.
        return [
            {
                "mode": "Train",
                "line": "T1 North Shore",
                "headsign": "Gordon",
                "dep_time": "2026-04-06T14:32:00+10:00",
                "platform": "Platform 1",
                "delay_seconds": 0,
            },
            {
                "mode": "Train",
                "line": "T1 North Shore",
                "headsign": "Berowra",
                "dep_time": "2026-04-06T14:37:00+10:00",
                "platform": "Platform 3",
                "delay_seconds": 120,
            },
            {
                "mode": "Bus",
                "line": "431",
                "headsign": "Balmain",
                "dep_time": "2026-04-06T14:40:00+10:00",
                "platform": None,
                "delay_seconds": -60,
            },
        ][:limit]

    # ── Stop search ───────────────────────────────────────────────────────────

    def find_stops(self, query: str, limit: int = 5) -> list[dict]:
        """
        Search for stops matching *query* (fuzzy name search).

        Each result dict contains:
          id (str), name (str), type (str: stop|station|wharf),
          modes (list[str]) — list of mode codes served.
        Returns an empty list when nothing matches.
        """
        print(f"APIService.find_stops: query={query!r} limit={limit}")
        # Mock — replace with TfNSW stop_finder endpoint.
        results = [
            {"id": "200060", "name": "Town Hall Station", "type": "station", "modes": ["1", "2"]},
            {"id": "200070", "name": "Wynyard Station",   "type": "station", "modes": ["1", "2"]},
            {"id": "200010", "name": "Central Station",   "type": "station", "modes": ["1", "5"]},
            {"id": "2000446", "name": "Circular Quay",    "type": "wharf",   "modes": ["9", "1"]},
            {"id": "200811", "name": "Bondi Junction",    "type": "station", "modes": ["1"]},
        ]
        q = query.lower()
        filtered = [r for r in results if q in r["name"].lower()]
        return filtered[:limit] or results[:limit]
