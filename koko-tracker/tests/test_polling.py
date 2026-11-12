import os
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from requests.exceptions import ConnectTimeout


APP_DIR = Path(__file__).resolve().parents[1] / 'app'
with patch.object(sys, 'path', [str(APP_DIR), *sys.path]), \
        patch.object(sys, 'stdout', sys.stdout), patch.object(sys, 'stderr', sys.stderr), \
        patch.dict(os.environ, {'SECRET_KEY': 'test-secret'}):
    import app as tracker


class StopPolling(BaseException):
    pass


class PollingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        db = patch.object(tracker, 'DB_PATH', str(Path(temp.name) / 'tracker.db'))
        db.start()
        self.addCleanup(db.stop)
        cache = patch.object(tracker, '_token_cache', {})
        cache.start()
        self.addCleanup(cache.stop)
        tracker.init_db()

    def test_direct_koko_qr_links_skip_request_to_scanned_host(self):
        client = tracker.app.test_client()
        balance = {'cash_balance': 5}
        for host in ('estore.kokoamusement.com.au', 'customer.kokoamusement.com.au'):
            with self.subTest(host=host), \
                    patch.object(tracker, 'get_current_user', return_value={'id': 1}), \
                    patch.object(tracker.requests, 'get') as get, \
                    patch.object(tracker, 'fetch_koko_balance', return_value=balance) as fetch_balance:
                url = f'https://{host}/BalanceMobile/BalanceMobile.aspx?locale=en&i=example-token#details'
                response = client.post('/api/cards/resolve-qr', json={'url': url})

                get.assert_not_called()
                fetch_balance.assert_called_once_with('example-token')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json(), {'success': True, 'token': 'example-token', 'balance': balance})

    def test_koko_timeout_defers_other_koko_cards_and_polling_recovers(self):
        with closing(tracker.get_db()) as conn, conn:
            conn.execute("INSERT INTO users (id, username, password_hash) VALUES (1, 'user', 'unused')")
            conn.executemany(
                'INSERT INTO cards (id, user_id, card_type, card_token, card_number, poll_interval) '
                'VALUES (?, 1, ?, ?, ?, 20)',
                [(1, None, 'koko-1', None), (2, 'koko', 'koko-2', None),
                 (3, 'timezone', 'timezone-3', '123')],
            )
            conn.execute('INSERT INTO balance_history (card_id, cash_balance) VALUES (1, 4)')
            conn.execute(
                "INSERT INTO timezone_sessions (user_id, bearer_token, token_expires_at) "
                "VALUES (1, 'bearer', '2099-01-01 00:00:00')"
            )

        now = 0
        attempts = []

        def fetch_koko(token, *, raise_connect_timeout=False):
            attempts.append((now, token, raise_connect_timeout))
            if len(attempts) == 1:
                raise ConnectTimeout()
            return {'cash_balance': 5}

        def advance_clock(_seconds):
            nonlocal now
            if now == 20:
                raise StopPolling()
            now += 10

        clock = SimpleNamespace(monotonic=lambda: now, sleep=advance_clock)
        guest = {'cards': [{'number': '123', 'cashBalance': 7}]}
        with patch.object(tracker, 'time', clock), \
                patch.object(tracker, 'is_koko_quiet_hour', return_value=False), \
                patch.object(tracker, 'fetch_koko_balance', side_effect=fetch_koko), \
                patch.object(tracker, 'fetch_timezone_guest', return_value=guest) as fetch_timezone, \
                patch.object(tracker, '_store_timezone_transactions'):
            with self.assertRaises(StopPolling):
                tracker.poll_cards('koko')
            fetch_timezone.assert_not_called()
            with self.assertRaises(StopPolling):
                tracker.poll_cards('timezone')
            fetch_timezone.assert_called_once_with('bearer', {}, user_id=1)

        self.assertEqual(attempts, [(0, 'koko-1', True), (10, 'koko-2', True), (20, 'koko-1', True)])
        with closing(tracker.get_db()) as conn:
            self.assertEqual(
                [tuple(row) for row in conn.execute('SELECT card_id, cash_balance FROM balance_history ORDER BY id')],
                [(1, 4), (2, 5), (1, 5), (3, 7)],
            )
            self.assertEqual(
                [tuple(row) for row in conn.execute('SELECT card_id, success FROM poll_log ORDER BY id')],
                [(1, 0), (2, 1), (1, 1), (3, 1)],
            )

    def test_timezone_refresh_checks_provider_even_after_estimated_expiry(self):
        with closing(tracker.get_db()) as conn, conn:
            conn.executemany(
                'INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)',
                [(1, 'legacy', 'unused'), (2, 'transient', 'unused'), (3, 'expired', 'unused')],
            )
            conn.executemany(
                "INSERT INTO timezone_sessions "
                "(user_id, bearer_token, refresh_token, token_expires_at, session_expires_at, last_poll_status) "
                "VALUES (?, 'old-bearer', ?, '2000-01-01 00:00:00', '2000-01-02 00:00:00', ?)",
                [(1, 'refreshable', None), (2, 'transient', 'ok'), (3, 'expired', 'ok')],
            )

        outcomes = {
            'refreshable': ('new-bearer', 'new-refresh', 840),
            'transient': (None, None, None),
            'expired': (tracker.TZ_REFRESH_TOKEN_EXPIRED, None, None),
        }
        refresh = Mock(side_effect=lambda token, _client_id: outcomes[token])
        with patch.object(tracker, 'tz_refresh_ms_token', refresh):
            tracker._refresh_tz_tokens('Test')

        self.assertCountEqual([call.args[0] for call in refresh.call_args_list], outcomes.keys())
        with closing(tracker.get_db()) as conn:
            sessions = conn.execute('SELECT * FROM timezone_sessions ORDER BY user_id').fetchall()
        self.assertEqual(tracker.tz_session_status(sessions[0]), 'connected')
        self.assertEqual([(row['bearer_token'], row['refresh_token'], row['last_poll_status']) for row in sessions], [
            ('new-bearer', 'new-refresh', 'ok'),
            ('old-bearer', 'transient', 'error'),
            (None, None, 'needs_reconnect'),
        ])
