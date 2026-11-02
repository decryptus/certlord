import asyncio
import unittest
from unittest.mock import Mock
from textual.widgets import DataTable
from dwho.tui.textual import StatusLine
from certlord.client.textual_tui import CertificateApp
from certlord.client.api import ClientError

class CertificateUITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().set_debug(False)

    async def test_inventory_detail_and_unavailable_retains_stale_inventory(self):
        record = dict(certificate_id='11111111-1111-4111-8111-111111111111', domains=['demo.invalid'], status='active')
        client = Mock(); client.inventory.return_value = [record]; client.detail.return_value = record
        app = CertificateApp(client)
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertEqual(app.query_one(DataTable).row_count, 1)
            await pilot.press('enter'); await pilot.pause()
            client.detail.assert_called_once_with(record['certificate_id'])
            client.inventory.side_effect = ValueError('private credential')
            await pilot.press('r'); await pilot.pause()
            self.assertEqual(app.query_one(DataTable).row_count, 1)
            notice = app.query_one(StatusLine)
            self.assertEqual(notice.state, 'warning')
            self.assertNotIn('private credential', notice.render().plain)
            client.create.assert_not_called(); client.remove.assert_not_called()

    async def test_endpoint_view_does_not_probe_and_clears_on_failed_refresh(self):
        record = dict(name='web', status='stale', connect_host='192.0.2.10', port=443,
            server_name='demo.invalid', fresh=False, checked_at=1, last_status='verified',
            expected_fingerprint_sha256=None, observed_fingerprint_sha256='a'*64, error_code=None)
        client = Mock()
        client.tls_endpoints.return_value = dict(total=1, verified=0, endpoints=[record])
        app = CertificateApp(client, endpoints=True)
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertEqual(app.query_one(DataTable).row_count, 1)
            await pilot.press('enter'); await pilot.pause()
            client.inventory.assert_not_called()
            client.detail.assert_not_called()
            client.check_tls.assert_not_called()
            client.tls_endpoints.side_effect = ClientError('API unavailable')
            await pilot.press('r'); await pilot.pause()
            self.assertEqual(app.query_one(DataTable).row_count, 0)
            self.assertEqual(app.query_one(StatusLine).state, 'warning')
