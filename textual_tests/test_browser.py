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
