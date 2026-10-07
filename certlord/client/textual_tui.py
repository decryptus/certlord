"""Optional certificate browser over the existing HTTP client."""
import json

from dwho.tui.textual import DetailPanel, ServiceDashboard, TableRow
from textual.widgets import DataTable

from certlord.client.api import ClientError
from certlord.services.certificate_ids import short_ids


class CertificateApp(ServiceDashboard):
    BINDINGS = ServiceDashboard.BINDINGS + [('r', 'refresh', 'Refresh')]

    def __init__(self, client, demo=False):
        super().__init__(product='CertLord', heading='Managed certificates',
                         columns=('DOMAINS', 'STATUS', 'CERTIFICATE'),
                         navigation=(('certificates', 'Certificates'),),
                         subtitle='SYNTHETIC DEMO' if demo else 'CERTIFICATE INVENTORY')
        self.client, self.records = client, {}

    def on_mount(self):
        self.action_refresh()

    def failure(self, error):
        self.set_notice('warning', str(error) if isinstance(error, ClientError) else 'Certificate service unavailable.')
        self.set_activity('Displayed inventory may be stale. Press r to retry the read.')

    def action_refresh(self):
        self.perform(self.client.inventory, self.loaded, self.failure)

    def loaded(self, records):
        ids = short_ids(records)
        self.records = {record['certificate_id']: record for record in records}
        self.display_rows([TableRow(record['certificate_id'],
            (', '.join(record['domains']), record['status'], ids[record['certificate_id']]),
            ', '.join(record['domains']), json.dumps(record, indent=2)) for record in records])
        self.set_notice('info', '%s managed certificates' % len(records))
        self.set_activity('Enter reads certificate details. Inventory and detail reads do not issue or remove certificates.')

    def on_data_table_row_selected(self, event):
        identity = event.row_key.value
        if identity not in self.records:
            return
        self.perform(lambda: self.client.detail(identity), self.detail_loaded, self.failure)

    def detail_loaded(self, record):
        self.query_one(DetailPanel).show_details(', '.join(record['domains']), json.dumps(record, indent=2))
        self.set_notice('info', 'Certificate details loaded.')


def run(client):
    CertificateApp(client).run()
