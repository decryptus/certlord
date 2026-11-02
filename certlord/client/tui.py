"""Read-only certificate browser, entered explicitly from a real terminal."""
import curses
from dwho.tui import put, view_details
from certlord.client.api import ClientError
from certlord.services.certificate_ids import short_ids
from certlord.client.presentation import destination_lines, endpoint_lines


def browse(screen, client, endpoints=False):
    records, selection, message = [], 0, ''

    def refresh():
        nonlocal records, selection, message
        try:
            records = client.tls_endpoints()['endpoints'] if endpoints else client.inventory()
            selection = min(selection, max(0, len(records) - 1))
            message = ''
        except ClientError as error:
            if endpoints:
                records = []
            message = str(error)

    refresh()
    while True:
        screen.erase()
        put(screen, 0, 'CertLord | Enter: details | r: refresh | q: quit')
        height, _width = screen.getmaxyx()
        capacity = max(1, height - 3)
        start = max(0, selection - capacity + 1)
        ids = {} if endpoints else short_ids(records)
        for row, record in enumerate(records[start:start + capacity], 1):
            label = ('%s  %s  %s' % (record['name'], record['status'], record['server_name']) if endpoints else
                     '%s  %s  %s' % (', '.join(record['domains']), record['status'], ids[record['certificate_id']]))
            put(screen, row, label, curses.A_REVERSE if start + row - 1 == selection else 0)
        if height > 1:
            put(screen, height - 1, message or (('No TLS endpoints' if endpoints else 'No managed certificates') if not records else ''))
        screen.refresh()
        key = screen.getch()
        if key in (ord('q'), 27):
            return
        if key == ord('r'):
            refresh()
        elif key == curses.KEY_UP:
            selection = max(0, selection - 1)
        elif key == curses.KEY_DOWN:
            selection = min(max(0, len(records) - 1), selection + 1)
        elif key in (10, 13, curses.KEY_ENTER) and records:
            try:
                if endpoints:
                    record = records[selection]
                    view_details(screen, record['name'], endpoint_lines(record))
                    continue
                record = client.detail(records[selection]['certificate_id'])
                view_details(screen, ', '.join(record['domains']),
                             ['UUID: ' + record['certificate_id'], 'Status: ' + record['status']]
                             + destination_lines(record))
            except ClientError as error:
                message = str(error)


def run(client, endpoints=False):
    curses.wrapper(browse, client, endpoints)
