"""Non-interactive commands; curses is loaded only by the explicit tui command."""
import argparse
import os
import sys
from dwho.cli import require_terminal, write_json
from certlord.client.api import CertificateClient, ClientError
from certlord.services.certificate_ids import resolve_certificate, short_ids

COMMANDS = ('list', 'show', 'create', 'remove', 'import', 'replace', 'tui')


def parser():
    result = argparse.ArgumentParser(prog='certlord', description='Certificate management over HTTP')
    subparsers = result.add_subparsers(dest='command', required=True)
    for command in COMMANDS:
        sub = subparsers.add_parser(command)
        sub.add_argument('--url', default=os.environ.get('CERTLORD_API_URL', 'http://127.0.0.1:8666'))
        sub.add_argument('--ca', default=os.environ.get('CERTLORD_API_CA') or True, help='Trusted CA bundle')
        sub.add_argument('--timeout', type=float, default=10)
        if command != 'tui':
            sub.add_argument('--json', action='store_true', help='Full UUIDs, machine-readable output')
        if command == 'list':
            sub.add_argument('--full-id', action='store_true')
        if command in ('show', 'remove', 'replace'):
            sub.add_argument('selector', help='Domain, full UUID or unambiguous UUID prefix (8+ characters)')
        if command in ('create', 'import'):
            sub.add_argument('domain')
        if command == 'replace':
            sub.add_argument('--expected-version', type=int, required=True, help='Version read from certlord show --json')
        if command in ('import', 'replace'):
            sub.add_argument('--cert-file', required=True)
            sub.add_argument('--key-file', required=True)
            sub.add_argument('--chain-file')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    client = None
    try:
        if args.command == 'tui':
            require_terminal('The TUI requires an interactive terminal; use certlord list --json in scripts')
        client = CertificateClient(args.url, os.environ.get('CERTLORD_API_USER'),
                                   os.environ.get('CERTLORD_API_PASSWORD'), args.ca, args.timeout)
        if args.command == 'tui':
            from certlord.client.tui import run
            run(client)
            return 0
        if args.command == 'list':
            value = client.inventory()
        elif args.command in ('import', 'replace'):
            def read_pem(path, limit):
                if not path:
                    return ''
                try:
                    with open(path, encoding='ascii') as source:
                        value = source.read(limit + 1)
                except (OSError, UnicodeError):
                    raise ValueError('Cannot read PEM input file') from None
                if len(value) > limit:
                    raise ValueError('PEM input exceeds size limit')
                return value
            if args.command == 'replace' and args.expected_version <= 0:
                raise ValueError('Expected version must be positive')
            material = (read_pem(args.cert_file, 65536), read_pem(args.key_file, 65536), read_pem(args.chain_file, 262144))
            if args.command == 'replace':
                identity = resolve_certificate(args.selector, client.inventory())
                value = client.replace_import(identity, args.expected_version, *material)
            else:
                value = client.import_certificate(args.domain, *material)
        elif args.command == 'create':
            value = client.create(args.domain)
        else:
            identity = resolve_certificate(args.selector, client.inventory())
            value = client.detail(identity) if args.command == 'show' else client.remove(identity)
        if args.json:
            write_json(value, sort_keys=True)
        elif args.command == 'list':
            ids = short_ids(value)
            for record in value:
                identity = record['certificate_id'] if args.full_id else ids[record['certificate_id']]
                print('%s  %s  %s' % (identity, ', '.join(record['domains']), record['status']))
        elif args.command == 'remove':
            print('Removal requested: %s' % value['certificate_id'])
        else:
            suffix = '  version=%s' % value['version'] if 'version' in value else ''
            print('%s  %s  %s%s' % (value['certificate_id'], ', '.join(value['domains']), value['status'], suffix))
        return 0
    except (ClientError, ValueError) as error:
        print('certlord: %s' % error, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if client is not None:
            client.close()


if __name__ == '__main__':
    sys.exit(main())
