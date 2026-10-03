"""Use Auton's structured single-job CLI protocol without forwarding output."""
import json
import re
import time
from urllib.parse import urlsplit
from certlord.adapters.processes import CommandRunner, CommandInterrupted, CommandTimeout


class InvalidReceipt(ValueError):
    pass


def receipt_target(uri, endpoint, args):
    # Restrict this opt-in contract to one destination and execution mode. Do not
    # let arbitrary CLI flags override identity, output format or submit targets.
    parsed = urlsplit(uri)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ('', '/')
            or not isinstance(endpoint, str)
            or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', endpoint) is None):
        raise ValueError('Receipt mode requires one plain HTTP origin and endpoint')
    if len(args) % 2 or any(args[i] not in ('--http-timeout', '--delay') for i in range(0, len(args), 2)):
        raise ValueError('Receipt mode only supports --http-timeout and --delay overrides')
    return {'origin': uri.rstrip('/'), 'endpoint': endpoint}


def run_receipted(runner, command, attempt_id, notify):
    target = command['receipt_target']
    expected = target['endpoint'] + ':' + attempt_id
    deadline = time.monotonic() + runner.timeout
    mode = 'run'
    observed_state = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CommandTimeout('Auton receipt deadline exceeded')
        bounded = CommandRunner(runner.stop_event, remaining, runner.grace)
        code, output, _ = bounded.run(command['args'] + ['--mode', mode, '--uid', attempt_id], command['env'])
        try:
            if not isinstance(output, bytes) or len(output) > 4 * 1024 * 1024:
                raise ValueError()
            result = json.loads(output)
            if (not isinstance(result, dict) or result.get('uid') != expected
                    or type(result.get('code')) is not int or result['code'] not in (200, 400)
                    or result.get('status') not in ('new', 'processing', 'complete')):
                raise ValueError()
            complete = result['status'] == 'complete'
            return_code = result.get('return_code')
            if complete and type(return_code) is not int:
                raise ValueError()
            if not complete and (code != 0 or result['code'] != 200 or return_code is not None):
                raise ValueError()
            if complete and (code not in (0, 1) or bool(code) != (result['code'] != 200)):
                raise ValueError()
        except (ValueError, TypeError, UnicodeError):
            raise InvalidReceipt('Auton returned no valid matching job receipt') from None
        # Metadata is constructed from trusted target and matching response identity.
        receipt = dict(target, uid=expected, status=result['status'], return_code=return_code)
        if receipt['status'] != observed_state:
            notify(receipt)
            observed_state = receipt['status']
        if complete:
            # Reject uncertain/interrupted completion even if a provider reports 0.
            successful = (return_code == 0 and result['code'] == 200
                          and not result.get('execution_uncertain')
                          and result.get('outcome') not in ('job.interrupted', 'job.cancelled'))
            return (0 if successful else 1), receipt
        mode = 'status'  # Never resubmit after a missing, failed or ambiguous read.
        if runner.stop_event.wait(min(1.0, max(0, deadline - time.monotonic()))):
            raise CommandInterrupted('Worker stopping')
