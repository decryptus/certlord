"""Durable writer safety; every certificate and provider boundary is synthetic."""
from copy import deepcopy
import io
import json
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from certlord.cloudfront.config import JobError, bind, endpoint_name, profile_digest
from certlord.cloudfront.job import main, read_private
from certlord.cloudfront.ledger import Ledger
from certlord.cloudfront.material import current_material, compatible, material_digest
from certlord.cloudfront.writer import Renewal
from certlord.services.deployment import certificate_generation
from import_fixture import material

IDENTITY = '11111111-2222-4333-8444-555555555555'
ARN = 'arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555'


def profile(directory):
    return {'target': {'account_id': '123456789012', 'distribution_id': 'E123EXAMPLE',
        'certificate_arn': ARN, 'domain': 'import.example.test'}, 'certificate_id': IDENTITY,
        'destination': 'cloudfront', 'state_dir': str(directory), 'poll_interval': 1,
        'propagation_timeout': 5, 'vault': {'url': 'https://vault.example.test', 'mount': 'secret',
        'key_name': 'certificates', 'role_id_file': '/private/role', 'secret_id_file': '/private/secret',
        'ca_file': None}}


def snapshot(record):
    leaf = x509.load_pem_x509_certificate(record['cert'].encode())
    return {'leaf': leaf, 'host': 'synthetic.cloudfront.net',
            'fingerprint': leaf.fingerprint(hashes.SHA256()).hex(),
            'material_sha256': material_digest(leaf, record['chain'])}


class Provider:
    def __init__(self, record):
        self.record = record
        self.calls = 0
        self.fail = False
        self.after_import = lambda: None

    def read(self):
        return snapshot(self.record)

    def reimport(self, candidate):
        self.calls += 1
        self.record = candidate
        self.after_import()
        if self.fail:
            raise TimeoutError('sensitive provider exception must never escape')


class Clock:
    def __init__(self): self.now = 1000
    def __call__(self): return self.now
    def is_set(self): return False
    def wait(self, duration): self.now += duration


def killed_writer(directory, record, ready):
    """SIGKILL cannot execute Python exception handling or release logic."""
    p = profile(directory)
    provider = Provider(dict(material(offset=1), status='generated'))
    def blocked():
        ready.set()
        threading.Event().wait()
    provider.after_import = blocked
    ledger = Ledger(directory)
    Renewal(p, profile_digest(p), ledger, lambda: record, provider, None,
            threading.Event()).run(certificate_generation(record))


class CloudFrontWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile = profile(self.root)
        self.digest = profile_digest(self.profile)
        self.record = dict(material(offset=1), status='generated')
        self.generation = certificate_generation(self.record)
        self.provider = Provider(dict(material(offset=1), status='generated'))
        self.ledger = Ledger(self.root)
        self.addCleanup(self.ledger.close)
        self.clock = Clock()
        self.verify = Mock(side_effect=lambda _record, seen: {
            'status': 'verified', 'observed_fingerprint_sha256': seen['fingerprint']})

    def engine(self):
        return Renewal(self.profile, self.digest, self.ledger, lambda: self.record,
            self.provider, self.verify, self.clock, clock=self.clock, monotonic=self.clock)

    def test_import_once_then_restart_rechecks_tls_without_importing(self):
        result = self.engine().run(self.generation)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(self.provider.calls, 1)
        self.clock.now += 100
        self.assertEqual(self.engine().run(self.generation)['intent_id'], result['intent_id'])
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(self.verify.call_count, 2)
        self.assertNotIn('PRIVATE KEY', json.dumps(self.ledger.read(ARN)))

    def test_already_installed_material_requires_live_tls_without_import(self):
        self.provider.record = self.record
        self.engine().run(self.generation)
        self.assertEqual(self.provider.calls, 0)
        self.verify.assert_called_once()

    def test_candidate_root_is_stripped_without_changing_source_generation(self):
        _, candidate, _ = current_material(lambda: self.record, self.generation, self.record['domain'])
        self.assertEqual(candidate['chain'], '')
        self.assertEqual(certificate_generation(self.record), self.generation)
        self.assertEqual(candidate['material_sha256'], snapshot(self.record)['material_sha256'])

    def test_same_leaf_but_different_intermediate_is_not_accepted(self):
        # Digest includes the ordered intermediate chain, not only the leaf.
        different = material(offset=1)['cert']
        leaf = snapshot(self.record)['leaf']
        self.assertNotEqual(material_digest(leaf, different), material_digest(leaf, ''))
        self.provider.read = Mock(return_value=dict(snapshot(self.record), material_sha256='0' * 64))
        with self.assertRaisesRegex(JobError, '^propagation_deadline$'):
            self.engine().run(self.generation)
        self.assertEqual(self.provider.calls, 1)
        self.verify.assert_not_called()

    def test_deleted_or_superseded_source_cannot_write(self):
        for change in ({'status': 'removed'}, {'cert': 'replacement'}):
            with self.subTest(change=change):
                original = self.record
                self.record = dict(original, **change)
                with self.assertRaisesRegex(JobError, '^superseded_generation$'):
                    self.engine().run(self.generation)
                self.record = original
        self.assertEqual(self.provider.calls, 0)

    def test_invalid_key_and_short_lived_candidate_cannot_write(self):
        self.record['key'] = material()['key']
        with self.assertRaisesRegex(JobError, '^invalid_candidate_material$'):
            self.engine().run(self.generation)
        self.assertEqual(self.provider.calls, 0)
        record = dict(material(), status='generated')
        with self.assertRaisesRegex(JobError, '^candidate_expires_too_soon$'):
            current_material(lambda: record, certificate_generation(record), record['domain'], 172800)

    def test_changed_key_type_cannot_reimport(self):
        self.record = dict(material(offset=1, key=ec.generate_private_key(ec.SECP384R1())), status='generated')
        with self.assertRaisesRegex(JobError, '^reimport_key_type_changed$'):
            self.engine().run(certificate_generation(self.record))
        self.assertEqual(self.provider.calls, 0)

    def test_generation_changed_during_import_cannot_be_verified(self):
        def replace(): self.record = dict(material(offset=1), status='generated')
        self.provider.after_import = replace
        with self.assertRaisesRegex(JobError, '^superseded_generation$'):
            self.engine().run(self.generation)
        self.assertEqual(self.ledger.read(ARN)['state'], 'accepted')
        self.verify.assert_not_called()
        self.provider.after_import = lambda: None
        self.engine().run(certificate_generation(self.record))
        self.assertEqual(self.provider.calls, 2)

    def test_generation_changed_during_tls_cannot_be_verified(self):
        def replace(_record, seen):
            self.record = dict(material(offset=1), status='generated')
            return {'status': 'verified', 'observed_fingerprint_sha256': seen['fingerprint']}
        self.verify.side_effect = replace
        with self.assertRaisesRegex(JobError, '^superseded_generation$'):
            self.engine().run(self.generation)
        self.assertEqual(self.ledger.read(ARN)['state'], 'accepted')

    def test_lost_reply_quarantines_matching_readback_and_new_profile_and_generation(self):
        self.provider.fail = True
        with self.assertRaisesRegex(JobError, '^import_outcome_uncertain$'):
            self.engine().run(self.generation)
        self.assertEqual(self.ledger.read(ARN)['state'], 'quarantined')
        self.assertEqual(self.provider.read()['fingerprint'], snapshot(self.record)['fingerprint'])
        self.record = dict(material(offset=1), status='generated')
        self.profile['poll_interval'] = 2
        self.digest = profile_digest(self.profile)
        with self.assertRaisesRegex(JobError, '^arn_quarantined$'):
            self.engine().run(certificate_generation(self.record))
        self.assertEqual(self.provider.calls, 1)

    def test_reconciliation_requires_matching_intent_fingerprint_and_explicit_quiescence(self):
        self.provider.fail = True
        with self.assertRaises(JobError): self.engine().run(self.generation)
        entry = self.ledger.read(ARN)
        fingerprint = self.provider.read()['fingerprint']
        for intent, fp, ack in ((entry['intent_id'], fingerprint, False),
                                ('wrong', fingerprint, True), (entry['intent_id'], '0' * 64, True)):
            with self.subTest(intent=intent, ack=ack), self.assertRaises(JobError):
                self.engine().reconcile(intent, fp, ack)
        self.engine().reconcile(entry['intent_id'], fingerprint, True)
        self.provider.fail = False
        self.engine().run(self.generation)
        self.assertEqual(self.provider.calls, 1)  # observed installed material, only TLS

    def test_timeout_and_bad_tls_never_trigger_a_second_import(self):
        self.verify.side_effect = None
        for result in ({'status': 'verified'}, {'status': 'verified', 'observed_fingerprint_sha256': '0' * 64},
                       {'status': 'pending'}):
            self.verify.return_value = result
            with self.assertRaisesRegex(JobError, '^propagation_deadline$'):
                self.engine().run(self.generation)
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(self.ledger.read(ARN)['state'], 'accepted')
        self.verify.return_value = {'status': 'verified', 'observed_fingerprint_sha256': snapshot(self.record)['fingerprint']}
        self.engine().run(self.generation)
        self.assertEqual(self.provider.calls, 1)

    def test_sigkill_leaves_durable_intent_and_no_replay_after_lock_release(self):
        context = multiprocessing.get_context('spawn')
        ready = context.Event()
        process = context.Process(target=killed_writer, args=(str(self.root), self.record, ready))
        process.start()
        try:
            self.assertTrue(ready.wait(10))
            with self.assertRaisesRegex(JobError, '^arn_busy$'):
                self.engine().run(self.generation)
            os.kill(process.pid, signal.SIGKILL)
            process.join(10)
            self.assertEqual(process.exitcode, -signal.SIGKILL)
            self.assertEqual(self.ledger.read(ARN)['state'], 'sending')
            with self.assertRaisesRegex(JobError, '^arn_quarantined$'):
                self.engine().run(self.generation)
            self.assertEqual(self.provider.calls, 0)
        finally:
            if process.is_alive(): process.kill()
            process.join(10)

    def test_profile_digest_pins_all_selectors_and_changes_endpoint(self):
        selectors = [IDENTITY, self.record['domain'], self.generation, 'cloudfront']
        self.assertEqual(bind(self.profile, self.digest, selectors), self.generation)
        for index in range(4):
            wrong = list(selectors)
            wrong[index] = 'wrong'
            with self.assertRaises(JobError): bind(self.profile, self.digest, wrong)
        changed = deepcopy(self.profile)
        changed['target']['distribution_id'] = 'EOTHER'
        self.assertNotEqual(endpoint_name(changed), endpoint_name(self.profile))
        with self.assertRaisesRegex(JobError, '^profile_changed$'): bind(changed, self.digest, selectors)

    def test_cli_accepts_auton_appended_selectors_and_rejects_modified_profile_before_effect(self):
        path = self.root / 'profile.json'
        path.write_text(json.dumps(self.profile)); path.chmod(0o600)
        args = ['run', '--config', str(path), '--profile-sha256', self.digest,
                IDENTITY, self.record['domain'], self.generation, 'cloudfront']
        with patch('certlord.cloudfront.job.execute', return_value={'status': 'verified'}) as execute, \
             patch('certlord.cloudfront.job.signal.signal'), patch('certlord.cloudfront.job.logging.disable'), \
             patch('certlord.cloudfront.job.os.umask'), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args), 0)
            execute.assert_called_once()
            self.profile['poll_interval'] = 2
            path.write_text(json.dumps(self.profile))
            self.assertEqual(main(args), 1)
            self.assertEqual(execute.call_count, 1)
            self.assertIn('profile_changed', output.getvalue())

    def test_private_file_and_ledger_permissions_fail_closed(self):
        path = self.root / 'secret'
        path.write_text('synthetic'); path.chmod(0o644)
        with self.assertRaisesRegex(JobError, '^insecure_private_file$'): read_private(path)
        path.chmod(0o600)
        link = self.root / 'link'; link.symlink_to(path)
        with self.assertRaises(OSError): read_private(link)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(JobError, '^insecure_state_dir$'): Ledger(self.root)
        self.root.chmod(0o700)
        with self.assertRaisesRegex(JobError, '^invalid_ledger_entry$'):
            self.ledger.save(ARN, {'key': 'private'})
        self.ledger.save(ARN, {'state': 'unknown'})
        with self.assertRaisesRegex(JobError, '^invalid_ledger_entry$'): self.engine().run(self.generation)

    def test_profile_revision_invalidates_existing_destination_target_identity(self):
        from certlord.adapters.destinations import DestinationPlan
        from certlord.adapters.processes import CommandRunner
        stop = threading.Event()
        config = {'credentials': {'cloudfront': {'uri': 'https://auton.example.test',
            'endpoint': endpoint_name(self.profile), 'auth-user': 'synthetic', 'auth-passwd': 'synthetic'}}}
        module = {'deployment_destinations': {IDENTITY: {'cloudfront': {'credentials': 'cloudfront',
            'tls': {'host': 'synthetic.cloudfront.net', 'port': 443}}}}}
        before = DestinationPlan(config, module, stop, CommandRunner(stop, 10, 0.2)).targets[IDENTITY]['cloudfront']
        self.profile['target']['distribution_id'] = 'ECHANGED'
        config['credentials']['cloudfront']['endpoint'] = endpoint_name(self.profile)
        after = DestinationPlan(config, module, stop, CommandRunner(stop, 10, 0.2)).targets[IDENTITY]['cloudfront']
        self.assertNotEqual(before, after)

    def test_reimport_cannot_remove_server_auth_usage(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID
        old = Mock()
        new = Mock()
        with patch('certlord.cloudfront.material.key_kind', return_value=('RSA', 2048)), \
             patch('certlord.cloudfront.material.usages', side_effect=[{'digital_signature'}, set()]):
            with self.assertRaisesRegex(JobError, '^reimport_key_usage_removed$'): compatible(old, new)
        server, client = (ExtendedKeyUsageOID.SERVER_AUTH.dotted_string, ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string)
        with patch('certlord.cloudfront.material.key_kind', return_value=('RSA', 2048)), \
             patch('certlord.cloudfront.material.usages', side_effect=[set(), set(), {server, client}, {client}]):
            with self.assertRaisesRegex(JobError, '^reimport_extended_usage_removed$'): compatible(old, new)
        with patch('certlord.cloudfront.material.key_kind', return_value=('RSA', 2048)), \
             patch('certlord.cloudfront.material.usages', side_effect=[set(), set(), {server, client}, {server}]):
            compatible(old, new)
