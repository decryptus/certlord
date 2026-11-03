"""One controlled writer host; durable intent never implies exactly-once AWS effects."""
import re
import time
from uuid import uuid4

from certlord.cloudfront.config import JobError, require
from certlord.cloudfront.material import current_material, compatible


class Renewal:
    def __init__(self, profile, digest, ledger, read, provider, verify, stop,
                 clock=time.time, monotonic=time.monotonic):
        self.profile, self.digest, self.ledger = profile, digest, ledger
        self.read, self.provider, self.verify, self.stop = read, provider, verify, stop
        self.clock, self.monotonic = clock, monotonic
        self.arn = profile['target']['certificate_arn']

    def material(self, generation, minimum_life=0):
        require(not self.stop.is_set(), 'interrupted')
        return current_material(self.read, generation, self.profile['target']['domain'], minimum_life)

    def run(self, generation):
        with self.ledger.locked(self.arn):
            entry = self.ledger.read(self.arn)
            if entry:
                require(isinstance(entry, dict) and {'state', 'intent_id', 'profile', 'generation',
                        'fingerprint', 'material_sha256', 'deadline'} <= set(entry), 'invalid_ledger_entry')
                require(entry['state'] in ('sending', 'quarantined', 'accepted', 'verified', 'resolved'),
                        'invalid_ledger_entry')
                # Check this before generation/profile changes. Neither may bypass
                # the possibility of a previous request still committing remotely.
                require(entry['state'] not in ('sending', 'quarantined'), 'arn_quarantined')
            record, candidate, leaf = self.material(generation)
            same = bool(entry and entry['generation'] == generation and entry['profile'] == self.digest
                        and entry['fingerprint'] == candidate['fingerprint_sha256']
                        and entry['material_sha256'] == candidate['material_sha256']
                        and entry['state'] in ('accepted', 'verified'))
            if not same:
                snapshot = self.provider.read()
                compatible(snapshot['leaf'], leaf)
                record, candidate, leaf = self.material(generation, self.profile['propagation_timeout'])
                entry = {'intent_id': str(uuid4()), 'profile': self.digest, 'generation': generation,
                         'fingerprint': candidate['fingerprint_sha256'], 'state': 'accepted',
                         'material_sha256': candidate['material_sha256'],
                         'deadline': self.clock() + self.profile['propagation_timeout'], 'error_code': None}
                if snapshot['material_sha256'] != entry['material_sha256']:
                    # Repeat both association and current-generation checks just
                    # before the only mutating request. AWS has no CAS here.
                    snapshot = self.provider.read()
                    compatible(snapshot['leaf'], leaf)
                    self.material(generation)
                    entry['state'] = 'sending'
                    self.ledger.save(self.arn, entry)
                    try:
                        self.provider.reimport(candidate)
                    except Exception:
                        entry.update(state='quarantined', error_code='import_outcome_uncertain')
                        self.ledger.save(self.arn, entry)
                        raise JobError('import_outcome_uncertain') from None
                    entry['state'] = 'accepted'
                self.ledger.save(self.arn, entry)
            # A resumed verified job rechecks live TLS; previous success isn't a
            # permanent claim. Never reimport an accepted generation to fix TLS.
            remaining = min(self.profile['propagation_timeout'], max(0, entry['deadline'] - self.clock()))
            end = self.monotonic() + remaining
            first_check = True
            while first_check or self.monotonic() < end:
                first_check = False
                record, _candidate, _leaf = self.material(generation)
                try:
                    snapshot = self.provider.read()
                    matched = (snapshot['fingerprint'] == entry['fingerprint']
                               and snapshot['material_sha256'] == entry['material_sha256'])
                    result = self.verify(record, snapshot) if matched else {'status': 'pending'}
                    verified = (result.get('status') == 'verified'
                                and result.get('observed_fingerprint_sha256') == entry['fingerprint'])
                except Exception:
                    verified = False
                self.material(generation)
                if verified:
                    entry.update(state='verified', error_code=None)
                    self.ledger.save(self.arn, entry)
                    return {'status': 'verified', 'fingerprint_sha256': entry['fingerprint'],
                            'generation': generation, 'intent_id': entry['intent_id']}
                entry.update(state='accepted', error_code='propagation_pending')
                self.ledger.save(self.arn, entry)
                self.stop.wait(min(self.profile['poll_interval'], max(0, end - self.monotonic())))
            raise JobError('propagation_deadline')

    def reconcile(self, intent_id, fingerprint, acknowledge_quiesced):
        """Operator asserts old request is quiescent; read-back alone cannot prove it."""
        require(acknowledge_quiesced is True and re.fullmatch(r'[0-9a-f]{64}', fingerprint),
                'reconciliation_acknowledgement_required')
        with self.ledger.locked(self.arn):
            entry = self.ledger.read(self.arn)
            require(entry and entry.get('intent_id') == intent_id and entry.get('profile') == self.digest
                    and entry.get('state') in ('sending', 'quarantined'), 'reconciliation_conflict')
            require(self.provider.read()['fingerprint'] == fingerprint, 'reconciliation_fingerprint_changed')
            entry.update(state='resolved', reconciled_fingerprint=fingerprint, error_code=None)
            self.ledger.save(self.arn, entry)
            return {'status': 'resolved', 'intent_id': intent_id, 'fingerprint_sha256': fingerprint}
