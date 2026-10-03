"""Generation identity and transactional Redis publication contracts."""
import unittest
from unittest.mock import Mock
from certlord.adapters.deployment_queue import DeploymentQueue


class DeploymentQueueTests(unittest.TestCase):
    def setUp(self):
        self.redis = Mock()
        self.conn = Mock()
        self.pipe = Mock()
        self.conn.pipeline.return_value.__enter__ = Mock(return_value=self.pipe)
        self.conn.pipeline.return_value.__exit__ = Mock(return_value=False)
        self.redis.servers = {'ssl_certs': {'conn': self.conn}}
        self.queue = DeploymentQueue(self.redis)

    def test_same_generation_has_same_identity(self):
        cert = {'cert': 'fixture', 'chain': 'chain', 'updated_at': 'first'}
        first = self.queue.enqueue('server', '6ff9418a-a4d7-5964-b0a3-78f920426989', 'EXAMPLE.ORG', cert)
        cert['updated_at'] = 'second'
        self.assertEqual(first, self.queue.enqueue('server', '6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', cert))
        cert['cert'] = 'renewed'
        self.assertNotEqual(first, self.queue.enqueue('server', '6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', cert))
        self.assertNotEqual(first, self.queue.enqueue('other-server', '6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', cert))

    def test_publication_uses_one_transaction_with_payload_before_membership(self):
        key = self.queue.enqueue('server', '6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', {'cert': 'fixture'})
        self.conn.pipeline.assert_called_once_with(transaction=True)
        self.assertEqual([c[0] for c in self.pipe.mock_calls], ['hsetnx', 'hset', 'sadd', 'execute'])
        self.pipe.sadd.assert_called_once_with('server', key)

    def test_acknowledgement_removes_hash_and_membership_together(self):
        self.queue.acknowledge('server', 'legacy-uuid')
        self.assertEqual([c[0] for c in self.pipe.mock_calls], ['srem', 'delete', 'execute'])
        self.pipe.delete.assert_called_once_with('legacy-uuid')

    def test_failed_publication_propagates(self):
        self.pipe.execute.side_effect = RuntimeError('Redis unavailable')
        with self.assertRaises(RuntimeError):
            self.queue.enqueue('server', '6ff9418a-a4d7-5964-b0a3-78f920426989', 'example.org', {'cert': 'fixture'})
