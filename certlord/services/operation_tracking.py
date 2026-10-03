"""Non-secret operation correlation; not an authorization or durable audit log."""
from contextvars import ContextVar
from functools import wraps
import json
import re
import logging
from uuid import UUID, uuid4

LOG = logging.getLogger(__name__)
_CURRENT = ContextVar('certlord_operation', default=None)


def valid_id(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return str(parsed) == value and parsed.version == 4


def current_id():
    return _CURRENT.get()


def record_id(record):
    value = record.get('operation_id')
    return value if valid_id(value) else None


def emit(event, operation_id, certificate_id=None, attempt_id=None, remote_job=None):
    # Explicit fields only: never accept payloads, exceptions, subprocess output,
    # callback credentials or lease tokens. Logging failure must not mutate work.
    if not valid_id(operation_id):
        return
    record = {'event': event, 'operation_id': operation_id}
    if isinstance(certificate_id, str):
        from certlord.services.certificate_ids import valid_certificate_id
        if valid_certificate_id(certificate_id):
            record['certificate_id'] = certificate_id
    if valid_id(attempt_id):
        record['attempt_id'] = attempt_id
    if isinstance(remote_job, str):
        endpoint, separator, job_id = remote_job.partition(':')
        if separator and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', endpoint) and valid_id(job_id):
            record['remote_job'] = remote_job
    try:
        LOG.info('operation_progress %s', json.dumps(record, sort_keys=True))
    except Exception:
        pass


def tracked(name):
    """Generate identity at the service boundary, shared by nested mutations."""
    def decorate(callback):
        @wraps(callback)
        def wrapped(*args, **kwargs):
            if current_id() is not None:
                return callback(*args, **kwargs)
            operation_id = str(uuid4())
            token = _CURRENT.set(operation_id)
            emit(name + '_started', operation_id)
            try:
                result = callback(*args, **kwargs)
            except BaseException:
                emit(name + '_raised', operation_id)
                raise
            else:
                emit(name + '_returned', operation_id)
                if isinstance(result, dict):
                    persisted = record_id(result)
                    if persisted and persisted != operation_id:
                        emit('existing_operation_returned', persisted,
                             result.get('certificate_id'), operation_id)
                return result
            finally:
                _CURRENT.reset(token)
        return wrapped
    return decorate


def stamp(payload, force_new=False):
    """Call only on server-owned mutation data, never on unvalidated requests."""
    payload['operation_id'] = current_id() or (None if force_new else record_id(payload)) or str(uuid4())
    return payload
