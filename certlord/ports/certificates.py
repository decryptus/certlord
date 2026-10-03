"""Certificate storage is independent of transport and credential providers."""


class StorageError(Exception):
    pass


class StorageNotFound(StorageError):
    pass


class StorageConflict(StorageError):
    pass


class CertificateStore(object):
    def reserve_identity(self, definition, candidate_id):
        raise NotImplementedError

    def get_versioned(self, certificate_id, domain):
        raise NotImplementedError

    def replace_if_version(self, certificate_id, domain, version, data):
        raise NotImplementedError

    def get(self, certificate_id, domain):
        raise NotImplementedError

    def put(self, certificate_id, domain, data):
        raise NotImplementedError

    def update(self, certificate_id, domain, data):
        raise NotImplementedError

    def delete(self, certificate_id, domain):
        raise NotImplementedError

    def list_domains(self, certificate_id):
        raise NotImplementedError

    def list_certificate_ids(self):
        raise NotImplementedError

    def bound_domains(self, certificate_id):
        """Return domains including retained removal metadata for identity checks."""
        raise NotImplementedError


class StorageSession(object):
    def client(self):
        raise NotImplementedError
