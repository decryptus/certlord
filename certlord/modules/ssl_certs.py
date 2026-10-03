# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""HTTP boundary for certificate use cases."""
import logging
from dwho.classes.modules import DWhoModuleBase, MODULES
from httpdis.ext.httpdis_json import HttpReqErrJson
from httpdis.httpdis import HttpResponse, HttpResponseJson
from sonicprobe.libs import network, xys
from certlord.composition import api_access, certificate_runtime
from certlord.modules.route_auth import authenticated_routes
from certlord.services.api_access import AccessDenied
from certlord.services.issuance import issuance_header
from certlord.services.certificate_ids import valid_certificate_id
from certlord.services.certificates import CertificateBusy, CertificateConflict, CertificateNotFound

from certlord.services.import_material import InvalidMaterial
from certlord.services.observations import operations_metrics

LOG = logging.getLogger(__name__)
xys.add_callback('ssl_certs.certificate_id', valid_certificate_id)
xys.add_callback('ssl_certs.sub_domain',
                 lambda x: network.valid_domain_cert(x, network.MASK_SUB_DOMAIN_TLD))

class SslCertsModule(DWhoModuleBase):
    MODULE_NAME = 'ssl_certs'

    def init(self, config):
        return super(SslCertsModule, self).init(authenticated_routes(config, self.MODULE_NAME))

    def safe_init(self, options):
        self._api_access = api_access(self.config)
        self._runtime = certificate_runtime(self.config, self.modconf)
        self._service = self._runtime.service

    def at_start(self, options):
        self._runtime.start()

    def at_stop(self):
        self._runtime.stop()

    @staticmethod
    def _call_service(callback, *args):
        try:
            return callback(*args)
        except InvalidMaterial as error:
            raise HttpReqErrJson(400, str(error))
        except CertificateNotFound as error:
            raise HttpReqErrJson(404, str(error))
        except CertificateConflict as error:
            raise HttpReqErrJson(409, str(error))
        except CertificateBusy as error:
            raise HttpReqErrJson(503, str(error))
        except Exception as error:
            LOG.error("Certificate operation failed (%s)", type(error).__name__)
            raise HttpReqErrJson(503, "Certificate service unavailable")

    def _authorize(self, request, operation):
        try:
            self._api_access.require(request, operation)
        except AccessDenied:
            raise HttpReqErrJson(403, 'API operation not permitted')

    def live(self, request):
        self._authorize(request, 'read')
        return HttpResponseJson(data=self._call_service(self._runtime.live),
                                headers={'Cache-Control': 'no-store'})

    def ready(self, request):
        self._authorize(request, 'read')
        result = self._call_service(self._runtime.readiness)
        return HttpResponseJson(code=200 if result['ready'] else 503, data=result,
                                headers={'Cache-Control': 'no-store'})

    def operations(self, request):
        self._authorize(request, 'read')
        return HttpResponseJson(data=self._call_service(self._runtime.operations),
                                headers={'Cache-Control': 'no-store'})

    def operation_metrics(self, request):
        self._authorize(request, 'read')
        value = self._call_service(self._runtime.operations)
        return HttpResponse(data=self._call_service(operations_metrics, value), headers={
            'Content-type': 'text/plain; version=0.0.4; charset=utf-8', 'Cache-Control': 'no-store'})

    def deploy(self, request):
        self._authorize(request, 'deploy')
        return self._call_service(self._service.deploy)


    SAVE_PSCHEMA = xys.load("""
    domain: !~~callback(ssl_certs.sub_domain)
    cert![1000,5000]: !!str
    chain*[0,6000]: !!str
    key![1000,5000]: !!str
    """)

    def save(self, request):
        self._authorize(request, 'write')
        payload = request.payload_params() or {}

        if not isinstance(payload, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(payload, self.SAVE_PSCHEMA):
            raise HttpReqErrJson(400, "invalid arguments for command")

        return self._call_service(self._service.save, payload, issuance_header(request.get_headers()))


    VALIDATE_QSCHEMA = xys.load("""
    sub_domain: !~~callback(ssl_certs.sub_domain)
    """)

    def validate(self, request):
        self._authorize(request, 'read')
        params = request.query_params() or {}

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.VALIDATE_QSCHEMA):
            raise HttpReqErrJson(400, "invalid arguments for command")

        return self._call_service(self._service.validate, params['sub_domain'])


    UPSERT_QSCHEMA = xys.load("""
    certificate_id: !~~callback(ssl_certs.certificate_id)
    """)

    UPSERT_PSCHEMA = xys.load("""
    domains: !~~seqlen(1,1) [ !~~callback(ssl_certs.sub_domain) ]
    """)

    def upsert(self, request):
        self._authorize(request, 'write')
        params  = request.query_params() or {}
        payload = request.payload_params() or {}

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.UPSERT_QSCHEMA):
            raise HttpReqErrJson(400, "invalid arguments for command")

        if not isinstance(payload, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(payload, self.UPSERT_PSCHEMA):
            raise HttpReqErrJson(400, "invalid arguments for command")

        self._call_service(self._service.update_existing, params['certificate_id'], payload['domains'])
        return self._call_service(self._service.detail, params['certificate_id'])


    INDEX_QSCHEMA = xys.load("""
    certificate_id: !~~callback(ssl_certs.certificate_id)
    """)

    def index(self, request):
        self._authorize(request, 'read')
        params  = request.query_params() or {}

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.INDEX_QSCHEMA):
            raise HttpReqErrJson(400, "invalid arguments for command")

        return self._call_service(self._service.detail, params['certificate_id'])

    def inventory(self, request):
        self._authorize(request, 'read')
        return self._call_service(self._service.inventory)

    def observations(self, request):
        self._authorize(request, 'read')
        value = self._call_service(self._service.observations)
        return HttpResponseJson(data=value, headers={'Cache-Control': 'no-store'})

    def metrics(self, request):
        self._authorize(request, 'read')
        value = self._call_service(self._service.metrics)
        return HttpResponse(data=value, headers={
            'Content-type': 'text/plain; version=0.0.4; charset=utf-8', 'Cache-Control': 'no-store'})

    def create(self, request):
        self._authorize(request, 'write')
        payload = request.payload_params()
        if not isinstance(payload, dict) or not xys.validate(payload, self.UPSERT_PSCHEMA):
            raise HttpReqErrJson(400, 'Exactly one valid domain is required')
        return self._call_service(self._service.create, payload['domains'])

    def import_certificate(self, request):
        self._authorize(request, 'write')
        return self._call_service(self._service.import_certificate, request.payload_params())

    def replace_import(self, request):
        self._authorize(request, 'write')
        params = request.query_params() or {}
        if not isinstance(params, dict) or not xys.validate(params, self.INDEX_QSCHEMA):
            raise HttpReqErrJson(400, 'Invalid certificate UUID')
        return self._call_service(self._service.replace_import, params['certificate_id'], request.payload_params())

    def remove(self, request):
        self._authorize(request, 'write')
        params = request.query_params() or {}
        if not isinstance(params, dict) or not xys.validate(params, self.INDEX_QSCHEMA):
            raise HttpReqErrJson(400, 'Invalid certificate UUID')
        return self._call_service(self._service.remove, params['certificate_id'])


if __name__ != '__main__':
    MODULES.register(SslCertsModule())
