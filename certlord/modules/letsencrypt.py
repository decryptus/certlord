# -*- coding: utf-8 -*-
# Copyright (C) 2019-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""certlord.modules.letsencrypt"""

import logging
import re

from six import string_types

from certlord.adapters.redis_client import redis_adapter
from certlord.classes.config import DEFAULT_CHALLENGE_TTL
from certlord.classes.exceptions import CertLordConfigError
from dwho.classes.modules import DWhoModuleBase, MODULES
from httpdis.ext.httpdis_json import HttpResponse, HttpReqErrJson
from sonicprobe.libs import xys
from certlord.composition import api_access
from certlord.modules.route_auth import authenticated_routes
from certlord.services.api_access import AccessDenied
from sonicprobe.libs.moresynchro import RWLock

LOG = logging.getLogger('certlord.modules.letsencrypt')

RE_VALIDATION_MATCH = re.compile(r'[0-9A-Za-z_\-\.]+').fullmatch

xys.add_regex('letsencrypt.challenge', re.compile(r'[0-9A-Za-z_\-]{43}').fullmatch)

class LetsEncryptModule(DWhoModuleBase):
    MODULE_NAME = 'letsencrypt'

    def init(self, config):
        return super(LetsEncryptModule, self).init(
            authenticated_routes(config, self.MODULE_NAME, ('well_known_get',)))

    LOCK        = RWLock()

    # pylint: disable-msg=attribute-defined-outside-init
    def safe_init(self, options):
        self.challenge_ttl = (self.modconf or {}).get('challenge_ttl', DEFAULT_CHALLENGE_TTL)
        if (isinstance(self.challenge_ttl, bool) or not isinstance(self.challenge_ttl, int)
                or not 0 < self.challenge_ttl <= 2147483647):
            raise CertLordConfigError('challenge_ttl must be a positive integer number of seconds (maximum 2147483647)')
        self._api_access = api_access(self.config)
        self.lock_timeout  = self.config['general']['lock_timeout']
        self.client        = None
        self.key_name      = None
        self._checker      = None
        self._redis = redis_adapter(self.config, prefix='letsencrypt')

        if not self._redis.servers:
            raise SystemError("missing redis server")

        self._redis.ping()


    WELL_KNOWN_DELETE_QSCHEMA = xys.load("""
    challenge: !~~regex(letsencrypt.challenge)
    """)

    def well_known_delete(self, request):
        try:
            self._api_access.require(request, "challenge")
        except AccessDenied:
            raise HttpReqErrJson(403, "API operation not permitted")
        params = request.query_params() or {}

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.WELL_KNOWN_DELETE_QSCHEMA):
            raise HttpReqErrJson(400, "invalid arguments for command")

        if not self.LOCK.acquire_write(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for writing after %s seconds" % self.lock_timeout)

        try:
            self._redis.del_key(request.get_path())
            return ""
        except HttpReqErrJson:
            raise
        except Exception as e:
            LOG.error("Challenge storage unavailable (%s)", type(e).__name__)
            raise HttpReqErrJson(503, "Challenge storage unavailable") from None
        finally:
            self.LOCK.release()


    WELL_KNOWN_GET_QSCHEMA = xys.load("""
    challenge: !~~regex(letsencrypt.challenge)
    """)

    def well_known_get(self, request):
        params  = request.query_params() or {}

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.WELL_KNOWN_GET_QSCHEMA):
            raise HttpReqErrJson(400, "invalid arguments for command")

        if not self.LOCK.acquire_read(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for reading after %s seconds" % self.lock_timeout)

        try:
            value = self._redis.get_key(request.get_path())
            if value is None:
                raise HttpReqErrJson(404, 'Challenge not found', headers={'Cache-Control': 'no-store'})
            return HttpResponse(data=value, headers={'Cache-Control': 'no-store'})
        except HttpReqErrJson:
            raise
        except Exception as e:
            LOG.error("Challenge storage unavailable (%s)", type(e).__name__)
            raise HttpReqErrJson(503, "Challenge storage unavailable") from None
        finally:
            self.LOCK.release()


    WELL_KNOWN_PUT_QSCHEMA = xys.load("""
    challenge: !~~regex(letsencrypt.challenge)
    """)

    def well_known_put(self, request):
        try:
            self._api_access.require(request, "challenge")
        except AccessDenied:
            raise HttpReqErrJson(403, "API operation not permitted")
        params  = request.query_params() or {}
        payload = request.payload_params()

        if not isinstance(params, dict):
            raise HttpReqErrJson(400, "invalid arguments type")

        if not xys.validate(params, self.WELL_KNOWN_PUT_QSCHEMA):
            raise HttpReqErrJson(400, "invalid arguments for command")

        if not isinstance(payload, string_types) or not RE_VALIDATION_MATCH(payload):
            raise HttpReqErrJson(400, "invalid payload for command")

        if not self.LOCK.acquire_write(self.lock_timeout):
            raise HttpReqErrJson(503, "unable to take LOCK for writing after %s seconds" % self.lock_timeout)

        try:
            self._redis.set_key(request.get_path(), payload, expire=self.challenge_ttl)
            return ""
        except HttpReqErrJson:
            raise
        except Exception as e:
            LOG.error("Challenge storage unavailable (%s)", type(e).__name__)
            raise HttpReqErrJson(503, "Challenge storage unavailable") from None
        finally:
            self.LOCK.release()


if __name__ != "__main__":
    def _start():
        MODULES.register(LetsEncryptModule())
    _start()
