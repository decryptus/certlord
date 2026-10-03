# -*- coding: utf-8 -*-
# Copyright (C) 2019-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""certlord.classes.config"""

DEFAULT_DELAY_RESET_RETRIES     = 86400
DEFAULT_PROCESSING_DELAY        = 900
DEFAULT_MAX_RETRIES             = 5

DEFAULT_CERTBOT_CHECK_INTERVAL  = 5
DEFAULT_DEPLOYER_CHECK_INTERVAL = 86400
DEFAULT_VAULT_CHECK_INTERVAL = 86400
DEFAULT_VAULT_BUSY_RETRY_INTERVAL = 1

DEFAULT_RENEW_BEFORE_EXPIRY     = 10

DEFAULT_BECOME_METHOD           = 'sudo'
DEFAULT_BECOME_USER             = 'root'
DEFAULT_BECOME_OPTS             = {'sudo': ['-H', '-E']}

DEFAULT_CERT_VENDOR             = 'letsencrypt'

CERT_VENDORS_AUTO               = [DEFAULT_CERT_VENDOR]

AUTON_PROG                      = 'auton'
CERTBOT_PROG                    = 'certbot'
DEFAULT_CERTBOT_ARGS            = ['--agree-tos',
                                   '--text',
                                   '--non-interactive',
                                   '-a',
                                   'certbot-httpreq:auth',
                                   '-i',
                                   'certbot-httpreq:installer',
                                   'run']

CERT_KEY_PREFIX                 = 'cert:'
DOMAIN_KEY_PREFIX               = 'domain:'
DEPLOY_SEARCH_FORMAT            = '*->ts'

STATUS_CREATE                   = 'create'
STATUS_EXISTS                   = 'exists'
STATUS_INVALID_DNS              = 'invalid-dns'
STATUS_DELETE                   = 'delete'
STATUS_RENEW                    = 'renew'

STATUS_PROCESSING               = 'processing'
STATUS_GENERATED                = 'generated'
STATUS_DEPLOYED                 = 'deployed'

ALLOWED_DNS_RTYPE               = ('a', 'aaaa', 'cname', 'txt')
DNS_RTYPE_CAA                   = 'caa'


DEFAULT_COMMAND_TIMEOUT = 300
DEFAULT_PROCESS_STOP_GRACE = 2
DEFAULT_WORKER_STOP_TIMEOUT = 10

DEFAULT_MONITORING_TIMEOUT = 10

DEFAULT_DEPLOY_LEASE_MARGIN = 5

# Storage-only marker: no certificate material, monotonically increasing Vault versions.
STATUS_REMOVED = 'removed'

ISSUANCE_HEADER = 'X-CertLord-Issuance'
CERTBOT_INSTALLER_CONFIG_OPTION = '--certbot-httpreq:installer-config'
DEFAULT_INSTALLER_CONFIG = '/etc/letsencrypt/certbot-httpreq.yml'

CERTIFICATE_ID_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

DEFAULT_DNS_TIMEOUT = 5
DEFAULT_REDIS_TIMEOUT = 5
DEFAULT_CHALLENGE_TTL = 3600
