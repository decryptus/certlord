# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build argv and explicit subprocess environments without running commands."""
import os
import re

from certlord.classes.config import (AUTON_PROG, CERTBOT_PROG,
                                    DEFAULT_BECOME_METHOD, DEFAULT_BECOME_OPTS,
                                    DEFAULT_BECOME_USER, DEFAULT_CERTBOT_ARGS)
from certlord.classes.exceptions import CertLordConfigError


CERTBOT_ENV = (
    'PATH', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
    'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
    'CBT_HTTPREQ_AUTH_CONFIG', 'CBT_HTTPREQ_INST_CONFIG',
)


class CommandBuilder(object):
    def __init__(self, config, modconf):
        self.config = config
        self.modconf = modconf
        self._auton_cred = {}

    @staticmethod
    def _get_become(cfg):
        if not isinstance(cfg, dict) or not cfg.get('enabled'):
            return []

        method = cfg.get('method') or DEFAULT_BECOME_METHOD
        become = [method]

        if method in DEFAULT_BECOME_OPTS:
            become += DEFAULT_BECOME_OPTS[method]

        if method == 'sudo':
            become += ['-u', cfg.get('user') or DEFAULT_BECOME_USER]

        return become

    def certbot_cmd(self):
        conf = {}

        if isinstance(self.modconf.get('certbot'), dict):
            conf = self.modconf['certbot']

        args = conf.get('args', DEFAULT_CERTBOT_ARGS)
        if not isinstance(args, list):
            raise CertLordConfigError("invalid certbot args configuration")

        extra = conf.get('pass_env', [])
        if not isinstance(extra, list) or any(not isinstance(name, str) or not
                re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) for name in extra):
            raise CertLordConfigError("certbot pass_env requires a list of environment variable names")

        names = set(extra)
        if 'search_paths' not in conf:
            names.update(CERTBOT_ENV)
        env = {name: os.environ[name] for name in names if name in os.environ}
        if 'search_paths' in conf:
            paths = conf['search_paths']
            if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
                raise CertLordConfigError("invalid certbot search_paths configuration")
            env['PATH'] = os.path.pathsep.join(paths)

        return {'args': self._get_become(conf.get('become')) + [CERTBOT_PROG] + args,
                'env': env}

    def _get_auton_cred(self):
        if self._auton_cred:
            return self._auton_cred

        creds = self.config['credentials']['auton']
        uri   = creds.get('uri') or os.environ.get('AUTON_URI')
        if not uri:
            raise CertLordConfigError("missing variable AUTON URI")

        endpoint = creds.get('endpoint') or os.environ.get('AUTON_ENDPOINT')
        if not endpoint:
            raise CertLordConfigError("missing variable AUTON endpoint")

        auth_user = creds.get('auth-user') or os.environ.get('AUTON_AUTH_USER') or ""
        auth_passwd = creds.get('auth-passwd') or os.environ.get('AUTON_AUTH_PASSWD') or ""

        self._auton_cred = {'args': ['--uri', uri,
                                     '--endpoint', endpoint],
                            'env':  {'AUTON_AUTH_USER': auth_user,
                                     'AUTON_AUTH_PASSWD': auth_passwd}}

        return self._auton_cred

    def auton_cmd(self):
        conf = {}

        if isinstance(self.modconf.get('auton'), dict):
            conf = self.modconf['auton']

        r = {'args': self._get_become(conf.get('become')) + [AUTON_PROG],
             'env':  dict(self._get_auton_cred()['env'])}

        if not conf:
            r['args'] += self._get_auton_cred()['args']
            return r

        if 'args' not in conf:
            r['args'] += self._get_auton_cred()['args']
        else:
            if not isinstance(conf['args'], list):
                raise CertLordConfigError("invalid auton args configuration")

            r['args'] += conf['args'] + self._get_auton_cred()['args']

        receipt_mode = conf.get('receipt_mode', False)
        if type(receipt_mode) is not bool:
            raise CertLordConfigError('auton receipt_mode must be boolean')
        if receipt_mode:
            from certlord.adapters.auton_receipt import receipt_target
            credentials = self._get_auton_cred()['args']
            r['receipt_target'] = receipt_target(credentials[1], credentials[3], conf.get('args', []))

        if 'search_paths' in conf:
            if not isinstance(conf['search_paths'], list):
                raise CertLordConfigError("invalid auton search_paths configuration")

            r['env']['PATH'] = os.path.pathsep.join(conf['search_paths'])

        return r

