# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build argv and explicit subprocess environments without running commands."""
import os

from certlord.classes.config import (AUTON_PROG, CERTBOT_PROG,
                                    DEFAULT_BECOME_METHOD, DEFAULT_BECOME_OPTS,
                                    DEFAULT_BECOME_USER, DEFAULT_CERTBOT_ARGS)
from certlord.classes.exceptions import CertLordConfigError


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

        r = {'args': self._get_become(conf.get('become')) + [CERTBOT_PROG],
             'env':  None}

        if not conf:
            r['args'] += DEFAULT_CERTBOT_ARGS
            return r

        if 'args' not in conf:
            r['args'] += DEFAULT_CERTBOT_ARGS
        else:
            if not isinstance(conf['args'], list):
                raise CertLordConfigError("invalid certbot args configuration")

            r['args'] += conf['args']

        if 'search_paths' in conf:
            if not isinstance(conf['search_paths'], list):
                raise CertLordConfigError("invalid certbot search_paths configuration")

            r['env'] = {'PATH': os.path.pathsep.join(conf['search_paths'])}

        return r

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

