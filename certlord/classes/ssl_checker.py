# -*- coding: utf-8 -*-
# Copyright (C) 2019-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""certlord.classes.ssl_checker"""

import abc
import logging
import math
import os
import re

from copy import deepcopy

from requests.exceptions import ConnectionError # pylint: disable=redefined-builtin

from six import iteritems

from statuscake import StatusCake
from sonicprobe.libs import urisup

import updownio

from certlord.classes.exceptions import CertLordConfigError
from certlord.classes.config import DEFAULT_MONITORING_TIMEOUT

LOG = logging.getLogger('certlord.classes.ssl_checkers.statuscake')

UPDOWN_RECIPIENTS_MATCHER = re.compile(r'^[a-z]+\:[0-9]+$').match


class SslCertsCheckers(dict):
    def register(self, ssl_checker):
        if not isinstance(ssl_checker, SslCertsChecker):
            raise TypeError("Invalid SSL Checker class. (class: %r)" % ssl_checker)
        return dict.__setitem__(self, ssl_checker.CHECKER_NAME, ssl_checker)

SSL_CHECKERS = SslCertsCheckers()


class SslCertsChecker(object): # pylint: disable=useless-object-inheritance
    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def CHECKER_NAME(self):
        return

    def __init__(self):
        self.config    = None
        self.conn      = None
        self.collector = {}

    def init(self, config, credentials):
        self.config = self.load_config(deepcopy(config), credentials)
        # Network initialization belongs to monitoring cycles, not API startup.
        return self

    def insert(self, domain, xid):
        if not domain.startswith('https://'):
            domain = "https://%s" % domain

        self.collector[domain] = str(xid)

        return self

    def pop(self, domain):
        if not domain.startswith('https://'):
            domain = "https://%s" % domain

        self.collector.pop(domain, None)

        return self

    @abc.abstractmethod
    def connect(self, reconnect = False):
        return self

    @abc.abstractmethod
    def load_config(self, config, credentials):
        if not credentials \
           or not isinstance(credentials, dict):
            raise CertLordConfigError("missing or invalid %r credentials configuration" % self.CHECKER_NAME)

        r = {'auth':   {},
             'params': {}}

        if not isinstance(config, dict):
            r['params']['enabled'] = False
            return r

        r['params'] = config
        r['params']['enabled'] = r['params'].get('enabled', True) or False
        if not r['params']['enabled']:
            return r

        timeout = r['params'].pop('timeout', DEFAULT_MONITORING_TIMEOUT)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
           or not math.isfinite(timeout) or timeout <= 0:
            raise CertLordConfigError('Monitoring timeout must be finite and positive')
        r['auth']['timeout'] = timeout
        return r

    @abc.abstractmethod
    def create(self, domain, collector = True, exists = True):
        return self

    @abc.abstractmethod
    def delete(self, xid, unset = True):
        return self

    @abc.abstractmethod
    def list(self, xset = True, xraise = False):
        return self


class SslCertsCheckerStatuscake(SslCertsChecker):

    CHECKER_NAME = 'statuscake'

    def connect(self, reconnect = False):
        if not self.config['params']['enabled']:
            return self.conn

        if reconnect:
            self.conn = None
        elif self.conn:
            return self.conn

        conn = StatusCake(**self.config['auth'])
        for contact in conn.get_contact_groups():
            if str(contact['ContactID']) in self.config['params']['contact_groups']:
                self.conn = conn
                break

        if not self.conn:
            raise CertLordConfigError("invalid contact groups for statuscake: %r"
                                       % self.config['params']['contact_groups'])

        return self.conn

    def load_config(self, config, credentials):
        r = SslCertsChecker.load_config(self, config, credentials)

        if not r['params']['enabled']:
            return r

        if not r['params'].get('contact_groups') \
           or not isinstance(r['params']['contact_groups'], list):
            raise CertLordConfigError("missing or invalid statuscake contact_groups configuration")

        contacts = []
        for x in r['params']['contact_groups']:
            contacts.append(str(x))
        r['params']['contact_groups'] = contacts

        r['auth']['api_user'] = credentials.get('api-user') or os.environ.get('STATUSCAKE_API_USER')
        if not r['auth']['api_user']:
            raise CertLordConfigError("missing variable STATUSCAKE_API_USER")

        r['auth']['api_key'] = credentials.get('api-key') or os.environ.get('STATUSCAKE_API_KEY')
        if not r['auth']['api_key']:
            raise CertLordConfigError("missing variable STATUSCAKE_API_KEY")

        return r

    def create(self, domain, collector = True, exists = True):
        if not domain.startswith('https://'):
            domain = "https://%s" % domain

        if exists and domain in self.collector:
            return None

        if not self.config['params']['enabled']:
            return None

        rs   = None
        conf = deepcopy(self.config['params'])
        conf.pop('enabled', None)
        conf['domain'] = domain

        try:
            # A lost response does not prove the provider rejected the mutation.
            rs = self.conn.insert_ssl(conf)

            if rs and rs.get('Success'):
                if collector:
                    self.insert(domain, rs['Message'])
                return str(rs['Message'])
        except Exception as e:
            LOG.error("Monitoring provider operation failed on %s", self.CHECKER_NAME)

        return False

    def delete(self, xid, unset = True):
        xid = str(xid)
        if not self.config['params']['enabled']:
            return None
        try:
            # A lost response does not prove the provider rejected the mutation.
            rs = self.conn.delete_ssl(xid)
            if not (isinstance(rs, dict) and rs.get('Success') is True):
                return False
        except Exception:
            LOG.error("Unable to delete monitoring check on %s", self.CHECKER_NAME)
            return False

        if unset:
            for domain, cid in list(iteritems(self.collector)):
                if cid == xid:
                    self.pop(domain)
        return True

    def list(self, xset = True, xraise = False):
        rs = None
        r  = {}

        if not self.config['params']['enabled']:
            return None

        if not self.conn:
            return r

        try:
            try:
                rs = self.conn.get_all_ssl()
            except ConnectionError:
                self.connect(reconnect = True)
                rs = self.conn.get_all_ssl()

            if rs:
                for check in rs:
                    for cgrp in check['contact_groups']:
                        if str(cgrp) in self.config['params']['contact_groups']:
                            domain = "https://%s" % urisup.uri_help_split(check['domain'])[1][2]
                            r[domain] = check['id']
        except Exception as e:
            LOG.error("Monitoring provider operation failed on %s", self.CHECKER_NAME)
            r = deepcopy(self.collector)
            if xraise:
                raise

        if xset:
            self.collector = r

        return r


#SSL_CHECKERS.register(SslCertsCheckerStatuscake())


class SslCertsCheckerUpdown(SslCertsChecker):

    CHECKER_NAME = 'updown'

    def connect(self, reconnect = False):
        if not self.config['params']['enabled']:
            return self.conn

        if reconnect:
            self.conn = None
        elif self.conn:
            return self.conn

        self.conn = updownio.service('checks', **self.config['auth'])

        return self.conn

    def load_config(self, config, credentials):
        r = SslCertsChecker.load_config(self, config, credentials)

        if not r['params']['enabled']:
            return r

        if not r['params'].get('recipients') \
           or not isinstance(r['params']['recipients'], list):
            raise CertLordConfigError("missing or invalid updown recipients configuration")

        recipients = []
        for x in r['params']['recipients']:
            m = UPDOWN_RECIPIENTS_MATCHER(x)
            if m:
                recipients.append(x)

        r['params']['recipients'] = recipients

        if not r['params']['recipients']:
            raise CertLordConfigError("unable to find any valid updown recipients in configuration")

        r['auth']['api_key'] = credentials.get('api-key') or os.environ.get('UPDOWN_API_KEY')
        if not r['auth']['api_key']:
            raise CertLordConfigError("missing variable UPDOWN_API_KEY")

        return r

    def create(self, domain, collector = True, exists = True):
        if not domain.startswith('https://'):
            domain = "https://%s" % domain

        if exists and domain in self.collector:
            return None

        if not self.config['params']['enabled']:
            return None

        rs   = None
        conf = deepcopy(self.config['params'])
        conf.pop('enabled', None)
        conf['domain'] = domain

        try:
            # A lost response does not prove the provider rejected the mutation.
            rs = self.conn.add(domain, conf)

            if rs and rs.get('token'):
                if collector:
                    self.insert(domain, rs['token'])
                return str(rs['token'])
        except Exception as e:
            LOG.error("Monitoring provider operation failed on %s", self.CHECKER_NAME)

        return False

    def delete(self, xid, unset = True):
        xid = str(xid)
        if not self.config['params']['enabled']:
            return None
        try:
            # A lost response does not prove the provider rejected the mutation.
            rs = self.conn.delete(xid)
            if not (rs is True):
                return False
        except Exception:
            LOG.error("Unable to delete monitoring check on %s", self.CHECKER_NAME)
            return False

        if unset:
            for domain, cid in list(iteritems(self.collector)):
                if cid == xid:
                    self.pop(domain)
        return True

    def list(self, xset = True, xraise = False):
        rs = None
        r  = {}

        if not self.conn:
            return r

        try:
            try:
                rs = self.conn.list()
            except ConnectionError:
                self.connect(reconnect = True)
                rs = self.conn.list()

            if rs:
                for check in rs:
                    for recipient in check['recipients']:
                        if str(recipient) in self.config['params']['recipients']:
                            domain = "https://%s" % urisup.uri_help_split(check['url'])[1][2]
                            r[domain] = check['token']
        except Exception as e:
            LOG.error("Monitoring provider operation failed on %s", self.CHECKER_NAME)
            r = deepcopy(self.collector)
            if xraise:
                raise

        if xset:
            self.collector = r

        return r


SSL_CHECKERS.register(SslCertsCheckerUpdown())

