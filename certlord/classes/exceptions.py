# -*- coding: utf-8 -*-
# Copyright (C) 2019-2022 fjord-technologies
# SPDX-License-Identifier: GPL-3.0-or-later
"""certlord.classes.exceptions"""

import logging

LOG = logging.getLogger('certlord.exceptions')


class CertLordError(Exception):
    def __init__(self, message = None, args = None):
        if isinstance(message, Exception):
            Exception.__init__(self, message.message, message.args)
        else:
            Exception.__init__(self, message, args)

class CertLordConfigError(CertLordError):
    pass
