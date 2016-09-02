# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from appconf import AppConf
from django.conf import settings


settings  # Pyflakes


class SSOAppConf(AppConf):
    # Basic settings.
    ENABLED = False
    STANDALONE = False
    USE_V2_LOGIN = False

    # Timing defaults. No need to adjust them.
    CREDENTIAL_CACHE_TIMEOUT_SECONDS = 60
    JWT_EXPIRATION_MINUTES = 5

    # Required settings for the v1 API.
    SERVER_PRIVATE_URL = ''
    SERVER_PUBLIC_URL = ''
    KEY = ''
    SECRET = ''

    # Required settings for the v2 API.
    SERVER_PUBLIC_URL_V2 = ''

    # Role syncing from signals.py
    CLIENT_SUPERUSER_ROLES = []
    CLIENT_STAFF_ROLES = []

    class Meta:
        prefix = 'sso'
