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
    KEY = ''
    SECRET = ''

    # Defaults. Normally no need to adjust them.
    CREDENTIAL_CACHE_TIMEOUT_SECONDS = 60
    JWT_EXPIRATION_MINUTES = 5
    JWT_ALGORITHM = 'HS256'

    # Required settings for the v1 API.
    SERVER_PRIVATE_URL = ''
    SERVER_PUBLIC_URL = ''

    # Required settings for the v2 API. Should include ``/api2/``.
    SERVER_API_START_URL = ''

    # Extra setting for the v2 API. Invitation language is the language used
    # by the SSO in the email when inviting the new user.
    ALLOW_ONLY_KNOWN_USERS = True
    INVITATION_LANGUAGE = 'en'

    # Role syncing from signals.py. V1 API only
    CLIENT_SUPERUSER_ROLES = []
    CLIENT_STAFF_ROLES = []

    class Meta:
        prefix = 'sso'
