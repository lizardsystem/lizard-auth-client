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

    # Role syncing from signals.py. V1 API only
    CLIENT_SUPERUSER_ROLES = []
    CLIENT_STAFF_ROLES = []

    # Management roles
    # manager is used by lizard-nxt and superman is used by 3di
    # 3di is about to adopt a more permission-based role naming, therefore
    # the can_manage role/permission
    MANAGER_ROLES = ['manager', 'superman', 'can_manage']

    class Meta:
        prefix = 'sso'
