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

    # A user can be connected to an organisation by a Role that has
    # the value of CONNECTED_ROLE_CODE as code. That way users can be
    # connected to organisations without having other UserOrganisationRole
    # instances.
    CONNECTED_ROLE_CODE = 'is_connected'
    IGNORE_ROLE_CODES = []

    # management role codes
    # manager is used by lizard-nxt and superman was previously used by 3di
    # 3di is about to adopt a more permission-based role naming, therefore
    # the can_manage role/permission
    MANAGER_ROLE_CODES = ['manager', 'superman', 'manage']

    class Meta:
        prefix = 'sso'
