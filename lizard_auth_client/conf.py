# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from appconf import AppConf
from django.conf import settings
from django.utils.translation import ugettext_lazy as _


settings  # NOQA


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

    # roles with the following codes will be ignored
    IGNORE_ROLE_CODES = []
    # ROLES_LABEL is used as label in forms, you can override this by setting
    # it to _('Permissions')
    ROLES_LABEL = _('Roles')

    # management role codes
    # manager is used by lizard-nxt and superman was previously used by 3di
    # 3di is about to adopt a more permission-based role naming, therefore
    # the can_manage role/permission
    MANAGER_ROLE_CODES = ['manager', 'superman', 'manage']

    class Meta:
        prefix = 'sso'
