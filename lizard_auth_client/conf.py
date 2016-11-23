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

    # available roles
    AVAILABLE_ROLES = [
        # viewer permissions
        {'code': 'follow_simulation', 'name': 'Follow simulation'},
        # operator permissions
        {'code': 'run_simulation', 'name': 'Run simulation'},
        # modeller permissions
        {'code': 'change_model', 'name': 'Change model'},
        # manager permission
        {'code': 'manage', 'name': 'Manage'},
    ]
    # A user can be connected to an organisation by a Role that has
    # the value of USER_IS_LINKED_ROLE_CODE as code. That way users can be
    # connected to organisations without having one of the permission
    # mentioned in the AVAILABLE_ROLES setting.
    CONNECTED_ROLE_CODE = 'is_connected'

    # management roles
    # manager is used by lizard-nxt and superman is used by 3di
    # 3di is about to adopt a more permission-based role naming, therefore
    # the can_manage role/permission
    MANAGER_ROLES = ['manager', 'superman', 'manage']

    class Meta:
        prefix = 'sso'
