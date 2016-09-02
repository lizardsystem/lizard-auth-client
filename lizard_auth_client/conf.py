# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from appconf import AppConf
from django.conf import settings


settings  # Pyflakes


class SSOAppConf(AppConf):
    SETTING_1 = "one"
    SETTING_2 = (
        "two",
    )

    class Meta:
        prefix = 'sso'
