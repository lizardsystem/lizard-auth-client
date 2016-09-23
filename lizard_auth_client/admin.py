# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib import admin
from lizard_auth_client import models


admin.site.register(models.Role)
admin.site.register(models.Organisation)
admin.site.register(models.UserOrganisationRole)
