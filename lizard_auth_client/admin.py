# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib import admin
from lizard_auth_client import models


class OrganisationAdmin(admin.ModelAdmin):
    model = models.Organisation
    list_display = ('name', 'unique_id', )
    search_fields = ('name', )


class UserOrganisationRoleAdmin(admin.ModelAdmin):
    model = models.UserOrganisationRole
    list_display = ('role', 'user', 'organisation', )
    search_fields = ('role__name', 'user__username', 'organisation__name', )
    list_filter = ('organisation', 'user',)


admin.site.register(models.Role)
admin.site.register(models.Organisation, OrganisationAdmin)
admin.site.register(models.UserOrganisationRole, UserOrganisationRoleAdmin)
