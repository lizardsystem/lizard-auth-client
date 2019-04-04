# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib import admin
from lizard_auth_client import models
from import_export.admin import ExportActionModelAdmin


@admin.register(models.Role)
class RoleAdmin(ExportActionModelAdmin, admin.ModelAdmin):
    list_display = ('name', 'code', 'unique_id')
    search_fields = ('name', 'code', 'unique_id')


@admin.register(models.Organisation)
class OrganisationAdmin(ExportActionModelAdmin, admin.ModelAdmin):
    list_display = ('name', 'unique_id')
    search_fields = ('name', 'unique_id')


@admin.register(models.UserOrganisationRole)
class UserOrganisationRoleAdmin(ExportActionModelAdmin, admin.ModelAdmin):
    list_display = ('user', 'organisation', 'role')
    search_fields = ('user', 'organisation', 'role')
    list_filter = ('organisation', 'role')
    list_display_links = ('user', 'organisation', 'role')
