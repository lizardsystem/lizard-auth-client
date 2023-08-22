from django.contrib import admin
from lizard_auth_client import models


@admin.register(models.Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'code', 'unique_id')
    search_fields = ('name', 'code', 'unique_id')


@admin.register(models.Organisation)
class OrganisationAdmin(admin.ModelAdmin):
    list_display = ('name', 'unique_id')
    search_fields = ('name', 'unique_id')


@admin.register(models.UserOrganisationRole)
class UserOrganisationRoleAdmin(admin.ModelAdmin):
    list_display = ('user', 'organisation', 'role')
    search_fields = ('user__username', 'organisation__name')
    list_filter = ('role', 'organisation')
    list_display_links = ('user', 'organisation', 'role')
