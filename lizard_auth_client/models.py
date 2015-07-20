# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.db import models


class Role(models.Model):
    unique_id = models.CharField(max_length=32, unique=True)
    code = models.CharField(max_length=255, null=False, blank=False)
    name = models.CharField(max_length=255, null=False, blank=False)
    external_description = models.TextField()
    internal_description = models.TextField()

    BILLING_ROLE_CODE = 'billing'

    def __unicode__(self):
        return self.name

    @classmethod
    def create_from_dict(cls, dict_from_server):
        """Sync Role locally from the result of the server's
        Role.to_dict(). Return created role."""
        unique_id = dict_from_server['unique_id']

        # If server is on a later version than we are, the dict may contain
        # extra fields. Use only these.
        expected_fields = (
            'unique_id', 'code', 'name',
            'external_description', 'internal_description')

        d = {field: dict_from_server[field] for field in expected_fields}

        role, created = cls.objects.get_or_create(
            unique_id=unique_id, defaults=d)

        if not created:
            # Check for changes.
            changed = False
            for field in expected_fields:
                if getattr(role, field) != d[field]:
                    setattr(role, field, d[field])
                    changed = True
            if changed:
                role.save()

        return role


class Organisation(models.Model):
    # Don't make Organisation name unique because data is only
    # synchronized when someone in an organisation logs in -- we can't
    # guarantee that names will stay unique that way.
    name = models.CharField(max_length=255, null=False, blank=False)
    unique_id = models.CharField(max_length=32, unique=True)

    def __unicode__(self):
        return self.name

    @classmethod
    def create_from_dict(cls, dict_from_server):
        """Sync Organisation locally from the result of the server's
        Organisation.to_dict(). Return organisation"""
        unique_id = dict_from_server['unique_id']
        name = dict_from_server['name']

        org, created = cls.objects.get_or_create(
            unique_id=unique_id, defaults=dict(name=name))

        if not created and org.name != name:
            # It changed
            org.name = name
            org.save()

        return org


class UserOrganisationRole(models.Model):
    """Stores which roles in which organisations a user has."""
    user_model = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
    user = models.ForeignKey(user_model)
    organisation = models.ForeignKey(Organisation)
    role = models.ForeignKey(Role)

    def __unicode__(self):
        return '%s %s %s' % (
            str(self.user), str(self.organisation), str(self.role))

    @classmethod
    def create_from_list_of_dicts(cls, user, organisation_roles):
        """Sync from a user and a list of {organisation: ..., role: ...}
        dicts as returned from the server."""
        orgs_synced = dict()
        roles_synced = dict()

        # Remove old ones, then add the new ones.
        cls.objects.filter(user=user).delete()

        for organisation_role in organisation_roles:
            # Sync organisations and roles from their dicts, keep track
            # of which ones we have synced already.
            organisation_dict = organisation_role['organisation']
            role_dict = organisation_role['role']

            organisation_id = organisation_dict['unique_id']
            role_id = role_dict['unique_id']

            if organisation_id not in orgs_synced:
                orgs_synced[organisation_id] = Organisation.create_from_dict(
                    organisation_dict)
            organisation = orgs_synced[organisation_id]

            if role_id not in roles_synced:
                roles_synced[role_id] = Role.create_from_dict(role_dict)
            role = roles_synced[role_id]

            # Actually create the UserOrganisationRole instance.
            cls.objects.get_or_create(
                user=user, organisation=organisation, role=role)


def get_organisations_with_role(user, rolecode):
    """Return a queryset of organisations in which user has this role."""
    return Organisation.objects.filter(
        userorganisationrole__user=user,
        userorganisationrole__role__code=rolecode)


def get_organisation_with_role(user, rolecode):
    """Use this version of the function if there must be only a single
    organisation in which the user has this role.

    Raises Organisation.DoesNotExist if user has no such organisation, or
    Organisation.MultipleObjectsReturned if he has more than one.
    """
    return get_organisations_with_role(user, rolecode).get()
