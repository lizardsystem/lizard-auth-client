# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models


class Role(models.Model):
    unique_id = models.CharField(max_length=32, unique=True)
    code = models.CharField(max_length=255, null=False, blank=False)
    name = models.CharField(max_length=255, null=False, blank=False)
    external_description = models.TextField()
    internal_description = models.TextField()

    def __unicode__(self):
        return self.name


class Organisation(models.Model):
    # Don't make Organisation name unique because data is only
    # synchronized when someone in an organisation logs in -- we can't
    # guarantee that names will stay unique that way.
    name = models.CharField(max_length=255, null=False, blank=False)
    unique_id = models.CharField(max_length=32, unique=True)

    def __unicode__(self):
        return self.name


class UserOrganisationRole(models.Model):
    """Stores which roles in which organisations a user has."""
    user_model = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
    organisation = models.ForeignKey(user_model)
    role = models.ForeignKey(Role)

    def __unicode__(self):
        return '%s %s %s' % (
            str(self.user), str(self.organisation), str(self.role))
