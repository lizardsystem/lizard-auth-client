# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User
from django.db.models.signals import post_save


class UserProfileManager(models.Manager):
    def fetch_for_user(self, user):
        if not user:
            raise AttributeError('Cant get UserProfile without user')
        return self.get(user=user)

class UserProfile(models.Model):
    '''
    Note: when migrating to Django 1.5, this is the ideal candidate
    for using the new custom User model features.

    Note: this is linked via Django's user profile support. This means
    all fields must be OPTIONAL.
    '''
    user = models.OneToOneField(User)
    organisations = models.ManyToManyField("Organisation", blank=True, null=True)
    roles = models.ManyToManyField("Role", blank=True, null=True)

    objects = UserProfileManager()

    def __unicode__(self):
        if self.user:
            return 'UserProfile {} ({}, {})'.format(self.pk, self.user, self.user.email)
        else:
            return 'UserProfile {}'.format(self.pk)

    def update_all(self, data):
        user = self.user

        user.email = data['email']
        user.first_name = data['first_name']
        user.last_name = data['last_name']
        user.save()

    @property
    def username(self):
        return self.user.username

    @property
    def full_name(self):
        return self.user.get_full_name()

    @property
    def first_name(self):
        return self.user.first_name

    @property
    def last_name(self):
        return self.user.last_name

    @property
    def email(self):
        return self.user.email

    @property
    def is_active(self):
        '''
        Returns True when the account is active, meaning the User has not been
        deactivated by an admin.

        Note: unrelated to account activation.
        '''
        return self.user.is_active

    @property
    def has_role(self, role):
    	'''
    	returns true if the user has the given role or False
    	'''
    	pass

    # @property
    # def roles(self):
    # 	'''
    # 	returns all the roles a user has
    # 	'''
    # 	pass

    @property
    def in_organization(self, organization):
    	pass

    # @property
    # def organizations(self):
    # 	pass
    

# have the creation of a User trigger the creation of a Profile
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

post_save.connect(create_user_profile, sender=User)


class Role(models.Model):
    code = models.CharField(max_length=255, null=False, blank=False)
    name = models.CharField(max_length=255, null=False, blank=False)
    external_description = models.TextField()
    internal_description = models.TextField()
    organisation = models.ForeignKey('Organisation')

    class Meta:
        unique_together = (('organisation', 'code'), )

    def __unicode__(self):
        return self.name


class Organisation(models.Model):
    name = models.CharField(max_length=255, null=False, blank=False, unique=True)
    unique_id = models.CharField(max_length=32, unique=True)

    def __unicode__(self):
        return self.name
