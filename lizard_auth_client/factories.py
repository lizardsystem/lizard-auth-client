# -*- coding: utf-8 -*-
# (c) Nelen & Schuurmans, see LICENSE.rst.

"""Convenient model factories to be used in tests.

"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.utils.text import slugify
import factory

from lizard_auth_client.models import Organisation
from lizard_auth_client.models import Role
from lizard_auth_client.models import UserOrganisationRole


class UserFactory(factory.DjangoModelFactory):
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    username = factory.LazyAttribute(
        lambda x: '{}.{}'.format(slugify(x.first_name), slugify(x.last_name)))
    password = factory.Faker('password')
    email = factory.LazyAttribute(
        lambda x: '{}@gmail'.format(x.username))
    is_superuser = False
    is_staff = False
    is_active = True

    class Meta:
        model = User

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        user = model_class(*args, **kwargs)
        user.raw_password = user.password
        user.set_password(user.password)
        user.save()
        return user


class OrganisationFactory(factory.DjangoModelFactory):
    name = factory.Faker('company')
    unique_id = factory.Faker('md5')

    class Meta:
        model = Organisation


class RoleFactory(factory.DjangoModelFactory):
    unique_id = factory.Faker('md5')
    code = factory.Faker('ssn')
    name = factory.Faker('job')
    external_description = factory.Faker('sentence')
    internal_description = factory.Faker('sentence')

    class Meta:
        model = Role


class UserOrganisationRoleFactory(factory.DjangoModelFactory):
    user = factory.SubFactory(UserFactory)
    organisation = factory.SubFactory(OrganisationFactory)
    role = factory.SubFactory(RoleFactory)

    class Meta:
        model = UserOrganisationRole
