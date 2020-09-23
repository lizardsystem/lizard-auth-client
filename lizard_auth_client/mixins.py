# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib.auth import get_user_model
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from django.utils.encoding import force_text
from django.utils.functional import cached_property
from lizard_auth_client import constants
from lizard_auth_client import models
from lizard_auth_client.conf import settings


def get_is_connected_role():
    """Get or create the connection role."""
    is_connected_role, created = models.Role.objects.get_or_create(
        code=constants.CONNECTED_ROLE_CODE,
        defaults={
            'unique_id': '0', 'name': 'Connected',
            'internal_description': '-', 'external_description': '-'
        }
    )
    return is_connected_role


class AccessMixin(object):
    """
    N.B. this mixin is from Django >= 1.9. For now, Django 1.8 still needs
    to be supported since it is an LTS release. Therefore, we copied the
    AccessMixin here. If Django 1.9 is the minimum requirement for
    lizard-auth-client, this class can be imported from Django by:

    from django.contrib.auth.mixins import AccessMixin

    Abstract CBV mixin that gives access mixins the same customizable
    functionality.
    """
    login_url = None
    permission_denied_message = ''
    raise_exception = False
    redirect_field_name = REDIRECT_FIELD_NAME

    def get_login_url(self):
        """
        Override this method to override the login_url attribute.
        """
        login_url = self.login_url or settings.LOGIN_URL
        if not login_url:
            raise ImproperlyConfigured(
                '{0} is missing the login_url attribute. Define {0}.login_url,'
                'settings.LOGIN_URL, or override {0}.get_login_url().'.format(
                    self.__class__.__name__)
            )
        return force_text(login_url)

    def get_permission_denied_message(self):
        """
        Override this method to override the permission_denied_message
        attribute.
        """
        return self.permission_denied_message

    def get_redirect_field_name(self):
        """
        Override this method to override the redirect_field_name attribute.
        """
        return self.redirect_field_name

    def handle_no_permission(self):
        if self.raise_exception:
            raise PermissionDenied(self.get_permission_denied_message())
        return redirect_to_login(
            self.request.get_full_path(), self.get_login_url(),
            self.get_redirect_field_name())


class RoleRequiredMixin(AccessMixin):
    """
    CBV mixin which verifies that the current user has one of the specified
    roles.

    """
    role_required = None  # can be a string or a list of strings

    @cached_property
    def available_roles(self):
        """
        Return the available roles.

        Always exclude a role with the ``constants.CONNECTED_ROLE_CODE`` as
        code.
        If an ``SSO_IGNORE_ROLE_CODES`` setting present, exclude those as well.

        """
        qs = models.Role.objects.all()
        excluded_roles = []
        # always exclude the connected role
        excluded_roles.append(constants.CONNECTED_ROLE_CODE)
        if settings.SSO_IGNORE_ROLE_CODES:
            excluded_roles.extend(settings.SSO_IGNORE_ROLE_CODES)
        if excluded_roles:
            qs = qs.exclude(code__in=excluded_roles)
        return qs

    def get_role_required(self):
        """
        Override this method to override the role attribute.
        Must return an iterable.
        """
        if not self.role_required:
            raise ImproperlyConfigured(
                '{0} is missing the role attribute. Define {0}.role, or '
                'override {0}.get_role_required().'.format(
                    self.__class__.__name__)
            )
        if isinstance(self.role_required, str):
            roles = (self.role_required,)
        else:
            roles = self.role_required
        return roles

    def has_role(self):
        """
        Override this method to customize the way permissions are checked.
        """
        user = self.request.user
        # superusers have all roles implicitly
        if user.is_superuser:
            return True

        roles = self.get_role_required()
        nr_of_user_organisation_roles = models.UserOrganisationRole.objects.\
            filter(user=user, role__code__in=roles).count()
        if nr_of_user_organisation_roles > 0:
            return True
        else:
            return False

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        if not self.has_role():
            return self.handle_no_permission()
        return super(RoleRequiredMixin, self).dispatch(
            request, *args, **kwargs)


class ManagedObjectsMixin(object):
    """
    CBV mixin which provides a number of role/permission management-related
    fields:

    - managed_organisations: the organisations managed by the request user
    - managed_users: the users managed by the request user for the given
        organisation(s)

    """
    @cached_property
    def managed_organisations(self):
        """
        Get the managed organisations for the current user. And set it as an
        instance variable.
        """
        # superusers are allowed to manage all objects
        if self.request.user.is_superuser:
            return models.Organisation.objects.all()

        # fetch the managed organisations based on the UserOrganisationRole
        # instances of the request user
        user_organisation_roles = models.UserOrganisationRole.objects.filter(
            user=self.request.user,
            role__code__in=settings.SSO_MANAGER_ROLE_CODES)
        return models.Organisation.objects.distinct().\
            filter(user_organisation_roles__in=user_organisation_roles).\
            order_by('name')

    def get_managed_users(self, managed_organisations):
        """
        Get all users for the managed organisations. And set it as an instance
        variable.

        :param managed_organisations - filter by these organisations
        """
        if hasattr(self, 'managed_users'):
            return self.managed_users

        # filter on organisation if given
        is_connected_role = get_is_connected_role()
        # filter on organisation if given
        user_organisation_roles = models.UserOrganisationRole.objects.filter(
            organisation__in=managed_organisations, role=is_connected_role)
        self.managed_users = get_user_model().objects.all().distinct().filter(
            user_organisation_roles__in=user_organisation_roles).order_by(
            'username')

        return self.managed_users
