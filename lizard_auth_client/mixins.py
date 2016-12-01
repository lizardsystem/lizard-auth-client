# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib.auth import get_user_model, REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import (
    ImproperlyConfigured, ObjectDoesNotExist, PermissionDenied)
from django.utils import six
from django.utils.decorators import method_decorator
from django.utils.encoding import force_text

from lizard_auth_client import models
from lizard_auth_client.conf import settings


def get_is_connected_role():
    """Get or create the connection role."""
    is_connected_role, created = models.Role.objects.get_or_create(
        code=settings.SSO_CONNECTED_ROLE_CODE,
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
    CBV mixin which verifies that the current user one of the specified
    roles.

    """
    role_required = None  # can be a string or a list of strings

    @property
    def available_roles(self):
        """
        Return the available roles.

        If there is a ``SSO_CONNECTED_ROLE_CODE`` or a ``SSO_IGNORE_ROLE_CODES``
        setting present, exclude those.
        """
        # return cached available roles if present
        if hasattr(self, '_available_roles'):
            return self._available_roles

        qs = models.Role.objects.all()
        excluded_roles = []
        if settings.SSO_CONNECTED_ROLE_CODE:
            excluded_roles.append(settings.SSO_CONNECTED_ROLE_CODE)
        if settings.SSO_IGNORE_ROLE_CODES:
            excluded_roles.extend(settings.SSO_IGNORE_ROLE_CODES)
        if excluded_roles:
            qs = qs.exclude(code__in=excluded_roles)

        self._available_roles = qs
        return self._available_roles

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
        if isinstance(self.role_required, six.string_types):
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

    def get_managed_organisations(self):
        """
        Get the managed organisations for the current user. And set it as an
        instance variable.
        """
        if hasattr(self, 'managed_organisations'):
            return self.managed_organisations

        # superusers are allowed to manage all objects
        if self.request.user.is_superuser:
            return models.Organisation.objects.all()

        # fetch the managed organisations based on the UserOrganisationRole
        # instances of the request user
        user_organisation_roles = models.UserOrganisationRole.objects.filter(
            user=self.request.user,
            role__code__in=settings.SSO_MANAGER_ROLE_CODES)
        self.managed_organisations = models.Organisation.objects.distinct().\
            filter(user_organisation_roles__in=user_organisation_roles).\
            order_by('name')
        return self.managed_organisations

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
        user_organisation_roles = models.UserOrganisationRole.objects.filter(
            organisation__in=managed_organisations, role=is_connected_role)
        self.managed_users = get_user_model().objects.all().distinct().filter(
            user_organisation_roles__in=user_organisation_roles).order_by(
            'username')

        return self.managed_users

    def manage_roles(self):
        """
        Get all management roles based on the SSO_MANAGER_ROLE_CODES setting.
        """
        if hasattr(self, 'manage_roles'):
            return self.manage_roles

        manage_role_codes = settings.SSO_MANAGER_ROLE_CODES
        self.manage_roles = []
        for role_code in manage_role_codes:
            try:
                role = models.Role.objects.get(code=role_code)
            except ObjectDoesNotExist:
                pass
            else:
                self.manage_roles.append(role)

        return self.manage_roles
