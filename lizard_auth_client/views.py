# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from collections import namedtuple
import datetime
import json

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import AccessMixin
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.db import transaction
from django.forms.models import model_to_dict
from django.http import Http404
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.http import HttpResponsePermanentRedirect
from django.http import HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from django.views.generic import FormView
from django.views.generic.base import RedirectView, TemplateView, View

from itsdangerous import URLSafeTimedSerializer
import jwt
import requests
import six

from lizard_auth_client import client
from lizard_auth_client.client import sso_server_url
from lizard_auth_client.forms import (
    ManageUserAddForm, OrganisationSelectorForm,
    ManageUserOrganisationDetailForm)
from lizard_auth_client.conf import settings
from lizard_auth_client.models import Organisation, Role, UserOrganisationRole

try:
    from urlparse import urljoin
    from urllib import urlencode
except ImportError:
    from urllib.parse import urljoin, urlencode


# Used so we can login User objects we instantiated ourselves
BACKEND = ModelBackend()
JWT_EXPIRATION = datetime.timedelta(
    minutes=settings.SSO_JWT_EXPIRATION_MINUTES)


def _sso_post(viewname, payload):
    """Send a payload to the named URL at the SSO server.
    Args:
        viewname (str): The name of the URL (a bit like Django's reverse).
            See https://sso.lizard.net/api2/.
        payload (dict): A Python dictionary with key-value pairs to send.
    Returns:
        dict: The decoded JSON response.
    Raises:
        HTTPError, if one occured.
    """
    url = sso_server_url(viewname)
    # Add required fields to the payload. These cannot/should not
    # be set by the caller (will be overwritten if set).
    payload['iss'] = settings.SSO_KEY
    payload['exp'] = datetime.datetime.utcnow() + JWT_EXPIRATION
    # Sign the message.
    signed_message = jwt.encode(
        payload,
        settings.SSO_SECRET,
        algorithm=settings.SSO_JWT_ALGORITHM,
    )
    # Send the key along with the signed message. This is a
    # peculiarity of the SSO server: the signed message
    # already contains the key.
    r = requests.post(
        url, data={
            'message': signed_message,
            'key': settings.SSO_KEY,
        }
    )
    # Check that the request is succesful.
    r.raise_for_status()
    # Return the decoded JSON response.
    return r.json()


class HttpResponseServiceUnavailable(HttpResponse):
    status_code = 503


class TestHomeView(View):
    """
    Test view, only used in standalone mode.
    Display a minimal HTML page with some URLS.
    """
    def get(self, request, *args, **kwargs):
        user = request.user
        return HttpResponse(
            '<a href="/">home</a> | <a href="/protected">protected</a>'
            '| <a href="/accounts/logout">logout</a> '
            '| <a href="/accounts/login">login</a> '
            '| user={} | home @ client'
            ''.format(user)
        )


class TestProtectedView(View):
    """
    Test view, only used in standalone mode.
    Display a minimal HTML page with some URLS, but is "protected" by
    a login_required decorator.
    """
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(TestProtectedView, self).dispatch(
            request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        user = request.user
        return HttpResponse(
            '<a href="/">home</a> | <a href="/protected">protected</a>'
            '| <a href="/accounts/logout">logout</a> '
            '| <a href="/accounts/login">login</a>'
            '| user={} | protected @ client'
            ''.format(user)
        )


class LoginViewV1(View):
    """
    View that redirects the user to the SSO server.

    Requests a Request Token and then redirects the User to the the SSO Server.
    """
    def get(self, request, *args, **kwargs):
        # store the GET parameter named 'next', so we can redirect the user
        # to the requested page, after SSO login.
        next = get_next(request)
        request.session['sso_after_login_next'] = next
        domain = request.GET.get('domain', None)

        # Possibly only attempt to login, don't force it
        attempt_login_only = 'true' in request.GET.get(
            'attempt_login_only', 'false').lower()

        wrapped_response = get_request_token_and_determine_response(
            domain, attempt_login_only)

        if (issubclass(wrapped_response.http_response, HttpResponseRedirect) or
            issubclass(wrapped_response.http_response,
                       HttpResponsePermanentRedirect)):
            return wrapped_response.http_response(
                wrapped_response.redirect_url
            )
        else:
            return wrapped_response.http_response(
                wrapped_response.message
            )


def abs_reverse(request, url_name):
    """Return absolute url including domain name"""
    return request.build_absolute_uri(reverse(url_name))


class JWTLoginView(View):
    """Log in using JWT API (i.e., the V2 SSO API)."""

    def get(self, request, *args, **kwargs):
        next = get_next(request)
        request.session['sso_after_login_next'] = next

        payload = {
            # JWT standard items.
            'iss': settings.SSO_KEY,
            'exp': datetime.datetime.utcnow() + JWT_EXPIRATION,
            # Our items.
            'login_success_url': abs_reverse(
                request, 'lizard_auth_client.sso_local_login'),
            }
        if request.GET.get('attempt_login_only', 'false').lower() == 'true':
            # We don't force the user to log in. To signal that, we pass our
            # 'the user is not logged in' url, too.
            payload['unauthenticated_is_ok_url'] = abs_reverse(
                request,
                'lizard_auth_client.sso_local_not_logged_in')

        signed_message = jwt.encode(payload, settings.SSO_SECRET,
                                    algorithm=settings.SSO_JWT_ALGORITHM)
        query_string = urlencode({
            'message': signed_message,
            'key': settings.SSO_KEY
            })

        # Build an absolute URL pointing to the SSO server out of it.
        url = sso_server_url('login')
        url_with_params = '%s?%s' % (url, query_string)
        return HttpResponseRedirect(url_with_params)


class LocalLoginView(View):
    """
    Verifies the user token with the SSO server, and logs the user in.
    """
    def get(self, request, *args, **kwargs):
        # verify the authentication token and
        # retrieve the User instance from the SSO server
        message = request.GET.get('message', None)
        if not message:
            return HttpResponseBadRequest('No message')

        if settings.SSO_USE_V2_LOGIN:
            try:
                payload = jwt.decode(message, settings.SSO_SECRET,
                                     audience=settings.SSO_KEY)
            except jwt.exceptions.DecodeError:
                return HttpResponseBadRequest(
                    "Failed to decode JWT signature.")
            except jwt.exceptions.ExpiredSignatureError:
                return HttpResponseBadRequest(
                    "JWT recieved from the SSO has expired.")
            user_data = json.loads(payload['user'])
            user = client.construct_user(user_data)
        else:
            user = verify_auth_token(message)

        if not user:
            return HttpResponseBadRequest('Verification failed')

        # link the user instance to the default database backend
        # and call django-auth's login function
        user.backend = "%s.%s" % (BACKEND.__module__,
                                  BACKEND.__class__.__name__)
        django_login(request, user)
        # redirect the user to the stored "next" url, which is probably a
        # protected page
        if 'sso_after_login_next' in request.session:
            sso_after_login_next = request.session['sso_after_login_next']
            del request.session['sso_after_login_next']
        else:
            sso_after_login_next = getattr(
                settings, 'LOGIN_REDIRECT_URL', '/')

        return HttpResponseRedirect(sso_after_login_next)


class LocalNotLoggedInView(View):
    """
    The user has returned from the SSO server without logging in.
    Return him to his original page, unauthenticated.
    """
    def get(self, request, *args, **kwargs):
        """Redirect the user to the stored "next" url."""
        sso_after_login_next = request.session.pop(
            'sso_after_login_next', '/')
        return HttpResponseRedirect(sso_after_login_next)


class LogoutViewV1(View):
    """
    Redirect user to SSO server, to log out there.
    """
    def get(self, request, *args, **kwargs):
        # store the 'next' parameter in the session so we can
        # redirect the user afterwards
        next = get_next(request)
        request.session['sso_after_logout_next'] = next
        domain = request.GET.get('domain', None)

        url = build_sso_portal_action_url('logout', domain)
        # send the redirect response
        return HttpResponseRedirect(url)


class JWTLogoutView(View):
    """
    Redirect user to SSO server, to log out there.
    """
    def get(self, request, *args, **kwargs):
        # store the 'next' parameter in the session so we can
        # redirect the user afterwards
        next = get_next(request)
        request.session['sso_after_logout_next'] = next

        payload = {
            # JWT standard items.
            'iss': settings.SSO_KEY,
            'exp': datetime.datetime.utcnow() + JWT_EXPIRATION,
            # Our items.
            'logout_url': abs_reverse(
                request, 'lizard_auth_client.sso_local_logout'),
        }

        signed_message = jwt.encode(payload, settings.SSO_SECRET,
                                    algorithm=settings.SSO_JWT_ALGORITHM)
        query_string = urlencode({
            'message': signed_message,
            'key': settings.SSO_KEY
            })

        url = sso_server_url('logout')
        url = '%s?%s' % (url, query_string)

        # send the redirect response
        return HttpResponseRedirect(url)


class LocalLogoutView(View):
    """
    Log out locally. Mostly the user is redirected here by the SSO server.
    """
    def get(self, request, *args, **kwargs):
        # get the redirect url
        next = request.session.get(
            'sso_after_logout_next',
            getattr(settings, 'LOGIN_REDIRECT_URL', '/'))

        # django_logout also calls session.flush()
        django_logout(request)

        return HttpResponseRedirect(next)


def get_request_token():
    """
    Requests a Request Token from the SSO Server. Returns False if the request
    failed.
    """
    # construct a signed message containing the portal key
    params = {
        'key': settings.SSO_KEY
    }

    message = URLSafeTimedSerializer(settings.SSO_SECRET).dumps(params)
    url = urljoin(settings.SSO_SERVER_PRIVATE_URL,
                  'sso/api/request_token') + '/'

    # send the message to the SSO server
    response = requests.get(
        url,
        params={
            'key': settings.SSO_KEY,
            'message': message
        },
        timeout=10
    )
    if response.status_code != 200:
        return False

    # grab the token from the response
    data = URLSafeTimedSerializer(settings.SSO_SECRET).loads(
        response.content, max_age=300)
    return data['request_token']


def verify_auth_token(untrusted_message):
    """
    Verifies a Auth Token. Returns a
    django.contrib.auth.models.User instance if successful or False.
    """
    # decrypt the message
    untrusted = URLSafeTimedSerializer(settings.SSO_SECRET).loads(
        untrusted_message, max_age=300)

    # do some extra validation
    if 'auth_token' not in untrusted:
        return False
    if 'request_token' not in untrusted:
        return False

    # call the SSO server to verify the token
    params = {
        'auth_token': untrusted['auth_token'],
        'key': settings.SSO_KEY
    }
    message = URLSafeTimedSerializer(settings.SSO_SECRET).dumps(params)
    url = urljoin(settings.SSO_SERVER_PRIVATE_URL, 'sso/api/verify') + '/'
    response = requests.get(
        url,
        params={
            'key': settings.SSO_KEY,
            'message': message
        },
        timeout=10
    )

    # ensure the response is sane
    if response.status_code != 200:
        return False

    # build a User object from the message
    data = URLSafeTimedSerializer(settings.SSO_SECRET).loads(
        response.content, max_age=300)
    user_data = json.loads(data['user'])

    user = client.construct_user(user_data)

    if 'roles' in data:
        role_data = json.loads(data['roles'])
        client.synchronize_roles(user, role_data)

    return user


def get_next(request):
    """
    Given a request, returns the URL where a user should be redirected to
    after login. Defaults to LOGIN_REDIRECT_URL, or '/' if that is not set.
    """
    default = getattr(settings, 'LOGIN_REDIRECT_URL', '/')
    return request.GET.get('next', default)


def get_request_token_and_determine_response(
        domain=None, attempt_login_only=False):
    """
    Retrieve a Request token from the SSO server, and determine the proper
    HttpResponse to send to the user.

    When logging using via the REST API, the response is wrapped in JSON,
    because the redirection takes place in a client-side script.
    """
    WrappedResponse = namedtuple(
        'WrappedResponse', 'http_response, message, redirect_url')

    # Get a request token, which is used by the SSO server to verify
    # that the user is allowed to make a login request
    request_token = get_request_token()
    if not request_token:
        # Status code 503 service (sso server) unavailable
        return WrappedResponse(HttpResponseServiceUnavailable,
                               'Unable to obtain token', None)

    # Construct a (signed) set of GET parameters which are passed in the
    # redirect URL that goes to the SSO server.
    params = {
        'request_token': request_token,
        'key': settings.SSO_KEY,
        'domain': domain,
    }

    # If this is true, the SSO server does not force a login and only logs
    # in a user that is already logged in on the SSO server.
    if attempt_login_only:
        params['force_sso_login'] = False

    message = URLSafeTimedSerializer(settings.SSO_SECRET).dumps(params)
    query_string = urlencode([('message', message),
                              ('key', settings.SSO_KEY)])
    # Build an absolute URL pointing to the SSO server out of it.
    url = urljoin(settings.SSO_SERVER_PUBLIC_URL, 'sso/authorize') + '/'
    url = '%s?%s' % (url, query_string)

    return WrappedResponse(HttpResponseRedirect, 'OK', url)


def build_sso_portal_action_url(action, domain=None):
    """
    Constructs and signs a message containing the specified action parameter,
    and returns a URL which can be used to redirect the user.

    For example, with action='logout', this can be used to logout the user
    on the SSO server.
    """
    params = {
        'action': action,
        'key': settings.SSO_KEY,
        'domain': domain,
    }
    message = URLSafeTimedSerializer(settings.SSO_SECRET).dumps(params)
    query_string = urlencode([('message', message),
                              ('key', settings.SSO_KEY)])
    url = urljoin(settings.SSO_SERVER_PUBLIC_URL, 'sso/portal_action') + '/'
    url = '%s?%s' % (url, query_string)
    return url


# Let this setting determine which version of the login/logout to use.
LoginView = JWTLoginView if settings.SSO_USE_V2_LOGIN else LoginViewV1
LogoutView = JWTLogoutView if settings.SSO_USE_V2_LOGIN else LogoutViewV1

### management views ###

class RoleRequiredMixin(AccessMixin):
    """
    CBV mixin which verifies that the current user one of the specified
    roles.

    """
    role_required = None  # can be a string or a list of strings

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
        nr_of_user_organisation_roles = UserOrganisationRole.objects.filter(
            user=user, role__code__in=roles).count()
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
            return Organisation.objects.all()

        # fetch the managed organisations based on the UserOrganisationRole
        # instances of the request user
        user_organisation_roles = UserOrganisationRole.objects.filter(
            user=self.request.user,
            role__code__in=settings.SSO_MANAGER_ROLES)
        self.managed_organisations = Organisation.objects.distinct().filter(
            user_organisation_roles__in=user_organisation_roles)
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
        user_organisation_roles = UserOrganisationRole.objects.filter(
            organisation__in=managed_organisations, role=is_connected_role)
        self.managed_users = get_user_model().objects.all().distinct().filter(
            user_organisation_roles__in=user_organisation_roles)

        return self.managed_users


class ManageOrganisationSelector(
    RoleRequiredMixin, ManagedObjectsMixin, FormView):
    """Index view for managing user permissions."""

    form_class = OrganisationSelectorForm
    template_name = 'lizard_auth_client/management/users/index.html'

    role_required = settings.SSO_MANAGER_ROLES

    def get_context_data(self, **kwargs):
        """Add managed organisations and users to the context."""
        context = super(ManageOrganisationSelector, self).get_context_data(
            **kwargs)
        # put the managed organisations in the context
        context['organisations'] = self.get_managed_organisations()
        return context

    def get_initial(self):
        """
        Add organisations to the initial dict to be used in the form_class.
        """
        initial = super(ManageOrganisationSelector, self).get_initial()
        initial['organisations'] = self.get_managed_organisations()
        return initial

    def form_valid(self, form):
        """
        If the form is valid, redirect to the organisation detail page.
        """
        organisation_pk = form.cleaned_data['organisation']
        success_url = reverse(
            'lizard_auth_client.management_organisation_detail',
            kwargs={'pk': organisation_pk})
        return HttpResponseRedirect(success_url)

    def dispatch(self, request, *args, **kwargs):
        """Redirect to organisation management page if """
        # put the managed organisations in the context
        organisations = self.get_managed_organisations()
        if not organisations:
            raise Http404
        elif len(organisations) == 1:
            # redirect to organisation detail page
            organisation = organisations[0]
            redirect_to = reverse(
                'lizard_auth_client.management_organisation_detail',
                kwargs={'pk': organisation.pk})
            return HttpResponseRedirect(redirect_to=redirect_to)
        else:
            return super(ManageOrganisationSelector, self).dispatch(
                request, *args, **kwargs)


def get_user_role_matrix_for_organisation(user, organisation, roles):
    """
    Make a role matrix for the given user.

    :param user - a User instantce
    :param organisation - an Organisation instance
    :param roles - a dict containing role data with code and name as keys

    :return a list of booleans representing whether the given user has the
        roles for the given organisation, e.g. [True, False, False, False]

    """
    role_matrix = []
    for role in roles:
        try:
            user.user_organisation_roles.get(
                organisation=organisation, role__code=role['code'])
        except ObjectDoesNotExist:
            # the user does NOT have this role for this organisation
            role_matrix.append(False)
        else:
            # the user has this role for this organisation
            role_matrix.append(True)
    return role_matrix


class ManageOrganisationDetail(
    RoleRequiredMixin, ManagedObjectsMixin, TemplateView):
    """
    Handle the organisation management page.
    """
    # TODO: use a ModelDetailView?
    template_name = 'lizard_auth_client/management/organisation/index.html'

    role_required = settings.SSO_MANAGER_ROLES

    def get_context_data(self, **kwargs):
        """Store organisation in the context."""
        context = super(ManageOrganisationDetail, self).get_context_data(
            **kwargs)

        # add organisation to context
        if hasattr(self, 'organisation'):
            context['organisation'] = self.organisation

        # add roles for header column title
        roles = settings.SSO_AVAILABLE_ROLES
        context['roles'] = roles

        # add users with their role matrices to the context
        managed_users = self.get_managed_users([self.organisation])

        users = []
        for user in managed_users:
            user.role_matrix = get_user_role_matrix_for_organisation(
                user, self.organisation, roles)
            users.append(user)
        context['users'] = users

        return context

    def get(self, request, pk=None, *args, **kwargs):
        # TODO: add authorisation; can the user view this page for this
        # organisation
        try:
            self.organisation = Organisation.objects.get(pk=pk)
        except ObjectDoesNotExist:
            raise Http404
        # now return
        return super(ManageOrganisationDetail, self).get(
            request, *args, **kwargs)


class ManageUserOrganisationDetail(
    RoleRequiredMixin, ManagedObjectsMixin, FormView):

    form_class = ManageUserOrganisationDetailForm
    template_name = 'lizard_auth_client/management/users/detail.html'

    role_required = settings.SSO_MANAGER_ROLES

    def get_context_data(self, **kwargs):
        """Add organisation and user to the context."""
        context = super(ManageUserOrganisationDetail, self).get_context_data(
            **kwargs)
        context['organisation'] = self.organisation
        roles = settings.SSO_AVAILABLE_ROLES
        context['roles'] = roles
        role_matrix = get_user_role_matrix_for_organisation(
            self.user, self.organisation, roles)
        self.user.role_matrix = role_matrix
        context['user'] = self.user
        return context

    def dispatch(self, request, organisation_pk=None, user_pk=None, *args,
                 **kwargs):
        """
        Fetch requested organisation and user and store it as a class
        variable, so that they can be used in the context.
        """
        # filtering on managed organisations and users makes sure that the
        # request user has manage rights to for the given organisation and user
        # combo
        managed_organisations = self.get_managed_organisations()
        try:
            self.organisation = managed_organisations.get(pk=organisation_pk)
        except ObjectDoesNotExist:
            return HttpResponseForbidden()
        managed_users = self.get_managed_users(managed_organisations)
        try:
            self.user = managed_users.get(pk=user_pk)
        except ObjectDoesNotExist:
            return HttpResponseForbidden()
        return super(ManageUserOrganisationDetail, self).dispatch(
            request, organisation_pk, user_pk, *args, **kwargs)

    def get_form_kwargs(self):
        # TODO: add organisation to form and list of organisations the request
        # user manages and has a UserOrganisationRole instance with this user
        # (self.user)
        form_kwargs = super(ManageUserOrganisationDetail,
                            self).get_form_kwargs()
        form_kwargs['instance'] = self.user
        roles = settings.SSO_AVAILABLE_ROLES
        role_matrix = get_user_role_matrix_for_organisation(
            self.user, self.organisation, roles)
        form_kwargs['roles'] = zip(roles, role_matrix)
        return form_kwargs

    def get_initial(self):
        # add organisation to the initial dict
        initial = super(ManageUserOrganisationDetail, self).get_initial()
        initial['organisation'] = self.organisation.name
        return initial

    @transaction.atomic
    def form_valid(self, form):
        """
        Save the user organisation roles.

        form.cleaned_data example:
        {
            'username': u'sander.smits', 'first_name': u'Sander',
            'last_name': u'Smits', 'organisation': u'Nelen & Schuurmans',
            u'role_run_simulation': True, u'role_manage': False,
            u'role_follow_simulation': True, u'role_change_model': True,
            'email': u'sander.smits@nelen-schuurmans.nl'
        }
        """
        user_role_codes = [
            k[5:] for k in form.cleaned_data if
            k.startswith('role_') and form.cleaned_data[k] is True]

        # check whether the roles exist and if not, add them
        for user_role_code in user_role_codes:
            role = Role.objects.get(code=user_role_code)
            try:
                UserOrganisationRole.objects.get(
                    user=self.user, organisation=self.organisation,
                    role=role)
            except ObjectDoesNotExist:
                new_uor = UserOrganisationRole(
                    user=self.user, organisation=self.organisation, role=role)
                new_uor.save()

        # and delete roles that were removed
        uors = UserOrganisationRole.objects.filter(
            user=self.user, organisation=self.organisation)
        for uor in uors:
            if uor.role.code not in user_role_codes:
                uor.delete()

        # add the connected role; no matter what happen before
        is_connected_role = get_is_connected_role()
        UserOrganisationRole.objects.get_or_create(
            user=self.user, organisation=self.organisation,
            role=is_connected_role)

        return super(ManageUserOrganisationDetail, self).form_valid(form)

    def post(self, request, organisation_pk=None, user_pk=None, *args,
             **kwargs):
        # set success message
        messages.add_message(
            request, messages.SUCCESS,
            _("Successfully updated user %(username)s.") % {
                'username': self.user.username},
            fail_silently=True
        )
        return super(ManageUserOrganisationDetail, self).post(
            request, *args, **kwargs)

    def get_success_url(self):
        """Redirect to organisation detail view."""
        return reverse(
            'lizard_auth_client.management_organisation_detail',
            kwargs={'pk': self.organisation.id})


def get_is_connected_role():
    # now connect the user to this organisation
    is_connected_role, created = Role.objects.get_or_create(
        code=settings.SSO_CONNECTED_ROLE_CODE,
        defaults={
            'unique_id': '0', 'name': 'Connected',
            'internal_description': '-', 'external_description': '-'
        }
    )
    return is_connected_role


class ManageUserAddView(RoleRequiredMixin, ManagedObjectsMixin, FormView):

    form_class = ManageUserAddForm
    template_name = 'lizard_auth_client/management/users/add.html'

    role_required = settings.SSO_MANAGER_ROLES

    def get_context_data(self, **kwargs):
        context = super(ManageUserAddView, self).get_context_data(**kwargs)
        context['organisation'] = self.organisation
        return context

    def get_success_url(self):
        return reverse(
            'lizard_auth_client.management_organisation_detail',
            kwargs={'pk': self.organisation.id})

    @transaction.atomic
    def form_valid(self, form):
        prototype = form.save(commit=False)
        payload = model_to_dict(prototype, form.Meta.fields)
        # Once the activation process is finished, users receive a link to the
        # portal that initiated the creation of the new SSO account. This may
        # vary since the server can have multiple hostnames.
        payload['visit_url'] = self.request.get_host()
        response = _sso_post('new-user', payload)
        updated_values = response['user']
        # From the perspective of a manager, it's a new user, but the user
        # might already exist in the lizard_nxt database. In that case,
        # we'll update his credentials with the latest info from SSO.
        user, created = get_user_model().objects.update_or_create(
            username=updated_values.pop('username'),
            defaults=updated_values,
        )
        # We are talking about SSO-managed users, so we want to be sure
        # that the account has an unusuable password.
        user.set_unusable_password()
        user.save()

        # now connect the user to this organisation
        is_connected_role = get_is_connected_role()
        UserOrganisationRole.objects.get_or_create(
            user=user, organisation=self.organisation, role=is_connected_role)

        # TODO: add the other roles

        # set success message
        messages.add_message(
            self.request, messages.SUCCESS,
            _("User %(username)s is now connected to %(organisation)s.") % {
                'username': user.username, 'organisation': self.organisation},
            fail_silently=True
        )

        return super(ManageUserAddView, self).form_valid(form)

    def dispatch(self, request, organisation_pk=None, *args, **kwargs):
        managed_organisations = self.get_managed_organisations()
        try:
            self.organisation = managed_organisations.get(pk=organisation_pk)
        except ObjectDoesNotExist:
            return HttpResponseForbidden()
        return super(ManageUserAddView, self).dispatch(
            request, *args, **kwargs)


class ManageUserDeleteDetail(
    RoleRequiredMixin, ManagedObjectsMixin, RedirectView):
    """
    Remove a user from an organisation by deleting the related user
    organisation roles.
    """
    role_required = settings.SSO_MANAGER_ROLES

    def get_redirect_url(self, *args, **kwargs):
        """Redirect to the organisation detail view."""
        return reverse('lizard_auth_client.management_organisation_detail',
                       kwargs={'pk': self.organisation.id})

    def get(self, request, organisation_pk=None, user_pk=None, *args,
            **kwargs):
        """
        Check whether the request user is a manager for this
        user-organisation combo.
        """
        managed_organisations = self.get_managed_organisations()
        try:
            self.organisation = managed_organisations.get(pk=organisation_pk)
        except ObjectDoesNotExist:
            raise Http404
        managed_users = self.get_managed_users(managed_organisations)
        try:
            self.user = managed_users.get(pk=user_pk)
        except ObjectDoesNotExist:
            raise Http404

        # all clear; disconnect the user from the organisation by deleting all
        # its UserOrganisationRole instances
        uors = self.user.user_organisation_roles.filter(
            organisation=self.organisation)
        for uor in uors:
            uor.delete()

        # add success message
        messages.add_message(
            self.request, messages.SUCCESS,
            _("Successfully deleted user %(username)s from %(organisation)s.")
            % {'username': self.user.username,
               'organisation': self.organisation},
            fail_silently=True
        )

        # now redirect via the super.get()
        return super(ManageUserDeleteDetail, self).get(
            request, *args, **kwargs)



