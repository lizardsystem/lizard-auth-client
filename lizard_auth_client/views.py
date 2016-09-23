# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from collections import namedtuple
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponsePermanentRedirect
from django.http import HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.views.generic.base import View
from itsdangerous import URLSafeTimedSerializer
from lizard_auth_client import client
from lizard_auth_client.conf import settings

import datetime
import json
import jwt
import requests


try:
    from urlparse import urljoin
    from urllib import urlencode
except ImportError:
    from urllib.parse import urljoin, urlencode


# Used so we can login User objects we instantiated ourselves
BACKEND = ModelBackend()
JWT_EXPIRATION = datetime.timedelta(
    minutes=settings.SSO_JWT_EXPIRATION_MINUTES)


class HttpResponseServiceUnavailable(HttpResponse):
    status_code = 503


class TestHomeView(View):
    '''
    Test view, only used in standalone mode.
    Display a minimal HTML page with some URLS.
    '''
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
    '''
    Test view, only used in standalone mode.
    Display a minimal HTML page with some URLS, but is "protected" by
    a login_required decorator.
    '''
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
    '''
    View that redirects the user to the SSO server.

    Requests a Request Token and then redirects the User to the the SSO Server.
    '''
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


def sso_server_url(name):
    """Return url of endpoint on the SSO server

    The v2 API has a starting point that lists the available endpoints. We
    wrap that url and cache it.

    Args:
        name: name of the endpoint. Currently it can be ``check-credentials``,
            ``login``, ``logout``.

    Returns:
        full URL of the requested endpoint.

    Raises:
        KeyError: if the name isn't a known endpoint of the SSO server.

    """
    cache_key = 'cached_sso_server_urls'
    sso_server_urls = cache.get(cache_key)
    if sso_server_urls is None:
        # First time, grab it from the server.
        response = requests.get(settings.SSO_SERVER_API_START_URL, timeout=10)
        sso_server_urls = response.json()
        cache.set(cache_key, sso_server_urls)
    return sso_server_urls[name]


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
            'login_success_url': reverse('lizard_auth_client.sso_local_login'),
            }
        if request.GET.get('attempt_login_only', 'false').lower() == 'true':
            # We don't force the user to log in. To signal that, we pass our
            # 'the user is not logged in' url, too.
            payload['unauthenticated_is_ok_url'] = reverse(
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
    '''
    Verifies the user token with the SSO server, and logs the user in.
    '''
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
    '''
    Redirect user to SSO server, to log out there.
    '''
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
    '''
    Redirect user to SSO server, to log out there.
    '''
    def get(self, request, *args, **kwargs):
        # store the 'next' parameter in the session so we can
        # redirect the user afterwards
        next = get_next(request)
        request.session['sso_after_logout_next'] = next

        payload = {
            # Identifier for this site
            'iss': settings.SSO_KEY,
            # Set timeout
            'exp': datetime.datetime.utcnow() + JWT_EXPIRATION
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
    '''
    Log out locally. Mostly the user is redirected here by the SSO server.
    '''
    def get(self, request, *args, **kwargs):
        # get the redirect url
        next = request.session.get(
            'sso_after_logout_next',
            getattr(settings, 'LOGIN_REDIRECT_URL', '/'))

        # django_logout also calls session.flush()
        django_logout(request)

        return HttpResponseRedirect(next)


def get_request_token():
    '''
    Requests a Request Token from the SSO Server. Returns False if the request
    failed.
    '''
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
    '''
    Verifies a Auth Token. Returns a
    django.contrib.auth.models.User instance if successful or False.
    '''
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
    '''
    Given a request, returns the URL where a user should be redirected to
    after login. Defaults to LOGIN_REDIRECT_URL, or '/' if that is not set.
    '''
    default = getattr(settings, 'LOGIN_REDIRECT_URL', '/')
    return request.GET.get('next', default)


def get_request_token_and_determine_response(
        domain=None, attempt_login_only=False):
    '''
    Retrieve a Request token from the SSO server, and determine the proper
    HttpResponse to send to the user.

    When logging using via the REST API, the response is wrapped in JSON,
    because the redirection takes place in a client-side script.
    '''
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
    '''
    Constructs and signs a message containing the specified action parameter,
    and returns a URL which can be used to redirect the user.

    For example, with action='logout', this can be used to logout the user
    on the SSO server.
    '''
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
