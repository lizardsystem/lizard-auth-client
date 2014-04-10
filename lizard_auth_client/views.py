# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from collections import namedtuple

import requests
import urllib
from urlparse import urljoin, urlparse

from django.conf import settings
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required
from django.http import (
    HttpResponseBadRequest,
    HttpResponsePermanentRedirect,
    HttpResponseRedirect,
)
from django.utils import simplejson
from django.http import HttpResponse
from django.views.generic.base import View
from django.utils.decorators import method_decorator

from itsdangerous import URLSafeTimedSerializer

from lizard_auth_client.client import construct_user


# used so we can login User objects we instantiated ourselves
BACKEND = ModelBackend()


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
            '| <a href="/accounts/logout">logout</a> | user={} | home @ client'
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
            '| user={} | protected @ client'
            ''.format(user)
        )


class LoginApiView(View):
    '''
    Login API, which can optionally be included in the urls of the
    root Django app. This allows a non-webbrowser client, like
    JavaScripts XmlHttpRequest, to implement HTTP redirects in their
    own custom way.
    '''
    def get(self, request, *args, **kwargs):
        # Redirect to the webclient after the SSO server dance
        request.session['sso_after_login_next'] = settings.WEBCLIENT

        # Get the login url with the token
        wrapped_response = get_request_token_and_determine_response()

        # This check could be done by checking if http_response is a
        # subclass of HttpResponseRedirectBase, but that class is
        # undocumented and has moved to another module between Django
        # 1.4 and 1.5, so don't do that.
        if issubclass(
            wrapped_response.http_response, HttpResponseRedirect
            ) or issubclass(
            wrapped_response.http_response, HttpResponsePermanentRedirect):

            # The response is a redirect (302) to the SSO server.
            # Wrap it in a normal HttpResponse, and have client-side code
            # handle the actual redirect.
            response_class = HttpResponse
            content_dict = {'login_url': wrapped_response.redirect_url}
        else:
            # Response is something else, like an error message.
            # Use the response class as-is and wrap the message
            # in JSON.
            response_class = wrapped_response.http_response
            content_dict = {'message': wrapped_response.message}

        content = simplejson.dumps(content_dict)
        return response_class(content=content, content_type='application/json')


class LogoutApiView(View):
    '''
    Logout API, which can optionally be included in the urls of the
    root Django app. This allows a non-webbrowser client, like
    JavaScripts XmlHttpRequest, to implement HTTP redirects in their
    own custom way.
    '''
    def get(self, request, *args, **kwargs):
        # Redirect to the webclient after the SSO server dance
        request.session['sso_after_logout_next'] = settings.WEBCLIENT

        # Simple wrap the logout url in a JSON dict
        logout_url = build_sso_portal_action_url('logout')
        content_dict = {'logout_url': logout_url}
        content = simplejson.dumps(content_dict)
        return HttpResponse(content=content, content_type='application/json')


class LoginView(View):
    '''
    View that redirects the user to the SSO server.

    Requests a Request Token and then redirects the User to the the SSO Server.
    '''
    def get(self, request, *args, **kwargs):
        # store the GET parameter named 'next', so we can redirect the user
        # to the requested page, after SSO login.
        next = get_next(request)
        request.session['sso_after_login_next'] = next

        wrapped_response = get_request_token_and_determine_response()

        if issubclass(wrapped_response.http_response,
                      HttpResponseRedirectBase):
            return wrapped_response.http_response(
                wrapped_response.redirect_url
            )
        else:
            return wrapped_response.http_response(
                wrapped_response.message
            )


class LocalLoginView(View):
    '''
    Verifies the user token with the SSO server, and logs the user in.
    '''
    def get(self, request, *args, **kwargs):
        # verify the authentication token and
        # retrieve the User instance from the SSO server
        user = verify_auth_token(request.GET['message'])
        if not user:
            return HttpResponseBadRequest('Verification failed')

        # link the user instance to the default database backend
        # and call django-auth's login function
        user.backend = "%s.%s" % (BACKEND.__module__,
                                  BACKEND.__class__.__name__)
        django_login(request, user)

        # redirect the user to the stored "next" url, which is probably a
        # protected page
        sso_after_login_next = request.session.get('sso_after_login_next', '/')
        request.session.delete('sso_after_login_next')
        return HttpResponseRedirect(sso_after_login_next)


class LogoutView(View):
    '''
    Redirect user to SSO server, to log out there.
    '''
    def get(self, request, *args, **kwargs):
        # store the 'next' parameter in the session so we can
        # redirect the user afterwards
        next = get_next(request)
        request.session['sso_after_logout_next'] = next

        url = build_sso_portal_action_url('logout')
        # send the redirect response
        return HttpResponseRedirect(url)


class LocalLogoutView(View):
    '''
    Log out locally. Mostly the user is redirected here by the SSO server.
    '''
    def get(self, request, *args, **kwargs):
        # get the redirect url
        next = request.session.get('sso_after_logout_next', '/')

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
    user_data = simplejson.loads(data['user'])
    return construct_user(user_data)


def get_next(request):
    '''
    Given a request, returns the URL where a user should be redirected to
    after login. Defaults to '/'.
    '''
    next = request.GET.get('next', None)
    if not next:
        return '/'
    netloc = urlparse(next)[1]

    # security check -- don't allow redirection to a different host
    # taken from django.contrib.auth.views.login
    if netloc and netloc != request.get_host():
        return '/'
    return next


def get_request_token_and_determine_response():
    '''
    Retrieve a Request token from the SSO server, and determine the proper
    HttpResponse to send to the user.

    When logging using via the REST API, the response is wrapped in JSON,
    because the redirection takes place in a client-side script.
    '''
    WrappedResponse = namedtuple('WrappedResponse', 'http_response, message, redirect_url')

    # get a request token, which is used by the SSO server to verify
    # that the user is allowed to make a login request
    request_token = get_request_token()
    if not request_token:
        # Status code 503 service (sso server) unavailable
        return WrappedResponse(HttpResponseServiceUnavailable, 'Unable to obtain token', None)

    # construct a (signed) set of GET parameters which are used to
    # redirect the user to the SSO server
    params = {
        'request_token': request_token,
        'key': settings.SSO_KEY
    }
    message = URLSafeTimedSerializer(settings.SSO_SECRET).dumps(params)
    query_string = urllib.urlencode([('message', message),
                                     ('key', settings.SSO_KEY)])
    # build an absolute URL pointing to the SSO server out of it
    url = urljoin(settings.SSO_SERVER_PUBLIC_URL, 'sso/authorize') + '/'
    url = '%s?%s' % (url, query_string)

    return WrappedResponse(HttpResponseRedirect, 'OK', url)


def build_sso_portal_action_url(action):
    '''
    Constructs and signs a message containing the specified action parameter,
    and returns a URL which can be used to redirect the user.

    For example, with action='logout', this can be used to logout the user
    on the SSO server.
    '''
    params = {
        'action': action,
        'key': settings.SSO_KEY
    }
    message = URLSafeTimedSerializer(settings.SSO_SECRET).dumps(params)
    query_string = urllib.urlencode([('message', message),
                                     ('key', settings.SSO_KEY)])
    url = urljoin(settings.SSO_SERVER_PUBLIC_URL, 'sso/portal_action') + '/'
    url = '%s?%s' % (url, query_string)
    return url
