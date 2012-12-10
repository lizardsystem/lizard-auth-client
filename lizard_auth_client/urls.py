# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf.urls.defaults import include
from django.conf.urls.defaults import patterns
from django.conf.urls.defaults import url
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

from lizard_auth_client import views


def check_settings():
    '''
    Ensure settings are valid, as this Django app is mostly included by
    other apps / sites.
    '''
    if not hasattr(settings, 'SSO_KEY'):
        raise ImproperlyConfigured(
            'Please define a value for SSO_KEY in your settings. '
            'This (random) key is referenced in the model "Client" on the SSO server, '
            'and is used to identify this webserver.'
        )
    if not hasattr(settings, 'SSO_SECRET'):
        raise ImproperlyConfigured(
            'Please define a value for SSO_SECRET in your settings. '
            'This (random) key is shared between SSO server and clients to sign / encrypt tokens.'
        )
    if not hasattr(settings, 'SSO_SERVER_PUBLIC_URL') or not hasattr(settings, 'SSO_SERVER_PRIVATE_URL'):
        raise ImproperlyConfigured(
            'Please define values for SSO_SERVER_PUBLIC_URL and SSO_SERVER_PRIVATE_URL in your settings. '
            'These URIs are used to locate the SSO server.'
        )
check_settings()

urlpatterns = patterns(
    '',
    # Note: ensure LOGIN_URL isn't defined in the settings
    # URLS the do the SSO redirect for login/logout
    url(r'^accounts/login/$',     views.LoginView.as_view(),        name='lizard_auth_client.sso_login'),
    url(r'^accounts/logout/$',    views.LogoutView.as_view(),       name='lizard_auth_client.sso_logout'),
    # Named aliases of the above URLs, for compatibility with other Django apps
    url(r'^accounts/login/$',     views.LoginView.as_view(),        name='login'),
    url(r'^accounts/logout/$',    views.LogoutView.as_view(),       name='logout'),
    # URLS that perform the local login/logout
    # these are used by the SSO server to redirect the user back again
    url(r'^sso/local_login/$',    views.LocalLoginView.as_view(),   name='lizard_auth_client.sso_local_login'),
    url(r'^sso/local_logout/$',   views.LocalLogoutView.as_view(),  name='lizard_auth_client.sso_local_logout'),
)

if getattr(settings, 'SSO_STANDALONE', False) is True:
    # when running standalone (for testing purposes), add some extra URLS
    admin.autodiscover()
    urlpatterns += (
        url(r'^$',           views.TestHomeView.as_view()),
        url(r'^protected/$', views.TestProtectedView.as_view()),
        url(r'^admin/',      include(admin.site.urls)),
    )
    if settings.DEBUG:
        urlpatterns += staticfiles_urlpatterns()
