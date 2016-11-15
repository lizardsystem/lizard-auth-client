# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.conf.urls import include
from django.conf.urls import url
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.core.exceptions import ImproperlyConfigured
from lizard_auth_client import views
from lizard_auth_client.conf import settings


def check_settings():
    """
    Ensure settings are valid, as this Django app is mostly included by
    other apps / sites.
    """
    if not settings.SSO_KEY:
        raise ImproperlyConfigured(
            'Please define a value for SSO_KEY in your settings. '
            'This (random) key is referenced in the model "Client" '
            'on the SSO server, and is used to identify this webserver.'
        )
    if not settings.SSO_SECRET:
        raise ImproperlyConfigured(
            'Please define a value for SSO_SECRET in your settings. '
            'This (random) key is shared between SSO server and clients '
            'to sign / encrypt tokens.'
        )

    if settings.SSO_USE_V2_LOGIN:
        if not settings.SSO_SERVER_API_START_URL:
            raise ImproperlyConfigured(
                'Please define a value for SSO_SERVER_API_START_URL '
                'your settings. This URL is used to locate the SSO server.'
            )
    else:
        if (not settings.SSO_SERVER_PUBLIC_URL or
            not settings.SSO_SERVER_PRIVATE_URL):
            raise ImproperlyConfigured(
                'Please define values for SSO_SERVER_PUBLIC_URL and '
                'SSO_SERVER_PRIVATE_URL in your settings. '
                'These URIs are used to locate the SSO server.'
            )

    # Check some old settings we don't want to use anymore.
    if hasattr(settings, 'SSO_SYNCED_USER_KEYS'):
        raise ImproperlyConfigured(
            "Deprecation warning: SSO_SYNCED_USER_KEYS isn't "
            "used anymore, see CHANGES.rst for version 1.0.")

    if "p-web-ws-00-d8" in settings.SSO_SERVER_PRIVATE_URL:
        raise ImproperlyConfigured(
            "Deprecation warning: outdated SSO_SERVER_PRIVATE_URL, "
            "use 110-sso-c1 instead of p-web-ws-00-d8.")


if settings.SSO_ENABLED:
    check_settings()

    urlpatterns = [
        # Note: ensure LOGIN_URL isn't defined in the settings
        # URLS the do the SSO redirect for login/logout
        url(r'^accounts/login/$',
            views.LoginView.as_view(),
            name='lizard_auth_client.sso_login'),
        url(r'^accounts/logout/$',
            views.LogoutView.as_view(),
            name='lizard_auth_client.sso_logout'),

        # Named aliases of the above URLs, for compatibility with
        # other Django apps
        url(r'^accounts/login/$',
            views.LoginView.as_view(),
            name='login'),
        url(r'^accounts/logout/$',
            views.LogoutView.as_view(),
            name='logout'),

        # URLS that perform the local login/logout
        # these are used by the SSO server to redirect the user back again
        url(r'^sso/local_login/$',
            views.LocalLoginView.as_view(),
            name='lizard_auth_client.sso_local_login'),
        url(r'^sso/local_not_logged_in/$',
            views.LocalNotLoggedInView.as_view(),
            name='lizard_auth_client.sso_local_not_logged_in'),
        url(r'^sso/local_logout/$',
            views.LocalLogoutView.as_view(),
            name='lizard_auth_client.sso_local_logout'),

        # User management views
        url(r'^sso/user_overview/$',
            views.UserOverviewView.as_view(),
            name='lizard_auth_client.user_overview'),
        url(r'^sso/search_new_user/$',
            views.SearchNewUserView.as_view(),
            name='lizard_auth_client.search_new_user'),
    ]
else:
    urlpatterns = []


if settings.SSO_STANDALONE is True:
    # when running standalone (for testing purposes), add some extra URLS
    admin.autodiscover()
    urlpatterns += [
        url(r'^$',           views.TestHomeView.as_view()),
        url(r'^protected/$', views.TestProtectedView.as_view()),
        url(r'^admin/',      include(admin.site.urls)),
    ]
    if settings.DEBUG:
        urlpatterns += staticfiles_urlpatterns()
