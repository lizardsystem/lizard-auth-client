# (c) Nelen & Schuurmans.  MIT licensed, see LICENSE.rst.
from __future__ import unicode_literals

import logging

from django.core.cache import cache
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.hashers import check_password, make_password

try:
    from django.contrib.auth.hashers import UNUSABLE_PASSWORD
except:
    #ImproperlyConfigured:
    # Don't know what is wrong
    UNUSABLE_PASSWORD = 'bla'

from django.conf import settings

from lizard_auth_client import client

logger = logging.getLogger(__name__)

SSO_CREDENTIAL_CACHE_TIMEOUT_SECONDS = getattr(
    settings, 'SSO_CREDENTIAL_CACHE_TIMEOUT_SECONDS', 60)


class SSOBackend(ModelBackend):
    """
    Backend which validates username and password by making
    a call to the configured SSO server.

    Credentials are cached for 60 seconds, unless configured otherwise.

    Set SSO_CREDENTIAL_CACHE_TIMEOUT_SECONDS for this.
    """

    def authenticate(self, username=None, password=None):
        try:
            if username and password:
                user_data = None
                cache_key = 'SSOBackend.authenticate.{0}'.format(username)
                # Try getting the user_data from cache first.
                cached_credentials = cache.get(cache_key)
                if cached_credentials is not None:
                    logger.debug(
                        'Found user "%s" in the credential cache.', username)
                    # Found in cache, check the (hashed) password.
                    (cached_user_data,
                     cached_hashed_password) = cached_credentials
                    if check_password(password, cached_hashed_password):
                        logger.debug('Cached hashed password is OK.')
                        user_data = cached_user_data
                    else:
                        logger.debug(
                            'Failed cached password check for user "%s".',
                            username)
                else:
                    logger.debug(
                        'Could not find user "%s" in the credential cache.',
                        username)
                    # Not found in cache, call the SSO server.
                    user_data = client.sso_authenticate_django(
                        username, password)
                    # Store user_data in cache.
                    hashed_password = make_password(password)
                    if hashed_password is UNUSABLE_PASSWORD:
                        return None
                    else:
                        cache.set(
                            cache_key,
                            (user_data, hashed_password),
                            SSO_CREDENTIAL_CACHE_TIMEOUT_SECONDS)
                # Use either the cached user profile data, or fresh data from
                # the SSO server to construct a Django User instance. If
                # fresh data is used, also synchronize roles.
                if user_data:
                    user = client.construct_user(user_data)
                    if not cached_credentials:
                        client.sso_sync_user_organisation_roles(user)
                    return user
        except:
            logger.exception('Error while authenticating user "%s".', username)
            return None
