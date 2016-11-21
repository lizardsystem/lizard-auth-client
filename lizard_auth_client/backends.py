# (c) Nelen & Schuurmans.  MIT licensed, see LICENSE.rst.
from __future__ import unicode_literals
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.hashers import check_password
from django.contrib.auth.hashers import is_password_usable
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.core.cache import cache
from lizard_auth_client import client
from lizard_auth_client.conf import settings

import logging


logger = logging.getLogger(__name__)


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
                    if settings.SSO_USE_V2_LOGIN:
                        if settings.SSO_ALLOW_ONLY_KNOWN_USERS:
                            # First check if the user is known.
                            if not User.objects.filter(
                                    username=username,
                                    is_active=True).exists():
                                logger.debug(
                                    "Username %s isn't known/active locally",
                                    username)
                                return None

                        user_data = client.sso_authenticate_django_v2(
                            username, password)
                    else:
                        user_data = client.sso_authenticate_django_v1(
                            username, password)

                    # Store user_data in cache.
                    hashed_password = make_password(password)
                    if not is_password_usable(hashed_password):
                        return None
                    else:
                        cache.set(
                            cache_key,
                            (user_data, hashed_password),
                            settings.SSO_CREDENTIAL_CACHE_TIMEOUT_SECONDS)
                # Use either the cached user profile data, or fresh data from
                # the SSO server to construct a Django User instance. If
                # fresh data is used, also synchronize roles.
                if user_data:
                    user = client.construct_user(user_data)
                    if not cached_credentials:
                        if not settings.SSO_USE_V2_LOGIN:
                            client.sso_sync_user_organisation_roles(user)
                    return user
        except client.AuthenticationFailed as e:
            logger.info(e)
            return None
        except:
            logger.exception('Error while authenticating user "%s".', username)
            return None
