# (c) Nelen & Schuurmans.  GPL licensed, see LICENSE.rst.
# -*- coding: utf-8 -*-

"""View decorators."""

# Python 3 is coming
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

import datetime
from functools import wraps
from django.contrib.auth.views import redirect_to_login
from lizard_auth_client.conf import settings
from django.utils.decorators import available_attrs
from django.utils.encoding import force_str
from django.utils.six.moves.urllib.parse import urlparse

RETRY_AFTER = datetime.timedelta(hours=1)  # Re-attempt autologin after this


# Note: the actual ISO 8601 is "%Y-%m-%dT%H:%M:%S.%fZ", which Python violates
ISO_8601_format = "%Y-%m-%dT%H:%M:%S.%f"


def attempt_auto_login(view):
    """Attempt to login an unauthenticated user using the SSO server.

    This decorator does several things:

    1. Attempt to log in a locally unauthenticated user using the SSO server.
    If this succeeds we are redirected back to the original page due to the
    way redirects are set up.

    2. If the user is not logged in in the SSO server, this happens:
    Contrary to login_required, this does not give an error or redirect
    to a login page if the user isn't logged in on the SSO server yet,
    but will then simply continue with an unauthenticated user.

    This attempt is only made once per session. The session field
    'AUTO_LOGIN_ATTEMPT' will be set, and subsequent calls will just continue
    on to the view with the user as currently set in the session.
    """

    @wraps(view, assigned=available_attrs(view))
    def wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated():
            return view(request, *args, **kwargs)

        now = datetime.datetime.now()
        if 'AUTO_LOGIN_ATTEMPT' in request.session:
            auto_login_attempt = datetime.datetime.strptime(
                request.session['AUTO_LOGIN_ATTEMPT'], ISO_8601_format)
            if auto_login_attempt >= (now - RETRY_AFTER):
                return view(request, *args, **kwargs)

        # datetime needs to be JSON serializable:
        request.session['AUTO_LOGIN_ATTEMPT'] = now.isoformat()

        path = request.build_absolute_uri()
        attempt_only_login_url = (
            force_str(settings.LOGIN_URL) + '?attempt_login_only=true')

        login_scheme, login_netloc = urlparse(attempt_only_login_url)[:2]
        current_scheme, current_netloc = urlparse(path)[:2]

        if ((not login_scheme or login_scheme == current_scheme) and
                (not login_netloc or login_netloc == current_netloc)):
            path = request.get_full_path()

        # the 'next' param is set with this redirect:
        return redirect_to_login(path, attempt_only_login_url)

    return wrapped_view
