# (c) Nelen & Schuurmans.  GPL licensed, see LICENSE.rst.
# -*- coding: utf-8 -*-

"""View decorators."""

# Python 3 is coming
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

from functools import wraps
from django.contrib.auth.views import redirect_to_login
from django.conf import settings
from django.utils.decorators import available_attrs
from django.utils.encoding import force_str
from django.utils.six.moves.urllib.parse import urlparse

SESSION_ATTEMPT_MADE = 'LIZARD_AUTH_CLIENT_LOGIN_ATTEMPT_MADE'


def attempt_auto_login(view):
    """Attempt to login an unauthenticated user using the SSO server.

    Contrary to login_required, this does not give an error or redirect
    to a login page if the user isn't logged in on the SSO server yet,
    but will then simply continue with an unauthenticated user.

    This attempt is only made once per session. The session field
    'LIZARD_AUTH_CLIENT_LOGIN_ATTEMPT_MADE' will be set, and subsequent
    calls will just continue on to the view with the user as currently
    set in the session.
    """

    @wraps(view, assigned=available_attrs(view))
    def wrapped_view(request, *args, **kwargs):
        if (SESSION_ATTEMPT_MADE in request.session or
                request.user.is_authenticated()):
            return view(request, *args, **kwargs)

        request.session[SESSION_ATTEMPT_MADE] = True

        path = request.build_absolute_uri()
        resolved_login_url = force_str(settings.LOGIN_URL)

        login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
        current_scheme, current_netloc = urlparse(path)[:2]

        if ((not login_scheme or login_scheme == current_scheme) and
                (not login_netloc or login_netloc == current_netloc)):
            path = request.get_full_path()

        return redirect_to_login(path, resolved_login_url)

    return wrapped_view
