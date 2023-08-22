# (c) Nelen & Schuurmans.  GPL licensed, see LICENSE.rst.

"""Signal that gets sent when a user is synchronized, and one
function making use of it."""

# Python 3 is coming
from lizard_auth_client.conf import settings

import django.dispatch


# This signal is sent whenever a user was synchronized. Receivers
# get the user object, and a list of (organisation, role)
# tuples.
user_synchronized = django.dispatch.Signal()


def set_superuser_staff_callback(user, organisation_roles, **kwargs):
    """Set user's is_superuser or is_staff flag if needed.

    If SSO_CLIENT_SUPERUSER_ROLES or SSO_CLIENT_STAFF_ROLES is
    set, and the user has one of those roles, his 'superuser'
    or 'staff' flags are set and saved."""

    changed = False

    if not user.is_superuser:
        for rolecode in settings.SSO_CLIENT_SUPERUSER_ROLES:
            if any(rolecode == role.code
                   for (organisation, role) in organisation_roles):
                changed = True
                user.is_superuser = True

    if not user.is_staff:
        for rolecode in settings.SSO_CLIENT_STAFF_ROLES:
            if any(rolecode == role.code
                   for (organisation, role) in organisation_roles):
                changed = True
                user.is_staff = True

    if changed:
        user.save()


user_synchronized.connect(set_superuser_staff_callback)
