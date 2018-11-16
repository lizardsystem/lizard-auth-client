Changelog of lizard-auth-client
===================================================


2.17 (unreleased)
-----------------

- Changed default ordering for Organisation (is now by name).

- Added a migration to delete duplicate UserOrganisationRoles (keeping 1).

- Added a unique_together constraint to UserOrganisationRole (user,
  organisation, role).

- Added support for dumping and restoring UserOrganisationRoles by natural key.


2.16 (2018-11-01)
-----------------

- Make the signature of the authenticate method of SSOBackend compatible with
  Django 2.1 without breaking older versions.


2.15 (2018-09-03)
-----------------

- Bugfix: don't remove logged in user when removing other users.


2.14 (2018-08-21)
-----------------

- Moved django-nose from install to test dependencies.


2.13 (2018-07-06)
-----------------

- Some minor changes to make the lib Django >= 2.0 compatible.


2.12 (2017-12-11)
-----------------

- Check if an email address exists on the SSO server before adding new user, add
  the user if the username is the same on the SSO server else show a form error.

- Show a form error if the username already exists on the SSO server.


2.11 (2017-10-31)
-----------------

- Make compatible again with Django 1.6.


2.10 (2017-01-23)
-----------------

- Add ``login_required`` decorator to selected management views (because
  decorators are not inherited from ``RoleRequiredMixin``).


2.9.1 (2017-01-20)
------------------

- Added migration for role META.

- Added fix for user_overview template condition typo.


2.9 (2016-12-20)
----------------

- Changed the method ``create`` to ``get_or_create`` in migration 0003*
  to avoid failing tests.

2.8 (2016-12-09)
----------------

- Nicer error messages with better feedback (in English...) from the SSO
  server if something goes wrong.

- Such errors are logged in the site itself at error level now, making it
  easier to figure out what went wrong.


2.7 (2016-12-06)
----------------

- Add roles/permissions management views.

- Don't cache server URLs forever, refresh them after an hour.

- Sorting users on ``/sso/user_overview/`` alphabetically by email.

- Added the function ``get_user_org_role_dict()`` to the models module.
  The dictionary it returns will be used as JWT payload for
  3Di services to share user permissions (roles).


2.6 (2016-11-21)
----------------

- Added new ``SSO_ALLOW_ONLY_KNOWN_USERS``, ``True`` by default. If you use
  the V2 API, only users that already have an existing local account are
  allowed to log in. Set it to False to retain the old 'everybody can log in'
  behaviour.

- Added ``/sso/user_overview/`` page for enabling/disabling users, plus pages
  to search for a user on the SSO by email or to create a whole new user on
  the SSO.


2.5 (2016-11-15)
----------------

- From django 1.8 the ``optparse`` module is deprecated. The management
  commands are now adopted to the ``argparse`` style. That is, using the
  method ``add_arguments()``.

- Added missing (textual) db migration step.

- Removed south migrations: none of the sites that use lizard-auth-client are
  old enough anymore.

- Improved README with V2 API instructions and attempt-login-only middleware
  and decorator documentation.


2.4 (2016-10-21)
----------------

- Fixed UserFactory: it now creates a syntactically valid email address.

- Added V2 support for `sso_sync_organisations` management command.


2.3 (2016-09-26)
----------------

- API v2 2.0..... Lots of changes to correspond to the lizard-auth-server
  changes.

- ``SSO_SERVER_PUBLIC_URL_V2`` has been renamed to ``SERVER_API_START_URL``,
  which better matches the meaning. This start url returns the available SSO
  endpoints, which means most of the hardcoded URLs have been removed.

- Adjusted the JWT payloads for the new API.


2.2 (2016-09-14)
----------------

- Fixed authentication backend: it now also supports the v2 API.


2.1.1 (2016-09-02)
------------------

- Fixed django-appconf dependency: it was in the test dependencies instead of
  in the regular dependencies...


2.1 (2016-09-02)
----------------

- Removed unused ``utils.py`` which provided the ``gen_secret_key()``
  function.

- Added django-appconf for easier settings management. All settings with their
  defaults are now in ``conf.py``.

- The ``JWT_EXPIRATION_MINUTES`` setting is now called
  ``SSO_JWT_EXPIRATION_MINUTES`` for consistency.

- Provided a default (False) for ``SSO_USE_V2_LOGIN``.


2.0.1 (2016-09-02)
------------------

- Added a default (5 minutes) for ``JWT_EXPIRATION_MINUTES`` so you don't need
  to specify it in your own settings.


2.0 (2016-09-02)
----------------

- Added JWT expiration of 15 minutes.

- Added new views + other changes for switching to V2 (JWT) SSO API.

- Renamed 'return_unauthenticated'.

- Put the attemp_auto_login function into a middleware.

- Added an ``@attempt_auto_login`` decorator that attempts to auto-login, but
  doesn't complain (and doesn't try again) if the user is not logged in yet.

  This is to get functionality from ``@login_required`` (if the user is
  already logged in on the SSO server, he is automatically logged in), without
  making it mandatory to be logged in.

- Made urls.py compatible with Django 1.10.


1.13 (2016-04-25)
-----------------

- Do not set unusable password twice.


1.12 (2016-04-15)
-----------------

- Log authentication failures at info level (relieving Sentry).

- Add model factories to be used in tests.


1.11 (2016-03-07)
-----------------

- Added natural key to Organisation model.


1.10 (2016-01-25)
-----------------

- Made sure the string representation on models also works on python 3 (it
  also keeps working on python 2, of course). See
  https://docs.djangoproject.com/en/1.8/ref/utils/#django.utils.encoding.python_2_unicode_compatible
  [reinout]


1.9 (2015-11-03)
----------------

- Redirects after login / logout default to '/', this should be
  settings.LOGIN_REDIRECT_URL if available.


1.8 (2015-11-02)
----------------

- Synchronize roles when authenticating via SSOBackend.


1.7.1 (2015-10-27)
------------------

- Remove a user from revoked organisation roles.

- Fix duplicate user organisation roles.


1.7 (2015-10-26)
----------------

- In 1.6, the ``next`` parameter was removed from the requests to the SSO
  server as it interfered with django's own ``next`` parameter usage. In its
  place, a ``domain`` parameter is now passed. You can use this to redirect to
  a specific domain if your site responds to multiple domains.
  [reinout]


1.6 (2015-09-24)
----------------

- Updated test setup. We're now tested on travis-ci.org and our code coverage
  is measured on coveralls.io.
  [reinout]

- Not passing django's ``next`` parameter to the SSO server anymore. That
  served no purpose and actually resulted in a bug.
  [reinout]

- Removed two unused Login/LogoutApiView classes.
  [reinout]


1.5 (2015-07-20)
----------------

- Added functions to synchronize a particular user's roles and
  organiations. Previously this was synced when the user logged in,
  but these functions can be called in toher contexts.

- Added a special 'billing' role code that platforms are encouraged to use
  to signify which organisations should receive bills.

- A method lizard_auth_client.client.get_billable_organisation(user) returns
  the billable organisation for that user. There should only be exactly 1
  billable organisation for each user, although the SSO server does not
  enforce that yet.

- Add from_dict helper functions to Role, Organisation, OrganisationRole.

- Add helper functions to find out in which organisations a user has a
  given role.


1.4.1 (2015-06-29)
------------------

- Packaging fix. The migrations/ and management/ directories were missing.


1.4 (2015-06-22)
----------------

- Added django 1.7 app name configuration.


1.3 (2015-05-06)
----------------

- Improved the documentation.


1.2 (2015-04-29)
----------------

- Added support for Django 1.7.
  Updated the Django requirement and moved South dependency to
  ``extras_require``.
  Had to follow these instructions to make lizard_auth_client Django 1.7
  compatible:
  https://docs.djangoproject.com/en/1.7/topics/migrations/#libraries-third-party-apps
  Note that South is only necessary for projects using Django < 1.7.

- Moved South ``migrations`` to ``south_migrations`` folder.
  South 1.0 will always check south_migrations first before using the normal
  migrations folder.
  See: https://docs.djangoproject.com/en/1.7/topics/migrations/#libraries-third-party-apps

- Added new Django-style migrations.

- Removed ``south`` from the ``INSTALLED_APPS`` in the ``testsettings``.

- Removed ``include_package_data`` from ``setup.py``.


1.1 (2015-01-12)
----------------

- Added support for login on custom domains.


1.0 (2014-11-28)
----------------

- Moved to a better solution for the is_staff and is_superuser User flags:

  1. SSO_SYNCED_USER_KEYS is not used anymore (and setting it gives a
     warning at import time of client.py). Only first_name, last_name,
     email and is_active of a user are copied.

  2. Instead of those, a setting SSO_CLIENT_SUPERUSER_ROLES and/or
     SSO_CLIENT_STAFF_ROLES can be set to an iterable of roll codes. If the
     user has one of those roles (regardless of in which organisation),
     then is_superuser and/or is_staff are set, respectively.

  3. This is implemented using Django signals. If you want more customization
     of user permissions, you can write your own callback for
     lizard_auth_client.signals.user_synchronized to react to the user's
     roles getting synchronized. In that case, the callback in signals.py
     is a handy example.

- Added a warning log in case an actual internal server name at Nelen &
  Schuurmans is set is private SSO URL; we should move to a new one (110-sso-c1)
  that is an alias, so we have more flexibility.



0.14 (2014-11-19)
-----------------

- Using ``get_user_model()`` and ``settings.AUTH_USER_MODEL`` where applicable
  to get the user model instead of just using the hardcoded default django
  ``User``. See
  https://docs.djangoproject.com/en/1.6/topics/auth/customizing/#referencing-the-user-model
  . With a try/except and hasattr to keep it working on django 1.4.

  Without this, lizard-auth-client doesn't work on our Sentry installation.

- Renamed the 'AutheticationFailure' exception to 'AuthenticationFailure'. I suspect that
  this exception wasn't used outside this app, but if it was, you need to fix the typo too.

- Fix the _do_post method in client.py. It seems this code has never worked before...

- Add functions to call the sync organisations API.

- Add a management command ``sso_sync_organisations`` that calls
  ``client.synchronise_organisations()``, copying all the organisations
  that didn't exist here yet from the SSO server (regardless of
  portals) and updating any changed names.

  This solves the situation where data belonging to some organisation needs to be
  imported (and foreign keys to it set), but no user of that organisation had ever
  logged in so it didn't exist yet.


0.13 (2014-06-06)
-----------------

- Fixed HttpResponseRedirectBase import error.


0.12 (2014-04-10)
-----------------

- Fix imports of HttpRedirect classes because their location changed
  between Django 1.4 and 1.5.


0.11 (2014-02-11)
-----------------

- Fixed import error UNUSABLE_PASSWORD in Django 1.6.

- Fixed import for python 2.x.


0.10 (2014-01-10)
-----------------

- Fixed a missing urllib import (for python 3) that I fixed in other places
  already.


0.9 (2013-12-04)
----------------

- Added optional ``SSO_SYNC_USER_KEYS`` setting. Use it for instance to
  prevent syncing of the ``is_superuser`` and ``is_staff`` user attributes.

- Added python 3 and django 1.6 support.


0.8 (2013-09-12)
----------------

- Fixed bug LocalLoginView delete session key.

- Added models to Admin.


0.7 (2013-08-30)
----------------

- We don't use UserProfile anymore, so it was deleted.


0.6 (2013-08-30)
----------------

- Added organisations and roles.
- Removed permissions
- Added middleware to log users in automatically


0.5 (2013-03-24)
----------------

- Fixed a bug when synching user profiles.


0.4 (2013-02-22)
----------------

- PEP8 and PyFlakes fixes.

- Add a rest API to get the HTTP redirect URLS.

- Made checking the SSO config more optional, so you can include this in your
  apps, but keep SSO disabled anyway.


0.3 (2013-02-11)
----------------

- Added support for lizard-auth-server's new URL scheme.

- Added a test for the new unsigned Auth API.


0.2 (2012-12-19)
----------------

- Added a timeout to all 'requests' calls.


0.1 (2012-12-18)
----------------

- Initial project structure created with nensskel 1.30.dev0.

- First release of lizard-auth-client based on a heavily modified
  django-simple-sso.
