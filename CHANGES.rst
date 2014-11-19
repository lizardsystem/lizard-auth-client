Changelog of lizard-auth-client
===================================================


0.14 (unreleased)
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
