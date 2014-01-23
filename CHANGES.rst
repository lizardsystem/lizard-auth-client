Changelog of lizard-auth-client
===================================================


0.10 (unreleased)
-----------------

- Fixed import for python 2.x.


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
