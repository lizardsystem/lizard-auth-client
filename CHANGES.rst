Changelog of lizard-auth-client
===================================================


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
