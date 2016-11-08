lizard-auth-client
==========================================

.. image:: https://travis-ci.org/lizardsystem/lizard-auth-client.svg?branch=reinout-next-nxt-removal
    :target: https://travis-ci.org/lizardsystem/lizard-auth-client


.. image:: https://coveralls.io/repos/lizardsystem/lizard-auth-client/badge.svg?branch=reinout-next-nxt-removal&service=github
  :target: https://coveralls.io/github/lizardsystem/lizard-auth-client?branch=reinout-next-nxt-removal



Based on the Django Simple SSO project (https://github.com/ojii/django-simple-sso). MIT license.


Usage
-----

Include this app as a dependency in setup.py::

    install_requires = [
        ...
        'lizard-auth-client',
        ...
    ],

And add it to ``INSTALLED_APPS`` in your django settings::

    INSTALLED_APPS = (
        ...
        'lizard_auth_client',
        ...)

Add the proper URLS to your urls.py. Because the app needs to override the login/logout URLS,
import them in the root of your urlpatterns::

    urlpatterns = patterns(
        '',
        (r'^', include('lizard_auth_client.urls')),
    )


Settings for the original V1 API
--------------------------------

Configure the SSO settings as seen in ``testsettings.py``::

    # SSO *can* be disabled for development with local accounts.
    SSO_ENABLED = True

    # Create a portal on the SSO server, this generates the SSO_KEY and
    # SSO_SECRET for you.
    # A key identifying this client. Can be published.
    SSO_KEY = 'random_generated_key_to_identify_the_client'
    # A *secret* shared between client and server.
    # Used to sign the messages exchanged between them.
    SSO_SECRET = 'random_generated_secret_key_to_sign_exchanged_messages'

    # URL used to redirect the user to the SSO server.
    # Note: needs a trailing slash
    SSO_SERVER_PUBLIC_URL = 'https://external-address.site.tld/'
    # URL used for server-to-server communication
    # Note: needs a trailing slash
    SSO_SERVER_PRIVATE_URL = 'http://10.0.0.1:80/'

Only for local testing of this very app do you need this additional setting::

    SSO_STANDALONE = True


Settings for the V2 API
-----------------------

The easiest way is to go to the SSO, create a portal in the admin and copy/paste
the settings directly from the portal's edit page in the admin. There's a
read-only field "settings for the V2 API" there. The result will be something
like this::

    SSO_ENABLED = True
    SSO_USE_V2_login = True
    SSO_SERVER_API_START_URL = 'https://sso.lizard.net/api2/'
    SSO_KEY = 'sdfkljlkasdflkasfdlkasfdlk;asdflkjlaksdfjlkas'
    SSO_SECRET = 'jklsdfjlksdfjklasdfkljasdfjlkasjkd;fasdf'



Custom authentication
---------------------

In a Django context, simple configure the app as above, and do::

    from lizard_auth_client import client as auth_client
    try:
        user_data = auth_client.sso_authenticate_django('username', 'password')
    except auth_client.AutheticationFailed as ex:
        return some_error_handler('Auth failed')
    except auth_client.CommunicationError as ex:
        return some_error_handler('Temporary comm error')
    except:
        return some_error_handler('Other error')

It should be usable without Django settings as well::

    user_data = auth_client.sso_authenticate('http://url.tld', 'key', 'secret' 'username', 'password')


Middleware: required login and attempted login
----------------------------------------------

Lizard-auth-client has two middleware classes.

The **first** middleware forces a login. If the user is already logged in to the
SSO, they are automatically logged in on our site. If not, they are forced to
login on the SSO first.

To enable it, add this to your settings' ``MIDDLEWARE_CLASSES``::

    ...
    'lizard_auth_client.middleware.LoginRequiredMiddleware',
    ...

The **second** middleware only attempts a login, it doesn't force it. If the
user is already logged in to the SSO, they are automatically logged in on our
site. If not, they are not forced to log in on the SSO and simply remain
anonymous.

This can be very handy if you point from one site to another and would prefer
the user to be logged in, but want to allow anonymous access, too.

To enable it, add this to your settings' ``MIDDLEWARE_CLASSES``::

    ...
    'lizard_auth_client.middleware.AttemptAutoLoginMiddleware',
    ...

Note: ``django.contrib.auth.middleware.AuthenticationMiddleware``, enabled by
default, should be *above* our middleware classes.


Decorators
----------

The first middleware's behaviour can be achieved by Django's standard
``@login_required`` decorator.

For the second middleware's behaviour we have our own ``@attempt_auto_login``
decorator::

    from lizard_auth_client.decorators import attempt_auto_login



Tests and local development
---------------------------

To run the tests, docker is used::

    $ docker-compose build
    $ docker-compose run web bin/test

For a test in your browser, you'll need to also start a local
lizard-auth-server. Or test against the staging SSO. For the V2 API, you can
use any of the development portals, as the new V2 API sends through full URLS
for the requests coming back to your development laptop, it won't look at the
portal's configuration regarding "redirect url" and "allowed domains". So any
portal is good, actually.
