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

Add the proper URLS to your urls.py. Because the app needs to override the login/logout URLS,
import them in the root of your urlpatterns::

    urlpatterns = patterns(
        '',
        (r'^', include('lizard_auth_client.urls')),
    )


Usage note for django < 1.7
---------------------------

On django versions older than 1.7, you need South 1.0 for the database
migrations.

In your project's ``setup.py``, add ``lizard-auth-client[south]`` in addition
to ``lizard-auth-client``::

    install_requires = [
        ...
        'lizard-auth-client',
        'lizard-auth-client[south]',
        ...
    ],

This adds the proper south (version) requirement to your project.


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


Middleware
----------

The middleware automaticaly logs in users when they are known at the
server. And forces users to login at the server if they are not known.

To enable it, add this to your settings' ``MIDDLEWARE_CLASSES``::

    ...
    'lizard_auth_client.middleware.LoginRequiredMiddleware',
    ...

Note: ``django.contrib.auth.middleware.AuthenticationMiddleware``, enabled by
default, should be *above* the LoginRequiredMiddleware.



Tests
-----

To run the tests a running lizard-auth-server is needed.
