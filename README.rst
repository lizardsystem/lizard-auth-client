lizard-auth-client
==========================================

.. image:: https://coveralls.io/repos/lizardsystem/lizard-auth-client/badge.svg?branch=master&service=github
  :target: https://coveralls.io/github/lizardsystem/lizard-auth-client?branch=master



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
        (r'', include('lizard_auth_client.urls')),
    )

If you use django >= 2.0 you have to use the ``path(route, view, kwargs=None, name=None)``
method like so::

    from django.urls import include, path

    urlpatterns = patterns(
        '',
        path(r'', include('lizard_auth_client.urls')),
        ...
    )

Optionally, add our authentication backend in addition to Django's default one::

    AUTHENTICATION_BACKENDS = ['django.contrib.auth.backends.ModelBackend',
                               'lizard_auth_client.backends.SSOBackend']

Normally, the authentication backend is not needed if you only log in through
the reguler part of your website, using the regular django login url. The
backend is used if you log in directly via ``/admin/`` or via django rest
framework.


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
    SSO_ALLOW_ONLY_KNOWN_USERS = True

Note that with these settings, logging in won't be allowed right away due to
the ``SSO_ALLOW_ONLY_KNOWN_USERS`` setting, see the section below.


Restricting access
------------------

In the V1 API, access to sites is handled in the SSO. In the V2 API, this is
considered authorization and thus it is not handled. Which means everyone can
theoretically log in to any site.

To prevent this, ``SSO_ALLOW_ONLY_KNOWN_USERS`` is set to ``True`` by
default. Only people that already have a local user object are allowed to log
in.

To create and manage user objects locally, a view (``/sso/user_overview/``)
exists that shows the known users, enabled and disabled ones. You can
disable/enable users and there's a link to search users on the SSO by email
and a link to create a completely new one. Note: you can set
``SSO_INVITATION_LANGUAGE``, this is the language used in the invitation email
send by the SSO to the new user.

For these management views, you need the ``auth.manage_users``
permission. This way you can allow customers without admin acces to manage
their users anyhow.

The layout is very, very basic. Create a custom
``templates/lizard_auth_server/base.html`` in your project and make sure
there's a ``{% block content %}``, this is where the actual template content
is placed. ``{{ view.title }}`` is available for the ``<title>`` tag.

You'll want to add a link to the ``lizard_auth_client.user_overview`` URL
somewhere in your site.


Custom authentication (normally not needed)
-------------------------------------------

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


Management pages for handling user-organisation roles/permissions
-----------------------------------------------------------------

Since SSO V2, authorisation management has been removed from the SSO server.
To still be able to manage user permissions per organisation, management pages
have been introduced to ``lizard-auth-client``. The main page is accessible
via ``/management/organisations/``. Users that are either superusers or have
management permissions see a list of manageable organisations on that page.
From there on, they can add users to their organisation(s) and manage their
permissions.

Users can be added to organisations without assigning permissions to them.
This is achieved by storing a ``UserOrganisationRole`` instance that has a
connected role. This happens automatically when a user is added to an
organisation. The connected role is only used for connecting users to
organisations.

Permissions can be added simply by adding a ``Role`` instance. This role will
show up automatically as a new role/permission, unless the role code is added
to the ``SSO_IGNORE_ROLE_CODES`` list setting.

The management pages depend on ``django-crispy-forms``. Therefore, to access the
role/permission management pages, you need to have ``django-crispy-forms``
installed and have it in your project's ``INSTALLED_APPS`` setting. Also, you need
to add the ``CRISPY_TEMPLATE_PACK`` setting to your project::

    CRISPY_TEMPLATE_PACK = 'bootstrap3'

Other settings:

- ``SSO_ROLES_LABEL``- the form label of the roles section (default: _("Permissions"))
- ``SSO_MANAGER_ROLE_CODES`` - role codes that define a manager role (default: ['manager', 'superman', 'manage'])


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

(Re)create & activate a virtualenv::

    $ rm -rf .venv
    $ virtualenv .venv --python=python3
    $ source .venv/bin/activate

Install package and run tests::

    (virtualenv)$ pip install django==2.2
    (virtualenv)$ pip install -e .[test]
    (virtualenv)$ python manage.py test

To not conflict with an optional local lizard-auth-server (running on port
5000, normally), we run on port **5050**::

    (virtualenv)$ python manage.py runserver 5050

For a test in your browser, you'll need to also start a local
lizard-auth-server. Or test against the staging SSO. For the V2 API, you can
use any of the development portals, as the new V2 API sends through full URLS
for the requests coming back to your development laptop, it won't look at the
portal's configuration regarding "redirect url" and "allowed domains". So any
portal is good, actually. Add the key and secret to
``lizard_auth_client/local_testsettings.py``::

    SSO_KEY = 'kljsdfljkdsfjlkdsf'
    SSO_SECRET = 'dfjkladjklsjklsdflkjf'

For local testing of this very app do you need this additional setting::

    SSO_STANDALONE = True

This setting is already there in the ``testsettings.py``.


Updating translations
---------------------

Go to the ``lizard_auth_client`` subdirectory::

    $ docker-compose run web /bin/bash
    $ cd lizard_auth_client
    $ ../bin/django makemessages --all

Update the translations (for Dutch), for instance with "poedit". Then compile
the new translations::

    $ ../bin/django compilemessages
