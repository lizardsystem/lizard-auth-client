lizard-auth-client
==========================================

Based on the Django Simple SSO project (https://github.com/ojii/django-simple-sso). MIT license.

Usage:

Include this app as a dependecy in setup.py:

    install_requires = [
        'lizard-auth-client',
    ],

Add it in your INSTALLED_APPS:

    INSTALLED_APPS = (
        'lizard_auth_client',
    )

Configure the SSO settings as seen in testsettings.py:

    # SSO
    SSO_STANDALONE = True
    # A key identifying this client. Can be published.
    SSO_KEY = 'random_generated_key_to_identify_the_client'
    # A *secret* shared between client and server. Used to sign the messages exchanged between them.
    SSO_SECRET = 'random_generated_secret_key_to_sign_exchanged_messages'
    # URL used to redirect the user to the SSO server
    SSO_SERVER_PUBLIC_URL = 'http://external-address.site.tld/'
    # URL used for server-to-server communication
    SSO_SERVER_PRIVATE_URL = 'http://10.0.0.1:80/'

Add the proper URLS to your urls.py. Because the app needs to override the login/logout URLS,
import them in the root of your urlpatterns:

    urlpatterns = patterns(
        '',
        (r'^', include('lizard_auth_client.urls')),
    )
