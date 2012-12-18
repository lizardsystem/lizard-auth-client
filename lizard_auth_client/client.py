import requests
import json
from urlparse import urljoin

from itsdangerous import URLSafeTimedSerializer, BadSignature

class AutheticationFailed(Exception):
    pass

class CommunicationError(Exception):
    pass

def _do_post(sso_server_private_url, sso_key, sso_secret, username, password):
    '''
    Posts the specified username and password combination to the
    authentication API listening on sso_server_private_url.

    Returns the response of the service as a dict.

    Raises :class:`HTTPError` or :class:`URLError`
    or :class:`CommunicationError`, if one occurred.
    '''
    # define the message we want to send
    params = {
        'username': username,
        'password': password,
        'key': sso_key,
    }

    # encrypt it
    message = URLSafeTimedSerializer(sso_secret).dumps(params)

    # determine headers and destination URL
    post_data = {
        'message': message,
        'key': sso_key,
    }
    headers = {
        'content-type': 'application/json'
    }
    url = urljoin(sso_server_private_url, 'sso/authenticate') + '/'

    # do the posts usings the rather nice 'requests' library
    r = requests.post(url, data=post_data, headers=headers)
    if r.status_code == requests.codes.ok:
        result = json.loads(r.text)
        if isinstance(result, dict):
            return result
        else:
            raise CommunicationError(
                'did not recieve a dict / associative array as response'
            )
    else:
        r.raise_for_status()

def sso_authenticate(sso_server_private_url, sso_key, sso_secret, username, password):
    '''
    Returns a dict containing user data, if authentication succeeds. Example
    keys are 'first_name', 'pk', 'last_name', 'organisation', et cetera.

    Raises :class:`AutheticationFailed`, if the username / password
    combination is incorrect.

    Raises :class:`HTTPError` or :class:`URLError`
    or :class:`CommunicationError`, if one occurred.
    '''
    try:
        data = _do_post(
            sso_server_private_url,
            sso_key,
            sso_secret,
            username,
            password
        )
    except Exception as ex:
        raise CommunicationError(ex)

    # validate response a bit
    if not 'success' in data:
        raise CommunicationError('got an OK result, but with unknown content')

    # either return the user instance as dict, or raise an authentication error
    if data['success'] is True:
        return data['user']
    else:
        raise AutheticationFailed(data['error'])

def sso_authenticate_django(username, password):
    '''
    Same as sso_authenticate(), but uses the Django settings module to import
    the URL base and encryption keys.
    '''
    # import here so this module can easily be reused outside of Django
    from django.conf import settings

    # call with django setting for SSO url
    return sso_authenticate(
        settings.SSO_SERVER_PRIVATE_URL,
        settings.SSO_KEY,
        settings.SSO_SECRET,
        username,
        password
    )
