import requests
import json
from urlparse import urljoin

class AutheticationFailed(Exception):
    pass

class CommunicationError(Exception):
    pass

def _do_post(url_base, username, password):
    url = urljoin(url_base, 'sso/authenticate') + '/'
    post_data = {
        'username': username,
        'password': password
    }
    headers = {
        'content-type': 'application/json'
    }
    r = requests.post(url, data=post_data, headers=headers)
    if r.status_code == requests.codes.ok:
        return json.loads(r.text)
    else:
        r.raise_for_status()

def sso_authenticate(url_base, username, password):
    try:
        data = _do_post(url_base, username, password)
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
    # import here so this module can easily be reused outside of Django
    from django.conf import settings

    # call with django setting for SSO url
    return sso_authenticate(settings.SSO_SERVER_PRIVATE_URL, username, password)
