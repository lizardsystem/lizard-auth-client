import requests
import json
from urlparse import urljoin

from itsdangerous import URLSafeTimedSerializer


class AutheticationFailed(Exception):
    pass


class CommunicationError(Exception):
    pass


class UserNotFound(Exception):
    pass


def _do_post(sso_server_private_url, sso_server_path, sso_key, sso_secret,
             **params):
    '''
    Posts the specified username and password combination to the
    authentication API listening on sso_server_private_url.

    Returns the response of the service as a dict.

    Raises :class:`HTTPError` or :class:`URLError`
    or :class:`CommunicationError`, if one occurred.
    '''
    # ensure nobody passes param 'key', because that's reserved
    # for the encryption method
    if 'key' in params:
        raise AttributeError('"key" is a reserved parameter')

    # augment the message we want to encrypt with the public key
    params['key'] = sso_key

    # encrypt it
    message = URLSafeTimedSerializer(sso_secret).dumps(params)

    # determine POST data
    post_data = {
        'message': message,
        'key': sso_key,
    }

    # determine headers and destination URL
    headers = {
        'content-type': 'application/json'
    }
    url = urljoin(sso_server_private_url, sso_server_path) + '/'

    # do the posts usings the rather nice 'requests' library
    r = requests.post(url, data=post_data, headers=headers, timeout=10)
    if r.status_code == requests.codes.ok:
        result = json.loads(r.text)
        if isinstance(result, dict):
            return result
        raise CommunicationError(
            'did not recieve a dict / associative array as response')
    r.raise_for_status()


def _do_post_unsigned(sso_server_private_url, sso_server_path, sso_key,
                      **params):
    '''
    Posts the specified username and password combination to the
    authentication API listening on sso_server_private_url.

    Returns the response of the service as a dict.

    Raises :class:`HTTPError` or :class:`URLError`
    or :class:`CommunicationError`, if one occurred.
    '''

    # determine POST data
    post_data = {
        'key': sso_key,
    }
    post_data.update(**params)

    # determine headers and destination URL
    headers = {
        'content-type': 'application/json'
    }
    url = urljoin(sso_server_private_url, sso_server_path) + '/'

    # do the posts usings the rather nice 'requests' library
    r = requests.post(url, data=post_data, headers=headers, timeout=10)
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


def sso_authenticate_unsigned(sso_server_private_url, sso_key, username,
                              password):
    '''
    Returns a dict containing user data, if authentication succeeds. Example
    keys are 'first_name', 'pk', 'last_name', 'organisation', et cetera.

    Raises :class:`AutheticationFailed`, if the username / password
    combination is incorrect.

    Raises :class:`HTTPError` or :class:`URLError`
    or :class:`CommunicationError`, if one occurred.
    '''
    try:
        data = _do_post_unsigned(
            sso_server_private_url,
            'api/authenticate_unsigned',
            sso_key,
            username=username,
            password=password
        )
    except Exception as ex:
        raise CommunicationError(ex)

    # validate response a bit
    if not 'success' in data:
        raise CommunicationError('got an OK result, but with unknown content')

    # either return the user instance as dict, or raise an authentication error
    if data['success'] is True:
        return data['user']
    raise AutheticationFailed(data['error'])


def sso_authenticate_unsigned_django(username, password):
    '''
    Same as sso_authenticate_unsigned(), but uses the Django settings module
    to import the URL base and portal key.
    '''
    # import here so this module can easily be reused outside of Django
    from django.conf import settings

    # call with django setting for SSO url
    return sso_authenticate_unsigned(
        settings.SSO_SERVER_PRIVATE_URL,
        settings.SSO_KEY,
        username,
        password
    )


def sso_authenticate(sso_server_private_url, sso_key, sso_secret, username,
                     password):
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
            'api/authenticate',
            sso_key,
            sso_secret,
            username=username,
            password=password
        )
    except Exception as ex:
        raise CommunicationError(ex)

    # validate response a bit
    if not 'success' in data:
        raise CommunicationError('got an OK result, but with unknown content')

    # either return the user instance as dict, or raise an authentication error
    if data['success'] is True:
        return data['user']
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


def sso_get_user(sso_server_private_url, sso_key, sso_secret, username):
    '''
    Returns a dict containing user data, if the username is found on the
    SSO server. Example keys are 'first_name', 'pk', 'last_name',
    'organisation', et cetera.

    Raises :class:`UserNotFound`, if the username can't be found.

    Raises :class:`HTTPError` or :class:`URLError`
    or :class:`CommunicationError`, if one occurred.
    '''
    try:
        data = _do_post(
            sso_server_private_url,
            'api/get_user',
            sso_key,
            sso_secret,
            username=username
        )
    except Exception as ex:
        raise CommunicationError(ex)

    # validate response a bit
    if not 'success' in data:
        raise CommunicationError('got an OK result, but with unknown content')

    # either return the user instance as dict, or raise an UserNotFound
    # exception
    if data['success'] is True:
        return data['user']
    raise UserNotFound(data['error'])


def sso_get_users(sso_server_private_url, sso_key, sso_secret):
    '''
    Returns a list of dicts containing user data for the portal in question.
    Example keys are 'first_name', 'pk', 'last_name', 'organisation', etc.

    Raises :class:`HTTPError` or :class:`URLError`
    or :class:`CommunicationError`, if one occurred.
    '''
    try:
        data = _do_post(
            sso_server_private_url,
            'api/get_users',
            sso_key,
            sso_secret
        )
    except Exception as ex:
        raise CommunicationError(ex)

    # validate response a bit
    if not 'success' in data:
        raise CommunicationError('got an OK result, but with unknown content')

    # either return the users as a list of dicts,
    # or raise an UserNotFound exception
    if data['success'] is True:
        return data['users']
    raise UserNotFound(data['error'])


def sso_get_user_django(username):
    '''
    Same as sso_get_user(), but uses the Django settings module to import
    the URL base and encryption keys.
    '''
    # import here so this module can easily be reused outside of Django
    from django.conf import settings

    # call with django setting for SSO url
    return sso_get_user(
        settings.SSO_SERVER_PRIVATE_URL,
        settings.SSO_KEY,
        settings.SSO_SECRET,
        username
    )


def sso_get_users_django():
    '''
    Same as sso_get_users(), but uses the Django settings module to import
    the URL base and encryption keys.
    '''
    # import here so this module can easily be reused outside of Django
    from django.conf import settings

    # call with django setting for SSO url
    return sso_get_users(
        settings.SSO_SERVER_PRIVATE_URL,
        settings.SSO_KEY,
        settings.SSO_SECRET
    )


def sso_populate_user_django(username):
    '''
    Returns an populated Django User instance with data fetched
    from the SSO server.

    Raises :class:`UserNotFound`, if the username can't be found.

    Raises :class:`HTTPError` or :class:`URLError`
    or :class:`CommunicationError`, if one occurred.
    '''
    return construct_user(sso_get_user_django(username))


def construct_user(data):
    '''
    Given a dict container user data, returns a populated and saved
    Django User instance.
    '''
    # import here so this module can easily be reused outside of Django
    from django.contrib.auth.models import User, Permission
    from django.contrib.contenttypes.models import ContentType

    # disabled for now
    # use the Primary Key of the User on the SSO server to
    # generate a new username
    #local_username = 'sso-user-{}'.format(data['pk'])
    # /disabled for now

    # just copy the username from the sso server for now
    local_username = data['username']

    # create or get a User instance
    try:
        user = User.objects.get(username=local_username)
    except User.DoesNotExist:
        user = User()

    # copy simple properies like email and first name
    for key in ['first_name', 'last_name', 'email']:
        setattr(user, key, data[key])
    user.username = local_username

    # ensure user can't login
    user.set_unusable_password()
    user.save()

    # copy permissions
    ctype_cache = {}
    permissions = []
    for perm in data['permissions']:
        ctype = ctype_cache.get(perm['codename'], None)
        if not ctype:
            try:
                ctype = ContentType.objects.get_by_natural_key(
                    perm['content_type'][0], perm['content_type'][1])
            except ContentType.DoesNotExist:
                continue
            ctype_cache[perm['codename']] = ctype
        try:
            permission = Permission.objects.get(content_type=ctype,
                                                codename=perm['codename'])
        except Permission.DoesNotExist:
            continue
        permissions.append(permission)
    user.user_permissions = permissions

    # user now contains a nice User object
    return user
