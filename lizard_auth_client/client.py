import requests
import json
try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin

from itsdangerous import URLSafeTimedSerializer

from lizard_auth_client import models



class AuthenticationFailed(Exception):
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

    Raises :class:`AuthenticationFailed`, if the username / password
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
    raise AuthenticationFailed(data['error'])


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
    raise AuthenticationFailed(data['error'])


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
    try:
        from django.contrib.auth import get_user_model
        # django 1.5+ custom user model.
        User = get_user_model()
    except ImportError:
        from django.contrib.auth.models import User

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

    # import here so this module can easily be reused outside of Django
    from django.conf import settings
    # copy simple properies like email and first name
    keys = getattr(settings, 'SSO_SYNCED_USER_KEYS',
                   ['first_name', 'last_name', 'email', 'is_active',
                    'is_staff', 'is_superuser'])
    for key in keys:
        setattr(user, key, data[key])
    user.username = local_username

    # ensure user can't login
    user.set_unusable_password()
    user.save()

    # Note we don't set any permissions here -- not handled by SSO
    # anymore.

    # user now contains a nice User object
    return user


def synchronize_roles(user, received_role_data):
    """Setup organizations and roles for this user based on information
    received from the SSO server.

    roles is a dictionary that has three keys:
    'organisations': a list of dictionaries describing some organisations
    'roles': a list of dictionaries describing some roles
    'organisation_roles': a list of pairs [organisation, role] that describes
                          which roles in which organisations this user has.

    Only the relevant organisations and roles are sent, so if we already
    have some role or organisation locally that isn't in the list, we should
    keep it. However, if an organisation_role isn't present, then the user
    doesn't have that role anymore, and we should remove it.

    We assume the data's structure is correct if present, and will get
    an internal server error if it's not."""

    organisations = dict()
    roles = dict()

    for org_data in received_role_data['organisations']:
        organisation, created = models.Organisation.objects.get_or_create(
            unique_id=org_data['unique_id'])
        if created or organisation.name != org_data['name']:
            organisation.name = org_data['name']
            organisation.save()
        organisations[organisation.unique_id] = organisation

    for role_data in received_role_data['roles']:
        role, created = models.Role.objects.get_or_create(
            unique_id=role_data['unique_id'])

        changed = False
        for field in (
                'code', 'name', 'external_description',
                'internal_description'):
            if getattr(role, field) != role_data[field]:
                setattr(role, field, role_data[field])
                changed = True

        if created or changed:
            role.save()
        roles[role.unique_id] = role

    # Delete existing organisation roles
    models.UserOrganisationRole.objects.filter(user=user).delete()

    # Renew them
    userorganisationroles = [
        models.UserOrganisationRole(
            user=user,
            organisation=organisations[org_unique_id],
            role=roles[role_unique_id])
        for org_unique_id, role_unique_id
        in received_role_data['organisation_roles']]
    models.UserOrganisationRole.objects.bulk_create(
        userorganisationroles)
