# -*- coding: utf-8 -*-
# Yet untested, but we want them reported by coverage.py, so we import them.
from __future__ import unicode_literals
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.http import Http404
from django.test import Client
from django.test import RequestFactory
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse
from faker import Faker
from lizard_auth_client import backends
from lizard_auth_client import client
from lizard_auth_client import factories
from lizard_auth_client import forms
from lizard_auth_client import mixins
from lizard_auth_client import models
from lizard_auth_client import signals
from lizard_auth_client import urls
from lizard_auth_client import views  # NOQA
from lizard_auth_client.client import sso_server_url
from lizard_auth_client.conf import settings
from lizard_auth_client.models import get_user_org_role_dict
from requests.exceptions import HTTPError

import inspect
import json
import jwt
import logging
import mock
import pprint

logger = logging.getLogger(__name__)
fake = Faker()


class TestAuthenticate(TestCase):
    """
    In function `django.contrib.auth.__init__.authenticate` the signature of
    the `authenticate` method of the various authentication backends is
    inspected. Django 2.1 silently skips backends that do not comply! Our
    custom SSOBackend is used across different versions of Django, so it
    is very important to have the signature right.

    """
    def setUp(self):
        self.backend = backends.SSOBackend()
        self.request = None
        self.credentials = {
            'username': fake.user_name(),
            'password': fake.password(),
        }
        self.expected = {'request': self.request, 'kwargs': {}}
        self.expected.update(self.credentials)

    def test_django_2_1(self):
        callargs = inspect.getcallargs(
            self.backend.authenticate, self.request, **self.credentials
        )
        self.assertIsInstance(callargs.pop('self'), backends.SSOBackend)
        self.assertEqual(self.expected, callargs)

    def test_django_1_11(self):
        callargs = inspect.getcallargs(
            self.backend.authenticate, request=self.request, **self.credentials
        )
        self.assertIsInstance(callargs.pop('self'), backends.SSOBackend)
        self.assertEqual(self.expected, callargs)

    def test_django_1_10(self):
        callargs = inspect.getcallargs(
            self.backend.authenticate, **self.credentials
        )
        self.assertIsInstance(callargs.pop('self'), backends.SSOBackend)
        self.assertEqual(self.expected, callargs)


@override_settings(SSO_USE_V2_LOGIN=False)
class TestClient(TestCase):
    def test_authenticate_root(self):
        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': True,
                'user': {'username': 'root',
                         'first_name': 'Willie',
                         'last_name': 'Wortel',
                         'email': 'noreply@example.com',
                         'is_active': True,
                         'is_staff': False,
                         'is_superuser': False}}):
            result = client.sso_authenticate_django_v1('root', 'a')
            self.assertEqual(result['username'], 'root')

    def test_authenticate_unsiged_root(self):
        with mock.patch('lizard_auth_client.client._do_post_unsigned',
                        return_value={
                            'success': True,
                            'user': {'username': 'root',
                                     'first_name': 'Willie',
                                     'last_name': 'Wortel',
                                     'email': 'noreply@example.com',
                                     'is_active': True,
                                     'is_staff': False,
                                     'is_superuser': False}}):

            result = client.sso_authenticate_unsigned_django('root', 'a')
            self.assertEqual(result['username'], 'root')

    def test_wrong_pw(self):
        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': False,
                'error': 'Wrong password'}):
            def wrong_pw():
                return client.sso_authenticate_django_v1(
                    'root', 'wrong_password')
            self.assertRaises(client.AuthenticationFailed, wrong_pw)

    def test_bad_url(self):
        def bad_url():
            return client.sso_authenticate('http://127.0.0.1:34577/', '', '',
                                           'root', 'a')
        self.assertRaises(client.CommunicationError, bad_url)

    def test_retrieve_user(self):
        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': True,
                'user': {'username': 'root'}}):
            user_data = client.sso_get_user_django('root')
            logger.debug(pprint.pformat(user_data))
            self.assertEqual(user_data['username'], 'root')

    def test_populate_user(self):
        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': True,
                'user': {'username': 'root',
                         'first_name': 'Willie',
                         'last_name': 'Wortel',
                         'email': 'noreply@example.com',
                         'is_active': True,
                         'is_staff': False,
                         'is_superuser': False}}):
            user = client.sso_populate_user_django('root')
            self.assertEqual(user.username, 'root')

    def test_unknown_user(self):
        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': False, 'error': 'No such user'}):

            def unknown_user():
                return client.sso_populate_user_django('non_existing_username')
            self.assertRaises(client.UserNotFound, unknown_user)

    def test_password_retains_when_login_twice(self):
        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': True,
                'user': {'username': 'root',
                         'first_name': 'Willie',
                         'last_name': 'Wortel',
                         'email': 'noreply@example.com',
                         'is_active': True,
                         'is_staff': False,
                         'is_superuser': False}}):
            user = client.sso_populate_user_django('root')
            password = user.password
            user = client.sso_populate_user_django('root')
            self.assertEqual(user.password, password)


@override_settings(SSO_USE_V2_LOGIN=False)
class TestSuperuserStaffCallback(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            username='testuser', is_staff=False, is_superuser=False)

    def test_without_settings(self):
        signals.set_superuser_staff_callback(self.user, [])
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)

    def test_with_one_superuser_role(self):
        role = models.Role(code='testrole')

        with self.settings(SSO_CLIENT_SUPERUSER_ROLES=('testrole',)):
            signals.set_superuser_staff_callback(self.user, [(None, role)])
            self.assertFalse(self.user.is_staff)
            self.assertTrue(self.user.is_superuser)

    def test_with_one_staff_role(self):
        role = models.Role(code='testrole')

        with self.settings(SSO_CLIENT_STAFF_ROLES=('testrole',)):
            signals.set_superuser_staff_callback(self.user, [(None, role)])
            self.assertTrue(self.user.is_staff)
            self.assertFalse(self.user.is_superuser)

    def test_client_calls_signal_correctly_neither(self):
        with self.settings(SSO_CLIENT_SUPERUSER_ROLES=('testrole',)):
            client.synchronize_roles(self.user, {
                'organisations': [{
                    'unique_id': 'WHEEEEE',
                    'name': 'Testorganisatie',
                }],
                'roles': [{
                    'unique_id': 'HMMMMMMM',
                    'code': 'testrole',
                    'name': "Testrol",
                    'external_description': 'Gewoon een testrol',
                    'internal_description': 'Gewoon een testrol',
                }],
                'organisation_roles': [
                    ['WHEEEEE', 'HMMMMMMM']
                ]
            })
        self.assertFalse(self.user.is_staff)
        self.assertTrue(self.user.is_superuser)


@override_settings(SSO_USE_V2_LOGIN=False)
class TestOrganisation(TestCase):
    def test_create_from_dict(self):
        org = models.Organisation.create_from_dict({
            'unique_id': "NENS",
            'name': "Nelen & Schuurmans"
        })

        # Check that is has been saved and the fields are correct
        self.assertTrue(org.pk)
        self.assertEquals(org.unique_id, "NENS")
        self.assertEquals(org.name, "Nelen & Schuurmans")

    def test_prepresentation(self):
        organisation = models.Organisation(name='Reinout')
        self.assertTrue(repr(organisation))


@override_settings(SSO_USE_V2_LOGIN=False)
class TestRole(TestCase):
    def test_create_from_dict(self):
        # Also add an irrelevant field
        role = models.Role.create_from_dict({
            'unique_id': 'KLANT',
            'code': 'klant',
            'name': 'Klant',
            'external_description': 'Hooggeachte klant',
            'internal_description': 'Melkkoe',
            'nog_een_veld': 'dat niet relevant is'
        })

        # Check that it has been saved and that the fields are correct
        self.assertTrue(role.pk)
        self.assertEquals(role.unique_id, 'KLANT')
        self.assertEquals(role.code, 'klant')
        self.assertEquals(role.name, 'Klant')
        self.assertEquals(role.external_description, 'Hooggeachte klant')
        self.assertEquals(role.internal_description, 'Melkkoe')
        self.assertFalse(hasattr(role, 'nog_een_veld'))

    def test_prepresentation(self):
        role = models.Role(name='Reinout')
        self.assertTrue(repr(role))


@override_settings(SSO_USE_V2_LOGIN=False)
class TestUserOrganisationRole(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            username='testuser', is_staff=False, is_superuser=False)

    def test_create_from_list_of_dicts(self):
        # Check that user has no roles yet
        self.assertFalse(models.UserOrganisationRole.objects.filter(
            user=self.user).exists())

        models.UserOrganisationRole.create_from_list_of_dicts(
            self.user, [{
                'organisation': {
                    'unique_id': "NENS",
                    'name': "Nelen & Schuurmans"
                },
                'role': {
                    'unique_id': 'KLANT',
                    'code': 'klant',
                    'name': 'Klant',
                    'external_description': 'Hooggeachte klant',
                    'internal_description': 'Melkkoe',
                    'nog_een_veld': 'dat niet relevant is'
                }
            }])

        # Check that user has the right role
        self.assertTrue(models.UserOrganisationRole.objects.get(
            user=self.user,
            organisation__unique_id='NENS',
            role__code='klant'))


@override_settings(SSO_USE_V2_LOGIN=False)
class TestGetUserOrgRoleDict(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            username='testuser', is_staff=False, is_superuser=False,
            email='testuser@beingused.to')
        models.UserOrganisationRole.create_from_list_of_dicts(
            self.user, [{
                'organisation': {
                    'unique_id': "61f5a464c35044c19bc7d4b42d7f58cb",
                    'name': "Velen & Huurmans"
                },
                'role': {
                    'unique_id': 'superpower',
                    'code': 'Hero',
                    'name': 'Spiderman',
                    'external_description': 'Spider',
                    'internal_description': 'Fake',
                }
            },
                {
                'organisation': {
                    'unique_id': "61f5a464c35044c19bc7d4b42d7f58cb",
                    'name': "Velen & Huurmans"
                },
                'role': {
                    'unique_id': 'extrasuperpower',
                    'code': 'superhero',
                    'name': 'Spidermanplus',
                    'external_description': 'Spider+',
                    'internal_description': 'Fake+',
                }
            },
                {
                'organisation': {
                    'unique_id': "77f5a464c35044c19bc7d4b42d7f58da",
                    'name': "Power Inc."
                },
                'role': {
                    'unique_id': 'superpower',
                    'code': 'Hero',
                    'name': 'Spiderman',
                    'external_description': 'Spider',
                    'internal_description': 'Fake',
                }
            },
            ])

    def test_user_org_role_dict_has_user_info(self):
        """
        make sure the user_org_role dict contains the user data
        """
        payload_dict = get_user_org_role_dict(self.user)
        self.assertEqual(payload_dict['username'], 'testuser')
        self.assertFalse(payload_dict['is_superuser'])
        self.assertEqual(payload_dict['email'], 'testuser@beingused.to')

    def test_user_org_role_dict_contains_roles(self):
        """
        a user can have different roles for different organisations
        """
        expected_roles_velen_huurmans = ['Hero', 'superhero']
        expected_roles_power_inc = ['Hero']
        payload_dict = get_user_org_role_dict(self.user)
        self.assertEqual(len(payload_dict['organisations']), 2)
        # should have two permissions
        self.assertEqual(
            len(payload_dict['organisations'][1]['permissions']), 2
        )
        self.assertIn(
            payload_dict['organisations'][1]['permissions'][0],
            expected_roles_velen_huurmans
        )
        self.assertIn(
            payload_dict['organisations'][1]['permissions'][1],
            expected_roles_velen_huurmans
        )
        # should only contain permission "Hero"
        self.assertEqual(
            len(payload_dict['organisations'][0]['permissions']), 1
        )
        self.assertIn(
            payload_dict['organisations'][0]['permissions'][0],
            expected_roles_power_inc
        )

    def test_user_org_role_is_connected_is_excluded(self):
        """
        the roles a user can have for an organisation might
        also include the role "is_connected". For the payload
        this role is irrelevant so it has to be filtered out
        """
        role = models.Role.create_from_dict({
            'unique_id': 'connected',
            'code': 'is_connected',
            'name': 'connector',
            'external_description': 'connected',
            'internal_description': 'connected',
        })
        # check if it is in the DB
        ic = models.Role.objects.get(code='is_connected')
        self.assertTrue(repr(ic))

        organisation = models.Organisation.objects.get(
            unique_id=u"77f5a464c35044c19bc7d4b42d7f58da"
        )
        models.UserOrganisationRole.objects.create(
            user=self.user, role=role, organisation=organisation)
        uor = models.UserOrganisationRole.objects.filter(role=ic)
        self.assertTrue(repr(uor))

        # is_connected role should be filtered so we just expect a
        # single role for the testuser for organisation "Power Inc."
        expected_roles_power_inc = ['Hero']
        payload_dict = get_user_org_role_dict(self.user)
        # should only contain permission "Hero"
        self.assertEqual(
            len(payload_dict['organisations'][0]['permissions']), 1
        )
        self.assertIn(
            payload_dict['organisations'][0]['permissions'][0],
            expected_roles_power_inc
        )


@override_settings(SSO_USE_V2_LOGIN=False)
class TestGetOrganisationsWithRole(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            username='testuser', is_staff=False, is_superuser=False)

        models.UserOrganisationRole.create_from_list_of_dicts(
            self.user, [{
                'organisation': {
                    'unique_id': "NENS",
                    'name': "Nelen & Schuurmans"
                },
                'role': {
                    'unique_id': 'KLANT',
                    'code': 'billing',
                    'name': 'Billing',
                    'external_description': 'Billing goes here',
                    'internal_description': 'Billing goes here',
                }
            }])

    def test_call_get_organisations_with_role(self):
        orgs = list(models.get_organisations_with_role(self.user, 'billing'))

        self.assertEquals(len(orgs), 1)
        self.assertEquals(orgs[0].name, 'Nelen & Schuurmans')

    def test_call_get_organisation_with_role(self):
        org = models.get_organisation_with_role(self.user, 'billing')
        self.assertEquals(org.name, 'Nelen & Schuurmans')


@override_settings(SSO_USE_V2_LOGIN=False)
class TestUserOrganisationRoles(TestCase):

    def setUp(self):
        self.user = User.objects.create(username='test_user')
        self.role_data = {
            'organisations': [{
                'unique_id': 'abc',
                'name': 'name',
            }],
            'roles': [{
                'unique_id': '123',
                'code': 'code',
                'name': 'name',
                'external_description': 'ext',
                'internal_description': 'int',
            }],
            'organisation_roles': [
                ['abc', '123'],
            ]
        }

    def test_duplicate_userorganisationroles(self):
        client.synchronize_roles(self.user, self.role_data)
        client.synchronize_roles(self.user, self.role_data)
        actual = models.UserOrganisationRole.objects.filter(
            user=self.user,
            organisation__unique_id='abc',
            role__unique_id='123'
        ).count()
        expected = 1
        self.assertEqual(expected, actual)

    def test_revoked_userorganisationroles(self):
        client.synchronize_roles(self.user, self.role_data)
        client.synchronize_roles(self.user, {
            'organisations': [],
            'roles': [],
            'organisation_roles': [],
        })
        actual = models.UserOrganisationRole.objects.filter(
            user=self.user,
            organisation__unique_id='abc',
            role__unique_id='123'
        ).count()
        expected = 0
        self.assertEqual(expected, actual)


@override_settings(SSO_USE_V2_LOGIN=False)
class TestGetBillableOrganisation(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            username='testuser', is_staff=False, is_superuser=False)
        self.role = models.Role.objects.create(
            unique_id='A', code=models.Role.BILLING_ROLE_CODE)

    def test_if_sync_is_called_and_valueerror_raised_when_db_empty(self):
        with mock.patch(
                'lizard_auth_client.client.'
                'sso_sync_user_organisation_roles') as patched:
            self.assertRaises(
                ValueError,
                lambda: client.get_billable_organisation(self.user))
            self.assertTrue(patched.called)

    def test_raises_value_error_if_two_organisations(self):
        org1 = models.Organisation.objects.create(unique_id='A')
        org2 = models.Organisation.objects.create(unique_id='B')

        models.UserOrganisationRole.objects.create(
            user=self.user, role=self.role, organisation=org1)
        models.UserOrganisationRole.objects.create(
            user=self.user, role=self.role, organisation=org2)

        with mock.patch(
                'lizard_auth_client.client.'
                'sso_sync_user_organisation_roles') as patched:
            self.assertRaises(
                ValueError,
                lambda: client.get_billable_organisation(self.user))
            self.assertTrue(patched.called)

    def test_function_actually_works_and_doesnt_sync(self):
        org1 = models.Organisation.objects.create(unique_id='A')
        models.UserOrganisationRole.objects.create(
            user=self.user, role=self.role, organisation=org1)
        with mock.patch(
                'lizard_auth_client.client.'
                'sso_sync_user_organisation_roles') as patched:
            org = client.get_billable_organisation(self.user)
            self.assertFalse(patched.called)

        self.assertEquals(org.pk, org1.pk)


def mock_get_request_token():
    return 'abcdefg'


class TestViews(TestCase):

    @mock.patch('lizard_auth_client.views.get_request_token',
                mock_get_request_token)
    def test_get_request_token_and_determine_response1(self):
        # Smoke test
        self.assertTrue(views.get_request_token_and_determine_response())

    @mock.patch('lizard_auth_client.views.get_request_token',
                mock_get_request_token)
    def test_get_request_token_and_determine_response2(self):
        # Smoke test
        self.assertTrue(views.get_request_token_and_determine_response(
            domain='ab.cd'))

    @mock.patch('lizard_auth_client.views.get_request_token',
                mock_get_request_token)
    def test_get_request_token_and_determine_response3(self):
        # Smoke test
        self.assertTrue(views.get_request_token_and_determine_response(
            attempt_login_only=True))

    @mock.patch('lizard_auth_client.views.get_request_token',
                mock_get_request_token)
    def test_get_request_token_and_determine_response4(self):
        # Smoke test
        self.assertTrue(views.get_request_token_and_determine_response(
            domain='ab.cd', attempt_login_only=True))

    def test_build_sso_portal_action_url1(self):
        # Smoke test
        self.assertTrue(views.build_sso_portal_action_url('something'))

    def test_build_sso_portal_action_url2(self):
        # Smoke test
        self.assertTrue(views.build_sso_portal_action_url('something',
                                                          domain='ab.cd'))

    def test_attempt_login_middleware(self):
        """Test that AttemptAutoLoginMiddleware redirects with a parameter"""
        c = Client()
        response = c.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue('attempt_login_only' in response.url)

    def test_attempt_login_middleware_second_request(self):
        """Test that you'll be logged in unauthenticated as an AnonymousUser
        with the AttemptAutoLoginMiddleware enabled.
        """
        c = Client()
        response = c.get('/')
        response = c.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'AnonymousUser' in response.content)

    def test_no_attempt_login_middleware(self):
        """Test that no authentication takes place when
        AttemptAutoLoginMiddleware isn't enabled"""
        middleware = {
            'remove':
                'lizard_auth_client.middleware.AttemptAutoLoginMiddleware',
        }
        with self.modify_settings(MIDDLEWARE=middleware):
            c = Client()
            response = c.get('/')
            self.assertEqual(response.status_code, 200)

    def test_attempt_login_middleware_with_protected_view(self):
        """Test that protected view is unaffected by
        AttemptAutoLoginMiddleware"""
        c = Client()
        response = c.get('/protected')
        self.assertEqual(response.status_code, 301)
        self.assertTrue('attempt_login_only' not in response.url)
        middleware = {
            'remove':
                'lizard_auth_client.middleware.AttemptAutoLoginMiddleware',
        }
        with self.modify_settings(MIDDLEWARE=middleware):
            c = Client()
            response = c.get('/protected')
            self.assertEqual(response.status_code, 301)


@override_settings(SSO_USE_V2_LOGIN=False)
class TestSSOBackendV1(TestCase):

    def test_communication_error(self):
        with mock.patch(
                'lizard_auth_client.client.sso_authenticate_django_v1',
                side_effect=client.CommunicationError):
            backend = backends.SSOBackend()
            username = fake.user_name()
            password = fake.password()
            user = backend.authenticate(username=username, password=password)
            self.assertIsNone(user)

    def test_authentication_failed(self):
        with mock.patch(
                'lizard_auth_client.client.sso_authenticate_django_v1',
                side_effect=client.AuthenticationFailed):
            backend = backends.SSOBackend()
            username = fake.user_name()
            password = fake.password()
            user = backend.authenticate(username=username, password=password)
            self.assertIsNone(user)

    def test_authenticate(self):
        username = fake.user_name()
        password = fake.password()
        user_dict = dict(
            first_name=fake.first_name(),
            last_name=fake.last_name(),
            username=username,
            password=password,
            email=fake.email(),
            is_active=True,
        )
        with mock.patch(
                'lizard_auth_client.client.sso_authenticate_django_v1',
                return_value=user_dict), mock.patch(
                'lizard_auth_client.client.sso_sync_user_organisation_roles',
                return_value=[]):
            backend = backends.SSOBackend()
            user = backend.authenticate(username=username, password=password)
            self.assertTrue(isinstance(user, User))
            self.assertEqual(username, user.username)


class Test(TestCase):

    def test_sso_key(self):
        with self.settings(SSO_KEY=None):
            self.assertRaises(ImproperlyConfigured, urls.check_settings)

    def test_sso_secret(self):
        with self.settings(SSO_SECRET=None):
            self.assertRaises(ImproperlyConfigured, urls.check_settings)

    def test_sso_server_api_start_url(self):
        with self.settings(SSO_USE_V2_LOGIN=True,
                           SSO_SERVER_API_START_URL=None):
            self.assertRaises(ImproperlyConfigured, urls.check_settings)

    def test_sso_server_public_url(self):
        with self.settings(SSO_USE_V2_LOGIN=False,
                           SSO_SERVER_PUBLIC_URL=None):
            self.assertRaises(ImproperlyConfigured, urls.check_settings)

    def test_sso_server_private_url(self):
        with self.settings(SSO_USE_V2_LOGIN=False,
                           SSO_SERVER_PRIVATE_URL=None):
            self.assertRaises(ImproperlyConfigured, urls.check_settings)

    def test_old_unused_setting(self):
        with self.settings(SSO_SYNCED_USER_KEYS='pietje'):
            self.assertRaises(ImproperlyConfigured, urls.check_settings)

    def test_old_unused_server(self):
        with self.settings(SSO_SERVER_PRIVATE_URL='p-web-ws-00-d8.pietje'):
            self.assertRaises(ImproperlyConfigured, urls.check_settings)


class ClientV2Test(TestCase):

    def test_exception(self):

        def mock_post(url, timeout, data):
            raise RuntimeError("na na na")

        with mock.patch('requests.post', mock_post):
            self.assertRaises(RuntimeError,
                              client.sso_authenticate_django_v2,
                              'someone',
                              'pass')

    def test_auth_ok(self):

        def mock_post(url, timeout, data):
            result = mock.Mock()
            result.status_code = 200
            result.json.return_value = {'user': {'a': 'dict'}}
            return result

        with mock.patch('requests.post', mock_post):
            self.assertEquals(
                {'a': 'dict'},
                client.sso_authenticate_django_v2('someone', 'pass'))

    def test_correct_jwt_message(self):

        def mock_post(url, timeout, data):
            result = mock.Mock()
            self.data = data
            result.status_code = 200
            result.json.return_value = {'user': {'a': 'dict'}}
            return result

        with mock.patch('requests.post', mock_post):
            with self.settings(SSO_KEY='pietje', SSO_SECRET='klaasje'):
                client.sso_authenticate_django_v2('someone', 'pass')
                key = 'pietje'
                message = self.data['message']
                decoded = jwt.decode(message, 'klaasje',
                                     issuer=key)
                self.assertEqual('someone', decoded['username'])

    def test_search_user(self):

        def mock_get(url, params, timeout):
            result = mock.Mock()
            result.json.return_value = {'user': {'a': 'dict'}}
            return result

        def mock_server_url(what):
            return 'http:/some/where/'

        with mock.patch('requests.get', mock_get):
            with mock.patch('lizard_auth_client.client.sso_server_url',
                            mock_server_url):
                self.assertEquals(
                    {'a': 'dict'},
                    client.sso_search_user_by_email('some@example.org'))

    def test_create_user(self):

        def mock_post(url, data, timeout):
            result = mock.Mock()
            result.json.return_value = {'user': {'a': 'dict'}}
            return result

        def mock_server_url(what):
            return 'http:/some/where/'

        with mock.patch('requests.post', mock_post):
            with mock.patch('lizard_auth_client.client.sso_server_url',
                            mock_server_url):
                self.assertEquals(
                    {'a': 'dict'},
                    client.sso_create_user('some', 'name',
                                           'some@example.org',
                                           'somename'))


class V2ViewsTest(TestCase):

    def setUp(self):
        self.server_urls = {
            'check-credentials': 'https://some.where/api2/check_credentials/',
            'login': 'https://some.where/api2/login/',
            'logout': 'https://some.where/api2/logout/'}

        def mock_get(url, timeout):
            result = mock.Mock()
            result.status_code = 200
            result.json.return_value = self.server_urls
            return result

        with mock.patch('lizard_auth_client.client.requests.get', mock_get):
            # Fill the cache (force reloading)
            views.sso_server_url('login', False)

        self.request_factory = RequestFactory()

    def test_sso_server_url(self):
        self.assertEqual('https://some.where/api2/logout/',
                         views.sso_server_url('logout'))

    def test_jwt_login_view_redirect(self):
        request = self.request_factory.get('/sso/login/')
        request.session = {}
        response = views.JWTLoginView.as_view()(request)
        self.assertEqual(302, response.status_code)

    def test_jwt_login_view_url_and_payload(self):
        request = self.request_factory.get('/sso/login/')
        request.session = {}
        response = views.JWTLoginView.as_view()(request)
        actual_url, argument_string = response.url.split('?')
        self.assertEqual('https://some.where/api2/login/',
                         actual_url)
        message = argument_string.split('message=')[-1].split('&')[0]
        payload = jwt.decode(message,
                             settings.SSO_SECRET,
                             issuer=settings.SSO_KEY)
        self.assertIn('login_success_url', payload.keys())

    def test_jwt_login_view_attempt_login_only(self):
        request = self.request_factory.get(
            '/sso/login/?attempt_login_only=true')
        request.session = {}
        response = views.JWTLoginView.as_view()(request)
        actual_url, argument_string = response.url.split('?')
        self.assertEqual('https://some.where/api2/login/',
                         actual_url)
        message = argument_string.split('message=')[-1].split('&')[0]
        payload = jwt.decode(message,
                             settings.SSO_SECRET,
                             issuer=settings.SSO_KEY)
        self.assertIn('login_success_url', payload.keys())
        self.assertIn('unauthenticated_is_ok_url', payload.keys())

    def test_jwt_logout_view_redirect(self):
        request = self.request_factory.get('/sso/logout/')
        request.session = {}
        response = views.JWTLogoutView.as_view()(request)
        self.assertEqual(302, response.status_code)

    def test_jwt_logout_view_url_and_payload(self):
        request = self.request_factory.get('/sso/logout/')
        request.session = {}
        response = views.JWTLogoutView.as_view()(request)
        actual_url, argument_string = response.url.split('?')
        self.assertEqual('https://some.where/api2/logout/',
                         actual_url)
        message = argument_string.split('message=')[-1].split('&')[0]
        payload = jwt.decode(message,
                             settings.SSO_SECRET,
                             issuer=settings.SSO_KEY)
        self.assertIn('logout_url', payload.keys())

    def test_user_overview_smoke(self):
        request = self.request_factory.get('/sso/some_url/')
        request.session = {}
        superuser = User.objects.create_superuser('myuser',
                                                  'myemail@test.com',
                                                  'mypass')
        request.user = superuser
        response = views.UserOverviewView.as_view()(request)
        self.assertEqual(200, response.status_code)

    def test_user_overview_post(self):
        User.objects.create_superuser('myuser',
                                      'myemail@test.com',
                                      'mypass')
        user1 = User.objects.create_user('user1',
                                         'user1@test.com',
                                         'user1')
        user2 = User.objects.create_user('user2',
                                         'user2@test.com',
                                         'user2')
        user2.is_active = False
        user2.save()

        c = Client()
        c.login(username='myuser', password='mypass')  # Superuser
        response = c.post('/sso/user_overview/',
                          {'to_disable': user1.id,
                           'to_enable': user2.id})
        self.assertEqual(response.status_code, 302)

    def test_search_user_smoke(self):
        request = self.request_factory.get('/sso/some_url/')
        request.session = {}
        superuser = User.objects.create_superuser('myuser',
                                                  'myemail@test.com',
                                                  'mypass')
        request.user = superuser
        response = views.SearchNewUserView.as_view()(request)
        self.assertEqual(200, response.status_code)

    def test_create_user_smoke(self):
        request = self.request_factory.get('/sso/some_url/')
        request.session = {}
        superuser = User.objects.create_superuser('myuser',
                                                  'myemail@test.com',
                                                  'mypass')
        request.user = superuser
        response = views.CreateNewUserView.as_view()(request)
        self.assertEqual(200, response.status_code)


@override_settings(SSO_USE_V2_LOGIN=True)
class TestRoleManagement(TestCase):

    def setUp(self):
        """
        Construct user, organisation and role instances that will be used in
        the tests.
        """
        self.user_1 = factories.UserFactory.create(username='user_1')
        self.user_2 = factories.UserFactory.create(username='user_2')
        self.organisation_1 = factories.OrganisationFactory.create(
            name='organisation_1')
        self.organisation_2 = factories.OrganisationFactory.create(
            name='organisation_2')

        # 3Di roles
        # is_connected role
        self.is_connected_role = factories.RoleFactory.create(
            unique_id='00', code='is_connected', name='Connected')
        # permission roles
        self.follow_simulation_role = factories.RoleFactory.create(
            unique_id='10', code='follow_simulation', name='Follow simulation')
        self.run_simulation_role = factories.RoleFactory.create(
            unique_id='15', code='run_simulation', name='Run simulation')
        self.change_model_role = factories.RoleFactory.create(
            unique_id='20', code='change_model', name='Change model')
        self.manage_role = factories.RoleFactory.create(
            unique_id='30', code='manage', name='Manage')

        self.available_roles = mixins.RoleRequiredMixin().available_roles

    def tearDown(self):
        """Clean up."""
        models.UserOrganisationRole.objects.all().delete()

    def test_get_available_roles(self):
        """
        Check whether available only has the permission roles and not the
        is_connected role."""
        available_roles = mixins.RoleRequiredMixin().available_roles
        self.assertEqual(len(available_roles), 4)
        self.assertNotIn(self.is_connected_role, available_roles)

    @override_settings(SSO_IGNORE_ROLE_CODES=['billing'])
    def test_ignore_role(self):
        """Check whether the SSO_IGNORE_ROLE_CODES setting works."""
        billing_role = factories.RoleFactory.create(
            unique_id='1', code='billing', name='Billing')
        all_roles = models.Role.objects.all()
        self.assertEqual(len(all_roles), 6)
        available_roles = mixins.RoleRequiredMixin().available_roles
        self.assertEqual(len(available_roles), 4)
        self.assertNotIn(billing_role, available_roles)

    def test_role_matrix_1(self):
        """Test whether the expected role matrix is correct."""

        # connect some roles to user 1 and organisation 1
        user_roles = [self.follow_simulation_role, self.run_simulation_role]
        for role in user_roles:
            models.UserOrganisationRole.objects.create(
                user=self.user_1, organisation=self.organisation_1, role=role)

        role_matrix = views.get_user_role_matrix_for_organisation(
            self.user_1, self.organisation_1, self.available_roles)
        self.assertEqual(role_matrix, [True, True, False, False])

    def test_role_matrix_2(self):
        """Test whether the expected role matrix is correct."""

        # connect one role to user 2 and organisation 1
        user_roles = [self.follow_simulation_role]
        for role in user_roles:
            models.UserOrganisationRole.objects.create(
                user=self.user_2, organisation=self.organisation_1, role=role)

        role_matrix = views.get_user_role_matrix_for_organisation(
            self.user_2, self.organisation_1, self.available_roles)
        self.assertEqual(role_matrix, [True, False, False, False])

    def test_role_matrix_3(self):
        """Test whether the expected role matrix is correct."""

        # connect all roles to user 2 and organisation 2
        user_roles = self.available_roles
        for role in user_roles:
            models.UserOrganisationRole.objects.create(
                user=self.user_2, organisation=self.organisation_2, role=role)

        role_matrix = views.get_user_role_matrix_for_organisation(
            self.user_2, self.organisation_2, self.available_roles)
        self.assertEqual(role_matrix, [True, True, True, True])

    # tests for usage permission management forms
    def test_add_user_form_check_role_field_keys(self):
        """
        Check whether the correct number of role fields are present in the
        ``add user`` form.
        """
        role_matrix = [False] * len(self.available_roles)
        form = forms.ManageUserAddForm(
            roles=zip(self.available_roles, role_matrix))

        role_field_keys = [
            role_field_key for role_field_key in form.fields.keys() if
            role_field_key.startswith('role_')]

        # 4 role keys should be present in the form
        self.assertEqual(len(role_field_keys), 4)
        # check each individual role field key
        self.assertTrue('role_follow_simulation' in form.fields.keys())
        self.assertTrue('role_run_simulation' in form.fields.keys())
        self.assertTrue('role_change_model' in form.fields.keys())
        self.assertTrue('role_manage' in form.fields.keys())

    def test_email_case_insensitive(self):
        """test for an existing user, we try to add to a different
        organization with an email containing capital letters"""
        user_3 = factories.UserFactory.create(username='user_3')
        data_user_4 = {
            'email': str(user_3.email).swapcase(),
            'username': user_3.username,
            'first_name': user_3.first_name,
            'last_name': user_3.last_name,
        }
        form = forms.ManageUserAddForm(
            data=data_user_4,
        )
        self.assertTrue(form.is_valid())
        self.assertEqual(form.validate_unique(), None)
        exclude = form._get_validation_unique_exclusions()
        self.assertTrue('username' in exclude)

    def test_change_user_form(self):
        user_roles = self.available_roles
        for role in user_roles:
            models.UserOrganisationRole.objects.create(
                user=self.user_1, organisation=self.organisation_1, role=role)
        role_matrix = views.get_user_role_matrix_for_organisation(
            self.user_1, self.organisation_1, self.available_roles)
        form = forms.ManageUserChangeForm(
            instance=self.user_1,
            roles=zip(self.available_roles, role_matrix))
        # check all user-related form fields
        self.assertTrue('email' in form.fields.keys())
        self.assertTrue('username' in form.fields.keys())
        self.assertTrue('first_name' in form.fields.keys())
        self.assertTrue('last_name' in form.fields.keys())


class MockResponse:
    """
    Mocks the requests.Response object
    """
    def __init__(self, status_code, user_data):
        self.status_code = status_code
        self.user_data = {
            'username': 'root',
            'first_name': 'willie',
            'last_name': 'wortel',
            'email': 'noreply@example.com',
            'is_active': True,
            'is_staff': False,
            'is_superuser': False}
        self.user_data.update(user_data)

    def json(self):
        return {'success': True, 'user': self.user_data}

    def raise_for_status(self):
        # Raise HTTPError for 4xx and 5xx
        if self.status_code // 100 in (4, 5):
            raise HTTPError(response=self)


@override_settings(SSO_USE_V2_LOGIN=True)
class TestManagementViews(TestCase):
    """Tests for permission/role management views."""

    def setUp(self):
        """Create a couple of reusable object instances."""
        self.user_1 = factories.UserFactory.create(username='user_1')
        self.user_2 = factories.UserFactory.create(username='user_2')

        self.organisation_1 = factories.OrganisationFactory.create(
            name='organisation_1')
        self.organisation_2 = factories.OrganisationFactory.create(
            name='organisation_2')

        # 3Di roles
        # is_connected role
        self.is_connected_role = factories.RoleFactory.create(
            unique_id='00', code='is_connected', name='Connected')
        # permission roles
        self.follow_simulation_role = factories.RoleFactory.create(
            unique_id='10', code='follow_simulation', name='Follow simulation')
        self.run_simulation_role = factories.RoleFactory.create(
            unique_id='15', code='run_simulation', name='Run simulation')
        self.change_model_role = factories.RoleFactory.create(
            unique_id='20', code='change_model', name='Change model')
        self.manage_role = factories.RoleFactory.create(
            unique_id='30', code='manage', name='Manage')

        # Init the sso_server_url cache
        logger.info(sso_server_url('find-user'))

        self.request_factory = RequestFactory()

    def _get_error_msg(self, response, key):
        _err = response.context_data['form'].errors
        if hasattr(_err, 'as_json'):
            data = json.loads(
                response.context_data['form'].errors.as_json(escape_html=True)
            )
            return data[key][0]['message']
        return _err[key][0]

    def test_organisation_index_view_404(self):
        """
        Test permission denied for non-superuser users that don't have a
        management role.

        ManageOrganisationIndex view should raise a 404 exception, since the
        request user is not a superuser and does not have a manager role.

        """
        request = self.request_factory.get(
            reverse('lizard_auth_client.management_users_index'))
        request.session = {}
        request.user = self.user_1

        self.assertRaises(
            Http404, views.ManageOrganisationIndex.as_view(), request)

    def test_organisation_index_view_superuser(self):
        """A superuser should have access to the management index view."""
        request = self.request_factory.get(
            reverse('lizard_auth_client.management_users_index'))
        request.session = {}
        request.user = self.user_1
        request.user.is_superuser = True
        response = views.ManageOrganisationIndex.as_view()(request)
        self.assertEqual(response.status_code, 200)

    def _get_new_user_response(self, post_data):
        request = self.request_factory.post(
            reverse('lizard_auth_client.management_users_add',
                    args=[self.organisation_1.id]))
        request.session = {}
        request.user = self.user_1
        request.user.is_superuser = True
        request.POST = post_data

        return views.ManageUserAddView.as_view()(
            request, self.organisation_1.id)

    def test_organisation_add_totally_new_user(self):
        """A manager should be able to add an user
           with an unknown email address and username


           Allowed:

           (local_email not in sso_email) and
           (local_username not in sso_username)
        """

        # find_user returns 404, user not found
        # new_user returns 201, user created
        with mock.patch(
                'lizard_auth_client.client.requests.post',
                side_effect=[MockResponse(201, {})]):
            with mock.patch(
                    'lizard_auth_client.client.requests.get',
                    side_effect=[MockResponse(404, {})]):

                response = self._get_new_user_response(
                    {'username': 'root_new',
                     'first_name': 'willie',
                     'email': 'noreply_new@example.com'})

                # Should return an HTTP redirect to detail page
                self.assertEqual(response.status_code, 302)

    def test_organisation_add_known_exact_match_user(self):
        """A manager should be able to add an user
           with an exactly matching email-address/username combination

           Allowed::

           (local_email == sso_user_X_email) and
           (local_username == sso_user_X_username)
        """
        # find_user returns 200, user found
        # Don't need to create the user on SSO server.
        with mock.patch(
                'lizard_auth_client.client.requests.get',
                side_effect=[
                    MockResponse(
                        200,
                        {'username': 'root',
                         'email': 'noreply@example.com'}
                    )
                ]):

            response = self._get_new_user_response(
                {'username': 'root',
                 'first_name': 'willie',
                 'email': 'noreply@example.com'})

            # Should return an HTTP redirect to new created user
            # detail page,
            self.assertEqual(response.status_code, 302)

    def test_organisation_add_user_with_existing_email_address(self):
        """A manager should not be able to add an user with an existing
           email address using a different username

           Not allowed::

           (local_email == sso_user_X_email) and
           (local_username != sso_user_X_username)
        """

        # find_user returns 200, user found
        # new_user is not called because username differs.
        with mock.patch(
                'lizard_auth_client.client.requests.get',
                side_effect=[
                    MockResponse(
                        200,
                        {'username': 'root_existing',
                         'email': 'noreply@example.com'}
                    ),
                ]):

            response = self._get_new_user_response(
                {'username': 'root_new',
                 'first_name': 'willie',
                 'email': 'noreply@example.com'})

            # Should return form validation error indicating
            # that a user with "root_existing" username already
            # exists for the given email-address

            self.assertEqual(response.status_code, 200)
            msg = self._get_error_msg(response, 'username')
            self.assertEqual(
                msg,
                'The given username does not match with the username on the'
                ' SSO server, please use: root_existing')

    def test_organisation_add_user_with_existing_username(self):
        """A manager should not be able to add an user with an existing
           username

           Not allowed::

           (local_email not in sso_emails) and
           (local_username in sso_usernames)
        """

        # find_user returns 404, user not found
        # new_user returns 409 conflict status
        with mock.patch(
                'lizard_auth_client.client.requests.post',
                side_effect=[MockResponse(409, {})]):
            with mock.patch(
                    'lizard_auth_client.client.requests.get',
                    side_effect=[MockResponse(404, {})]):

                response = self._get_new_user_response(
                    {'username': 'root',
                     'first_name': 'willie',
                     'email': 'noreply_new@example.com'})
                # Returns form with validation error
                self.assertEqual(response.status_code, 200)
                msg = self._get_error_msg(response, 'username')
                self.assertEqual(
                    msg,
                    'This username is already in use on the SSO server, '
                    'please specify a different one')

    def test_organisation_index_view_manager(self):
        """A manager should have access to the management index view."""
        request = self.request_factory.get(
            reverse('lizard_auth_client.management_users_index'))
        request.session = {}
        # give user_1 the management role for organisation_1
        models.UserOrganisationRole.objects.create(
            user=self.user_1, organisation=self.organisation_1,
            role=self.manage_role)
        request.user = self.user_1
        response = views.ManageOrganisationIndex.as_view()(request)
        # redirects to the organisation detail page, because the user only
        # manages one organisation
        self.assertEqual(response.status_code, 302)
