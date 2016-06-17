# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import mock
import pprint

from django.contrib.auth.models import User
from django.test import TestCase
from faker import Faker

from lizard_auth_client import backends
from lizard_auth_client import client
from lizard_auth_client import models
from lizard_auth_client import signals

# Yet untested, but we want them reported by coverage.py, so we import them.
from lizard_auth_client import admin  # NOQA
from lizard_auth_client import apps  # NOQA
from lizard_auth_client import middleware  # NOQA
from lizard_auth_client import utils  # NOQA
from lizard_auth_client import views  # NOQA

logger = logging.getLogger(__name__)
fake = Faker()


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
            result = client.sso_authenticate_django('root', 'a')
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
                return client.sso_authenticate_django('root', 'wrong_password')
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

class TestSSOBackend(TestCase):

    def test_communication_error(self):
        with mock.patch(
                'lizard_auth_client.client.sso_authenticate_django',
                side_effect=client.CommunicationError):
            backend = backends.SSOBackend()
            username = fake.user_name()
            password = fake.password()
            user = backend.authenticate(username, password)
            self.assertIsNone(user)

    def test_authentication_failed(self):
        with mock.patch(
                'lizard_auth_client.client.sso_authenticate_django',
                side_effect=client.AuthenticationFailed):
            backend = backends.SSOBackend()
            username = fake.user_name()
            password = fake.password()
            user = backend.authenticate(username, password)
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
                'lizard_auth_client.client.sso_authenticate_django',
                return_value=user_dict), mock.patch(
                'lizard_auth_client.client.sso_sync_user_organisation_roles',
                return_value=[]):
            backend = backends.SSOBackend()
            user = backend.authenticate(username, password)
            self.assertTrue(isinstance(user, User))
            self.assertEqual(username, user.username)
