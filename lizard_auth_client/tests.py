# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import pprint

import mock

from django.contrib.auth.models import User
from django.test import TestCase

from lizard_auth_client import client
from lizard_auth_client import signals
from lizard_auth_client import models


logger = logging.getLogger(__name__)


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
