# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import pprint

import mock

from django.test import TestCase


logger = logging.getLogger(__name__)


class TestClient(TestCase):
    def test_authenticate_root(self):
        from lizard_auth_client import client

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
        from lizard_auth_client import client
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
        from lizard_auth_client import client
        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': False,
                'error': 'Wrong password'}):
            def wrong_pw():
                return client.sso_authenticate_django('root', 'wrong_password')
            self.assertRaises(client.AuthenticationFailed, wrong_pw)

    def test_bad_url(self):
        from lizard_auth_client import client

        def bad_url():
            return client.sso_authenticate('http://127.0.0.1:34577/', '', '',
                                           'root', 'a')
        self.assertRaises(client.CommunicationError, bad_url)

    def test_retrieve_user(self):
        from lizard_auth_client import client

        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': True,
                'user': {'username': 'root'}}):
            user_data = client.sso_get_user_django('root')
            logger.debug(pprint.pformat(user_data))
            self.assertEqual(user_data['username'], 'root')

    def test_populate_user(self):
        from lizard_auth_client import client

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
        from lizard_auth_client import client
        with mock.patch('lizard_auth_client.client._do_post', return_value={
                'success': False, 'error': 'No such user'}):

            def unknown_user():
                return client.sso_populate_user_django('non_existing_username')
            self.assertRaises(client.UserNotFound, unknown_user)
