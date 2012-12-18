# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import pprint

from django.test import TestCase


logger = logging.getLogger(__name__)

class TestClient(TestCase):
    def test_authenticate_root(self):
        from lizard_auth_client import client

        result = client.sso_authenticate_django('root', 'a')
        self.assertEqual(result['username'], 'root')

        def wrong_pw():
            return client.sso_authenticate_django('root', 'wrong_password')
        self.assertRaises(client.AutheticationFailed, wrong_pw)

        def bad_url():
            return client.sso_authenticate('http://127.0.0.1:34577/', '', '', 'root', 'a')
        self.assertRaises(client.CommunicationError, bad_url)

        def bad_key():
            return client.sso_authenticate('http://127.0.0.1:8001/', 'asd', 'asd', 'root', 'a')
        self.assertRaises(client.CommunicationError, bad_key)

    def test_populate_user(self):
        from lizard_auth_client import client

        user_data = client.sso_get_user_django('root')
        logger.debug(pprint.pformat(user_data))
        self.assertEqual(user_data['username'], 'root')

        user = client.sso_populate_user_django('root')
        self.assertEqual(user.username, 'root')

        def unknown_user():
            return client.sso_populate_user_django('non_existing_username')
        self.assertRaises(client.UserNotFound, unknown_user)
