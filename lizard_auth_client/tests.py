# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.test import TestCase


class TestClient(TestCase):
    def test_authenticate_root(self):
        from lizard_auth_client import client
        result = client.sso_authenticate_django('root', 'a')
        self.assertEqual(result['pk'], 1)

        def wrong_pw():
            return client.sso_authenticate_django('root', 'wrongpassword')
        self.assertRaises(client.AutheticationFailed, wrong_pw)

        def bad_url():
            return client.sso_authenticate('http://127.0.0.1:34577/', 'root', 'wrongpassword')
        self.assertRaises(client.CommunicationError, bad_url)
