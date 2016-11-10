# import sys
from __future__ import print_function
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from lizard_auth_client import client


class Command(BaseCommand):
    """
    Comamnd to retrieve all user_organisation_roles (serialized) from
    the SSO server.
    """
    help = 'Please provide a username'

    def add_arguments(self, parser):
        parser.add_argument('sso_user', type=str)

    def handle(self, *args, **options):
        """
        """
        sso_user = options.get('sso_user')
        if not sso_user:
            raise CommandError('\n[E] Please provide a username')
        else:
            try:
                user_model = get_user_model()
                user = user_model.objects.get(username=sso_user)
            except Exception as err:
                raise CommandError("\n[E] unexpected exception: '%s'" % str(err))
            billable_org = client.get_billable_organisation(user)
            print(billable_org)
