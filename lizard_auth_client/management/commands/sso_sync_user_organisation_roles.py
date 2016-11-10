from __future__ import print_function
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from django.db.utils import IntegrityError
from lizard_auth_client.client import sso_get_roles_django
from lizard_auth_client.client import sso_get_user_organisation_roles_django
from lizard_auth_client.client import sso_sync_user_organisation_roles
from lizard_auth_client.models import Organisation
from lizard_auth_client.models import Role
from lizard_auth_client.models import UserOrganisationRole

import sys


txt = {
    'provide_username':
        '[E] Please provide the username for the user you are trying to sync.',
    'winrar':
        "[+] Succesfully wrote UserOrganisationRole instance(s) to " \
        "database. Currently we have %i instance(s) for '%s' in the db."
}

class Command(BaseCommand):
    """
    Comamnd to retrieve all user_organisation_roles (serialized) from
    the SSO server.
    """
    help = 'Please provide a username'

    def add_arguments(self, parser):
        parser.add_argument('sso_user', type=str)


    def handle(self, *args, **options):

        wanted_username = options.get('sso_user')

        if not wanted_username:
            raise Exception(txt['provide_username'])
        else:
            user_model = get_user_model()
            wanted_user = user_model.objects.get(username=wanted_username)
            call_command('sso_sync_organisations')
            call_command('sso_sync_user', wanted_username)
            sso_sync_user_organisation_roles(wanted_user)
            print(txt['winrar'] %
                (UserOrganisationRole.objects.filter(user=wanted_user).count(),
                 wanted_user.username))
