from __future__ import print_function

import sys

from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command
from django.contrib.auth import get_user_model
from django.db.utils import IntegrityError

from lizard_auth_client.client import sso_get_roles_django, \
                                      sso_get_user_organisation_roles_django, \
                                      sso_sync_user_organisation_roles

from lizard_auth_client.models import Role, \
                                      Organisation, \
                                      UserOrganisationRole

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
    args = '<username>'

    def __init__(self):
        super(Command, self).__init__()
        self.arg_help_msg = 'Please provide a username'
        help = (self.arg_help_msg)

    def handle(self, *args, **kwargs):
        if len(args) != 1:
            raise Exception(txt['provide_username'])
        else:
            wanted_username = args[0]
            user_model = get_user_model()
            wanted_user = user_model.objects.get(username=wanted_username)
            call_command('sso_sync_organisations')
            call_command('sso_sync_user', wanted_username)
            sso_sync_user_organisation_roles(wanted_user)
            print(txt['winrar'] %
                (UserOrganisationRole.objects.filter(user=wanted_user).count(),
                 wanted_user.username))

