from __future__ import print_function

import sys

from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command
from django.contrib.auth import get_user_model
from django.db.utils import IntegrityError

from lizard_auth_client.client import sso_get_roles_django, \
                                      sso_get_user_organisation_roles_django

from lizard_auth_client.models import Role, \
                                      Organisation, \
                                      UserOrganisationRole

txt = {
    'provide_username':
        '[E] Please provide the username for the user you are trying to sync.',
    'del_old_uors': "[E] There was an unexpected Exception while trying " \
        "to delete readily existing UserOrgRole instances " \
        "for the user called '%s'.\n[E] msg: '%s'\n[E] Aborting..",
    'winrar':
        '[+] Succesfully wrote %i UserOrganisationRole instance(s) to database.\n'
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
        """
        """
        if len(args) != 1:
            raise Exception(txt['provide_username'])
        wanted_username = args[0]
        for role_data in sso_get_roles_django():
            try:
                role = Role(**role_data)
                role.save()
            except IntegrityError:
                # Catch exception for duplicate key/attr errors:
                # This happens when a role is already present, and
                # therefore there's no reason to build/save the a new
                # Role instance for it.
                pass
        call_command('sso_sync_organisations')
        call_command('sso_sync_user', wanted_username)
        user_model = get_user_model()
        wanted_user = user_model.objects.get(username=wanted_username)
        # Delete existing UserOrganisationRoles for the curent user
        UserOrganisationRole.objects.filter(user=wanted_user).delete()
        uor_data = sso_get_user_organisation_roles_django(wanted_user)
        count = 0
        for uor_dict in uor_data:
            uor_prepared_dict = {}
            uor_prepared_dict['user'] = wanted_user
            the_organisation = Organisation.create_from_dict(
                uor_dict['organisation'])
            the_role = Role.create_from_dict(uor_dict['role'])
            uor_prepared_dict['organisation'] = the_organisation
            uor_prepared_dict['role'] = the_role
            uor = UserOrganisationRole(**uor_prepared_dict)
            uor.save()
            count += 1
        print(txt['winrar'] % count)