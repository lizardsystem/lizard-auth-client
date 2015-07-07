from __future__ import print_function

import os
import sys
import shutil

from django.core.management.base import BaseCommand
from django.conf import settings
from lizard_auth_client.client import sso_get_roles_django
from lizard_auth_client.models import Role

class Command(BaseCommand):
    """
    Comamnd to retrieve all roles (serialized) from
    the SSO server
    """

    def handle(self, *args, **kwargs):
        """
        """
        print("[*] About to SSO-sync Roles data...")
        try:
            roles_data = sso_get_roles_django()
            print("[+] OK, got Role data from lizard_auth_server API: %s" % str(roles_data))
        except Exception as err:
            print("[E] err = '%s'" % str(err))

        init_role_count = Role.objects.count()
        Role.objects.all().delete()

        print("[*] Trying to build Role instance...")
        for role_data in roles_data['roles']:
            try:
                role = Role(**role_data)
                role.save()
                print("[+] OK, succesfully build Role instance: %s" % role)
            except Exception as err:
                print("[E] Could not build Role instance from: %s" % str(role_data))
                print("[-] The message: %s" % str(err))
                print("[-] Aborting...\n")
                sys.exit(-1)

        final_role_count = Role.objects.count()
        if init_role_count == final_role_count:
            print("[*] The amount of Role instances (%i) has not changed."
                  % final_role_count)
        else:
            print("[+] OK, we now have %i Role instances (used to be: %i)"
                  % (final_role_count, init_role_count))
