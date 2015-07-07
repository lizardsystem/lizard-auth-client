from __future__ import print_function

import sys

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from lizard_auth_client.models import (
    Role,
    Organisation,
    UserOrganisationRole)

class Command(BaseCommand):
    """
    Comamnd to retrieve all roles (serialized) from
    the SSO server
    """

    def handle(self, *args, **kwargs):
        models = [get_user_model(), Role, Organisation, UserOrganisationRole]
        prefixes = ['<MAIN_APP>.models.'] + 3 * ['lizard_auth_client.models.']
        map(lambda m, p: kill_m_all(m, p), models, prefixes)


def kill_m_all(model, prefix=''):
    name = prefix + model.__name__
    amount = model.objects.count()
    print("\n[*] About to delete %d %s instances..." % (amount, name))
    try:
        model.objects.all().delete()
        print("[+] OK, deleted all %s instances." % name)
    except Exception as err:
        print("[E] Fail while killing all %s instances: %s" \
              % (name, str(err)))
        print("[-] Aborting...")
        sys.exit(-1)


