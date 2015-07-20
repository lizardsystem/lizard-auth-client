from __future__ import print_function

# import sys
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from lizard_auth_client import client

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
            raise CommandError('\n[E] Please provide a username')
        else:
            username = args[0]
            try:
                user_model = get_user_model()
                user = user_model.objects.get(username=username)
            except Exception as err:
                raise CommandError("\n[E] unexpected exception: '%s'" % str(err))
            billable_org = client.get_billable_organisation(user)
            print(billable_org)
