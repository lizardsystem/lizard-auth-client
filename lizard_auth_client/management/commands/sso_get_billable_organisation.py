from __future__ import print_function

# import sys
from django.core.management.base import BaseCommand, CommandError
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
            raise CommandError('[E] Please provide a username')
        else:
            username = args[0]
            billable_org = client.get_billable_organisation(username)
