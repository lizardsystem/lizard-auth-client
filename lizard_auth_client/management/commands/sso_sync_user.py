from __future__ import print_function

from django.core.management.base import BaseCommand
from lizard_auth_client.client import sso_get_user_django, construct_user

VERBOSE = V = True

class Command(BaseCommand):
    """
    Comamnd to retrieve a single user's (serialized) data from
    the SSO server
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
            msg = '[E] Please provide the username for the user you are trying'\
                   ' to sync.'
            raise Exception(msg)
        else:
            username = args[0]
            if V:
                print("[*] About to SSO-sync data for a User with username " \
                       "'%s'..." % username)
            try:
                user_data = sso_get_user_django(username)
                if V:
                    print("[+] Received serialized User object: %s"
                          % str(user_data))
                user = construct_user(user_data)
                if V:
                    print("[+] OK, build User instance: %s" % str(user))
                user.save()
                if V:
                    print("[+] OK, succesfully saved this User instance!")
            except Exception as err:
                print("[E] err = '%s'" % str(err))
