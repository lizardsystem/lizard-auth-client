from django.core.management.base import BaseCommand
from lizard_auth_client.client import construct_user
from lizard_auth_client.client import sso_get_user_django


VERBOSE = V = True


class Command(BaseCommand):
    """
    Comamnd to retrieve a single user's (serialized) data from
    the SSO server
    """
    help = 'Please provide a username'

    def add_arguments(self, parser):
        parser.add_argument('sso_user', type=str)

    def handle(self, *args, **options):
        """
        """
        sso_user = options.get('sso_user')
        if not sso_user:
            msg = '[E] Please provide the username for the user ' \
                  'you are trying to sync.'
            raise Exception(msg)
        if V:
            print("[*] About to SSO-sync data for a User "
                  "with username '%s'..." % sso_user)
        try:
            user_data = sso_get_user_django(sso_user)
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
