from django.core.management.base import BaseCommand
from lizard_auth_client import client


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        self.stdout.write("Synchronizing organisations... ")

        new, updated = client.synchronize_organisations()

        self.stdout.write(
            "Done. {} new organisations, {} updated organisations.\n"
            .format(new, updated))
