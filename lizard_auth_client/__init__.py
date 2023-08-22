from django import VERSION

# Automatically discovered since Django 3.2.
# Completely removed in Django 4.1.
if VERSION < (3, 2):
    default_app_config = "lizard_auth_client.apps.LizardAuthClientConfig"
