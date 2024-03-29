from django.conf import settings
from django.db import migrations
from django.db import models


class Migration(migrations.Migration):

    dependencies = [
        ('lizard_auth_client', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userorganisationrole',
            name='organisation',
            field=models.ForeignKey(
                related_name='user_organisation_roles',
                to='lizard_auth_client.Organisation',
                on_delete=models.CASCADE
            ),
        ),
        migrations.AlterField(
            model_name='userorganisationrole',
            name='role',
            field=models.ForeignKey(
                related_name='user_organisation_roles',
                to='lizard_auth_client.Role',
                on_delete=models.CASCADE
            ),
        ),
        migrations.AlterField(
            model_name='userorganisationrole',
            name='user',
            field=models.ForeignKey(
                related_name='user_organisation_roles',
                to=settings.AUTH_USER_MODEL,
                on_delete=models.CASCADE
            ),
        ),
    ]
