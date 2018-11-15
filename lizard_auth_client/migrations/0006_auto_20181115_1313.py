# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lizard_auth_client', '0005_auto_20181115_1249'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='userorganisationrole',
            unique_together=set([('user', 'organisation', 'role')]),
        ),
    ]
