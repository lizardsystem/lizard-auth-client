# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


def add_custom_permission(apps, schema_editor):
    Permission = apps.get_model('auth', 'Permission')
    User = apps.get_model('auth', 'User')
    ContentType = apps.get_model('contenttypes', 'ContentType')
    content_type = ContentType.objects.get_for_model(User)
    obj, created = Permission.objects.get_or_create(
        codename='manage_users',
        name='Can manage users',
        content_type=content_type
    )


class Migration(migrations.Migration):

    dependencies = [
        ('lizard_auth_client', '0002_auto_20160926_1129'),
    ]

    operations = [
        migrations.RunPython(add_custom_permission),
    ]
