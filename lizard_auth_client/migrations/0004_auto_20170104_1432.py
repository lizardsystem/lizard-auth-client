# Generated by Django 1.9.9 on 2017-01-04 13:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('lizard_auth_client', '0003_auto_20161115_1151'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='role',
            options={'ordering': ['unique_id']},
        ),
    ]
