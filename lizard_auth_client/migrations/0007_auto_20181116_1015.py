from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lizard_auth_client', '0006_auto_20181115_1313'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='organisation',
            options={'ordering': ['name']},
        ),
    ]
