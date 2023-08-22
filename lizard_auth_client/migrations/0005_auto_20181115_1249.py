from django.db import migrations


def delete_duplicate_uors(apps, schema_editor):
    """Delete duplicate UserOrganisationRoles."""
    UOR = apps.get_model('lizard_auth_client', 'UserOrganisationRole')
    for row in UOR.objects.all():
        if UOR.objects.filter(
            user=row.user,
            organisation=row.organisation,
            role=row.role
        ).count() > 1:
            row.delete()


class Migration(migrations.Migration):

    dependencies = [
        ('lizard_auth_client', '0004_auto_20170104_1432'),
    ]

    operations = [
        migrations.RunPython(delete_duplicate_uors),
    ]
