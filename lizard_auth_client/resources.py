from import_export import resources
from lizard_auth_client import models


class RoleResource(resources.ModelResource):
    class Meta:
        model = models.Role


class OrganisationResource(resources.ModelResource):
    class Meta:
        model = models.Organisation


class UserOrganisationRoleResource(resources.ModelResource):
    class Meta:
        model = models.UserOrganisationRole
