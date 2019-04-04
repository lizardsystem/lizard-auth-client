from import_export import resources
from lizard_auth_client import models


class RoleResource(resources.ModelResource):
    class Meta:
        model = Role


class OrganisationResource(resources.ModelResource):
    class Meta:
        model = Organisation


class UserOrganisationRoleResource(resources.ModelResource):
    class Meta:
        model = UserOrganisationRole