from django import forms
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _

from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import (
    ButtonHolder, Fieldset, Layout, Submit, HTML)

from lizard_auth_client.models import Role
from lizard_auth_client.conf import settings


class ManageUserBaseForm(forms.ModelForm):
    """Base form for managing a user."""
    class Meta:
        model = get_user_model()
        fields = [
            'email',
            'username',
            'first_name',
            'last_name',
        ]

    def __init__(self, *args, **kwargs):
        # pop the user roles from the kwargs
        roles = kwargs.pop('roles', [])

        super(ManageUserBaseForm, self).__init__(*args, **kwargs)

        # create role fields
        self.role_field_names = []
        for i, (role, checked) in enumerate(roles):
            role_field_name = 'role_%s' % role.code
            self.fields[role_field_name] = forms.BooleanField(
                label=role.name.lower(), required=False, initial=checked)
            self.role_field_names.append(role_field_name)

    def get_role_field_names(self):
        """Return the role field names."""
        return self.role_field_names

    def clean(self):
        """
        Add the Role instances to the cleaned data.

        cleaned_data example:
        {
            'username': u'sander.smits', 'first_name': u'Sander',
            'last_name': u'Smits', 'organisation': u'Nelen & Schuurmans',
            u'role_run_simulation': True, u'role_manage': False,
            u'role_follow_simulation': True, u'role_change_model': True,
            'email': u'sander.smits@nelen-schuurmans.nl'
        }
        """
        cleaned_data = super(ManageUserBaseForm, self).clean()
        user_role_codes = [
            k[5:] for k in cleaned_data if
            k.startswith('role_') and cleaned_data[k] is True]
        roles = Role.objects.filter(code__in=user_role_codes)
        cleaned_data['roles'] = roles
        return cleaned_data


class ManageUserAddForm(ManageUserBaseForm):
    """Form for adding a user with its roles/permissions."""
    def __init__(self, *args, **kwargs):
        """Initialize this form with a crispy forms FormHelper instance."""
        super(ManageUserAddForm, self).__init__(*args, **kwargs)

        self.fields['email'].required = True
        self.fields['email'].help_text = _(
            "Required. An activation email will be sent to this address.")
        self.fields['email'].widget.attrs.update({'autofocus': ''})

        self.helper = FormHelper(self)
        self.helper.form_method = 'POST'
        self.helper.layout = Layout(
            Fieldset(
                None,
                'email',
                'username',
                'first_name',
                'last_name',
            ),
            HTML("<br/>"),
            Fieldset(
                settings.SSO_ROLES_LABEL,
                *self.get_role_field_names()
            ),
            HTML("<br/>"),
            ButtonHolder(
                Submit('save', _('Save'), css_class='btn-primary'),
            )
        )

    def _get_validation_exclusions(self):
        # A user might be `new` to an organisation, but already exist in the
        # database, because he has roles in other organsitions. In that
        # case, `validate_unique` should not fire. NB: the SSO server
        # matches on email address, not on username.
        exclude = super(ManageUserAddForm, self)._get_validation_exclusions()
        if 'email' in self.cleaned_data:
            model = get_user_model()
            email = self.cleaned_data['email']
            if model.objects.filter(email=email).exists():
                exclude.append('username')
        return exclude


class ManageUserChangeForm(ManageUserBaseForm):
    """Form for changing user roles/permissions."""

    # organisation name is set by the initial dict
    organisation = forms.CharField(
        label=_("Organisation"), disabled=True, required=False, help_text=None)

    def __init__(self, *args, **kwargs):
        """Add a crispy forms FormHelper instance."""
        super(ManageUserChangeForm, self).__init__(*args, **kwargs)

        for field in self.Meta.fields:
            # A manager is not allowed to change user data like `username`,
            # `email address`, etc. once an account has been created.
            self.fields[field].disabled = True
            # Disabled fields are not submitted as form data, so make sure that
            # they are allowed to be empty.
            self.fields[field].required = False
            # any help text for editing is now obsolete
            self.fields[field].help_text = None

        # django-crispy-forms
        self.helper = FormHelper(self)
        self.helper.form_method = 'POST'
        self.helper.layout = Layout(
            Fieldset(
                None,
                'organisation',
                'email',
                'username',
                'first_name',
                'last_name'
            ),
            HTML("<br/>"),
            Fieldset(
                settings.SSO_ROLES_LABEL,
                *self.get_role_field_names()
            ),
            HTML("<br/>"),
            FormActions(
                HTML(
                    """{% load i18n %}<a role="button" class="btn btn-danger"
                    href="{% url 'lizard_auth_client.management_users_delete' organisation.id user.id %}">{% trans 'Delete' %}</a>
                    """),  # NOQA
                Submit('save', _("Save")),
            ),
        )
