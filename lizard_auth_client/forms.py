import logging

from requests import HTTPError
from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import ButtonHolder
from crispy_forms.layout import Fieldset
from crispy_forms.layout import Layout
from crispy_forms.layout import Submit
from crispy_forms.layout import HTML
from lizard_auth_client import client
from lizard_auth_client.models import Role
from lizard_auth_client.conf import settings

logger = logging.getLogger(__name__)


# The API errors from the SSO are nice short textual messages. Older versions
# returned big html pages. We strip the error messages to a max length to
# prevent huge feedback messages.
MAX_ERROR_MESSAGE_LENGTH = 200


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

        super().__init__(*args, **kwargs)

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
            'username': 'sander.smits',
            'first_name': 'Sander',
            'last_name': 'Smits',
            'organisation': 'Nelen & Schuurmans',
            'role_run_simulation': True,
            'role_manage': False,
            'role_follow_simulation': True,
            'role_change_model': True,
            'email': 'sander.smits@nelen-schuurmans.nl'
        }
        """
        cleaned_data = super().clean()
        user_role_codes = [
            key[5:] for key in cleaned_data if
            key.startswith('role_') and cleaned_data[key] is True]
        roles = Role.objects.filter(code__in=user_role_codes)
        cleaned_data['roles'] = roles
        return cleaned_data


class ManageUserAddForm(ManageUserBaseForm):
    """Form for adding a user with its roles/permissions."""
    def __init__(self, *args, **kwargs):
        """Initialize this form with a crispy forms FormHelper instance."""
        super().__init__(*args, **kwargs)

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

    def validate_unique(self):
        """
        Calls the instance's validate_unique() method and updates the form's
        validation errors if any were raised.
        """
        exclude = self._get_validation_unique_exclusions()
        try:
            self.instance.validate_unique(exclude=exclude)
        except ValidationError as e:
            self._update_errors(e)

    def _get_validation_unique_exclusions(self):
        # A user might be `new` to an organisation, but already exist in the
        # database, because he has roles in other organsitions. In that
        # case, `validate_unique` should not fire. NB: the SSO server
        # matches on email address, not on username.
        exclude = self._get_validation_exclusions()
        if 'email' in self.cleaned_data:
            model = get_user_model()
            email = self.cleaned_data['email']
            if model.objects.filter(email__iexact=email).exists():
                exclude.append('username')
        return exclude


class ManageUserChangeForm(ManageUserBaseForm):
    """Form for changing user roles/permissions."""

    # organisation name is set by the initial dict
    organisation = forms.CharField(
        label=_("Organisation"), required=False, help_text=None)

    def __init__(self, *args, **kwargs):
        """Add a crispy forms FormHelper instance."""
        super().__init__(*args, **kwargs)

        for field in self.Meta.fields:
            # A manager is not allowed to change user data like `username`,
            # `email address`, etc. once an account has been created.
            self.fields[field].disabled = True  # Django >= 1.9
            self.fields[field].widget.attrs['readonly'] = True  # Django < 1.9
            # Disabled fields are not submitted as form data, so make sure that
            # they are allowed to be empty.
            self.fields[field].required = False
            # any help text for editing is now obsolete
            self.fields[field].help_text = None

        self.fields['organisation'].disabled = True  # Django >= 1.9
        # Django < 1.9
        self.fields['organisation'].widget.attrs['readonly'] = True

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
                    href="{% url 'lizard_auth_client.management_users_delete' organisation.id user_to_manage.id %}">{% trans 'Delete' %}</a>
                    """),  # NOQA
                Submit('save', _("Save")),
            ),
        )


class SearchEmailForm(forms.Form):

    email = forms.EmailField(
        required=True,
        label=_('Email'),
    )

    def clean(self):

        try:
            user_dict = client.sso_search_user_by_email(
                self.cleaned_data['email'])
        except HTTPError as e:
            error_text = e.response.text
            if e.response.status_code == 404:
                msg = _("User with email %s not found")
                raise ValidationError(
                    {'email': msg % self.cleaned_data['email']})
            logger.error("Error when searching user on the SSO: %s",
                         error_text)
            raise ValidationError(error_text[:MAX_ERROR_MESSAGE_LENGTH])
        user = client.construct_user(user_dict)
        logger.info("Added SSO user %s locally", user)


class CreateNewUserForm(forms.Form):

    first_name = forms.CharField(
        max_length=30,
        label=_('first name'),
        required=True
    )
    last_name = forms.CharField(
        max_length=30,
        label=_('last name'),
        required=True
    )
    email = forms.EmailField(
        required=True,
        label=_('email'),
    )
    username = forms.CharField(
        max_length=128,
        label=_('username'),
    )

    def clean(self):

        try:
            user_dict = client.sso_create_user(
                self.cleaned_data['first_name'],
                self.cleaned_data['last_name'],
                self.cleaned_data['email'],
                self.cleaned_data['username'])
        except HTTPError as e:
            error_text = e.response.text
            if 'duplicate username' in error_text:
                raise ValidationError(
                    {'username': (_("Username %s already used") %
                                  self.cleaned_data['username'])}
                )
            logger.error("Error when creating user on the SSO: %s",
                         error_text)
            raise ValidationError(error_text[:MAX_ERROR_MESSAGE_LENGTH])
        user = client.construct_user(user_dict)
        logger.info("Created user %s on the SSO and added it locally",
                    user)
