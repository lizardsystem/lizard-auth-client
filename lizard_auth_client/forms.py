from django import forms
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _

from crispy_forms.helper import FormHelper
from crispy_forms.layout import ButtonHolder
from crispy_forms.layout import Field
from crispy_forms.layout import Fieldset
from crispy_forms.layout import Layout
from crispy_forms.layout import Submit
from crispy_forms.layout import HTML


class OrganisationSelectorForm(forms.Form):

    organisation = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super(OrganisationSelectorForm, self).__init__(*args, **kwargs)

        # get the choices
        self.fields['organisation'].choices = [
            (org.pk, org.name) for org in kwargs['initial']['organisations']]

        self.helper = FormHelper(self)
        self.helper.form_method = 'POST'
        self.helper.layout = Layout(
            Fieldset(
                self.legend,
                # 'organisations',
                # 'username',
                # 'first_name',
                # 'last_name',
                Field('organisation', css_class='selectpicker'),
                # Field('admin_in', css_class='selectpicker'),
                # Field('manager_in', css_class='selectpicker'),
            ),
            ButtonHolder(
                Submit('next', _('Manage this organisation'), css_class='btn-primary'),
            )
        )

    @property
    def legend(self):
        return _('For which organisation do you want to manage its users?')


class ManageUserAddForm(forms.ModelForm):
    """Form for adding a user."""
    # username = forms.CharField(label=_("Username"), max_length=100)
    # email = forms.CharField(label=_("Email address"), max_length=100)
    # first_name = forms.CharField(label=_("First name"), max_length=100)
    # last_name = forms.CharField(label=_("Last name"), max_length=100)

    class Meta:
        model = get_user_model()
        fields = [
            'email',
            'username',
            'first_name',
            'last_name',
        ]

    def __init__(self, *args, **kwargs):
        """Initialize this from with a crispy-forms FormHelper instance."""
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
                # Field('user_in', css_class='selectpicker'),
                # Field('admin_in', css_class='selectpicker'),
                # Field('manager_in', css_class='selectpicker'),
            ),
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


class ManageUserOrganisationDetailForm(forms.ModelForm):
    """
    """
    # organisation name is set by the initial dict
    organisation = forms.CharField(
        label=_("Organisation"), disabled=True, required=False, help_text=None)

    class Meta:
        model = get_user_model()
        fields = [
            'username',
            'email',
            'first_name',
            'last_name',
        ]

    def __init__(self, *args, **kwargs):

        # pop the user roles from the kwargs
        roles = kwargs.pop('roles', [])

        super(ManageUserOrganisationDetailForm, self).__init__(*args, **kwargs)

        for field in self.Meta.fields:
            # A manager is not allowed to change user data like `username`,
            # `email address`, etc. once an account has been created.
            self.fields[field].disabled = True
            # Disabled fields are not submitted as form data, so make sure that
            # they are allowed to be empty.
            self.fields[field].required = False
            # any help text for editing is now obsolete
            self.fields[field].help_text = None

        # create role fields
        role_field_names = []
        for i, (role, checked) in enumerate(roles):
            role_field_name = 'role_%s' % role['code']
            self.fields[role_field_name] = forms.BooleanField(
                label=role['name'].lower(), required=False, initial=checked)
            role_field_names.append(role_field_name)

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
                # TODO: make this label a setting with default: _("Roles")
                _("Permissions"),
                *role_field_names
            ),
            HTML("<br/>"),
            ButtonHolder(
                # TODO: implement delete user-organisation relation
                Submit('delete', _("Delete"), css_class='btn-danger'),
                Submit('save', _("Save"), css_class='btn-primary'),
            )
        )
