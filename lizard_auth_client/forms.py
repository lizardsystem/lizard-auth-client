from django import forms
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _

from crispy_forms.helper import FormHelper
from crispy_forms.layout import ButtonHolder
from crispy_forms.layout import Field
from crispy_forms.layout import Fieldset
from crispy_forms.layout import Layout
from crispy_forms.layout import Submit


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


class UserAddForm(forms.ModelForm):
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
        super(UserAddForm, self).__init__(*args, **kwargs)

        self.fields['email'].required = True
        self.fields['email'].help_text = _(
            "Required. An activation email will be sent to this address.")
        self.fields['email'].widget.attrs.update({'autofocus': ''})

        self.helper = FormHelper(self)
        self.helper.form_method = 'POST'
        self.helper.layout = Layout(
            Fieldset(
                self.legend,
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

    @property
    def legend(self):
        return _('Add a user')