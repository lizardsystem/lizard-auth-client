# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from lizard_auth_client import client
from requests import HTTPError

import logging


logger = logging.getLogger(__name__)


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
            logger.info("Error when searching user on the SSO: %s",
                        e.response.text)
            if e.response.status_code == 404:
                msg = _("User with email %s not found")
                raise ValidationError(
                    {'email': msg % self.cleaned_data['email']})
            raise ValidationError(e)
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
            logger.warn("Error when creating user on the SSO: %s",
                        e.response.text)
            if e.response.status_code == 400:
                # According to lizard-auth-server, this normally means a
                # duplicate username. Assuming we've send a correct message.
                raise ValidationError(
                    {'username': (_("Username %s already used") %
                                  self.cleaned_data['username'])}
                )
            raise ValidationError(e)
        user = client.construct_user(user_dict)
        logger.info("Created user %s on the SSO and added it locally",
                    user)
