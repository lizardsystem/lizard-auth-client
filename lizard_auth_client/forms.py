# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django import forms
from lizard_auth_client import client
from django.core.exceptions import ValidationError
from requests import HTTPError


class SearchEmailForm(forms.Form):

    email = forms.EmailField(
        required=True,
    )

    def clean(self):

        try:
            user_dict = client.sso_search_user_by_email(
                self.cleaned_data['email'])
        except HTTPError as e:
            if e.response.status_code == 404:
                raise ValidationError(
                    {'email': "User with email %s not found" % self.cleaned_data['email']})
            raise ValidationError(e)
        user = client.construct_user(user_dict['user'])
        print("Added user %s" % user)
