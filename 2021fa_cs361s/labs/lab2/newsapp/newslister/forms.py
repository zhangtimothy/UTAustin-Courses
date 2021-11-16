from django import forms
from django.contrib.auth.models import User
from .models import NewsListing


class UpdateUserForm(forms.Form):
    update_user_select = forms.ModelChoiceField(
        label="Username",
        queryset=User.objects.filter(is_superuser=False))
    update_user_token = forms.CharField(label="Token ID", required=False)
    update_user_secrecy = forms.IntegerField(label="Secrecy Level")

    def clean(self):
        # STUDENT TODO
        # This is where the "update user" form is validated.
        # The "cleaned_data" is a dictionary with the data
        # entered from the POST request. So, for example,
        # cleaned_data["update_user_secrecy"] returns that
        # form value. You need to update this method to
        # enforce the security policies related to tokens
        # and secrecy.
        # Return a "ValidationError(<err msg>)" if something 
        # is wrong
        cleaned_data = super().clean()
        if cleaned_data["update_user_secrecy"] not in range(0, 10):
            raise forms.ValidationError("invalid update user secrecy")
        return cleaned_data


class CreateNewsForm(forms.Form):
    new_news_query = forms.CharField(label="New Query", required=False)
    new_news_sources = forms.CharField(label="Sources", required=False)
    new_news_secrecy = forms.IntegerField(label="Secrecy Level", required=False)

    def __init__(self, user_secrecy, *args, **kargs):
        super().__init__(*args, **kargs)
        self.user_secrecy = user_secrecy

    def clean(self):
        # STUDENT TODO
        # This is where newslisting update form is validated.
        # The "cleaned_data" is a dictionary with the data
        # entered from the POST request. So, for example,
        # cleaned_data["new_news_query"] returns that
        # form value. You need to update this method to
        # enforce the security policies related to tokens
        # and secrecy.
        # Return a "ValidationError(<err msg>)" if something 
        # is wrong
        cleaned_data = super().clean()
        if cleaned_data["new_news_secrecy"] not in range(0, 10):
            raise forms.ValidationError("new_news_secrecy not in range [0, 9]")
        if cleaned_data["new_news_secrecy"] < self.user_secrecy:
            raise forms.ValidationError("new_news_secrecy < self.user_secrecy")
        return cleaned_data


class UpdateNewsForm(forms.Form):
    update_news_select = forms.ModelChoiceField(
        label="Update News",
        # queryset=NewsListing.objects.all(),
        queryset=None,
        required=False)
    update_news_query = forms.CharField(label="Update Query", required=False)
    update_news_sources = forms.CharField(label="Update Sources", required=False)
    update_news_secrecy = forms.IntegerField(label="Update Secrecy", required=False)


    def __init__(self, user_secrecy, *args, **kargs):
        super().__init__(*args, **kargs)
        # STUDENT TODO
        # you should change the "queryset" in update_news_select to be None.
        # then, here in the constructor, you can change it to be the filtered
        # data passed in. See this page:
        # https://docs.djangoproject.com/en/3.1/ref/forms/fields/
        # Look specifically in the section "Fields which handle relationships¶"
        # where it talks about starting with an empty queryset.
        #
        # This form is constructed in views.py. Modify this constructor to
        # accept the passed-in (filtered) queryset.
        query_set = NewsListing.objects.filter(secrecy=user_secrecy)
        self.fields["update_news_select"].queryset = query_set
        self.user_secrecy = user_secrecy

    def clean(self):
        cleaned_data = super().clean()
        # STUDENT TODO
        # This is where newslisting update form is validated.
        # The "cleaned_data" is a dictionary with the data
        # entered from the POST request. So, for example,
        # cleaned_data["new_news_query"] returns that
        # form value. You need to update this method to
        # enforce the security policies related to tokens
        # and secrecy.
        # Return a "ValidationError(<err msg>)" if something 
        # is wrong
        # if cleaned_data["update_news_secrecy"] not in range(0, 10):
        #     assert(False)
        #     raise forms.ValidationError("update_news_secrecy not in range [0, 9]")
        if cleaned_data["update_news_secrecy"] and cleaned_data["update_news_secrecy"] < self.user_secrecy:
            raise forms.ValidationError("update_news_secrecy != self.user_secrecy")
        # to_update = NewsListing.objects.get(queryId=cleaned_data["update_news_select"])
        # if to_update.secrecy != self.user_secrecy:
        #     raise forms.ValidationError("secrecy of news to update != our secrecy")
        return cleaned_data
