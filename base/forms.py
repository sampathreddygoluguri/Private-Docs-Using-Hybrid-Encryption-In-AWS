from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django import forms

class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']


class UploadKeysForm(forms.Form):
    key1 = forms.FileField(label='Upload Key 1')
    key2 = forms.FileField(label='Upload Key 2')
    key3 = forms.FileField(label='Upload Key 3')