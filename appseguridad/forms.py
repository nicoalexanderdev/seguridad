from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from captcha.fields import CaptchaField


class CustomAuthenticationForm(AuthenticationForm):
    captcha = CaptchaField(label="Confirma que eres humano")

    class Meta:
        fields = ['username', 'password', 'captcha']
