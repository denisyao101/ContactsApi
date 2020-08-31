from django.contrib.auth.forms import UserCreationForm, UserChangeForm

from .models import User


class CUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm):
        model = User
        fields = ('email',)


class CUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ('email',)
