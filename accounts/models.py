from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _
from .models_managers import UserManager
from rest_framework_simplejwt.tokens import RefreshToken


class User(AbstractUser):
    """
        Custom user class for authentication, here user authenticate using
        email and password
    """
    username = None
    email = models.EmailField(_('email address'), unique=True)
    is_verified = models.BooleanField(
        _('verified'),
        default=False,
        help_text=_(
            'Designates whether this user has verified this account '
        ),
    )
    last_update = models.DateTimeField(_('last modification date'), auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    def __str__(self):
        return f'{self.email} -- {self.full_name}'

    def tokens(self):
        refresh_tokens = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh_tokens),
            'access': str(refresh_tokens.access_token)
        }
