from django.db import models
from accounts.models import User


class Contact(models.Model):
    owner = models.ForeignKey(to=User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=20)
    last_name = models.CharField(max_length=50)
    country_code = models.CharField(max_length=10)
    phone_number = models.CharField(max_length=20)
    contact_picture = models.URLField(null=True, blank=True)
    is_favorite = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_update_date = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.first_name} {self.last_name}'
