from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .forms import CUserCreationForm, CUserChangeForm
from .models import User


class CustomUserAdmin(UserAdmin):
    add_form = CUserCreationForm
    form = CUserChangeForm
    model = User
    list_display = ('email', 'first_name', 'is_staff', 'is_active',)
    list_filter = ('email', 'is_staff', 'is_active',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_staff', 'is_active')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_staff', 'is_active')}
         ),
    )
    search_fields = ('first_name', 'email',)
    ordering = ('first_name', 'email',)


admin.site.register(User, CustomUserAdmin)
