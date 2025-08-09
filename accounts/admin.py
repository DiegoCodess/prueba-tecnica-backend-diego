from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = (*BaseUserAdmin.fieldsets, ('Voucher', {'fields': ('voucher',)}),)
    list_display = ('username', 'email', 'is_superuser', 'voucher')
# Register your models here.
