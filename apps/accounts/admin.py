from allauth.account.models import EmailAddress
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import AdminPasswordChangeForm, BaseUserCreationForm, UserChangeForm
from django.db.models import Exists, OuterRef

from .models import User


class UserCreationForm(BaseUserCreationForm):
    class Meta:
        model = User
        fields = ("email", "name")


class UserChangeAdminForm(UserChangeForm):
    class Meta:
        model = User
        fields = "__all__"


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    """Admin for the email-identified user. Verification is shown from allauth, never edited here."""

    form = UserChangeAdminForm
    add_form = UserCreationForm
    change_password_form = AdminPasswordChangeForm
    ordering = ("email",)
    list_display = ("email", "name", "email_verified", "is_active", "is_staff")
    list_filter = ("is_active", "is_staff", "is_superuser")
    search_fields = ("email", "name")
    readonly_fields = ("email_verified", "last_login", "date_joined")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("name", "email_verified")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = ((None, {"classes": ("wide",), "fields": ("email", "name", "password1", "password2")}),)

    def get_queryset(self, request):
        verified = EmailAddress.objects.filter(user_id=OuterRef("pk"), email=OuterRef("email"), verified=True)
        return super().get_queryset(request).annotate(_email_verified=Exists(verified))

    @admin.display(boolean=True, description="Email verified")
    def email_verified(self, obj):
        if hasattr(obj, "_email_verified"):
            return obj._email_verified
        return obj.is_email_verified
