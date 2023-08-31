from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from multiselectfield import MultiSelectField


# Create your models here.
class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    slug = models.CharField(max_length=50, null=False, blank=False)

    def __str__(self):
        return self.name


class Module(models.Model):
    name = models.CharField(max_length=50, unique=True)
    slug = models.CharField(max_length=50, null=False, blank=False)

    def __str__(self):
        return self.name


class CustomPermission(models.Model):
    name = models.CharField(max_length=50)
    slug = models.CharField(max_length=50, null=False, blank=False)

    module = models.ForeignKey(Module, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.name


class PermissionRole(models.Model):
    permission = models.ForeignKey(CustomPermission, on_delete=models.SET_NULL, null=True, blank=True)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.permission_id.name + ' ' + self.role_id.name


class Advice(models.Model):
    advice_uuid = models.CharField(max_length=50)
    title = models.CharField(max_length=200, null=True, blank=True)
    body = models.TextField()
    bg_color = models.CharField(max_length=8, null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


PROFILE_LEVEL = (
    ('beginners', 'Beginners'),
    ('intermediate', 'Intermediate'),
    ('professional', 'Professional')
)

USER_DEVICE = [
    ('computer', 'Computer'),
    ('tablet', 'Tablet'),
    ('mobile', 'Mobile'),
]
WEEKDAYS = [
    ('mon', 'Monday'),
    ('tue', 'Tuesday'),
    ('wed', 'Wednesday'),
    ('thu', 'Thursday'),
    ('fri', 'Friday'),
    ('sat', 'Saturday'),
    ('sun', 'Sunday'),
]


class CustomUser(AbstractUser):
    full_name = models.CharField(max_length=220, null=True, blank=True)
    email = models.EmailField(_('email'), unique=True)
    email_verified = models.BooleanField(default=False)
    reminder = models.BooleanField(default=False)
    weekday = MultiSelectField(max_length=30, choices=WEEKDAYS, null=True, blank=True)
    device = models.CharField(max_length=20, choices=USER_DEVICE, default='computer')

    user_level = models.CharField(max_length=100, choices=PROFILE_LEVEL, default='beginners')

    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)

    groups = models.ManyToManyField(Group, blank=True, related_name='custom_users')
    user_permissions = models.ManyToManyField(Permission, blank=True, related_name='custom_users')
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username


class OTP(models.Model):
    token = models.CharField(max_length=8)
    created_on = models.DateTimeField(auto_now_add=True)
    expire_time = models.DateTimeField(auto_now_add=False)
    reason = models.CharField(max_length=50, blank=True)

    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.user.username


class Plan(models.Model):
    plan_uuid = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=50)
    monthly_price = models.DecimalField(max_digits=10, decimal_places=2)
    yearly_discount = models.DecimalField(max_digits=3, decimal_places=2)
    plan_permission = models.JSONField()
    active = models.BooleanField(default=True)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.title


class Subscription(models.Model):
    plan = models.OneToOneField(Plan, on_delete=models.SET_NULL, null=True)
    start_date = models.DateField(auto_now_add=False)
    end_date = models.DateField(auto_now_add=False)
    active = models.BooleanField(default=True)
    permission = models.JSONField()

    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.user.username + " " + self.plan.title


TRANSACTION_STATUS = (
    ('success', 'Success'),
    ('fail', 'Fail'),
    ('cancel', 'Cancel')
)


class Transaction(models.Model):
    transaction_uuid = models.CharField(max_length=50)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_gateway = models.CharField(max_length=20, default='stripe')
    transaction_status = models.CharField(max_length=30, choices=TRANSACTION_STATUS, default='success')

    plan = models.ForeignKey(Plan, on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.user.username + ' ' + self.transaction_uuid + ' ' + self.transaction_status


class Invoice(models.Model):
    invoice_uuid = models.CharField(max_length=50)
    invoice_from = models.JSONField()
    invoice_to = models.JSONField()
    payment_status = models.BooleanField(default=False)

    transaction = models.OneToOneField(Transaction, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.transaction.user.username + ' ' + self.invoice_uuid


ACTIVITY_ACTION = (
    ('create', 'Create'),
    ('update', 'Update'),
    ('delete', 'Delete')
)


class UserActivityLog(models.Model):
    activity_uuid = models.CharField(max_length=50)
    message = models.TextField(null=True, blank=True)
    details = models.JSONField(null=True, blank=True)
    action = models.CharField(max_length=30, choices=ACTIVITY_ACTION, default='create')
    created_on = models.DateTimeField(auto_now_add=True)

    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.activity_uuid


class Glossary(models.Model):
    glossary_uuid = models.CharField(max_length=50)
    title = models.CharField(max_length=100)
    body = models.TextField()

    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.title


class NotePad(models.Model):
    notepad_uuid = models.CharField(max_length=50)
    title = models.CharField(max_length=100)
    body = models.TextField(null=True, blank=True)
    color = models.CharField(max_length=8)
    created_on = models.DateTimeField(auto_now_add=True)
    notepad_no = models.IntegerField(default=1)

    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.title


class Music(models.Model):
    music_uuid = models.CharField(max_length=50)
    title = models.CharField(max_length=200, null=True, blank=True)
    sound = models.FileField(upload_to='music/', null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True)

    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        if self.title:
            return self.title
        return self.music_uuid


class IdeaSparkFolder(models.Model):
    idea_spark_folder_uuid = models.CharField(max_length=50)
    title = models.CharField(max_length=150)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(default=timezone.now, blank=True)

    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.title


class IdeaSpark(models.Model):
    idea_spark_uuid = models.CharField(max_length=50)
    idea_spark_format = models.CharField(max_length=150, null=True, blank=True)
    genre = models.CharField(max_length=150, null=True, blank=True)
    protagonist_gender = models.CharField(max_length=150, null=True, blank=True)
    protagonist_desire = models.CharField(max_length=150, null=True, blank=True)
    area = models.CharField(max_length=150, null=True, blank=True)
    location = models.CharField(max_length=150, null=True, blank=True)
    protagonist_vice = models.CharField(max_length=150, null=True, blank=True)
    film_name = models.CharField(max_length=250, null=True, blank=True)
    protagonist = models.TextField(null=True, blank=True)
    secondary_character = models.TextField(null=True, blank=True)
    plot = models.TextField(null=True, blank=True)
    number_of_generated = models.IntegerField(default=1)
    created_on = models.DateTimeField(auto_now_add=True)

    idea_spark_folder = models.ForeignKey(IdeaSparkFolder, on_delete=models.SET_NULL, null=True, blank=True)
    created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        if self.protagonist:
            return self.protagonist
        return self.idea_spark_uuid
