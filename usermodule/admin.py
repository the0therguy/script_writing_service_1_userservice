from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(Role)
admin.site.register(Module)
admin.site.register(CustomPermission)
admin.site.register(PermissionRole)
admin.site.register(Advice)
admin.site.register(CustomUser)
admin.site.register(OTP)
admin.site.register(Plan)
admin.site.register(Subscription)
admin.site.register(Transaction)
admin.site.register(Invoice)
admin.site.register(UserActivityLog)
admin.site.register(Glossary)
admin.site.register(NotePad)
admin.site.register(Music)
admin.site.register(IdeaSpark)