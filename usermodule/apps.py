from django.apps import AppConfig


class UsermoduleConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'usermodule'

    def ready(self):
        import usermodule.signals