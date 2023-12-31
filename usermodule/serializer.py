from rest_framework import serializers
from datetime import datetime, timedelta
import random
import string
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer as JwtTokenObtainPairSerializer
from .models import *
from django.contrib.auth import get_user_model


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'full_name', 'email', 'password', 'user_level')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()

        # Generate and save OTP
        otp = self.generate_otp()
        self.save_otp(user, otp)

        # Send OTP via email (as shown in the previous response)

        return user

    def generate_otp(self):
        digits = string.digits
        otp = ''.join(random.choice(digits) for i in range(5))
        return otp

    def save_otp(self, user, otp):
        otp_expiry = datetime.now() + timedelta(minutes=15)
        OTP.objects.create(token=otp, expire_time=otp_expiry, user=user)


class OTPVerificationSerializer(serializers.Serializer):
    otp_token = serializers.CharField(max_length=8)


class OTPResendSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)


class TokenObtainPairSerializer(JwtTokenObtainPairSerializer):
    username_field = get_user_model().USERNAME_FIELD

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['name'] = user.name
        token['email'] = user.email
        token['is_superuser'] = user.is_superuser
        token['is_staff'] = user.is_staff

        return token


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('email', 'password')


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class GlossarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Glossary
        fields = '__all__'
        read_only_fields = ['glossary_uuid', 'user']

    def create(self, validated_data):
        # Automatically set the created_by field to the current user
        validated_data['user'] = self.context['request'].user
        return super(GlossarySerializer, self).create(validated_data)


class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = '__all__'
        read_only_fields = ['plan_uuid']