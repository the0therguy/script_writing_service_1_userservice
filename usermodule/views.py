from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializer import *
from .models import *
from datetime import datetime
from datetime import datetime, timedelta
import random
import string
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
import uuid
from rest_framework.parsers import JSONParser


# Create your views here.

class CustomUserCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = (AllowAny,)


class OTPVerificationView(generics.CreateAPIView):
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return OTPVerificationSerializer

    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        otp_token = request.data.get('otp_token')
        username = kwargs.get('username')  # Assuming you pass the user ID as a URL parameter

        try:
            otp = OTP.objects.get(user__username=username, token=otp_token, expire_time__gte=datetime.now())
        except OTP.DoesNotExist:
            return Response({"message": "Invalid OTP or OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

        # If OTP is valid, activate the user or perform any other required action
        user = CustomUser.objects.get(username=username)
        user.is_active = True
        user.email_verified = True
        user.save()

        # Optionally, delete the OTP entry once it's verified and used
        otp.delete()

        return Response({"message": "Account activated successfully"}, status=status.HTTP_200_OK)


class OTPResendView(generics.CreateAPIView):
    serializer_class = OTPResendSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')  # Get the username from the request data

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate and save new OTP
        otp = self.generate_otp()
        self.save_otp(user, otp)

        # Send new OTP via email
        self.send_otp_email(user, otp)

        return Response({"message": "New OTP sent successfully"}, status=status.HTTP_200_OK)

    def generate_otp(self):
        digits = string.digits
        otp = ''.join(random.choice(digits) for i in range(5))
        return otp

    def save_otp(self, user, otp):
        otp_expiry = datetime.now() + timedelta(minutes=15)
        OTP.objects.create(token=otp, expire_time=otp_expiry, user=user)

    def send_otp_email(self, user, otp):
        current_site = get_current_site(self.request)
        mail_subject = 'Your New OTP'
        message = render_to_string('otp_email_template.html', {
            'user': user,
            'otp': otp,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        })
        to_email = user.email
        send_mail(mail_subject, message, 'your_email@example.com', [to_email])


class CustomTokenObtainPairView(TokenObtainPairView):
    # Replace the serializer with your custom
    serializer_class = CustomLoginSerializer


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            old_password = serializer.data.get('old_password')
            new_password = serializer.data.get('new_password')

            # Check if the old password matches the current password
            if not check_password(old_password, request.user.password):
                return Response({"message": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

            # Change the password and save the user object
            request.user.set_password(new_password)
            request.user.save()

            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GlossaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        glossaries = Glossary.objects.all()
        serializer = GlossarySerializer(glossaries, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.role or request.user.role.name != 'admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = GlossarySerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            activity = ActivityLog.objects.create(
                **{'activity_uuid': uuid.uuid4(), 'message': 'glossary created', 'created_by': request.user})
            activity.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GlossaryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, uuid):
        try:
            return Glossary.objects.get(glossary_uuid=uuid)
        except Glossary.DoesNotExist:
            return None

    def get(self, request, uid):
        glossary = self.get_object(uid)
        if not glossary:
            return Response({"message": "Glossary not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = GlossarySerializer(glossary)
        return Response(serializer.data)

    def put(self, request, uid):
        if not request.user.role or request.user.role.name != 'admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        glossary = self.get_object(uid)
        if not glossary:
            return Response({"message": "Glossary not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = GlossarySerializer(glossary, data=request.data)
        if serializer.is_valid():
            serializer.save()
            activity = ActivityLog.objects.create(
                **{'activity_uuid': uuid.uuid4(), 'message': 'glossary updated', 'created_by': request.user})
            activity.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, uid):
        if not request.user.role or request.user.role.name != 'admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)
        glossary = self.get_object(uid)
        if not glossary:
            return Response({"message": "Glossary not found."}, status=status.HTTP_404_NOT_FOUND)

        glossary.delete()
        activity = ActivityLog.objects.create(
            **{'activity_uuid': uuid.uuid4(), 'message': 'glossary deleted', 'created_by': request.user})
        activity.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class PlanListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        plans = Plan.objects.filter(active=True)
        serializer = PlanSerializer(plans, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.role or request.user.role.name != 'admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = PlanSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PlanDetailView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def get_object(self, pk):
        try:
            return Plan.objects.get(plan_uuid=pk, active=True)
        except Plan.DoesNotExist:
            return None

    def get(self, request, plan_uuid):
        plan = self.get_object(plan_uuid)
        if not Plan:
            return Response({"message": "Plan not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = PlanSerializer(plan)
        return Response(serializer.data)

    def put(self, request, plan_uuid):
        if not request.user.role or request.user.role.name != 'admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        plan = self.get_object(plan_uuid)
        if not plan:
            return Response({"message": "Plan not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = PlanSerializer(plan, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, plan_uuid):
        if not request.user.role or request.user.role.name != 'admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        plan = self.get_object(plan_uuid)
        if not plan:
            return Response({"message": "Plan not found."}, status=status.HTTP_404_NOT_FOUND)
        plan.active = False  # Mark the plan as inactive instead of deleting it
        plan.save()
        return Response(status=status.HTTP_204_NO_CONTENT)