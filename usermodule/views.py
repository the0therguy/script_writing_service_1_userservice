import json

from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializer import *
from .models import *
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
import stripe
from django.core.mail import send_mail
from django.contrib.auth.hashers import check_password

# Create your views here.

stripe.api_key = 'sk_test_51NbFFrL2MME1ps3wfbAiYaOfux9XN4i25NGlNVgBcsOPcAxnwsKRRxoUdHDkX9nToy4zV84V8zgCVT3t1XPbVoc200VShiI03H'


def create_user_activity(data):
    data['activity_uuid'] = str(uuid.uuid4())
    activity = UserActivityLog.objects.create(**data)
    activity.save()


class CustomUserCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = (AllowAny,)


class OTPVerificationView(generics.CreateAPIView):
    permission_classes = (AllowAny,)

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return OTPVerificationSerializer

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
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)


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
            create_user_activity({'action': 'update',
                                  'message': f"{request.user.username}'s password updated",
                                  'created_by': request.user})
            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GlossaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        glossaries = Glossary.objects.all()
        serializer = GlossarySerializer(glossaries, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = GlossarySerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'create', 'message': "glossary created",
                                  'created_by': request.user})
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
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        glossary = self.get_object(uid)
        if not glossary:
            return Response({"message": "Glossary not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = GlossarySerializer(glossary, data=request.data)
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'update', 'message': 'glossary updated',
                                  'created_by': request.user})
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, uid):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)
        glossary = self.get_object(uid)
        if not glossary:
            return Response({"message": "Glossary not found."}, status=status.HTTP_404_NOT_FOUND)

        glossary.delete()
        create_user_activity({'action': 'delete', 'message': f'{uid} glossary deleted',
                              'created_by': request.user})
        return Response(status=status.HTTP_204_NO_CONTENT)


class PlanListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        plans = Plan.objects.filter(active=True)
        serializer = PlanSerializer(plans, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = PlanSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'create', 'message': 'new plan created',
                                  'created_by': request.user})
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
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        plan = self.get_object(plan_uuid)
        if not plan:
            return Response({"message": "Plan not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = PlanSerializer(plan, data=request.data)
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'update', 'message': 'new plan updated',
                                  'created_by': request.user})
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, plan_uuid):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        plan = self.get_object(plan_uuid)
        if not plan:
            return Response({"message": "Plan not found."}, status=status.HTTP_404_NOT_FOUND)
        plan.active = False  # Mark the plan as inactive instead of deleting it
        plan.save()
        create_user_activity({'action': 'delete', 'message': 'plan deleted',
                              'created_by': request.user})
        return Response(status=status.HTTP_204_NO_CONTENT)


class CustomUserViewByEmail(APIView):

    def get_object(self, email):
        try:
            return CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return None

    def get(self, request, email):
        user = self.get_object(email)
        if not user:
            return Response('No user found', status=status.HTTP_400_BAD_REQUEST)
        if email != request.user.email:
            return Response("You don't have access on this page", status=status.HTTP_403_FORBIDDEN)
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CustomUserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        user = request.user
        serializer = CustomUserInfoUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'update', 'message': 'user updated', 'created_by': user})
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomUserViewById(APIView):

    def get_object(self, pk):
        user = CustomUser.objects.get(pk=pk)
        return user

    def get(self, request, pk):
        user = self.get_object(pk)
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AdviceListCreate(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        advices = Advice.objects.all()
        serializer = AdviceSerializer(advices, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = AdviceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'create', 'message': 'new advice crated',
                                  'created_by': request.user})

            return Response(serializer.data, status=status.HTTP_201_CREATED)


class AdviceRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, advice_uuid):
        try:
            return Advice.objects.get(advice_uuid=advice_uuid)
        except Advice.DoesNotExist:
            return None

    def get(self, request, advice_uuid):
        advice = self.get_object(advice_uuid)
        if not advice:
            return Response('No advice found', status=status.HTTP_400_BAD_REQUEST)
        serializer = AdviceSerializer(advice)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, advice_uuid):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        advice = self.get_object(advice_uuid)
        if not advice:
            return Response('No advice found', status=status.HTTP_400_BAD_REQUEST)

        serializer = AdviceSerializer(advice, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            create_user_activity(
                {'action': 'update', 'message': f"advice {advice_uuid} was updated", 'created_by': request.user})
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, advice_uuid):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        advice = self.get_object(advice_uuid)
        if not advice:
            return Response('No advice found', status=status.HTTP_400_BAD_REQUEST)
        advice.delete()
        create_user_activity(
            {'action': 'delete', 'message': f"advice {advice_uuid} was deleted", 'created_by': request.user})
        return Response(status=status.HTTP_204_NO_CONTENT)


class MusicListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        musics = Music.objects.all()
        serializer = MusicSerializer(musics, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        request.data['created_by'] = request.user.id

        serializer = MusicSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'create', 'message': 'new music crated',
                                  'created_by': request.user})
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors)


class MusicRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, music_uuid):
        try:
            return Music.objects.get(music_uuid=music_uuid)
        except Music.DoesNotExist:
            return None

    def get(self, request, music_uuid):
        music = self.get_object(music_uuid=music_uuid)
        if not music:
            return Response("There is no music about this id", status=status.HTTP_400_BAD_REQUEST)
        serializer = MusicSerializer(music)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, music_uuid):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)
        music = self.get_object(music_uuid=music_uuid)
        if not music:
            return Response("There is no music about this id", status=status.HTTP_400_BAD_REQUEST)

        serializer = MusicUpdateSerializer(music, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            create_user_activity(
                {'action': 'update', 'message': f"advice {music_uuid} was updated", 'created_by': request.user})
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, music_uuid):
        if not request.user.role or request.user.role.name != 'Admin':
            return Response({"message": "You are not authorized to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)
        music = self.get_object(music_uuid=music_uuid)
        if not music:
            return Response("There is no music about this id", status=status.HTTP_400_BAD_REQUEST)
        music.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class IdeaSparkCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        idea_spark = IdeaSpark.objects.filter(created_by=request.user)
        serializer = IdeaSparkSerializer(idea_spark, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        request.data['created_by'] = request.user.id
        serializer = IdeaSparkSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class IdeaSparkRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, idea_spark_uuid, user):
        try:
            return IdeaSpark.objects.get(idea_spark_uuid=idea_spark_uuid, created_by=user)
        except IdeaSpark.DoesNotExist:
            return None

    def get(self, request, idea_spark_uuid):
        idea_spark = self.get_object(idea_spark_uuid=idea_spark_uuid, user=request.user)
        if not idea_spark:
            return Response("There is no idea spark about this id", status=status.HTTP_400_BAD_REQUEST)
        serializer = IdeaSparkSerializer(idea_spark)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, idea_spark_uuid):
        idea_spark = self.get_object(idea_spark_uuid=idea_spark_uuid, user=request.user)
        if not idea_spark:
            return Response("There is no idea spark about this id", status=status.HTTP_400_BAD_REQUEST)
        serializer = IdeaSparkUpdateSerializer(idea_spark, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, idea_spark_uuid):
        idea_spark = self.get_object(idea_spark_uuid=idea_spark_uuid, user=request.user)
        if not idea_spark:
            return Response("There is no idea spark about this id", status=status.HTTP_400_BAD_REQUEST)
        idea_spark.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CreatePaymentIntent(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, plan_uuid):
        try:
            return Plan.objects.get(plan_uuid=plan_uuid, active=True)
        except Plan.DoesNotExist:
            return None

    def get_subscription(self, plan, user):
        try:
            return Subscription.objects.get(plan=plan, user=user)
        except Subscription.DoesNotExist:
            return None

    def post(self, request):
        plan = self.get_object(plan_uuid=request.data.get('plan_uuid'))
        if not plan:
            return Response("no plan found with this id", status=status.HTTP_400_BAD_REQUEST)

        subscription = self.get_subscription(plan=plan, user=request.user)
        current_date = datetime.today().date()
        if subscription.end_date > current_date:
            return Response("Your subscription is still active", status=status.HTTP_200_OK)
        subscription.delete()
        try:
            # Create a PaymentIntent with the order amount and currency
            package = request.data.get('package')
            if package == 'yearly':
                amount = int((plan.monthly_price * 12) - (plan.yearly_discount * 12))
            else:
                amount = int(plan.monthly_price)
            intent = stripe.PaymentIntent.create(
                amount=amount,
                currency='usd',
                # In the latest version of the API, specifying the `automatic_payment_methods` parameter is optional
                # because Stripe enables its functionality by default.
                automatic_payment_methods={
                    'enabled': True,
                },
            )
            return Response({
                'clientSecret': intent['client_secret']
            }, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response(str(e), status=status.HTTP_403_FORBIDDEN)


class TransactionCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, plan_uuid):
        try:
            return Plan.objects.get(plan_uuid=plan_uuid, active=True)
        except Plan.DoesNotExist:
            return None

    def post(self, request, transaction_status):
        body = json.loads(request.body.decode('utf-8'))
        if transaction_status == 'success':
            plan = self.get_object(plan_uuid=body.get('plan_uuid'))
            if not plan:
                return Response("No plan found", status=status.HTTP_400_BAD_REQUEST)
            if body.get('package') == 'yearly':
                end_date = datetime.today().date() + timedelta(days=365)
            else:
                end_date = datetime.today().date() + timedelta(days=30)
            subscription = Subscription.objects.create(**{
                'plan': plan,
                'start_date': datetime.today().date(),
                'end_date': end_date,
                'permission': plan.plan_permission,
                'user': request.user
            })
            subscription.save()

            transaction = Transaction.objects.create(**{
                'transaction_uuid': str(uuid.uuid4()),
                'amount': body.get('amount'),
                'payment_gateway': 'stripe',
                'transaction_status': 'success',
                'plan': plan,
                'user': request.user
            })
            transaction.save()
            invoice = Invoice.objects.create(**{
                'invoice_uuid': str(uuid.uuid4()),
                'transaction': transaction,
                'payment_status': True,
                'invoice_from': {'email': 'w@s.com'},
                'invoice_to': {'email': request.user.email}
            })
            invoice.save()
            subject = 'Your Invoice'
            message = 'Your subscript created successfully'
            from_email = 'email'  # Your email address
            recipient_list = [request.user.email]  # Recipient's email address(es)

            send_mail(subject, message, from_email, recipient_list, fail_silently=True)
            return Response("Invoice has been sent to your email, please check", status=status.HTTP_201_CREATED)

        plan = self.get_object(plan_uuid=body.get('plan_uuid'))
        if not plan:
            return Response("No plan found", status=status.HTTP_400_BAD_REQUEST)
        transaction = Transaction.objects.create(**{
            'transaction_uuid': str(uuid.uuid4()),
            'amount': body.get('amount'),
            'payment_gateway': 'stripe',
            'transaction_status': 'fail',
            'plan': plan,
            'user': request.user
        })
        transaction.save()
        invoice = Invoice.objects.create(**{
            'invoice_uuid': str(uuid.uuid4()),
            'transaction': transaction,
            'payment_status': True,
            'invoice_from': {'email': 'w@s.com'},
            'invoice_to': {'email': request.user.email}
        })
        invoice.save()
        subject = 'Your Invoice'
        message = 'Your subscription create failed'
        from_email = 'email'  # Your email address
        recipient_list = [request.user.email]  # Recipient's email address(es)

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        return Response("Your Invoice failed", status=status.HTTP_400_BAD_REQUEST)


class IdeaSparkFolderCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        folders = IdeaSparkFolder.objects.filter(created_by=request.user).order_by('updated_on')
        serializer = IdeaSparkFolderSerializer(folders, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        if not request.data.get('title'):
            request.data['title'] = request.data.get('idea_spark_folder_uuid')

        request.data['created_by'] = request.user.id
        serializer = IdeaSparkFolderSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'create', 'message': 'new idea spark folder crated',
                                  'created_by': request.user})

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class IdeaSparkFolderRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, idea_spark_folder_uuid, user):
        try:
            return IdeaSparkFolder.objects.get(idea_spark_folder_uuid=idea_spark_folder_uuid, created_by=user)
        except IdeaSparkFolder.DoesNotExist:
            return None

    def get(self, request, idea_spark_folder_uuid):
        folder = self.get_object(idea_spark_folder_uuid=idea_spark_folder_uuid, user=request.user)
        if not folder:
            return Response("No folder found", status=status.HTTP_400_BAD_REQUEST)
        idea_sparks = IdeaSpark.objects.filter(idea_spark_folder=folder, created_by=request.user)
        serializer = IdeaSparkSerializer(idea_sparks, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, idea_spark_folder_uuid):
        folder = self.get_object(idea_spark_folder_uuid=idea_spark_folder_uuid, user=request.user)
        if not folder:
            return Response("No folder found", status=status.HTTP_400_BAD_REQUEST)
        request.data['updated_on'] = timezone.now()
        serializer = IdeaSparkFolderUpdateSerializer(folder, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            create_user_activity({'action': 'update', 'message': f"idea spark folder {idea_spark_folder_uuid} updated",
                                  'created_by': request.user})
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, idea_spark_folder_uuid):
        folder = self.get_object(idea_spark_folder_uuid=idea_spark_folder_uuid, user=request.user)
        if not folder:
            return Response("No folder found", status=status.HTTP_400_BAD_REQUEST)

        idea_spark = IdeaSpark.objects.filter(idea_spark_folder=folder, created_by=request.user)
        idea_spark.delete()
        folder.delete()
        create_user_activity({'action': 'update', 'message': f"idea spark folder {idea_spark_folder_uuid} deleted",
                              'created_by': request.user})
        return Response(status=status.HTTP_204_NO_CONTENT)


class MoveIdeaSparkToFolder(APIView):
    permission_classes = [IsAuthenticated]

    def get_idea_spark(self, idea_spark_uuid, user):
        try:
            return IdeaSpark.objects.get(idea_spark_uuid=idea_spark_uuid, created_by=user)
        except IdeaSpark.DoesNotExist:
            return None

    def get_folder(self, idea_spark_folder_uuid, user):
        try:
            return IdeaSparkFolder.objects.get(idea_spark_folder_uuid=idea_spark_folder_uuid, created_by=user)
        except IdeaSparkFolder.DoesNotExist:
            return None

    def put(self, request):
        idea_spark = self.get_idea_spark(request.data.get('idea_spark_uuid'), request.user)
        if not idea_spark:
            return Response("No idea spark found", status=status.HTTP_400_BAD_REQUEST)
        idea_spark_folder = self.get_folder(request.data.get('idea_spark_folder_uuid'), request.user)
        if not idea_spark_folder:
            return Response("No idea spark folder found", status=status.HTTP_400_BAD_REQUEST)

        serializer = IdeaSparkUpdateSerializer(idea_spark, data={'idea_spark_folder': idea_spark_folder.id},
                                               partial=True)
        if serializer.is_valid():
            serializer.save()
            idea_spark_folder.updated_on = timezone.now()
            idea_spark_folder.save()
            create_user_activity({'action': 'update',
                                  'message': f"idea spark {idea_spark.idea_spark_uuid} move to {idea_spark_folder.idea_spark_folder_uuid}",
                                  'created_by': request.user})

            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
