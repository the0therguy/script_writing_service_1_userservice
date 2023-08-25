from django.urls import path, include
from .views import *
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)

urlpatterns = [
    path('api/v1/signup/', CustomUserCreateView.as_view(), name='signup'),
    path('api/v1/verify-otp/<str:username>/', OTPVerificationView.as_view(), name='otp_verification_view'),
    path('api/v1/resend-otp/<str:username>/', OTPResendView.as_view(), name='resend_otp'),
    path('api/v1/signin/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/v1/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/v1/logout/', LogoutView.as_view(), name='auth_logout'),
    path('api/v1/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('api/v1/glossaries/', GlossaryView.as_view(), name='glossary-list-view'),
    path('api/v1/get-glossary/<str:uid>/', GlossaryDetailView.as_view(), name='glossary-view-update-delete'),
    path('api/v1/plans/', PlanListView.as_view(), name='plan-list'),
    path('api/v1/get-plan/<str:plan_uuid>/', PlanDetailView.as_view(), name='plan-list'),
    path('api/v1/password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('api/v1/get-user-by-email/<str:email>/', CustomUserViewByEmail.as_view(), name='user-view-by-email'),
    path('api/v1/get-user-by-id/<int:pk>/', CustomUserViewById.as_view(), name='user-view-by-id'),
    path('api/v1/advices/', AdviceListCreate.as_view(), name='advice-get-create'),
    path('api/v1/advice/<str:advice_uuid>/', AdviceRetrieveView.as_view(), name='advice-get-update-delete'),
    path('api/v1/musics/', MusicListCreateView.as_view(), name='music-list-create'),
    path('api/v1/music/<str:music_uuid>/', MusicRetrieveView.as_view(), name='music-get-update-delete'),
    path('api/v1/idea-sparks/', IdeaSparkCreateView.as_view(), name='idea-spark-list-create'),
    path('api/v1/idea-spark/<str:idea_spark_uuid>/', IdeaSparkRetrieveView.as_view(),
         name='idea-spark-get-update-delete'),
    path('api/v1/create-payment-intent/', CreatePaymentIntent.as_view(), name='payment-intent'),
]
