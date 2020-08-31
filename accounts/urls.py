from django.urls import path
from .views import RegisterView, ListUsersView, EmailVerify, LoginView, ForgotPasswordView, PasswordTokenCheckAPI, \
    PasswordResetView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('users/', ListUsersView.as_view(), name='list-users'),
    path('email-verify/', EmailVerify.as_view(), name='email-verify'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh-token'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('password-token-check/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-token-check'),
    path('reset-password/', PasswordResetView.as_view(), name='reset-password'),

]
