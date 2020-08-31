from rest_framework import generics, views, permissions
from rest_framework.response import Response
from rest_framework import status
from .serialisers import RegisterSerializer, TokenSerializer, LoginSerializer, CheckPasswordTokenSerializer, \
    SetNewPasswordSerialiser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Utils
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


class RegisterView(generics.GenericAPIView):
    User = get_user_model()
    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = self.User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        abs_url = 'http://' + current_site + relative_link + "?token=" + str(token)
        email_body = 'Hi ' + user.last_name + '\n Welcome to Share Contact platform. \n' + \
                     'Use the link below to activate your account \n' + abs_url

        data = {'email_body': email_body, 'email_subject': 'Account Verification', 'to_user': user.email}

        Utils.send_email(data)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ListUsersView(generics.ListAPIView):
    User = get_user_model()
    queryset = User.objects.all()
    serializer_class = RegisterSerializer


class EmailVerify(views.APIView):
    serializer_class = TokenSerializer
    token_params_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description',
                                            type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_params_config])
    def get(self, request):
        token = request.GET.get('token')
        User = get_user_model()
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'account': 'account successfully activated'}, status=status.HTTP_201_CREATED)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'activation link expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'Invalid token request new one'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ForgotPasswordView(generics.GenericAPIView):
    User = get_user_model()
    serializer_class = CheckPasswordTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        print(email)
        if self.User.objects.filter(email=email).exists():
            user = self.User.objects.get(email=email)
            print(user)
            user_idb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request).domain
            relative_link = reverse('reset-password', kwargs={'uidb64': smart_str(user_idb64), 'token': token})
            abs_url = 'http://' + current_site + relative_link
            email_body = 'Hi ' + user.last_name + '\n Use this link bellow to rest your password. \n' + abs_url
            data = {'email_body': email_body, 'email_subject': 'Reset your Account Password', 'to_user': user.email}

            Utils.send_email(data)

        return Response({'success': f"We'll send a link to reset password to {email}."}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    User = get_user_model()
    serializer_class = CheckPasswordTokenSerializer

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = self.User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token=token):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token})

        except DjangoUnicodeDecodeError:
            return Response({'error': 'Token is not valid, please request a new one'},
                            status=status.HTTP_401_UNAUTHORIZED)


class PasswordResetView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerialiser

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'massage': 'password reset successfully'}, status=status.HTTP_200_OK)
