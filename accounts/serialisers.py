from abc import ABC
from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(min_length=8, max_length=65, write_only=True)
    last_name = serializers.CharField(max_length=100, required=True)
    first_name = serializers.CharField(max_length=100, required=True)

    class Meta:
        model = User
        fields = ('email', 'last_name', 'first_name', 'password')

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=128)
    password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    full_name = serializers.CharField(read_only=True)
    tokens = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'full_name', 'tokens',)

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credential, please try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disable please contact the Admin')
        if not user.is_verified:
            raise AuthenticationFailed('Account is not activated, please verify your emails')

        return {
            'email': user.email,
            'Nom complet': user.full_name,
            'tokens': user.tokens()
        }


class TokenSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=512)

    class Meta:
        model = User
        fields = ('token',)

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ('email',)

class CheckPasswordTokenSerializer(serializers.Serializer):
    uidb64 = serializers.EmailField(required=True)
    token = serializers.EmailField(required=True)


class SetNewPasswordSerialiser(serializers.Serializer):
    password = serializers.CharField(required=True, write_only=True)
    uidb64 = serializers.CharField(required=True, write_only=True)
    token = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            uidb64 = attrs.get('uidb64')
            token = attrs.get('token')
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('the reset link is Invalid', 401)
            user.set_password(raw_password=password)
            user.save()

        except Exception as e:
            print(e)
            raise AuthenticationFailed('the reset link is Invalid', 401)
        return super().validate(attrs)



