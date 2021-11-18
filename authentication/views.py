from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.shortcuts import render
from django.utils.encoding import DjangoUnicodeDecodeError, smart_str
from rest_framework import generics, status, views
from rest_framework.utils import serializer_helpers
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRender
from django.utils.http import urlsafe_base64_decode

# Create your views here.

class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRender,)

    def post(self, request):
        user = request.data
        serialize = self.serializer_class(data = user)
        serialize.is_valid(raise_exception = True)
        serialize.save()

        user_data = serialize.data

        user = User.objects.get(email = user_data['email'])

        
        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)
        email_body = 'Hi ' + user.username + ' Use link below to verify your email \n' + absurl
        data = {
            'email_body': email_body,
            'email_subject': 'Verify your email',
            'to_email': user.email
        }
        Util.send_email(data)

        return Response(user_data, status = status.HTTP_201_CREATED)

class VerifyEmail(views.APIView):

    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token',in_= openapi.IN_QUERY, description = "Description", type = openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters = [token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id = payload['user_id'])

            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({'email': 'Successfuly activated'}, status = status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as e:
            return Response({'error': 'Activation Expired'}, status = status.HTTP_400_BAD_REQUEST)

        except jwt.exceptions.DecodeError as e:
            return Response({'error': 'Invalid token'}, status = status.HTTP_400_BAD_REQUEST)

class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)
        
        return Response(serializer.data, status = status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):

    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        data = {
            'request': request,
            'data': request.data,
            'email': request.data['email']
        }
        serializer = self.serializer_class(data = data)
        serializer.is_valid(raise_exception = True)
        return Response({'success': 'We have sent you a link to reset your password'}, status = status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id = id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'})

            return Response({
                'success': True,
                'message': 'Credentials Valid',
                'uidb64': uidb64,
                'token': token
            }, status = status.HTTP_200_OK)


        except DjangoUnicodeDecodeError as e:
            return Response({'error': 'Token is not valid, please request a new one'})

class SetNewPasswordAPIView(generics.GenericAPIView):

    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)
        return Response({
                'success': True,
                'message': 'Password reset success'
            }, status = status.HTTP_200_OK)

