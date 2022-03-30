from django.urls import reverse
from django.conf import settings
from django.db.models import Q
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.hashers import make_password
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

import jwt

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer, ResetPasswordEmailSerializer, SetNewPasswordSerializer, GroupUserSerializer
from .models import User
from .utils import Util
from .renderers import UserRender
from .utils import Util


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRender, )

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)   # calls the validate method from serializers
        serializer.save()                           # calls create method from serializers
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        
        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relativeLink = reverse('verify_email')
        
        absurl = 'http://' + current_site + relativeLink + "?token="+str(token)
        email_body = 'Hi ' + user.username + ' Use the link below to verify the email. \n' + absurl
        data = {'email_body':email_body,'to_email':user.email, 'email_subject':'Verify your Email'}
        Util.send_email(data)
    
        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):

    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')        # getting the token?= query form URL
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email':'Successfully Activated'}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as identifier:
            return Response({'error':'Activation Link Expired'}, status=status.HTTP_400_BAD_REQUEST)
        # except jwt.exceptions.DecodeError as identifier:
        #     return Response({'error':'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64':uidb64, 'token':token})
            
            absurl = 'http://' + current_site + relativeLink
            email_body = 'Hi, \n Use the link below to reset your Password. \n' + absurl
            data = {'email_body':email_body,'to_email':user.email, 'email_subject':'Reset Your Password'}
            Util.send_email(data)

        return Response({'success':'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)

class PasswordTokenCheckAPIView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error':'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success':True, 'messsage':'Credentials Valid', 'uidb':uidb64, 'token':token}, status=status.HTTP_200_OK)

            
        except DjangoUnicodeDecodeError as identifier:
            return Response({'error':'Token is not valid please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)

        serializer.is_valid(raise_exception=True)
        return Response({'success':True, 'message':'Password reset success'}, status=status.HTTP_200_OK)


class UserAPIView(views.APIView):
    permission_classes = (IsAuthenticated,)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data = None

    # POST request to add the new user to the database
    # Student (Group no 3) is unable to add anyone to the database
    # Teacher (Group no 2) is able to add Students to the database
    # Super-admin (Group no 1) is able to add anyone to the database
    def post(self, request):
        try:
            if request.user.groups.exists():
                group = request.user.groups.all()[0].name # requesting user's group name
                condition01 = (group == "Super-admin")
                condition02 = ((group == "Teacher") and (request.data['groups']==[3]))
                if condition01 or condition02:
                    user = request.data
                    # encrypting password with sha_256 algorithm
                    user['password'] = make_password(user['password'])
                    serializer = GroupUserSerializer(data=user)
                    serializer.is_valid(raise_exception=True)
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                else:
                    err_message = {'status': 401, 'err_message': "user can't add user to same level"}
                    return Response(status=status.HTTP_401_UNAUTHORIZED, data=err_message)
            else:
                err_message = {'status': 401, 'err_message': "user has no admin/super user role assigned."}
                return Response(status=status.HTTP_401_UNAUTHORIZED, data=err_message)
        except Exception as ex:
            return Response(ex.args, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

    # GET request to list users
    # Student (Group no 3) is able to list his information from the database
    # Teacher (Group no 2) is able to list Students' information from the database
    # Super-admin (Group no 1) is able to list anyone's information from the database
    def get(self, request):

        try:
            if request.user.groups.exists():
                group = request.user.groups.all()[0].name
                if group == "Super-admin":
                    users = User.objects.filter(Q(groups=1) | Q(groups=2) | Q(groups=3)) # Filter every user belongs to all three groups
                    serializer = GroupUserSerializer(users, many=True)
                elif group == "Teacher":
                    users = User.objects.filter(groups=3) # Filter user belogs to Students' group
                    serializer = GroupUserSerializer(users, many=True)
                elif group == "Student":
                    users = User.objects.get(id=request.user.id)
                    serializer = GroupUserSerializer(users)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.data)
