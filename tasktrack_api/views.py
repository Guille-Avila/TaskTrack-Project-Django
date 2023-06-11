from django.shortcuts import get_object_or_404
from rest_framework import status, generics, viewsets, permissions, authentication
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import LoginSerializer, UserSerializer, TaskSerializer, GroupSerializer, ListSerializer, MemberSerializer, PersonalUserSerializer, RegisterSerializer, ChangePasswordSerializer, EmailPasswordResetSerializer, ResetPasswordSerializer
from django.contrib.auth import get_user_model
from .models import Task, Group, List
from rest_framework.decorators import api_view
from django.contrib.auth.hashers import make_password
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.utils.http import urlsafe_base64_decode
from rest_framework.generics import DestroyAPIView


User = get_user_model()


@api_view(['GET'])
def get_current_user(request):
    user = request.user

    if user.is_authenticated:
        serializer = UserSerializer(user)
        return Response(serializer.data)
    else:
        return Response({'error': 'User not authenticated'})


class UserView(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = PersonalUserSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return User.objects.filter(pk=user.pk)

    def get_object(self):
        return self.request.user

    def perform_update(self, serializer):
        password = self.request.data.get('password', None)
        if password:
            serializer.validated_data['password'] = make_password(password)
        serializer.save()


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    def post(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError, Token.DoesNotExist):
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)


class CheckLoginView(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({'message': 'El usuario ha iniciado sesión correctamente.'}, status=status.HTTP_200_OK)


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        username = email.split('@')[0]

        password = serializer.validated_data['password']
        password_confirm = serializer.validated_data['password_confirm']

        if password != password_confirm:
            return Response({'message': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            email=email,
            password=password,
            username=username,
        )

        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=status.HTTP_201_CREATED)


class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = ChangePasswordSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, *args, **kwargs):
        user = self.request.user
        password = request.data.get('password')
        new_password = request.data.get('new_password')
        confirm_new_password = request.data.get('confirm_new_password')

        if not user.check_password(password):
            return Response({'message': 'Incorrect password'}, status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_new_password:
            return Response({'message': 'New passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(user, data=request.data)
        serializer.is_valid(raise_exception=True)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password updated successfully'}, status=status.HTTP_200_OK)


class IsGroupMember(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        group_id = obj.group_id
        print(group_id)
        print(user.group_set.filter(pk=group_id).exists())
        if group_id is None:
            return True
        return user.group_set.filter(pk=group_id).exists()


class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated, IsGroupMember]

    def get_queryset(self):
        user = self.request.user
        done_param = self.request.query_params.get('done', None)
        tasks = user.task_set.all()
        group_tasks = Task.objects.filter(group__users=user)

        tasks = tasks | group_tasks

        if done_param is not None:
            if done_param.lower() == 'true':
                tasks = tasks.filter(done=True)
            elif done_param.lower() == 'false':
                tasks = tasks.filter(done=False)
        return tasks.distinct()

    def perform_create(self, serializer):
        user = self.request.user
        serializer.save(user=user)


class GroupViewSet(viewsets.ModelViewSet):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        groups = user.group_set.all()
        return groups

    def perform_create(self, serializer):
        group = serializer.save()
        group.users.add(self.request.user)


class ListViewSet(viewsets.ModelViewSet):
    queryset = List.objects.all()
    serializer_class = ListSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        lists = List.objects.filter(user=user)
        return lists

    def perform_create(self, serializer):
        user = self.request.user  # not array simple relation 1.n
        serializer.save(user=user)


class MemberViewSet(viewsets.ModelViewSet):
    serializer_class = MemberSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        group_id = self.kwargs.get('id')
        queryset = Group.users.through.objects.filter(group_id=group_id)
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        user_ids = [relation.user_id for relation in queryset]
        users = User.objects.filter(id__in=user_ids)
        serializer = UserSerializer(users, many=True)
        data = serializer.data

        return Response(data)

    def create(self, request, *args, **kwargs):
        group_id = self.kwargs.get('id')
        username = request.data.get('username')
        email = request.data.get('email')

        group = get_object_or_404(Group, id=group_id)
        user = None

        if username:
            user = get_object_or_404(User, username=username)
        elif email:
            user = get_object_or_404(User, email=email)

        if user:
            group.users.add(user)
            return Response({'message': 'New member {} added to group {}'.format(user.username, group.name)},
                            status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Failed to add new member'},
                            status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        group_id = self.kwargs.get('group_id')
        user_id = self.kwargs.get('user_id')

        username = request.data.get('username')
        email = request.data.get('email')

        if username:
            user = get_object_or_404(User, username=username)
            new_user_id = user.id
        elif email:
            user = get_object_or_404(User, email=email)
            new_user_id = user.id

        group = get_object_or_404(Group, id=group_id)
        try:
            member = group.users.through.objects.get(
                group_id=group_id, user_id=user_id)
        except group.users.through.DoesNotExist:
            return Response({'message': 'Failed to get member'}, status=status.HTTP_400_BAD_REQUEST)

        if member:
            member.user_id = new_user_id
            member.save()
            return Response({'message': 'Edit member {} in group {}'.format(member.user_id, member.group_id)},
                            status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Failed to update member'}, status=status.HTTP_400_BAD_REQUEST)


class MemberDestroyView(DestroyAPIView):
    queryset = Group.objects.all()
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        # Reemplaza con tu origen adecuado
        response["Access-Control-Allow-Origin"] = "http://localhost:3000"
        return response

    def destroy(self, request, *args, **kwargs):
        group_id = self.kwargs.get('group_id')
        user_id = self.kwargs.get('user_id')

        group = get_object_or_404(Group, id=group_id)

        try:
            member = group.users.through.objects.get(
                group_id=group_id, user_id=user_id)
            member.delete()
            return Response({'message': 'Member {} has been removed from group {}'.format(user_id, group_id)},
                            status=status.HTTP_204_NO_CONTENT)
        except group.users.through.DoesNotExist:
            return Response({'message': 'Failed to delete member'},
                            status=status.HTTP_400_BAD_REQUEST)

# views to Reset Password sending an Email


class EmailPasswordResetView(generics.GenericAPIView):
    serializer_class = EmailPasswordResetSerializer

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data["email"]
        user = User.objects.filter(email=email).first()

        if user:
            encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)

            reset_link = f"http://localhost:3000/restart-password/?pk={encoded_pk}&token={token}"

            html_message = f"<h5>Info</h5><h2>TaskTrack</h2><p>You have requested to reset your password. If you have not done so, ignore this message.</p><a href='{reset_link}'>Click to reset you Password</a><p><i>Cordially the TaskTrack team</i></p>"

            email = EmailMultiAlternatives(
                'Reset password TaskTrack',
                html_message,
                settings.EMAIL_HOST_USER,
                [email]
            )

            email.content_subtype = "html"
            email.send()

            return Response(
                {"message": f"Your password rest link: {reset_link}"},
                status=status.HTTP_200_OK,
            )

        else:
            return Response(
                {"message": "User doesn't exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ResetPasswordview(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def patch(self, request, *args, **kwargs):
        password = request.data.get("password")
        password_confirm = request.data.get("password_confirm")

        if password != password_confirm:
            return Response(
                {"message": "Passwords do not match"},
                status=status.HTTP_400_BAD_REQUEST
            )

        token = kwargs.get("token")
        encoded_pk = kwargs.get("encoded_pk")

        if token is None or encoded_pk is None:
            return Response(
                {"message": "Missing data."},
                status=status.HTTP_400_BAD_REQUEST
            )

        pk = urlsafe_base64_decode(encoded_pk).decode()
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(
                {"message": "User does not exist."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response(
                {"message": "The reset token is invalid"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(password)
        user.save()

        return Response(
            {"message": "Password reset complete"},
            status=status.HTTP_200_OK
        )
