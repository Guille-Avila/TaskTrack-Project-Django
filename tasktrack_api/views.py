from django.shortcuts import render
from rest_framework import status, generics, viewsets, permissions, authentication
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import LoginSerializer, UserSerializer, TaskSerializer, GroupSerializer, ListSerializer
from django.contrib.auth import get_user_model, logout
from .models import Task, Group, List

User = get_user_model()


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


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        done_param = self.request.query_params.get('done', None)
        tasks = user.task_set.all()

        if done_param is not None:
            if done_param.lower() == 'true':
                tasks = tasks.filter(done=True)
            elif done_param.lower() == 'false':
                tasks = tasks.filter(done=False)
        return tasks

    # save user and task in the intermediate table n.n
    def perform_create(self, serializer):
        users = [self.request.user]  # create list cause is relation n.n
        serializer.save(users=users)


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
        users = [self.request.user]
        serializer.save(users=users)


class ListViewSet(viewsets.ModelViewSet):
    queryset = List.objects.all()
    serializer_class = ListSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        lists = user.list_set.all()
        return lists

    def perform_create(self, serializer):
        users = self.request.user  # not array simple relation 1.n
        serializer.save(users=users)
