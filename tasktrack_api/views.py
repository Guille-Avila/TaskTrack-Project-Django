from django.shortcuts import render
from django.shortcuts import get_object_or_404
from rest_framework import status, generics, viewsets, permissions, authentication
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import LoginSerializer, UserSerializer, TaskSerializer, GroupSerializer, ListSerializer, MemberSerializer
from django.contrib.auth import get_user_model
from .models import Task, Group, List
from django.core.exceptions import ObjectDoesNotExist

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
        group = serializer.save()
        group.users.add(self.request.user)


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


class MemberViewSet(viewsets.ModelViewSet):
    serializer_class = MemberSerializer

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
            return Response({'message': 'New member {} added to group {}'.format(user.username, group.name)}, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Failed to add new member'}, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        group_id = self.kwargs.get('id')
        user_id = request.data.get('user_id')

        group = get_object_or_404(Group, id=group_id)
        try:
            member = group.users.through.objects.get(
                group_id=group_id, user_id=user_id)
            member.delete()
            return Response({'message': 'Member {} has been removed from group {}'.format(user_id, group_id)},
                            status=status.HTTP_204_NO_CONTENT)
        except group.users.through.DoesNotExist:
            raise Response({'message': 'Failed to delete member'},
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
            member = group.users.through.objects.get(group_id=group_id, user_id=user_id)
            print(member)
        except group.users.through.DoesNotExist:
            return Response({'message': 'Failed to get member'}, status=status.HTTP_400_BAD_REQUEST)

        if member:
            member.user_id = new_user_id
            member.save()
            return Response({'message': 'Edit member {} in group {}'.format(member.user_id, member.group_id)}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Failed to update member'}, status=status.HTTP_400_BAD_REQUEST)
