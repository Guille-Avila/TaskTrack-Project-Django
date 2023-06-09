from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Task, Group, List

User = get_user_model()


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError('Invalid email or password')


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):

        email = validated_data['email']
        username = email.split('@')[0]

        user = User.objects.create_user(
            email=email,
            password=validated_data['password'],
            username=username,
        )
        return user

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'password', 'password_confirm')


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    email = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'password_confirm')


class PersonalUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username',
                  'name', 'phone', 'company', 'college')


class ChangePasswordSerializer(serializers.ModelSerializer):
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'password', 'new_password', 'confirm_new_password')


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ('id', 'title', 'description',
                  'due_date', 'priority', 'group',
                  'list', 'done', 'done_date', 'creation_date')


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id', 'name')


class ListSerializer(serializers.ModelSerializer):
    class Meta:
        model = List
        fields = ('id', 'name')


class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group.users.through
        fields = ('id', 'group_id', 'user_id')


# code to reset the password --------------------------------

class EmailPasswordResetSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']
        model = User


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, min_length=1)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        fields = ("password", "password_confirm")
