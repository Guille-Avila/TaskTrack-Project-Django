from typing import Any
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager

# Create your models here.


class UserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("Enter a valid email")
        if not password:
            raise ValueError("Enter avalid password")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, max_length=150)
    password = models.CharField(max_length=128)
    username = models.CharField(max_length=150, unique=True)
    name = models.CharField(max_length=150, null=True, blank=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    company = models.CharField(max_length=150, null=True, blank=True)
    college = models.CharField(max_length=150, null=True, blank=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


class Task(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField(null=True)
    due_date = models.DateField(null=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    done_date = models.DateTimeField(null=True, blank=True)
    done = models.BooleanField(default=False)
    priority = models.ForeignKey(
        'Priority', on_delete=models.CASCADE, default=1)
    list = models.ForeignKey(
        'List', on_delete=models.CASCADE, null=True)
    group = models.ForeignKey(
        'Group', on_delete=models.CASCADE, null=True)
    user = models.ForeignKey(
        'User', on_delete=models.CASCADE, null=True)


class Priority(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class List(models.Model):
    name = models.CharField(max_length=100)
    user = models.ForeignKey('User', on_delete=models.CASCADE)


class Group(models.Model):
    name = models.CharField(max_length=100)
    users = models.ManyToManyField(User)
