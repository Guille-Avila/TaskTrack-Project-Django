from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import LoginView, RegisterView, TaskViewSet, LogoutView, GroupViewSet, ListViewSet
from rest_framework.authtoken.views import obtain_auth_token

router = DefaultRouter()
router.register('tasks', TaskViewSet)
router.register('groups', GroupViewSet)
router.register('lists', ListViewSet)

urlpatterns = [
    # Otras URL de tu aplicación
    path('user-token/', obtain_auth_token,
         name='api_token_auth'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
] + router.urls
