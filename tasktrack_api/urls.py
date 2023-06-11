from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import LoginView, RegisterView, TaskViewSet, LogoutView, GroupViewSet, ListViewSet, MemberViewSet, get_current_user, UserView, ChangePasswordView, CheckLoginView, EmailPasswordResetView, ResetPasswordview, MemberDestroyView
from rest_framework.authtoken.views import obtain_auth_token

router = DefaultRouter()
router.register('tasks', TaskViewSet)
router.register('groups', GroupViewSet)
router.register('lists', ListViewSet)
router.register('user', UserView)

urlpatterns = [
    # Otras URL de tu aplicación
    path('user-token/', obtain_auth_token,
         name='api_token_auth'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', RegisterView.as_view(), name='register'),
    path('members/<int:id>/',
         MemberViewSet.as_view({'get': 'list', 'post': 'create'}), name='members'),
    path('members/<int:group_id>/<int:user_id>/',
         MemberViewSet.as_view({'put': 'update'}), name='member-update'),
    path('delete-member/<int:group_id>/<int:user_id>/',
         MemberDestroyView.as_view(), name='member-delete'),
    path('current-user/', get_current_user, name='current-user'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('check-login/', CheckLoginView.as_view(), name='check_login'),
    path("email-password/", EmailPasswordResetView.as_view(),
         name="request-password-reset"),
    path("reset-password/<str:encoded_pk>/<str:token>/",
         ResetPasswordview.as_view(), name="reset-password")
] + router.urls
