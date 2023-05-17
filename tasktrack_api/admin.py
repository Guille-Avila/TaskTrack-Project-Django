from django.contrib import admin

# Register your models here.

from .models import User, Task, Priority, List, Group

admin.site.register(User)
admin.site.register(Task)
admin.site.register(Priority)
admin.site.register(List)
admin.site.register(Group)
