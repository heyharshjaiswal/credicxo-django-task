from django.contrib import admin
from .models import User, StudentInfoByTeacher

# Register your models here.
admin.site.register(User)
admin.site.register(StudentInfoByTeacher)