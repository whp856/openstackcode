from django.contrib import admin
from django.urls import path, re_path
import app01.views as view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',view.home),
    path('home/',view.home,name='home'),
    path('login_check/',view.login_check,name='login_check'),
    path('register/', view.register, name='register'),
    path('containers/',view.containers,name='containers'),
    path('objects/<data2>',view.objects,name='objects'),
    path('addContainer/<data>',view.addContainer,name='addContainer'),
    path('logout/',view.logout,name='logout'),
    path('download/<container>/<object>',view.download,name='download'),
    path('upload/<object>',view.upload,name='upload'),
    path('delete/<container>/<object>',view.delete,name='delete'),
    re_path(r'^view_file/(?P<container>[^/]+)/(?P<object>[^/]+)/(?P<content_type>.*)$', view.view_file, name='view_file'),
    path('check_container_objects/<container>',view.check_container_objects,name='check_container_objects'),
    path('delete_container/<container>',view.delete_container,name='delete_container'),
    path('logs/',view.view_logs,name='view_logs')
]
