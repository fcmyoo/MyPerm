"""MyPerm URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from user import urls
from MyPerm.views import *

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', index, name='index'),
    # # url(r'^api/user/$', 'api_user'),
    url(r'^skin_config/$', skin_config, name='skin_config'),
    url(r'^login/$', Login, name='login'),
    url(r'^logout/$', Logout, name='logout'),
    # url(r'^exec_cmd/$', 'exec_cmd', name='exec_cmd'),
    # url(r'^file/upload/$', 'upload', name='file_upload'),
    # url(r'^file/download/$', 'download', name='file_download'),
    url(r'^setting', setting, name='setting'),
    # url(r'^terminal/$', 'web_terminal', name='terminal'),
    url(r'^user/', include(urls)),
    # url(r'^jasset/', include('jasset.urls')),
    # url(r'^jlog/', include('jlog.urls')),
    # url(r'^jperm/', include('jperm.urls')),
]
