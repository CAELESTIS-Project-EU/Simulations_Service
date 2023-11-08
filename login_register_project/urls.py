"""login_register_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from accounts.views import custom_404_view, custom_400_view, custom_403_view, custom_500_view, csrf_failure
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('accounts.urls')),
]

from django.conf.urls import handler404, handler500, handler403, handler400

handler404 = 'accounts.views.custom_404_view'
handler500 = 'accounts.views.custom_500_view'
handler403 = 'accounts.views.custom_403_view'
handler400 = 'accounts.views.custom_400_view'
CSRF_FAILURE_VIEW = 'accounts.views.csrf_failure'
