"""
URL configuration for WaterMetro project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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

from django.urls import path
from Guest import views
app_name = "WebGuest"

urlpatterns = [
    path('',views.index,name='Index'),
    path('Login/',views.login_view,name='Login'),
    path('ForgetPassword/',views.forgetpassword,name='ForgetPassword'),
    path('OtpVer/', views.OtpVerification,name="Verification"),
    path('Ajaxemail/', views.ajaxemail,name="AjaxEmail"),
    path('Create/', views.CreateNewPass,name="Create"), 
    path('UserRegistration/',views.user_registration,name='UserRegistration'),
    path('validate_email/', views.validate_email, name='validate_email'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('Logout/', views.logoutView, name='Logout'),
]
