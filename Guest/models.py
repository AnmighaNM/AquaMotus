from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

# Create your models here.

class CustomDetails(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('stationmaster', 'Station Master'),
        ('user', 'User'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    
    def __str__(self):
        return self.username
    
class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    user_contact = models.CharField(max_length=10, unique=True)
    user_address = models.CharField(max_length=255)
    user_gender = models.CharField(max_length=6, choices=(('Male','male'), ('Female','male')))
    user_photo = models.ImageField(upload_to='user_photos/', blank=True, null=True)

    def __str__(self):
        return self.user.username