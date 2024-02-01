from django.db import models

# Create your models here.

class KeysModel(models.Model):
    access_key = models.CharField(max_length=255)
    secret_access_key = models.CharField(max_length=255)
    region_name = models.CharField(max_length=255)
    