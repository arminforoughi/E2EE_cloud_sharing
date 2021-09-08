import argon2
from django.db import models


class Public_Key(models.Model):
    username = models.CharField(max_length= 450)
    public_key = models.CharField(max_length= 450)


