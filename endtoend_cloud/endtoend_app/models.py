from django.db import models


class Key_Store(models.Model):
    username = models.CharField(max_length= 450, primary_key=True)
    public_key = models.CharField(max_length= 450)


class Data_Store(models.Model):
    user_key = models.CharField(max_length= 450, primary_key=True)
    data = models.BinaryField()
