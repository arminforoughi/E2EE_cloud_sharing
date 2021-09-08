import argon2
from django.db import models


class User:
    username = None
    data_db_key = None
    enc_key = None
    hmac_key = None
    rsa_private_key = None



class Public_Key(models.Model):
    username = models.CharField(max_length= 450)
    public_key = models.CharField(max_length= 450)


