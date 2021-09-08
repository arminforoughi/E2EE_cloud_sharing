import hashlib
import hmac
import uuid
from Crypto.PublicKey import RSA
import argon2
from django.shortcuts import render

from E2EE.E2EE_app.models import *


def signup(req):
    return render(req, 'signup.html')


def get_pke_key(): # returns: RSA key object -- use .e for public & .d for private
    return RSA.generate(2048)




def get_argon_key(password, salt, argon_hash_len):
    return argon2.low_level.hash_secret(  # return: bytes
        bytes(password, 'ascii'),  # pass
        bytes(salt, 'ascii'),  # salt
        time_cost=1,
        memory_cost=64 * 1024,
        parallelism=4,
        hash_len=argon_hash_len,
        type=argon2.low_level.Type.D
    )

def get_uuid(password_argon_hash, username):
    return uuid.UUID(hmac.new(password_argon_hash, username, hashlib.sha256))






def init_user(username, password):
    rsa_key = RSA.generate(2048)

    # store username + rsa_public_key in Public_Key DB
    Public_Key(username, rsa_key.publickey().exportKey()).save()

















def process_signup(req):
    if req.method == 'POST':
        user = req.POST.get("username")
        password = req.POST.get("password")
        if user and password:
            argon_hash_len = 32
            password_argon_hash = get_argon_key(password, user, argon_hash_len)
            uuid = get_uuid(password_argon_hash, user)

