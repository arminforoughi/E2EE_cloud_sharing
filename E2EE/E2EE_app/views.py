import hashlib
import hmac
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

import json
import argon2
from Crypto.Util.Padding import pad
from django.shortcuts import render

from E2EE.E2EE_app.models import *

RSA_KEY_SIZE_BITS = 2048
HASH_SIZE_BYTES = hashlib.sha512.Size



def signup(req):
    return render(req, 'signup.html')


def get_pke_key():  # returns: RSA key object -- use .e for public & .d for private
    return RSA.generate(RSA_KEY_SIZE_BITS)


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




def sym_enc(enc_key, iv, to_enc_text):
    if len(iv) != AES.block_size:
        raise RuntimeError
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(to_enc_text, AES.block_size))





















def init_user(username, password):
    rsa_key = RSA.generate(2048)

    # store username + rsa_public_key in Public_Key DB
    Public_Key(username, rsa_key.publickey().exportKey()).save()
    user = User()

    user.username = username
    user.data_db_key = get_argon_key(password, username, len(username))
    user.enc_key = get_argon_key(f"enc_{password}", username, RSA_KEY_SIZE_BITS // 8)
    user.hmac_key = get_argon_key(f"hmac_{password}", username, HASH_SIZE_BYTES)
    user.rsa_private_key = rsa_key.export_key()

    user_data_to_encrypt = json.dumps(user.__dict__)



    cipher = AES.new(user.enc_key, AES.MODE_CFB, )

    cipher_rsa = PKCS1_OAEP.new(user.enc_key)
    enc_session_key = cipher_rsa.encrypt(user_data_to_encrypt)


def process_signup(req):
    if req.method == 'POST':
        user = req.POST.get("username")
        password = req.POST.get("password")
        if user and password:
            argon_hash_len = 32
            password_argon_hash = get_argon_key(password, user, argon_hash_len)
            uuid = get_uuid(password_argon_hash, user)
