import hashlib, hmac, uuid, os, json
from base64 import b64encode, b64decode

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import argon2
from Crypto.Util.Padding import pad, unpad
from cprint import cprint
from django.shortcuts import render

from E2EE.E2EE_app.models import *

RSA_KEY_SIZE_BITS = 2048
HASH_SIZE_BYTES = hashlib.sha512.Size


def signup(req):
    return render(req, 'signup.html')


def get_pke_key():  # returns: RSA key object -- use .e for public & .d for private
    return RSA.generate(RSA_KEY_SIZE_BITS)


def get_argon_key(password: str, salt: str, argon_hash_len: int) -> bytes:
    return argon2.low_level.hash_secret(  # return: bytes
        bytes(password, 'ascii'),
        bytes(salt, 'ascii'),
        time_cost=1,
        memory_cost=64 * 1024,
        parallelism=4,
        hash_len=argon_hash_len,
        type=argon2.low_level.Type.D
    )


def get_uuid(password_argon_hash, username):
    return uuid.UUID(hmac.new(password_argon_hash, username, hashlib.sha256))


def sym_enc(enc_key: bytes, iv: bytes, to_enc_json: json) -> json:
    to_enc_bytes = b64encode(to_enc_json)

    if len(iv) != AES.block_size:
        raise ValueError(f"The Initialization vector must be the same size as AES block size of {AES.block_size}!")

    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(to_enc_bytes, AES.block_size))
    return json.dumps({'iv': cipher.iv, "cipher_text": cipher_text})




def


def get_random_bytes(num_bytes: int) -> bytes:
    return os.urrandom(num_bytes)


def sym_dec(key: bytes, cipher_data: json) -> bytes:
    try:
        cipher_data_dict = json.loads(cipher_data)
        iv = b64decode(cipher_data_dict['iv'])
        cipher_text = b64decode(cipher_data_dict['cipher_text'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(cipher_text), AES.block_size)
    except ValueError:
        cprint('Symmetric Decryption Failed! ', c='rB')


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

    user_class_json = json.dumps(user.__dict__)
    cipher_json = sym_enc(user.enc_key, get_random_bytes(AES.block_size), user_class_json)



def process_signup(req):
    if req.method == 'POST':
        user = req.POST.get("username")
        password = req.POST.get("password")
        if user and password:
            argon_hash_len = 32
            password_argon_hash = get_argon_key(password, user, argon_hash_len)
            uuid = get_uuid(password_argon_hash, user)
