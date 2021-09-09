import ast
import hashlib, hmac, uuid, os, json
# from base64 import b64encode, b64decode
#
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import AES
# import argon2
# from Crypto.Util.Padding import pad, unpad
# from cprint import cprint
# from django.shortcuts import render
#
# from E2EE.E2EE_app.models import *
#
#
#
#
#
# RSA_KEY_SIZE_BITS = 2048
# # HASH_SIZE_BYTES = hashlib.sha512.Size
#
#
# def signup(req):
#     return render(req, 'signup.html')
#
#
# def get_pke_key():  # returns: RSA key object -- use .e for public & .d for private
#     return RSA.generate(RSA_KEY_SIZE_BITS)


# def get_argon_key(password: str, salt: str, argon_hash_len: int) -> bytes:
#     return argon2.low_level.hash_secret(  # return: bytes
#         bytes(password, 'ascii'),
#         bytes(salt, 'ascii'),
#         time_cost=1,
#         memory_cost=64 * 1024,
#         parallelism=4,
#         hash_len=argon_hash_len,
#         type=argon2.low_level.Type.D
#     )
import json
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cprint import cprint


def sym_enc(enc_key: bytes, iv: bytes, to_enc_json: json) -> dict:
    to_enc_bytes = b64encode(json.dumps(to_enc_json).encode('ascii'))

    if len(iv) != AES.block_size:
        raise ValueError(f"The Initialization vector must be the same size as AES block size of {AES.block_size}!")

    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(to_enc_bytes, AES.block_size))
    return {'iv': b64encode(cipher.iv), "cipher_text": b64encode(cipher_text)}

#
# def get_hmac(hmac_key: bytes, data_to_hash: bytes) -> bytes:
#     return hmac.new(hmac_key, data_to_hash, hashlib.sha256)
#
#
def get_random_bytes(num_bytes: int) -> bytes:
    return os.urandom(num_bytes)


def sym_dec(key: bytes, cipher_data: dict) -> bytes:
    try:
        cipher_data_dict = cipher_data
        iv = b64decode(cipher_data_dict['iv'])
        cipher_text = b64decode(cipher_data_dict['cipher_text'])



        cipher = AES.new(key, AES.MODE_CBC, iv)
        return json.loads(b64decode((unpad(cipher.decrypt(cipher_text), AES.block_size))).decode('ascii'))

    except ValueError:
        cprint('Symmetric Decryption Failed! ', c='rB')

#
# def init_user(username, password):
#     rsa_key = RSA.generate(2048)
#
#     # store username + rsa_public_key in Public_Key DB
#     Public_Key(username, rsa_key.publickey().exportKey()).save()
#
#     user = {}
#     user.username = username
#     user.data_db_key = get_argon_key(password, username, len(username))
#     user.enc_key = get_argon_key(f"enc_{password}", username, RSA_KEY_SIZE_BITS // 8)
#     user.hmac_key = get_argon_key(f"hmac_{password}", username, HASH_SIZE_BYTES)
#     user.rsa_private_key = rsa_key.export_key()
#
#     user_class_json = json.dumps(user.__dict__)
#     cipher_json = sym_enc(user.enc_key, get_random_bytes(AES.block_size), user_class_json)
#     cipher_hmac = get_hmac(user.hmac_key, user_class_json.encode('ascii'))
#
#     encrypted_hmac_user_cipher_bytearray = bytearray(cipher_json.encode('ascii')).append(cipher_hmac)
