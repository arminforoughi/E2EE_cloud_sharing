import argon2
from django.shortcuts import render


def signup(req):
    return render(req, 'signup.html')


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


def process_signup(req):
    if req.method == 'POST':
        user = req.POST.get("username")
        password = req.POST.get("username")
        if user and password:
            argon_hash_len = 64

            password_argon_hash = get_argon_key(password, user, argon_hash_len)
