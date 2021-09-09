from django.shortcuts import render

RSA_KEY_SIZE_BITS = 2048
# HASH_SIZE_BYTES = hashlib.sha512.Size


def signup(req):
    return render(req, 'signup.html')



