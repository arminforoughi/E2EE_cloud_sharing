from django.shortcuts import render


def signup(req):
    return render(req, 'signup.html')
