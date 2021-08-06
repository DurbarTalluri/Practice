from django.shortcuts import render
from django.http import HttpResponse
import os
from .models import Details
# Create your views here.
def index(request):
    User=os.getenv("USERNAME")
    Domain=os.getenv("USERDOMAIN")
    temp=Details.objects.create(user=User,domain=Domain)
    temp.save()
    return HttpResponse(User+'\n'+Domain)