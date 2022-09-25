from django.shortcuts import render
from django.contrib.auth.decorators import login_required

from accounts.forms import UserProfileForm
from accounts.models import User

# Create your views here.

@login_required(login_url='login')
def cprofile(request):
    profile_form = UserProfileForm()

    context = {}
    return render(request, 'customers/cprofile.html', context)


