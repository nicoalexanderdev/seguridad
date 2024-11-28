from django.shortcuts import redirect, render
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages

# Create your views here.


def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            auth_login(request, form.get_user())
            messages.success(request, 'Inicio de sesión exitoso')
            return redirect('home')
        else:
            messages.error(
                request, 'Credenciales inválidas. Inténtalo de nuevo.')
    else:
        form = AuthenticationForm()

    return render(request, 'app/login.html', {"form": form})


@login_required(login_url='login')
def home(request):
    return render(request, 'app/home.html')


def user_logout(request):
    logout(request)
    return redirect('login')
