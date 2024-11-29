from django.shortcuts import redirect, render
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from .forms import CustomAuthenticationForm

from Crypto.Cipher import AES
import base64
import json

def decrypt_data(encrypted_data, key, iv):
    if len(key) not in [16, 24, 32]:
        raise ValueError(f"Longitud de la clave AES inválida: {len(key)} bytes")
    if len(iv) != 16:
        raise ValueError(f"Longitud del vector de inicialización (IV) inválida: {len(iv)} bytes")

    try:
        # Decodificar datos desde Base64
        encrypted_data_bytes = base64.b64decode(encrypted_data)

        # Crear el objeto de cifrado AES
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))

        # Desencriptar los datos
        decrypted_data = cipher.decrypt(encrypted_data_bytes)

        # Remover padding PKCS7
        padding_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_length]

        # Retornar como cadena decodificada
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error al desencriptar los datos: {e}")

def user_login(request):
    if request.method == 'POST':

        # Recuperar captcha
        captcha_0 = request.POST.get('captcha_0')
        captcha_1 = request.POST.get('captcha_1')

        # Recuperar los campos encriptados
        encrypted_username = request.POST.get('encrypted_username')
        encrypted_password = request.POST.get('encrypted_password')

        if not encrypted_username or not encrypted_password:
            messages.error(request, 'Error en los datos enviados.')
            return redirect('login')

        # Desencriptar los datos usando la clave compartida
        encryption_key = 'clave_secreta_16' 
        encryption_iv = 'clave_inicial_16'

        try:
            username = decrypt_data(encrypted_username, encryption_key, encryption_iv)
            password = decrypt_data(encrypted_password, encryption_key, encryption_iv)
        except Exception as e:
            messages.error(request, f'Error en los datos cifrados: {e}')
            return redirect('login')

        # Crear un nuevo formulario de autenticación con los datos desencriptados
        form = CustomAuthenticationForm(data={'username': username, 'password': password, 'captcha_0': captcha_0, 'captcha_1': captcha_1})
        if form.is_valid():
            auth_login(request, form.get_user())
            request.session.cycle_key()
            messages.success(request, 'Inicio de sesión exitoso')
            return redirect('home')
        else:
            messages.error(
                request, 'Credenciales inválidas. Inténtalo de nuevo.')
    else:
        form = CustomAuthenticationForm()

    return render(request, 'app/login.html', {"form": form})


@login_required(login_url='login')
def home(request):
    return render(request, 'app/home.html')


def user_logout(request):
    logout(request)
    return redirect('login')
