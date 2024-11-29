$.validator.addMethod("espacios", function (value, element) {
    return value == ' ' || value.trim().length != 0
}, "Espacios no son permitidos");

// Método para validar caracteres especiales
$.validator.addMethod("sinCaracteresEspeciales", function (value, element) {
    return /^[a-zA-Z0-9]*$/.test(value);
}, "No se permiten caracteres especiales");

// Método para validar longitud máxima
$.validator.addMethod("longitudMaxima", function (value, element, param) {
    return value.length <= param;
}, "La longitud no debe superar los {0} caracteres");

$(document).ready(function () {
    $('#formularioLogin').validate({
        rules: {
            username:{
                required: true,
                espacios: true,
                sinCaracteresEspeciales: true,
                longitudMaxima: 10 // Limitar a 10 caracteres
            },
            password: {
                required: true,
                espacios: true,
                sinCaracteresEspeciales: true,
                longitudMaxima: 10 // Limitar a 10 caracteres
            }
        },
        messages: {
            username: {
                required: "Por favor ingresa nombre de usuario",
                espacios: "No se aceptan espacios",
                sinCaracteresEspeciales: "No se permiten caracteres especiales",
                longitudMaxima: "La longitud no debe superar los 10 caracteres"
            },
            password: {
                required: "Contraseña es requerido",
                espacios: "No se aceptan espacios",
                sinCaracteresEspeciales: "No se permiten caracteres especiales",
                longitudMaxima: "La longitud no debe superar los 10 caracteres"
            }
        },
        submitHandler: function(form) {
            // Encriptar los datos antes de enviar
            var username = $('#id_username').val();
            var password = $('#id_password').val();

            // Encriptar usando CryptoJS
            var encryptedUsername = CryptoJS.AES.encrypt(username, 'tu_clave_secreta').toString();
            var encryptedPassword = CryptoJS.AES.encrypt(password, 'tu_clave_secreta').toString();
            

            // Reemplazar los valores en el formulario con los encriptados
            // $('#id_username').val(encryptedUsername);
            // $('#id_password').val(encryptedPassword);

            // Enviar el formulario
            form.submit();
        }
    });

    event.preventDefault();
})