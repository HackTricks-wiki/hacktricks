# Otros trucos web

{{#include ../banners/hacktricks-training.md}}

### Host header

En varias ocasiones, el back-end confía en el **Host header** para realizar determinadas acciones. Por ejemplo, podría utilizar su valor como el **dominio al que enviar un restablecimiento de contraseña**. Por lo tanto, cuando recibes un correo electrónico con un enlace para restablecer tu contraseña, el dominio utilizado es el que incluiste en el Host header. Luego, puedes solicitar el restablecimiento de contraseña de otros usuarios y cambiar el dominio por uno controlado por ti para robar sus códigos de restablecimiento de contraseña. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Ten en cuenta que es posible que ni siquiera necesites esperar a que el usuario haga clic en el enlace de restablecimiento de contraseña para obtener el token, ya que quizá **los filtros de spam u otros dispositivos o bots intermediarios hagan clic en él para analizarlo**.

### Session booleans

A veces, cuando completas correctamente alguna verificación, el back-end **simplemente añade un booleano con el valor "True" a un atributo de seguridad de tu sesión**. Entonces, otro endpoint sabrá si superaste correctamente esa comprobación.\
Sin embargo, si **superas la comprobación** y tu sesión recibe ese valor "True" en el atributo de seguridad, puedes intentar **acceder a otros recursos** que **dependan del mismo atributo**, pero a los que **no deberías tener permisos** para acceder. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Funcionalidad de registro

Intenta registrarte como un usuario que ya existe. Prueba también utilizando caracteres equivalentes (puntos, muchos espacios y Unicode).

### Correos electrónicos takeover

Registra un correo electrónico y, antes de confirmarlo, cambia el correo electrónico. Después, si el nuevo correo de confirmación se envía al primer correo registrado, puedes tomar el control de cualquier correo electrónico. O, si puedes habilitar el segundo correo confirmando el primero, también puedes tomar el control de cualquier cuenta.

### Acceder al servicedesk interno de empresas mediante atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Los desarrolladores podrían olvidar deshabilitar varias opciones de depuración en el entorno de producción. Por ejemplo, el método HTTP `TRACE` está diseñado con fines de diagnóstico. Si está habilitado, el servidor web responderá a las solicitudes que utilicen el método `TRACE` repitiendo en la respuesta la solicitud exacta que recibió. Este comportamiento suele ser inofensivo, pero ocasionalmente provoca una divulgación de información, como el nombre de los headers de autenticación internos que los reverse proxies pueden añadir a las solicitudes.![Imagen de la publicación](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagen de la publicación](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Referencias

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
