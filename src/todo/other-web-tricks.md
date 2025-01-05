# Otros trucos web

{{#include ../banners/hacktricks-training.md}}

### Encabezado Host

Varias veces el back-end confía en el **encabezado Host** para realizar algunas acciones. Por ejemplo, podría usar su valor como el **dominio para enviar un restablecimiento de contraseña**. Así que cuando recibes un correo electrónico con un enlace para restablecer tu contraseña, el dominio que se utiliza es el que pusiste en el encabezado Host. Luego, puedes solicitar el restablecimiento de contraseña de otros usuarios y cambiar el dominio a uno controlado por ti para robar sus códigos de restablecimiento de contraseña. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Ten en cuenta que es posible que ni siquiera necesites esperar a que el usuario haga clic en el enlace de restablecimiento de contraseña para obtener el token, ya que incluso **los filtros de spam u otros dispositivos/bots intermedios pueden hacer clic en él para analizarlo**.

### Booleanos de sesión

A veces, cuando completas correctamente alguna verificación, el back-end **simplemente agregará un booleano con el valor "True" a un atributo de seguridad de tu sesión**. Luego, un endpoint diferente sabrá si pasaste esa verificación con éxito.\
Sin embargo, si **pasas la verificación** y tu sesión recibe ese valor "True" en el atributo de seguridad, puedes intentar **acceder a otros recursos** que **dependen del mismo atributo** pero a los que **no deberías tener permisos** para acceder. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funcionalidad de registro

Intenta registrarte como un usuario ya existente. También intenta usar caracteres equivalentes (puntos, muchos espacios y Unicode).

### Toma de correos electrónicos

Registra un correo electrónico, antes de confirmarlo cambia el correo, luego, si el nuevo correo de confirmación se envía al primer correo registrado, puedes tomar cualquier correo. O si puedes habilitar el segundo correo confirmando el primero, también puedes tomar cualquier cuenta.

### Acceso al servicio interno de atención al cliente de empresas usando Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Método TRACE

Los desarrolladores pueden olvidar deshabilitar varias opciones de depuración en el entorno de producción. Por ejemplo, el método HTTP `TRACE` está diseñado para fines de diagnóstico. Si está habilitado, el servidor web responderá a las solicitudes que utilicen el método `TRACE` replicando en la respuesta la solicitud exacta que se recibió. Este comportamiento a menudo es inofensivo, pero ocasionalmente conduce a la divulgación de información, como el nombre de los encabezados de autenticación internos que pueden ser añadidos a las solicitudes por proxies inversos.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
