# Otros trucos web

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Encabezado de host

En varias ocasiones, el back-end confía en el **encabezado de host** para realizar algunas acciones. Por ejemplo, podría usar su valor como el **dominio para enviar un restablecimiento de contraseña**. Por lo tanto, cuando reciba un correo electrónico con un enlace para restablecer su contraseña, el dominio que se está utilizando es el que colocó en el encabezado de host. Entonces, puede solicitar el restablecimiento de contraseña de otros usuarios y cambiar el dominio a uno controlado por usted para robar sus códigos de restablecimiento de contraseña. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Tenga en cuenta que es posible que ni siquiera necesite esperar a que el usuario haga clic en el enlace de restablecimiento de contraseña para obtener el token, ya que tal vez incluso **los filtros de spam u otros dispositivos/bots intermedios hagan clic en él para analizarlo**.
{% endhint %}

### Booleanos de sesión

A veces, cuando completa alguna verificación correctamente, el back-end **simplemente agrega un booleano con el valor "True" a un atributo de seguridad de su sesión**. Luego, un punto final diferente sabrá si pasó con éxito esa verificación.\
Sin embargo, si **aprueba la verificación** y su sesión se le otorga ese valor "True" en el atributo de seguridad, puede intentar **acceder a otros recursos** que **dependen del mismo atributo** pero que **no debería tener permisos** para acceder. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funcionalidad de registro

Intente registrarse como un usuario que ya existe. Intente también usar caracteres equivalentes (puntos, muchos espacios y Unicode).

### Tomar el control de correos electrónicos

Registre un correo electrónico, antes de confirmarlo cambie el correo electrónico, luego, si el nuevo correo electrónico de confirmación se envía al primer correo electrónico registrado, puede tomar el control de cualquier correo electrónico. O si puede habilitar el segundo correo electrónico confirmando el primero, también puede tomar el control de cualquier cuenta.

### Acceder al servicio de atención al cliente interno de empresas que usan Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Método TRACE

Los desarrolladores pueden olvidar desactivar varias opciones de depuración en el entorno de producción. Por ejemplo, el método HTTP `TRACE` está diseñado para fines de diagnóstico. Si está habilitado, el servidor web responderá a las solicitudes que usen el método `TRACE` repitiendo en la respuesta la solicitud exacta que se recibió. Este comportamiento a menudo es inofensivo, pero ocasionalmente conduce a la divulgación de información, como el nombre de los encabezados de autenticación internos que pueden ser agregados a las solicitudes por los servidores proxy inversos.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
