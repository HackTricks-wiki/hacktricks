# Ataque con macOS xpc\_connection\_get\_audit\_token

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta técnica fue copiada de** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

## Información Básica de Mensajes Mach

Si no sabes qué son los Mensajes Mach, comienza revisando esta página:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Por el momento recuerda que:
Los mensajes Mach se envían a través de un _puerto mach_, que es un canal de comunicación **de receptor único, múltiples emisores** integrado en el kernel mach. **Múltiples procesos pueden enviar mensajes** a un puerto mach, pero en cualquier momento **solo un proceso puede leerlo**. Al igual que los descriptores de archivos y los sockets, los puertos mach son asignados y gestionados por el kernel y los procesos solo ven un entero, que pueden usar para indicar al kernel cuál de sus puertos mach quieren usar.

## Conexión XPC

Si no sabes cómo se establece una conexión XPC, revisa:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Resumen de la Vulnerabilidad

Lo interesante que debes saber es que la abstracción de **XPC es una conexión uno a uno**, pero se basa en una tecnología que **puede tener múltiples emisores, así que:**

* Los puertos mach son de receptor único, _**múltiples emisores**_.
* El token de auditoría de una conexión XPC es el token de auditoría _**copiado del mensaje más recientemente recibido**_.
* Obtener el **token de auditoría** de una conexión XPC es crítico para muchos **controles de seguridad**.

Aunque la situación anterior suena prometedora, hay algunos escenarios donde esto no va a causar problemas:

* Los tokens de auditoría a menudo se usan para un control de autorización para decidir si aceptar una conexión. Como esto ocurre usando un mensaje al puerto de servicio, **todavía no hay una conexión establecida**. Más mensajes en este puerto simplemente se manejarán como solicitudes de conexión adicionales. Por lo tanto, cualquier **control antes de aceptar una conexión no es vulnerable** (esto también significa que dentro de `-listener:shouldAcceptNewConnection:` el token de auditoría es seguro). Por lo tanto, **estamos buscando conexiones XPC que verifiquen acciones específicas**.
* Los manejadores de eventos XPC se manejan de forma sincrónica. Esto significa que el manejador de eventos para un mensaje debe completarse antes de llamarlo para el siguiente, incluso en colas de despacho concurrentes. Por lo tanto, dentro de un **manejador de eventos XPC el token de auditoría no puede ser sobrescrito** por otros mensajes normales (¡no de respuesta!).

Esto nos dio la idea de dos métodos diferentes en los que esto podría ser posible:

1. Variante1:
* **Exploit** **se conecta** al servicio **A** y al servicio **B**
* El servicio **B** puede llamar a una **funcionalidad privilegiada** en el servicio A que el usuario no puede
* El servicio **A** llama a **`xpc_connection_get_audit_token`** mientras _**no**_ está dentro del **manejador de eventos** para una conexión en un **`dispatch_async`**.
* Así que un **mensaje diferente** podría **sobrescribir el Token de Auditoría** porque se está despachando de forma asincrónica fuera del manejador de eventos.
* El exploit pasa al **servicio B el derecho de ENVÍO al servicio A**.
* Entonces el svc **B** en realidad estará **enviando** los **mensajes** al servicio **A**.
* El **exploit** intenta **llamar** a la **acción privilegiada.** En una RC svc **A** **verifica** la autorización de esta **acción** mientras **svc B sobrescribió el Token de Auditoría** (dando al exploit acceso para llamar a la acción privilegiada).
2. Variante 2:
* El servicio **B** puede llamar a una **funcionalidad privilegiada** en el servicio A que el usuario no puede
* El exploit se conecta con **el servicio A** que **envía** al exploit un **mensaje esperando una respuesta** en un puerto de **respuesta** específico.
* El exploit envía **al servicio** B un mensaje pasando **ese puerto de respuesta**.
* Cuando el servicio **B responde**, **envía el mensaje al servicio A**, **mientras** el **exploit** envía un mensaje diferente **al servicio A** intentando **alcanzar una funcionalidad privilegiada** y esperando que la respuesta del servicio B sobrescriba el Token de Auditoría en el momento perfecto (Condición de Carrera).

## Variante 1: llamando a xpc\_connection\_get\_audit\_token fuera de un manejador de eventos <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Escenario:

* Dos servicios mach **A** y **B** a los que ambos podemos conectarnos (basado en el perfil de sandbox y los controles de autorización antes de aceptar la conexión).
* **A** debe tener un **control de autorización** para una **acción específica que **_**B**_** puede pasar** (pero nuestra aplicación no puede).
* Por ejemplo, si B tiene algunos **entitlements** o se ejecuta como **root**, podría permitirle pedirle a A que realice una acción privilegiada.
* Para este control de autorización, **A** **obtiene el token de auditoría de forma asincrónica**, por ejemplo llamando a `xpc_connection_get_audit_token` desde **`dispatch_async`**.

{% hint style="danger" %}
En este caso, un atacante podría desencadenar una **Condición de Carrera** haciendo un **exploit** que **pide a A que realice una acción** varias veces mientras hace que **B envíe mensajes a A**. Cuando la RC es **exitosa**, el **token de auditoría** de **B** será copiado en memoria **mientras** la solicitud de nuestro **exploit** está siendo **manejada** por A, dándole **acceso a la acción privilegiada que solo B podría solicitar**.
{% endhint %}

Esto ocurrió con **A** como `smd` y **B** como `diagnosticd`. La función [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb se puede usar para instalar una nueva herramienta de ayuda privilegiada (como **root**). Si un **proceso que se ejecuta como root contacta** **smd**, no se realizarán otros controles.

Por lo tanto, el servicio **B** es **`diagnosticd`** porque se ejecuta como **root** y se puede usar para **monitorear** un proceso, por lo que una vez que comienza el monitoreo, enviará **varios mensajes por segundo**.

Para realizar el ataque:

1. Establecemos nuestra **conexión** con **`smd`** siguiendo el protocolo XPC normal.
2. Luego, establecemos una **conexión** con **`diagnosticd`**, pero en lugar de generar dos nuevos puertos mach y enviar esos, reemplazamos el derecho de envío del puerto del cliente con una copia del **derecho de envío que tenemos para la conexión con `smd`**.
3. Lo que esto significa es que podemos enviar mensajes XPC a `diagnosticd`, pero cualquier **mensaje que `diagnosticd` envíe va a `smd`**.&#x20;
* Para `smd`, los mensajes tanto nuestros como de `diagnosticd` parecen llegar en la misma conexión.

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

4. Pedimos a **`diagnosticd`** que **comience a monitorear** nuestro proceso (o cualquier proceso activo) y **enviamos mensajes de rutina 1004 a `smd`** (para instalar una herramienta privilegiada).
5. Esto crea una condición de carrera que necesita golpear una ventana muy específica en `handle_bless`. Necesitamos que la llamada a `xpc_connection_get_pid` devuelva el PID de nuestro propio proceso, ya que la herramienta de ayuda privilegiada está en nuestro paquete de aplicaciones. Sin embargo, la llamada a `xpc_connection_get_audit_token` dentro de la función `connection_is_authorized` debe usar el token de auditoría de `diganosticd`.

## Variante 2: reenvío de respuesta

Como se mencionó antes, el manejador para eventos en una conexión XPC nunca se ejecuta varias veces de forma concurrente. Sin embargo, los **mensajes de respuesta XPC se manejan de manera diferente**. Existen dos funciones para enviar un mensaje que espera una respuesta:

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`, en cuyo caso el mensaje XPC se recibe y se analiza en la cola especificada.
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`, en cuyo caso el mensaje XPC se recibe y se analiza en la cola de despacho actual.

Por lo tanto, **los paquetes de respuesta XPC pueden ser analizados mientras se ejecuta un manejador de eventos XPC**. Aunque `_xpc_connection_set_creds` utiliza bloqueo, esto solo previene la sobrescritura parcial del token de auditoría, no bloquea todo el objeto de conexión, lo que hace posible **reemplazar el token de auditoría entre el análisis** de un paquete y la ejecución de su manejador de eventos.

Para este escenario necesitaríamos:

* Como antes, dos servicios mach _A_ y _B_ a los que ambos podemos conectarnos.
* Nuevamente, _A_ debe tener un control de autorización para una acción específica que _B_ puede pasar (pero nuestra aplicación no puede).
* _A_ nos envía un mensaje que espera una respuesta.
* Podemos enviar un mensaje a _B_ que responderá.

Esperamos a que _A_ nos envíe un mensaje que espera una respuesta (1), en lugar de responder tomamos el puerto de respuesta y lo usamos para un mensaje que enviamos a _B_ (2). Luego, enviamos un mensaje que utiliza la acción prohibida y esperamos que llegue concurrentemente con la respuesta de _B_ (3).

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Problemas de Descubrimiento

Pasamos mucho tiempo tratando de encontrar otras instancias, pero las condiciones hicieron que fuera difícil buscarlas de manera estática o dinámica. Para buscar llamadas asincrónicas a `xpc_connection_get_audit_token`, usamos Frida para enganchar esta función y verificar si el backtrace incluye `_xpc_connection_mach_event` (lo que significa que no se llama desde un manejador de eventos). Pero esto solo encuentra llamadas en el proceso que tenemos actualmente enganchado y de las acciones que se utilizan activamente. Analizar todos los servicios mach accesibles en IDA/Ghidra fue muy intensivo en tiempo, especialmente cuando las llamadas involucraban la caché compartida de dyld. Intentamos automatizar esto para buscar llamadas a `xpc_connection_get_audit_token` accesibles desde un bloque enviado usando `dispatch_async`, pero analizar bloques y llamadas que pasan a la caché compartida de dyld también fue difícil. Después de pasar un tiempo en esto, decidimos que sería mejor enviar lo que teníamos.

## La solución <a href="#the-fix" id="the-fix"></a>

Al final, informamos del problema general y del problema específico en `smd`. Apple lo solucionó solo en `smd` reemplazando la llamada a `xpc_connection_get_audit_token` con `xpc_dictionary_get_audit_token`.

La función `xpc_dictionary_get_audit_token` copia el token de auditoría del mensaje mach en el que se recibió este mensaje XPC, lo que significa que no es vulnerable. Sin embargo, al igual que `xpc_dictionary_get_audit_token`, esto no es parte de la API pública. Para la API de nivel superior `NSXPCConnection`, no existe un método claro para obtener el token de auditoría del mensaje actual, ya que esto abstrae todos los mensajes en llamadas a métodos.

No está claro para nosotros por qué Apple no aplicó una solución más general, por ejemplo, descartando mensajes que no coinciden con el token de auditoría guardado de la conexión. Puede haber escenarios en los que el token de auditoría de un proceso cambie legítimamente pero la conexión deba permanecer abierta (por ejemplo, llamar a `setuid` cambia el campo UID), pero cambios como un PID diferente o una versión de PID son poco probables que sean intencionados.

En cualquier caso, este problema sigue presente con iOS 17 y macOS 14, así que si quieres ir a buscarlo, ¡buena suerte!

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62
