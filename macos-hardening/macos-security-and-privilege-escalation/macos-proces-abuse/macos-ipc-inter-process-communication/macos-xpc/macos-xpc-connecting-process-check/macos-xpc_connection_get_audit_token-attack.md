# Ataque xpc\_connection\_get\_audit\_token en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta técnica fue copiada de** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

## Información básica sobre los mensajes Mach

Si no sabes qué son los mensajes Mach, comienza revisando esta página:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Por ahora, recuerda que:
Los mensajes Mach se envían a través de un _puerto Mach_, que es un canal de comunicación de **un solo receptor, múltiples remitentes** integrado en el kernel Mach. **Múltiples procesos pueden enviar mensajes** a un puerto Mach, pero en cualquier momento **solo un proceso puede leer de él**. Al igual que los descriptores de archivos y los sockets, los puertos Mach son asignados y gestionados por el kernel, y los procesos solo ven un número entero, que pueden usar para indicar al kernel qué puerto Mach desean utilizar.

## Conexión XPC

Si no sabes cómo se establece una conexión XPC, consulta:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Resumen de la vulnerabilidad

Lo interesante que debes saber es que **la abstracción de XPC es una conexión uno a uno**, pero se basa en una tecnología que **puede tener múltiples remitentes, por lo que:**

* Los puertos Mach son de un solo receptor, _**múltiples remitentes**_.
* El token de auditoría de una conexión XPC es el token de auditoría **copiado del mensaje más recientemente recibido**.
* Obtener el **token de auditoría** de una conexión XPC es fundamental para muchas **verificaciones de seguridad**.

Aunque la situación anterior suena prometedora, hay algunos escenarios en los que esto no causará problemas:

* Los tokens de auditoría se utilizan a menudo para una verificación de autorización para decidir si se acepta una conexión. Como esto ocurre utilizando un mensaje al puerto de servicio, **aún no se ha establecido una conexión**. Los mensajes adicionales en este puerto solo se manejarán como solicitudes de conexión adicionales. Por lo tanto, **las verificaciones antes de aceptar una conexión no son vulnerables** (esto también significa que dentro de `-listener:shouldAcceptNewConnection:` el token de auditoría está seguro). Por lo tanto, **buscamos conexiones XPC que verifiquen acciones específicas**.
* Los controladores de eventos XPC se manejan de forma sincrónica. Esto significa que el controlador de eventos para un mensaje debe completarse antes de llamarlo para el siguiente, incluso en colas de despacho concurrentes. Por lo tanto, dentro de un **controlador de eventos XPC, el token de auditoría no puede ser sobrescrito** por otros mensajes normales (¡no de respuesta!).

Esto nos dio la idea de dos métodos diferentes en los que esto puede ser posible:

1. Variante 1:
* El **exploit** se **conecta** al servicio **A** y al servicio **B**.
* El servicio **B** puede llamar a una **funcionalidad privilegiada** en el servicio A a la que el usuario no puede acceder.
* El servicio **A** llama a **`xpc_connection_get_audit_token`** mientras **no** está dentro del controlador de eventos para una conexión en un **`dispatch_async`**.
* Por lo tanto, un mensaje **diferente** podría **sobrescribir el Token de Auditoría** porque se está despachando de forma asíncrona fuera del controlador de eventos.
* El exploit pasa a **service B el derecho de ENVÍO a service A**.
* Por lo tanto, svc **B** realmente **enviará** los **mensajes** a service **A**.
* El **exploit** intenta **llamar** a la **acción privilegiada**. En un RC svc **A verifica** la autorización de esta **acción** mientras **svc B sobrescribe el Token de Auditoría** (dando al exploit acceso para llamar a la acción privilegiada).
2. Variante 2:
* El servicio **B** puede llamar a una **funcionalidad privilegiada** en el servicio A a la que el usuario no puede acceder.
* El exploit se conecta con el **servicio A**, que **envía** al exploit un **mensaje esperando una respuesta** en un **puerto de respuesta** específico.
* El exploit envía al **servicio B** un mensaje pasando **ese puerto de respuesta**.
* Cuando el servicio **B responde**, envía el mensaje al servicio **A**, **mientras** que el **exploit** envía un mensaje **diferente al servicio A** intentando **alcanzar una funcionalidad privilegiada** y esperando que la respuesta de service B sobrescriba el Token de Auditoría en el momento perfecto (Condición de Carrera).
## Variante 1: llamando a xpc\_connection\_get\_audit\_token fuera de un controlador de eventos <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Escenario:

* Dos servicios mach **A** y **B** a los que podemos conectarnos (basado en el perfil de sandbox y las comprobaciones de autorización antes de aceptar la conexión).
* **A** debe tener una **comprobación de autorización** para una **acción específica** que **B** puede pasar (pero nuestra aplicación no puede).
* Por ejemplo, si B tiene algunos **permisos** o se está ejecutando como **root**, podría permitirle pedirle a A que realice una acción privilegiada.
* Para esta comprobación de autorización, **A obtiene el token de auditoría de forma asíncrona**, por ejemplo, llamando a `xpc_connection_get_audit_token` desde **`dispatch_async`**.

{% hint style="danger" %}
En este caso, un atacante podría desencadenar una **condición de carrera** creando un **exploit** que **pida a A que realice una acción** varias veces mientras **B envía mensajes a A**. Cuando la condición de carrera tiene éxito, el **token de auditoría** de **B** se copiará en memoria **mientras** la solicitud de nuestro **exploit** está siendo **manejada** por A, dándole acceso a la acción privilegiada que solo B podría solicitar.
{% endhint %}

Esto sucedió con **A** como `smd` y **B** como `diagnosticd`. La función [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb se puede utilizar para instalar una nueva herramienta auxiliar privilegiada (como **root**). Si un **proceso que se ejecuta como root** se pone en contacto con **smd**, no se realizarán otras comprobaciones.

Por lo tanto, el servicio **B** es `diagnosticd` porque se ejecuta como **root** y se puede utilizar para **monitorizar** un proceso, por lo que una vez que se inicia la monitorización, enviará **múltiples mensajes por segundo**.

Para realizar el ataque:

1. Establecemos nuestra **conexión** a **`smd`** siguiendo el protocolo XPC normal.
2. Luego, establecemos una **conexión** a **`diagnosticd`**, pero en lugar de generar dos nuevos puertos mach y enviarlos, reemplazamos el derecho de envío del puerto del cliente con una copia del **derecho de envío que tenemos para la conexión a `smd`**.
3. Esto significa que podemos enviar mensajes XPC a `diagnosticd`, pero cualquier **mensaje que `diagnosticd` envíe irá a `smd`**.
* Para `smd`, tanto nuestros mensajes como los mensajes de `diagnosticd` llegan a la misma conexión.

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

4. Le pedimos a **`diagnosticd`** que **comience a monitorizar** nuestro (o cualquier otro) proceso y **enviamos mensajes rutinarios 1004 a `smd`** (para instalar una herramienta privilegiada).
5. Esto crea una condición de carrera que debe alcanzar una ventana muy específica en `handle_bless`. Necesitamos que la llamada a `xpc_connection_get_pid` devuelva el PID de nuestro propio proceso, ya que la herramienta auxiliar privilegiada está en nuestro paquete de aplicaciones. Sin embargo, la llamada a `xpc_connection_get_audit_token` dentro de la función `connection_is_authorized` debe usar el token de auditoría de `diagnosticd`.

## Variante 2: reenvío de respuestas

Como se mencionó antes, el controlador de eventos para una conexión XPC nunca se ejecuta varias veces simultáneamente. Sin embargo, las respuestas de XPC se manejan de manera diferente. Existen dos funciones para enviar un mensaje que espera una respuesta:

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`, en cuyo caso el mensaje XPC se recibe y se analiza en la cola especificada.
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`, en cuyo caso el mensaje XPC se recibe y se analiza en la cola de despacho actual.

Por lo tanto, los paquetes de respuesta de XPC pueden analizarse mientras se está ejecutando un controlador de eventos de XPC. Si bien `_xpc_connection_set_creds` utiliza bloqueo, esto solo evita la sobrescritura parcial del token de auditoría, no bloquea el objeto de conexión completo, lo que permite reemplazar el token de auditoría entre el análisis de un paquete y la ejecución de su controlador de eventos.

Para este escenario necesitaríamos:

* Como antes, dos servicios mach A y B a los que podemos conectarnos.
* Nuevamente, A debe tener una comprobación de autorización para una acción específica que B puede pasar (pero nuestra aplicación no puede).
* A nos envía un mensaje que espera una respuesta.
* Podemos enviar un mensaje a B al que responderá.

Esperamos a que A nos envíe un mensaje que espera una respuesta (1), en lugar de responder, tomamos el puerto de respuesta y lo usamos para un mensaje que enviamos a B (2). Luego, enviamos un mensaje que utiliza la acción prohibida y esperamos que llegue concurrentemente con la respuesta de B (3).

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Problemas de descubrimiento

Pasamos mucho tiempo tratando de encontrar otras instancias, pero las condiciones dificultaron la búsqueda tanto estática como dinámicamente. Para buscar llamadas asíncronas a `xpc_connection_get_audit_token`, usamos Frida para enganchar esta función y comprobar si la traza de llamadas incluye `_xpc_connection_mach_event` (lo que significa que no se llama desde un controlador de eventos). Pero esto solo encuentra llamadas en el proceso al que actualmente estamos enganchados y de las acciones que se utilizan activamente. Analizar todos los servicios mach alcanzables en IDA/Ghidra fue muy lento, especialmente cuando las llamadas involucraban la caché compartida de dyld. Intentamos escribir un script para buscar llamadas a `xpc_connection_get_audit_token` alcanzables desde un bloque enviado usando `dispatch_async`, pero analizar bloques y llamadas que pasan a la caché compartida de dyld dificultó esto también. Después de pasar un tiempo en esto, decidimos que sería mejor enviar lo que teníamos.
## La solución <a href="#la-solución" id="la-solución"></a>

Al final, informamos sobre el problema general y el problema específico en `smd`. Apple lo solucionó solo en `smd` reemplazando la llamada a `xpc_connection_get_audit_token` con `xpc_dictionary_get_audit_token`.

La función `xpc_dictionary_get_audit_token` copia el token de auditoría del mensaje mach en el que se recibió este mensaje XPC, lo que significa que no es vulnerable. Sin embargo, al igual que `xpc_dictionary_get_audit_token`, esto no forma parte de la API pública. Para la API de nivel superior `NSXPCConnection`, no existe un método claro para obtener el token de auditoría del mensaje actual, ya que esto abstrae todos los mensajes en llamadas de método.

No está claro por qué Apple no aplicó una solución más general, por ejemplo, descartar los mensajes que no coinciden con el token de auditoría guardado de la conexión. Puede haber escenarios en los que el token de auditoría de un proceso cambie legítimamente pero la conexión debe permanecer abierta (por ejemplo, llamar a `setuid` cambia el campo UID), pero cambios como un PID diferente o una versión de PID diferente es poco probable que sea intencional.

En cualquier caso, este problema aún persiste en iOS 17 y macOS 14, así que si quieres buscarlo, ¡buena suerte!

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
