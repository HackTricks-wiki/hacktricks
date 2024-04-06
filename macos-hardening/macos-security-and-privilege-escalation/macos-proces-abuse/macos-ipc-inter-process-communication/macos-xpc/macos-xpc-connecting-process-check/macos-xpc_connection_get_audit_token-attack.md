# macOS xpc\_connection\_get\_audit\_token Attack

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en GitHub.

</details>

**Para obtener más información, consulta la publicación original:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Este es un resumen:

## Información básica sobre Mensajes Mach

Si no sabes qué son los Mensajes Mach, comienza revisando esta página:

{% content-ref url="../../" %}
[..](../../)
{% endcontent-ref %}

Por el momento, recuerda que ([definición desde aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Los mensajes Mach se envían a través de un _puerto mach_, que es un canal de comunicación de **un solo receptor, múltiples emisores** integrado en el núcleo mach. **Múltiples procesos pueden enviar mensajes** a un puerto mach, pero en cualquier momento **solo un proceso puede leerlo**. Al igual que los descriptores de archivos y los sockets, los puertos mach son asignados y gestionados por el núcleo y los procesos solo ven un entero, que pueden usar para indicar al núcleo cuál de sus puertos mach desean utilizar.

## Conexión XPC

Si no sabes cómo se establece una conexión XPC, consulta:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Resumen de la Vulnerabilidad

Lo interesante que debes saber es que **la abstracción de XPC es una conexión uno a uno**, pero se basa en una tecnología que **puede tener múltiples emisores, por lo tanto:**

* Los puertos mach son de un solo receptor, **múltiples emisores**.
* El token de auditoría de una conexión XPC es el token de auditoría **copiado del mensaje más recientemente recibido**.
* Obtener el **token de auditoría** de una conexión XPC es crítico para muchas **verificaciones de seguridad**.

Aunque la situación anterior suena prometedora, hay escenarios donde esto no causará problemas ([desde aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Los tokens de auditoría se utilizan a menudo para una verificación de autorización para decidir si aceptar una conexión. Como esto sucede utilizando un mensaje al puerto de servicio, **aún no se ha establecido una conexión**. Más mensajes en este puerto solo se manejarán como solicitudes de conexión adicionales. Por lo tanto, **las verificaciones antes de aceptar una conexión no son vulnerables** (esto también significa que dentro de `-listener:shouldAcceptNewConnection:` el token de auditoría está seguro). Por lo tanto, **buscamos conexiones XPC que verifiquen acciones específicas**.
* Los manejadores de eventos XPC se manejan de forma síncrona. Esto significa que el manejador de eventos para un mensaje debe completarse antes de llamarlo para el siguiente, incluso en colas de despacho concurrentes. Por lo tanto, dentro de un **manejador de eventos XPC, el token de auditoría no puede ser sobrescrito** por otros mensajes normales (¡no de respuesta!).

Dos métodos diferentes en los que esto podría ser explotable:

1. Variante 1:

* El **exploit se conecta** al servicio **A** y al servicio **B**.
* El servicio **B** puede llamar a una **funcionalidad privilegiada** en el servicio **A** que el usuario no puede.
* El servicio **A** llama a **`xpc_connection_get_audit_token`** mientras _**no**_ está dentro del **manejador de eventos** para una conexión en un **`dispatch_async`**.
* Por lo tanto, un **mensaje diferente** podría **sobrescribir el Token de Auditoría** porque se está despachando de forma asíncrona fuera del manejador de eventos.
* El exploit pasa a **servicio B el derecho de ENVÍO a servicio A**.
* Entonces svc **B** realmente estará **enviando** los **mensajes** al servicio **A**.
* El **exploit** intenta **llamar** a la **acción privilegiada**. En un RC, svc **A** **verifica** la autorización de esta **acción** mientras **svc B sobrescribió el Token de Auditoría** (dando al exploit acceso para llamar a la acción privilegiada).

2. Variante 2:

* El servicio **B** puede llamar a una **funcionalidad privilegiada** en el servicio **A** que el usuario no puede.
* El exploit se conecta con el **servicio A** que **envía** al exploit un **mensaje esperando una respuesta** en un **puerto de respuesta** específico.
* El exploit envía al **servicio** B un mensaje pasando **ese puerto de respuesta**.
* Cuando el servicio **B responde**, **envía el mensaje al servicio A**, **mientras** que el **exploit** envía un **mensaje diferente al servicio A** intentando **acceder a una funcionalidad privilegiada** y esperando que la respuesta de servicio B sobrescriba el Token de Auditoría en el momento perfecto (Condición de Carrera).

## Variante 1: llamando a xpc\_connection\_get\_audit\_token fuera de un manejador de eventos <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Escenario:

* Dos servicios mach **`A`** y **`B`** a los que ambos podemos conectarnos (según el perfil de sandbox y las verificaciones de autorización antes de aceptar la conexión).
* _**A**_ debe tener una **verificación de autorización** para una acción específica que **`B`** puede pasar (pero nuestra aplicación no puede).
* Por ejemplo, si B tiene algunos **privilegios** o se está ejecutando como **root**, podría permitirle pedir a A que realice una acción privilegiada.
* Para esta verificación de autorización, **`A`** obtiene el token de auditoría de forma asíncrona, por ejemplo, llamando a `xpc_connection_get_audit_token` desde **`dispatch_async`**.

{% hint style="danger" %}
En este caso, un atacante podría desencadenar una **Condición de Carrera** creando un **exploit** que **pide a A que realice una acción** varias veces mientras hace que **B envíe mensajes a `A`**. Cuando la CC es **exitosa**, el **token de auditoría** de **B** se copiará en la memoria **mientras** la solicitud de nuestro **exploit** está siendo **manejada** por A, dándole **acceso a la acción privilegiada que solo B podría solicitar**.
{% endhint %}

Esto ocurrió con **`A`** como `smd` y **`B`** como `diagnosticd`. La función [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb se puede utilizar para instalar una nueva herramienta auxiliar privilegiada (como **root**). Si un **proceso que se ejecuta como root** contacta a **smd**, no se realizarán otras verificaciones.

Por lo tanto, el servicio **B** es **`diagnosticd`** porque se ejecuta como **root** y se puede utilizar para **monitorear** un proceso, por lo que una vez que comienza el monitoreo, **enviará múltiples mensajes por segundo.**

Para realizar el ataque:

1. Iniciar una **conexión** al servicio llamado `smd` utilizando el protocolo XPC estándar.
2. Formar una **conexión secundaria** a `diagnosticd`. Contrariamente al procedimiento normal, en lugar de crear y enviar dos nuevos puertos mach, el derecho de envío del puerto del cliente se sustituye por una duplicado del **derecho de envío** asociado con la conexión de `smd`.
3. Como resultado, los mensajes XPC pueden ser despachados a `diagnosticd`, pero las respuestas de `diagnosticd` se redirigen a `smd`. Para `smd`, parece como si los mensajes tanto del usuario como de `diagnosticd` provinieran de la misma conexión.

![Imagen que representa el proceso de explotación](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png) 4. El siguiente paso implica instruir a `diagnosticd` para que inicie el monitoreo de un proceso elegido (potencialmente el del usuario). Concurrentemente, se envía una avalancha de mensajes rutinarios 1004 a `smd`. La intención aquí es instalar una herramienta con privilegios elevados. 5. Esta acción desencadena una condición de carrera dentro de la función `handle_bless`. El momento es crítico: la llamada a la función `xpc_connection_get_pid` debe devolver el PID del proceso del usuario (ya que la herramienta privilegiada reside en el paquete de la aplicación del usuario). Sin embargo, la función `xpc_connection_get_audit_token`, específicamente dentro de la subrutina `connection_is_authorized`, debe hacer referencia al token de auditoría perteneciente a `diagnosticd`.

## Variante 2: reenvío de respuestas

En un entorno de Comunicación entre Procesos Cruzados (XPC), aunque los manejadores de eventos no se ejecutan concurrentemente, el manejo de mensajes de respuesta tiene un comportamiento único. Específicamente, existen dos métodos distintos para enviar mensajes que esperan una respuesta:

1. **`xpc_connection_send_message_with_reply`**: Aquí, el mensaje XPC es recibido y procesado en una cola designada.
2. **`xpc_connection_send_message_with_reply_sync`**: Por el contrario, en este método, el mensaje XPC es recibido y procesado en la cola de despacho actual.

Esta distinción es crucial porque permite la posibilidad de que **los paquetes de respuesta sean analizados concurrentemente con la ejecución de un manejador de eventos XPC**. Es importante destacar que mientras `_xpc_connection_set_creds` implementa bloqueo para proteger contra la sobrescritura parcial del token de auditoría, no extiende esta protección al objeto de conexión completo. En consecuencia, esto crea una vulnerabilidad donde el token de auditoría puede ser reemplazado durante el intervalo entre el análisis de un paquete y la ejecución de su manejador de eventos.

Para explotar esta vulnerabilidad, se requiere la siguiente configuración:

* Dos servicios mach, referidos como **`A`** y **`B`**, ambos capaces de establecer una conexión.
* El servicio **`A`** debe incluir una verificación de autorización para una acción específica que solo **`B`** puede realizar (la aplicación del usuario no puede).
* El servicio **`A`** debe enviar un mensaje que espera una respuesta.
* El usuario puede enviar un mensaje a **`B`** al que responderá.

El proceso de explotación implica los siguientes pasos:

1. Esperar a que el servicio **`A`** envíe un mensaje que espera una respuesta.
2. En lugar de responder directamente a **`A`**, se secuestra el puerto de respuesta y se utiliza para enviar un mensaje a servicio **`B`**.
3. Posteriormente, se despacha un mensaje que involucra la acción prohibida, con la expectativa de que se procese concurrentemente con la respuesta de **`B`**.

A continuación se muestra una representación visual del escenario de ataque descrito:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas de Descubrimiento

* **Dificultades para Localizar Instancias**: La búsqueda de instancias de uso de `xpc_connection_get_audit_token` fue desafiante, tanto estática como dinámicamente.
* **Metodología**: Se empleó Frida para enganchar la función `xpc_connection_get_audit_token`, filtrando llamadas que no se originaban desde manejadores de eventos. Sin embargo, este método estaba limitado al proceso enganchado y requería un uso activo.
* **Herramientas de Análisis**: Se utilizaron herramientas como IDA/Ghidra para examinar servicios mach alcanzables, pero el proceso fue lento, complicado por llamadas que involucraban la caché compartida dyld.
* **Limitaciones de Scripting**: Los intentos de escribir un script para el análisis de llamadas a `xpc_connection_get_audit_token` desde bloques `dispatch_async` se vieron obstaculizados por complejidades en el análisis de bloques e interacciones con la caché compartida dyld.

## La solución <a href="#the-fix" id="the-fix"></a>

* **Problemas Reportados**: Se envió un informe a Apple detallando los problemas generales y específicos encontrados dentro de `smd`.
* **Respuesta de Apple**: Apple abordó el problema en `smd` sustituyendo `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.
* **Naturaleza de la Solución**: La función `xpc_dictionary_get_audit_token` se considera segura ya que recupera el token de auditoría directamente del mensaje mach vinculado al mensaje XPC recibido. Sin embargo, no forma parte de la API pública, similar a `xpc_connection_get_audit_token`.
* **Ausencia de una Solución más Amplia**: No está claro por qué Apple no implementó una solución más integral, como descartar mensajes que no se alinean con el token de auditoría guardado de la conexión. La posibilidad de cambios legítimos en el token de auditoría en ciertos escenarios (por ejemplo, uso de `setuid`) podría ser un factor.
* **Estado Actual**: El problema persiste en iOS 17 y macOS 14, lo que representa un desafío para aquellos que intentan identificarlo y comprenderlo.
