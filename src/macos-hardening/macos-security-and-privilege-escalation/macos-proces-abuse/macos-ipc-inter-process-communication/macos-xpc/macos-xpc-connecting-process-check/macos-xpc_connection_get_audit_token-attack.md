# macOS xpc_connection_get_audit_token Ataque

{{#include ../../../../../../banners/hacktricks-training.md}}

**Para más información, consulta la publicación original:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Este es un resumen:

## Información Básica sobre Mensajes Mach

Si no sabes qué son los Mensajes Mach, comienza a revisar esta página:

{{#ref}}
../../
{{#endref}}

Por el momento, recuerda que ([definición de aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Los mensajes Mach se envían a través de un _mach port_, que es un canal de comunicación de **un solo receptor, múltiples emisores** integrado en el núcleo mach. **Múltiples procesos pueden enviar mensajes** a un mach port, pero en cualquier momento **solo un único proceso puede leer de él**. Al igual que los descriptores de archivo y los sockets, los mach ports son asignados y gestionados por el núcleo y los procesos solo ven un entero, que pueden usar para indicar al núcleo cuál de sus mach ports desean usar.

## Conexión XPC

Si no sabes cómo se establece una conexión XPC, consulta:

{{#ref}}
../
{{#endref}}

## Resumen de Vulnerabilidades

Lo que es interesante que sepas es que **la abstracción de XPC es una conexión uno a uno**, pero se basa en una tecnología que **puede tener múltiples emisores, así que:**

- Los mach ports son de un solo receptor, **múltiples emisores**.
- El token de auditoría de una conexión XPC es el token de auditoría **copiado del mensaje recibido más recientemente**.
- Obtener el **token de auditoría** de una conexión XPC es crítico para muchas **verificaciones de seguridad**.

Aunque la situación anterior suena prometedora, hay algunos escenarios donde esto no causará problemas ([de aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Los tokens de auditoría se utilizan a menudo para una verificación de autorización para decidir si aceptar una conexión. Como esto ocurre utilizando un mensaje al puerto de servicio, **no se ha establecido ninguna conexión aún**. Más mensajes en este puerto simplemente se manejarán como solicitudes de conexión adicionales. Por lo tanto, cualquier **verificación antes de aceptar una conexión no es vulnerable** (esto también significa que dentro de `-listener:shouldAcceptNewConnection:` el token de auditoría es seguro). Por lo tanto, **buscamos conexiones XPC que verifiquen acciones específicas**.
- Los controladores de eventos XPC se manejan de manera sincrónica. Esto significa que el controlador de eventos para un mensaje debe completarse antes de llamarlo para el siguiente, incluso en colas de despacho concurrentes. Por lo tanto, dentro de un **controlador de eventos XPC, el token de auditoría no puede ser sobrescrito** por otros mensajes normales (¡no de respuesta!).

Dos métodos diferentes en los que esto podría ser explotable:

1. Variante 1:
- **El exploit** **se conecta** al servicio **A** y al servicio **B**
- El servicio **B** puede llamar a una **funcionalidad privilegiada** en el servicio A que el usuario no puede
- El servicio **A** llama a **`xpc_connection_get_audit_token`** mientras _**no**_ está dentro del **controlador de eventos** para una conexión en un **`dispatch_async`**.
- Por lo tanto, un **mensaje diferente** podría **sobrescribir el Token de Auditoría** porque se está despachando de manera asíncrona fuera del controlador de eventos.
- El exploit pasa a **servicio B el derecho de ENVÍO al servicio A**.
- Por lo tanto, el svc **B** estará realmente **enviando** los **mensajes** al servicio **A**.
- El **exploit** intenta **llamar** a la **acción privilegiada.** En un RC, el svc **A** **verifica** la autorización de esta **acción** mientras **svc B sobrescribió el token de auditoría** (dando al exploit acceso para llamar a la acción privilegiada).
2. Variante 2:
- El servicio **B** puede llamar a una **funcionalidad privilegiada** en el servicio A que el usuario no puede
- El exploit se conecta con **el servicio A** que **envía** al exploit un **mensaje esperando una respuesta** en un **puerto de respuesta** específico.
- El exploit envía a **servicio** B un mensaje pasando **ese puerto de respuesta**.
- Cuando el servicio **B responde**, **envía el mensaje al servicio A**, **mientras** el **exploit** envía un **mensaje diferente al servicio A** tratando de **alcanzar una funcionalidad privilegiada** y esperando que la respuesta del servicio B sobrescriba el token de auditoría en el momento perfecto (Condición de Carrera).

## Variante 1: llamando a xpc_connection_get_audit_token fuera de un controlador de eventos <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Escenario:

- Dos servicios mach **`A`** y **`B`** a los que ambos podemos conectarnos (basado en el perfil de sandbox y las verificaciones de autorización antes de aceptar la conexión).
- _**A**_ debe tener una **verificación de autorización** para una acción específica que **`B`** puede pasar (pero nuestra aplicación no puede).
- Por ejemplo, si B tiene algunos **derechos** o se está ejecutando como **root**, podría permitirle pedir a A que realice una acción privilegiada.
- Para esta verificación de autorización, **`A`** obtiene el token de auditoría de manera asíncrona, por ejemplo, llamando a `xpc_connection_get_audit_token` desde **`dispatch_async`**.

> [!CAUTION]
> En este caso, un atacante podría desencadenar una **Condición de Carrera** haciendo un **exploit** que **pide a A que realice una acción** varias veces mientras hace que **B envíe mensajes a `A`**. Cuando la RC es **exitosa**, el **token de auditoría** de **B** será copiado en memoria **mientras** la solicitud de nuestro **exploit** está siendo **manejada** por A, dándole **acceso a la acción privilegiada que solo B podría solicitar**.

Esto ocurrió con **`A`** como `smd` y **`B`** como `diagnosticd`. La función [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb se puede usar para instalar un nuevo ayudante privilegiado (como **root**). Si un **proceso que se ejecuta como root contacta** **smd**, no se realizarán más verificaciones.

Por lo tanto, el servicio **B** es **`diagnosticd`** porque se ejecuta como **root** y se puede usar para **monitorear** un proceso, así que una vez que se ha iniciado el monitoreo, **enviará múltiples mensajes por segundo.**

Para realizar el ataque:

1. Iniciar una **conexión** al servicio llamado `smd` utilizando el protocolo XPC estándar.
2. Formar una **conexión** secundaria a `diagnosticd`. A diferencia del procedimiento normal, en lugar de crear y enviar dos nuevos mach ports, el derecho de envío del puerto del cliente se sustituye por un duplicado del **derecho de envío** asociado con la conexión `smd`.
3. Como resultado, los mensajes XPC pueden ser despachados a `diagnosticd`, pero las respuestas de `diagnosticd` se redirigen a `smd`. Para `smd`, parece que los mensajes del usuario y de `diagnosticd` provienen de la misma conexión.

![Imagen que representa el proceso de exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. El siguiente paso implica instruir a `diagnosticd` para que inicie el monitoreo de un proceso elegido (potencialmente el propio del usuario). Al mismo tiempo, se envía una inundación de mensajes rutinarios 1004 a `smd`. La intención aquí es instalar una herramienta con privilegios elevados.
5. Esta acción desencadena una condición de carrera dentro de la función `handle_bless`. El tiempo es crítico: la llamada a la función `xpc_connection_get_pid` debe devolver el PID del proceso del usuario (ya que la herramienta privilegiada reside en el paquete de la aplicación del usuario). Sin embargo, la función `xpc_connection_get_audit_token`, específicamente dentro de la subrutina `connection_is_authorized`, debe hacer referencia al token de auditoría perteneciente a `diagnosticd`.

## Variante 2: reenvío de respuestas

En un entorno XPC (Comunicación entre Procesos), aunque los controladores de eventos no se ejecutan de manera concurrente, el manejo de mensajes de respuesta tiene un comportamiento único. Específicamente, existen dos métodos distintos para enviar mensajes que esperan una respuesta:

1. **`xpc_connection_send_message_with_reply`**: Aquí, el mensaje XPC se recibe y procesa en una cola designada.
2. **`xpc_connection_send_message_with_reply_sync`**: Por el contrario, en este método, el mensaje XPC se recibe y procesa en la cola de despacho actual.

Esta distinción es crucial porque permite la posibilidad de que **los paquetes de respuesta se analicen de manera concurrente con la ejecución de un controlador de eventos XPC**. Notablemente, mientras que `_xpc_connection_set_creds` implementa un bloqueo para protegerse contra la sobrescritura parcial del token de auditoría, no extiende esta protección a todo el objeto de conexión. En consecuencia, esto crea una vulnerabilidad donde el token de auditoría puede ser reemplazado durante el intervalo entre el análisis de un paquete y la ejecución de su controlador de eventos.

Para explotar esta vulnerabilidad, se requiere la siguiente configuración:

- Dos servicios mach, denominados **`A`** y **`B`**, ambos de los cuales pueden establecer una conexión.
- El servicio **`A`** debe incluir una verificación de autorización para una acción específica que solo **`B`** puede realizar (la aplicación del usuario no puede).
- El servicio **`A`** debe enviar un mensaje que anticipa una respuesta.
- El usuario puede enviar un mensaje a **`B`** al que este responderá.

El proceso de explotación implica los siguientes pasos:

1. Esperar a que el servicio **`A`** envíe un mensaje que espera una respuesta.
2. En lugar de responder directamente a **`A`**, se secuestra el puerto de respuesta y se utiliza para enviar un mensaje al servicio **`B`**.
3. Posteriormente, se despacha un mensaje que involucra la acción prohibida, con la expectativa de que se procese de manera concurrente con la respuesta de **`B`**.

A continuación se muestra una representación visual del escenario de ataque descrito:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas de Descubrimiento

- **Dificultades para Localizar Instancias**: Buscar instancias del uso de `xpc_connection_get_audit_token` fue un desafío, tanto estática como dinámicamente.
- **Metodología**: Se utilizó Frida para enganchar la función `xpc_connection_get_audit_token`, filtrando llamadas que no provenían de controladores de eventos. Sin embargo, este método estaba limitado al proceso enganchado y requería uso activo.
- **Herramientas de Análisis**: Se utilizaron herramientas como IDA/Ghidra para examinar servicios mach alcanzables, pero el proceso fue lento, complicado por llamadas que involucraban la caché compartida de dyld.
- **Limitaciones de Scripting**: Los intentos de scriptar el análisis para llamadas a `xpc_connection_get_audit_token` desde bloques `dispatch_async` se vieron obstaculizados por complejidades en el análisis de bloques e interacciones con la caché compartida de dyld.

## La solución <a href="#the-fix" id="the-fix"></a>

- **Problemas Reportados**: Se presentó un informe a Apple detallando los problemas generales y específicos encontrados en `smd`.
- **Respuesta de Apple**: Apple abordó el problema en `smd` sustituyendo `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.
- **Naturaleza de la Solución**: La función `xpc_dictionary_get_audit_token` se considera segura ya que recupera el token de auditoría directamente del mensaje mach vinculado al mensaje XPC recibido. Sin embargo, no forma parte de la API pública, similar a `xpc_connection_get_audit_token`.
- **Ausencia de una Solución Más Amplia**: No está claro por qué Apple no implementó una solución más integral, como descartar mensajes que no se alineen con el token de auditoría guardado de la conexión. La posibilidad de cambios legítimos en el token de auditoría en ciertos escenarios (por ejemplo, uso de `setuid`) podría ser un factor.
- **Estado Actual**: El problema persiste en iOS 17 y macOS 14, representando un desafío para aquellos que buscan identificarlo y comprenderlo.

{{#include ../../../../../../banners/hacktricks-training.md}}
