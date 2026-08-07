# Attack de macOS xpc_connection_get_audit_token

{{#include ../../../../../../banners/hacktricks-training.md}}

**Para obtener más información, consulta el post original:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Este es un resumen:<sup>[[1]](#references)</sup>

## Información básica sobre Mach Messages

Si no sabes qué son los Mach Messages, empieza consultando esta página:


{{#ref}}
../../
{{#endref}}

Por ahora, recuerda que ([definición disponible aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Los Mach messages se envían a través de un _mach port_, que es un canal de comunicación de **un único receptor y múltiples emisores** integrado en el kernel de mach. **Múltiples procesos pueden enviar mensajes** a un mach port, pero en cualquier momento **solo un proceso puede leer de él**. Al igual que los file descriptors y los sockets, los mach ports son asignados y gestionados por el kernel, y los procesos solo ven un entero que pueden utilizar para indicar al kernel cuál de sus mach ports quieren usar.

## XPC Connection

Si no sabes cómo se establece una XPC connection, consulta:


{{#ref}}
../
{{#endref}}

## Resumen de la vulnerabilidad

Lo que es importante saber es que **la abstracción de XPC es una conexión uno a uno**, pero se basa en una tecnología que **puede tener múltiples emisores, por lo que:**

- Los Mach ports tienen un único receptor y **múltiples emisores**.
- El audit token de una XPC connection es el audit token **copiado del mensaje recibido más recientemente**.
- Obtener el **audit token** de una XPC connection es fundamental para muchas **comprobaciones de seguridad**.<sup>[[1]](#references)</sup>

Aunque la situación anterior parece prometedora, hay algunos escenarios en los que esto no causará problemas ([de aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Los audit tokens se utilizan a menudo para una comprobación de autorización que decide si se acepta una connection. Como esto ocurre mediante un mensaje al service port, todavía **no se ha establecido ninguna connection**. Los mensajes adicionales en este port simplemente se gestionarán como solicitudes de conexión adicionales. Por tanto, **las comprobaciones realizadas antes de aceptar una connection no son vulnerables** (esto también significa que, dentro de `-listener:shouldAcceptNewConnection:`, el audit token es seguro). Por ello, **buscamos XPC connections que verifiquen acciones específicas**.
- Los XPC event handlers se gestionan de forma síncrona. Esto significa que el event handler de un mensaje debe completarse antes de llamar al siguiente, incluso en dispatch queues concurrentes. Por tanto, dentro de un **XPC event handler, el audit token no puede ser sobrescrito** por otros mensajes normales (¡no de respuesta!).<sup>[[1]](#references)</sup>

Hay dos métodos diferentes mediante los que esto podría ser explotable:

1. Variante 1:
- El **exploit** se **conecta** a los servicios **A** y **B**.
- El servicio **B** puede llamar a una **funcionalidad privilegiada** del servicio A que el usuario no puede utilizar.
- El servicio **A** llama a **`xpc_connection_get_audit_token`** mientras _**no**_ está dentro del **event handler** de una connection en un **`dispatch_async`**.
- Por tanto, un mensaje **diferente** podría **sobrescribir el Audit Token**, ya que se está procesando de forma asíncrona fuera del event handler.
- El exploit pasa al **servicio B** el **SEND right** del servicio A.
- Por tanto, el servicio **B** será quien realmente **envíe** los **mensajes** al servicio **A**.
- El **exploit** intenta **llamar a la acción privilegiada**. En una RC, el servicio **A** **comprueba** la autorización de esta **acción** mientras el **servicio B ha sobrescrito el Audit token** (dando al exploit acceso para llamar a la acción privilegiada).
2. Variante 2:
- El servicio **B** puede llamar a una **funcionalidad privilegiada** del servicio A que el usuario no puede utilizar.
- El exploit se conecta con el **servicio A**, que **envía** al exploit un **mensaje que espera una respuesta** en un **port de replay** específico.
- El exploit envía al **servicio B** un mensaje pasando **ese reply port**.
- Cuando el servicio **B responde**, **envía el mensaje al servicio A**, mientras el **exploit** envía un **mensaje diferente al servicio A** intentando **acceder a una funcionalidad privilegiada** y esperando que la respuesta del servicio B sobrescriba el Audit token en el momento perfecto (Race Condition).

## Variante 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Escenario:

- Dos mach services, **`A`** y **`B`**, a los que podemos conectarnos (según el sandbox profile y las comprobaciones de autorización realizadas antes de aceptar la connection).
- _**A**_ debe tener una **comprobación de autorización** para una acción específica que **B** pueda superar (pero nuestra app no).
- Por ejemplo, si B tiene algunos **entitlements** o se ejecuta como **root**, podría permitirle pedir a A que realice una acción privilegiada.
- Para esta comprobación de autorización, **A** obtiene el audit token de forma asíncrona, por ejemplo, llamando a `xpc_connection_get_audit_token` desde `dispatch_async`.

> [!CAUTION]
> En este caso, un atacante podría provocar una **Race Condition**, creando un **exploit** que solicite a A realizar una acción varias veces mientras hace que **B envíe mensajes a `A`**. Cuando la RC tiene éxito, el **audit token** de **B** se copiará en memoria **mientras** A está gestionando la solicitud del **exploit**, dándole acceso a la acción privilegiada que solo B podría solicitar.

Esto ocurrió con **`A`** como `smd` y **`B`** como `diagnosticd`. La función [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb se puede utilizar para instalar un nuevo helper tool privilegiado (como **root**). Si un **proceso que se ejecuta como root contacta con** `smd`, no se realizarán más comprobaciones.

Por tanto, el servicio **B** es **`diagnosticd`**, porque se ejecuta como **root** y puede utilizarse para **monitorizar** un proceso; una vez iniciado el monitoring, **enviará varios mensajes por segundo**.

Para realizar el ataque:

1. Inicia una **connection** con el servicio llamado `smd` utilizando el protocolo XPC estándar.
2. Establece una **connection** secundaria con `diagnosticd`. A diferencia del procedimiento normal, en lugar de crear y enviar dos nuevos mach ports, el client port send right se sustituye por un duplicado del **send right** asociado a la connection con `smd`.
3. Como resultado, los mensajes XPC pueden enviarse a `diagnosticd`, pero las respuestas de `diagnosticd` se redirigen a `smd`. Para `smd`, parece que los mensajes tanto del usuario como de `diagnosticd` se originan en la misma connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. El siguiente paso consiste en ordenar a `diagnosticd` que inicie el monitoring de un proceso elegido (posiblemente el del propio usuario). Al mismo tiempo, se envía una avalancha de mensajes rutinarios 1004 a `smd`. El objetivo es instalar una tool con privilegios elevados.
5. Esta acción activa una race condition dentro de la función `handle_bless`. El momento es crítico: la llamada a la función `xpc_connection_get_pid` debe devolver el PID del proceso del usuario (ya que la tool privilegiada se encuentra en el app bundle del usuario). Sin embargo, la función `xpc_connection_get_audit_token`, específicamente dentro de la subrutina `connection_is_authorized`, debe hacer referencia al audit token perteneciente a `diagnosticd`.<sup>[[1]](#references)</sup>

## Variante 2: reply forwarding

En un entorno XPC (Cross-Process Communication), aunque los event handlers no se ejecutan de forma concurrente, la gestión de los reply messages tiene un comportamiento único. En concreto, existen dos métodos distintos para enviar mensajes que esperan una respuesta:

1. **`xpc_connection_send_message_with_reply`**: aquí, el mensaje XPC se recibe y procesa en una queue designada.
2. **`xpc_connection_send_message_with_reply_sync`**: por el contrario, en este método, el mensaje XPC se recibe y procesa en la dispatch queue actual.

Esta distinción es crucial porque permite que los **reply packets se analicen de forma concurrente con la ejecución de un XPC event handler**. Cabe destacar que, aunque `_xpc_connection_set_creds` implementa locking para proteger contra la sobrescritura parcial del audit token, esta protección no se extiende a todo el connection object. En consecuencia, se crea una vulnerabilidad en la que el audit token puede reemplazarse durante el intervalo entre el análisis de un packet y la ejecución de su event handler.

Para explotar esta vulnerabilidad, se requiere la siguiente configuración:

- Dos mach services, denominados **`A`** y **`B`**, que puedan establecer una connection.
- El servicio **`A`** debe incluir una comprobación de autorización para una acción específica que solo **`B`** pueda realizar (la aplicación del usuario no puede).
- El servicio **`A`** debe enviar un mensaje que espere una respuesta.
- El usuario debe poder enviar un mensaje a **`B`** al que este responda.

El proceso de explotación implica los siguientes pasos:

1. Espera a que el servicio **`A`** envíe un mensaje que espere una respuesta.
2. En lugar de responder directamente a **`A`**, se secuestra el reply port y se utiliza para enviar un mensaje al servicio **`B`**.
3. Posteriormente, se envía un mensaje relacionado con la acción prohibida, esperando que se procese de forma concurrente con la respuesta de **`B`**.<sup>[[1]](#references)</sup>

A continuación se muestra una representación visual del escenario de ataque descrito:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas de discovery

- **Dificultades para localizar instancias**: buscar instancias en las que se utilizara `xpc_connection_get_audit_token` resultó complicado, tanto estática como dinámicamente.
- **Metodología**: se utilizó Frida para hookear la función `xpc_connection_get_audit_token`, filtrando las llamadas que no se originaban en event handlers. Sin embargo, este método estaba limitado al proceso hookeado y requería un uso activo.
- **Herramientas de análisis**: se utilizaron herramientas como IDA/Ghidra para examinar los mach services accesibles, pero el proceso requirió mucho tiempo y se complicó por las llamadas relacionadas con la dyld shared cache.
- **Limitaciones de scripting**: los intentos de crear scripts para analizar las llamadas a `xpc_connection_get_audit_token` desde bloques `dispatch_async` se vieron obstaculizados por la complejidad de analizar bloques y las interacciones con la dyld shared cache.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Problemas reportados**: se envió a Apple un informe detallando los problemas generales y específicos encontrados en `smd`.
- **Respuesta de Apple**: Apple solucionó el problema en `smd` sustituyendo `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Naturaleza de la solución**: la función `xpc_dictionary_get_audit_token` se considera segura porque obtiene el audit token directamente del mach message asociado al mensaje XPC recibido. Sin embargo, no forma parte de la API pública, al igual que `xpc_connection_get_audit_token`.
- **Ausencia de una solución más amplia**: no está claro por qué Apple no implementó una solución más completa, como descartar los mensajes que no coincidan con el audit token guardado de la connection. La posibilidad de que se produzcan cambios legítimos del audit token en ciertos escenarios (por ejemplo, al utilizar `setuid`) podría ser un factor.
- **Estado actual**: el problema persiste en iOS 17 y macOS 14, lo que supone un desafío para quienes intentan identificarlo y comprenderlo.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

Al auditar XPC services para esta clase de bug, céntrate en las autorizaciones realizadas fuera del event handler del mensaje o de forma concurrente con el procesamiento de replies.

Indicadores para el triage estático:
- Busca llamadas a `xpc_connection_get_audit_token` accesibles desde bloques puestos en cola mediante `dispatch_async`/`dispatch_after` u otras worker queues que se ejecuten fuera del message handler.
- Busca authorization helpers que mezclen estado por connection y por message (por ejemplo, obtener el PID de `xpc_connection_get_pid`, pero el audit token de `xpc_connection_get_audit_token`).
- En código NSXPC, verifica que las comprobaciones se realicen en `-listener:shouldAcceptNewConnection:` o, para comprobaciones por mensaje, que la implementación utilice un audit token por mensaje (por ejemplo, el dictionary del mensaje mediante `xpc_dictionary_get_audit_token` en código de nivel inferior).

Indicadores para el triage dinámico:
- Hookea `xpc_connection_get_audit_token` y marca las invocaciones cuyo user stack no incluya la ruta de entrega del evento (por ejemplo, `_xpc_connection_mach_event`). Ejemplo de Frida hook:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Notas:
- En macOS, instrumentar binarios protegidos/de Apple puede requerir que SIP esté deshabilitado o utilizar un entorno de desarrollo; se recomienda probar tus propios builds o servicios userland.
- Para las race conditions de reply-forwarding (Variant 2), monitoriza el análisis concurrente de los paquetes de respuesta haciendo fuzzing de los tiempos de `xpc_connection_send_message_with_reply` frente a las solicitudes normales y comprobando si el audit token efectivo utilizado durante la autorización puede verse influido.

## Primitives de explotación que probablemente necesitarás

- Configuración multi-sender (Variant 1): crea conexiones a A y B; duplica el send right del client port de A y úsalo como client port de B para que las respuestas de B se entreguen a A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): captura el derecho send-once de la solicitud pendiente de A (puerto de respuesta) y, a continuación, envía un mensaje diseñado a B usando ese puerto de respuesta, de modo que la respuesta de B llegue a A mientras se analiza tu solicitud con privilegios.

Estas técnicas requieren la creación de mensajes mach de bajo nivel para los formatos de bootstrap y de mensajes de XPC; revisa las páginas introductorias sobre mach/XPC de esta sección para consultar las estructuras exactas de los paquetes y los flags.

## Herramientas útiles

- Sniffing/inspección dinámica de XPC: gxpc (sniffer de XPC de código abierto) puede ayudar a enumerar conexiones y observar el tráfico para validar configuraciones con múltiples emisores y la sincronización. Ejemplo: `gxpc -p <PID> --whitelist <service-name>`.
- Interposing clásico de dyld para libxpc: realiza interposing sobre `xpc_connection_send_message*` y `xpc_connection_get_audit_token` para registrar los puntos de llamada y las pilas durante el testing de caja negra.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
