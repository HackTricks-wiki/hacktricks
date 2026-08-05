# Attack de macOS xpc_connection_get_audit_token

{{#include ../../../../../../banners/hacktricks-training.md}}

**Para más información, consulta el post original:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Este es un resumen:

## Información básica sobre Mach Messages

Si no sabes qué son los Mach Messages, empieza consultando esta página:


{{#ref}}
../../
{{#endref}}

Por ahora, recuerda que ([definición disponible aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Los Mach messages se envían mediante un _mach port_, que es un canal de comunicación de **un único receptor y múltiples emisores** integrado en el kernel de mach. **Múltiples procesos pueden enviar mensajes** a un mach port, pero en cualquier momento **solo un proceso puede leer de él**. Al igual que los descriptores de archivo y los sockets, los mach ports son asignados y gestionados por el kernel, y los procesos solo ven un entero que pueden utilizar para indicar al kernel cuál de sus mach ports quieren usar.

## XPC Connection

Si no sabes cómo se establece una conexión XPC, consulta:


{{#ref}}
../
{{#endref}}

## Resumen de la vulnerabilidad

Lo importante es saber que **la abstracción de XPC es una conexión uno a uno**, pero se basa en una tecnología que **puede tener múltiples emisores, por lo que:**

- Los Mach ports tienen un único receptor y **múltiples emisores**.
- El audit token de una XPC connection es el audit token **copiado del mensaje recibido más recientemente**.
- Obtener el **audit token** de una XPC connection es fundamental para muchos **security checks**.<sup>[[1]](#references)</sup>

Aunque la situación anterior parece prometedora, hay algunos escenarios en los que esto no causará problemas ([fuente](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Los audit tokens se utilizan a menudo para realizar un authorization check que decide si se acepta una connection. Como esto ocurre mediante un mensaje enviado al service port, **todavía no existe una connection establecida**. Los mensajes adicionales en este port simplemente se gestionarán como solicitudes de conexión adicionales. Por tanto, **los checks realizados antes de aceptar una connection no son vulnerables** (esto también significa que dentro de `-listener:shouldAcceptNewConnection:` el audit token es seguro). Por tanto, **buscamos XPC connections que verifiquen acciones específicas**.
- Los XPC event handlers se gestionan de forma síncrona. Esto significa que el event handler de un mensaje debe completarse antes de invocarlo para el siguiente, incluso en dispatch queues concurrentes. Por tanto, dentro de un **XPC event handler, el audit token no puede ser sobrescrito** por otros mensajes normales (¡no reply!).<sup>[[1]](#references)</sup>

Hay dos métodos diferentes mediante los que esto podría ser explotable:

1. Variant1:
- El **exploit** se **conecta** al service **A** y al service **B**.
- El service **B** puede llamar a una **privileged functionality** del service A que el usuario no puede utilizar.
- El service **A** llama a **`xpc_connection_get_audit_token`** mientras _**no**_ está dentro del **event handler** de una connection en un **`dispatch_async`**.
- Por tanto, un mensaje **diferente** podría **sobrescribir el Audit Token**, ya que se está procesando de forma asíncrona fuera del event handler.
- El exploit pasa al **service B** el **SEND right del service A**.
- De este modo, svc **B** será quien realmente **envíe** los **mensajes** al service **A**.
- El **exploit** intenta **invocar la acción privilegiada**. En una RC, svc **A** **comprueba** la autorización de esta **acción** mientras **svc B sobrescribe el Audit token** (proporcionando al exploit acceso para invocar la acción privilegiada).
2. Variant 2:
- El service **B** puede llamar a una **privileged functionality** del service A que el usuario no puede utilizar.
- El exploit se conecta al **service A**, que **envía** al exploit un **mensaje que espera una respuesta** en un **reply** **port** específico.
- El exploit envía al **service B** un mensaje pasando **ese reply port**.
- Cuando el service **B** responde, **envía el mensaje al service A**, mientras el **exploit** envía un **mensaje diferente al service A** intentando **acceder a una privileged functionality** y esperando que la respuesta del service B sobrescriba el Audit token en el momento perfecto (Race Condition).

## Variant 1: llamar a xpc_connection_get_audit_token fuera de un event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Escenario:

- Dos mach services **`A`** y **`B`** a los que podemos conectarnos (según el sandbox profile y los authorization checks realizados antes de aceptar la connection).
- _**A**_ debe tener un **authorization check** para una acción específica que **B** pueda superar (pero nuestra app no).
- Por ejemplo, si B tiene algunos **entitlements** o se ejecuta como **root**, podría permitirle solicitar a A que realice una acción privilegiada.
- Para este authorization check, **A** obtiene el audit token de forma asíncrona, por ejemplo, llamando a `xpc_connection_get_audit_token` desde `dispatch_async`.

> [!CAUTION]
> En este caso, un atacante podría activar una **Race Condition**, creando un **exploit** que solicite a A realizar una acción varias veces mientras hace que **B envíe mensajes a `A`**. Cuando la RC tiene éxito, el **audit token** de **B** se copiará en memoria **mientras** A está procesando la solicitud de nuestro **exploit**, proporcionándole acceso a la acción privilegiada que solo B podría solicitar.

Esto ocurrió con **`A`** como `smd` y **`B`** como `diagnosticd`. La función [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb puede utilizarse para instalar un nuevo privileged helper toot (como **root**). Si un **proceso que se ejecuta como root contacta con** `smd`, no se realizarán más checks.

Por tanto, el service **B** es **`diagnosticd`**, porque se ejecuta como **root** y puede utilizarse para **monitorizar** un proceso; una vez iniciado el monitoring, **enviará varios mensajes por segundo**.

Para realizar el attack:

1. Inicia una **connection** al service denominado `smd` utilizando el protocolo XPC estándar.
2. Establece una **connection** secundaria con `diagnosticd`. A diferencia del procedimiento normal, en lugar de crear y enviar dos mach ports nuevos, el client port send right se sustituye por un duplicado del **send right** asociado a la connection con `smd`.
3. Como resultado, los XPC messages pueden enviarse a `diagnosticd`, pero las respuestas de `diagnosticd` se redirigen a `smd`. Para `smd`, parece que los mensajes procedentes tanto del usuario como de `diagnosticd` se originan en la misma connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. El siguiente paso consiste en indicar a `diagnosticd` que inicie el monitoring de un proceso elegido (potencialmente el propio proceso del usuario). Simultáneamente, se envía a `smd` una avalancha de mensajes rutinarios 1004. El objetivo es instalar una herramienta con privilegios elevados.
5. Esta acción activa una race condition dentro de la función `handle_bless`. El momento es crítico: la llamada a la función `xpc_connection_get_pid` debe devolver el PID del proceso del usuario (ya que la herramienta privilegiada se encuentra en el app bundle del usuario). Sin embargo, la función `xpc_connection_get_audit_token`, concretamente dentro de la subrutina `connection_is_authorized`, debe hacer referencia al audit token perteneciente a `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

En un entorno XPC (Cross-Process Communication), aunque los event handlers no se ejecutan de forma concurrente, el procesamiento de los reply messages tiene un comportamiento único. Concretamente, existen dos métodos distintos para enviar mensajes que esperan una respuesta:

1. **`xpc_connection_send_message_with_reply`**: aquí, el XPC message se recibe y procesa en una queue designada.
2. **`xpc_connection_send_message_with_reply_sync`**: por el contrario, en este método, el XPC message se recibe y procesa en la dispatch queue actual.

Esta distinción es crucial porque permite que los **reply packets se analicen de forma concurrente con la ejecución de un XPC event handler**. Cabe destacar que, aunque `_xpc_connection_set_creds` implementa locking para proteger contra la sobrescritura parcial del audit token, no extiende esta protección al objeto connection completo. En consecuencia, se crea una vulnerabilidad por la que el audit token puede sustituirse durante el intervalo entre el análisis de un packet y la ejecución de su event handler.

Para explotar esta vulnerabilidad, se requiere la siguiente configuración:

- Dos mach services, denominados **`A`** y **`B`**, a los que se pueda establecer una connection.
- El service **`A`** debe incluir un authorization check para una acción específica que solo **`B`** pueda realizar (la aplicación del usuario no puede).
- El service **`A`** debe enviar un mensaje que espere una respuesta.
- El usuario puede enviar un mensaje a **`B`**, que responderá a él.

El proceso de exploitation incluye los siguientes pasos:

1. Espera a que el service **`A`** envíe un mensaje que espere una respuesta.
2. En lugar de responder directamente a **`A`**, se secuestra el reply port y se utiliza para enviar un mensaje al service **`B`**.
3. Posteriormente, se envía un mensaje relacionado con la acción prohibida, esperando que se procese de forma concurrente con la respuesta de **`B`**.<sup>[[1]](#references)</sup>

A continuación se muestra una representación visual del escenario de attack descrito:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas durante el descubrimiento

- **Dificultades para localizar instancias**: buscar instancias de uso de `xpc_connection_get_audit_token` resultó complicado, tanto estática como dinámicamente.
- **Metodología**: se utilizó Frida para hookear la función `xpc_connection_get_audit_token`, filtrando las llamadas que no se originaban en event handlers. Sin embargo, este método estaba limitado al proceso hookeado y requería un uso activo.
- **Herramientas de análisis**: se utilizaron herramientas como IDA/Ghidra para examinar los mach services accesibles, pero el proceso consumía mucho tiempo y se complicaba por las llamadas relacionadas con el dyld shared cache.
- **Limitaciones del scripting**: los intentos de crear scripts para analizar las llamadas a `xpc_connection_get_audit_token` desde bloques `dispatch_async` se vieron obstaculizados por la complejidad de analizar bloques y las interacciones con el dyld shared cache.<sup>[[1]](#references)</sup>

## La solución <a href="#the-fix" id="the-fix"></a>

- **Problemas reportados**: se envió a Apple un informe detallando los problemas generales y específicos encontrados en `smd`.
- **Respuesta de Apple**: Apple solucionó el problema en `smd` sustituyendo `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Naturaleza de la solución**: la función `xpc_dictionary_get_audit_token` se considera segura porque obtiene el audit token directamente del mach message asociado al XPC message recibido. Sin embargo, no forma parte de la API pública, al igual que `xpc_connection_get_audit_token`.
- **Ausencia de una solución más amplia**: no está claro por qué Apple no implementó una solución más completa, como descartar los mensajes que no coincidan con el audit token guardado de la connection. La posibilidad de que se produzcan cambios legítimos en el audit token en determinados escenarios (por ejemplo, al utilizar `setuid`) podría ser un factor.
- **Estado actual**: el problema persiste en iOS 17 y macOS 14, lo que supone un desafío para quienes intentan identificarlo y comprenderlo.<sup>[[1]](#references)</sup>

## Encontrar code paths vulnerables en la práctica (2024–2025)

Al auditar XPC services para esta clase de bug, céntrate en las autorizaciones realizadas fuera del event handler del mensaje o de forma concurrente con el procesamiento de replies.

Indicadores para el triage estático:
- Busca llamadas a `xpc_connection_get_audit_token` accesibles desde bloques puestos en cola mediante `dispatch_async`/`dispatch_after` u otras worker queues que se ejecuten fuera del message handler.
- Busca authorization helpers que mezclen estado por connection y por message (por ejemplo, obtener el PID mediante `xpc_connection_get_pid`, pero el audit token mediante `xpc_connection_get_audit_token`).
- En código NSXPC, verifica que los checks se realicen en `-listener:shouldAcceptNewConnection:` o, para checks por message, que la implementación utilice un audit token por message (por ejemplo, el dictionary del message mediante `xpc_dictionary_get_audit_token` en código de nivel inferior).

Indicadores para el triage dinámico:
- Hookea `xpc_connection_get_audit_token` y marca las invocaciones cuya user stack no incluya el event-delivery path (por ejemplo, `_xpc_connection_mach_event`). Ejemplo de Frida hook:
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
- En macOS, instrumentar binarios protegidos/de Apple puede requerir SIP deshabilitado o un entorno de desarrollo; prioriza probar tus propios builds o servicios userland.
- Para las condiciones de carrera de reply-forwarding (Variante 2), monitoriza el análisis concurrente de los paquetes de respuesta mediante fuzzing de los timings de `xpc_connection_send_message_with_reply` frente a las solicitudes normales y comprobando si el audit token efectivo utilizado durante la autorización puede verse influido.

## Primitivas de explotación que probablemente necesitarás

- Configuración multi-sender (Variante 1): crea conexiones a A y B; duplica el send right del client port de A y úsalo como client port de B para que las respuestas de B se entreguen a A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): captura el send-once right de la pending request de A (reply port), y luego envía un mensaje crafted a B usando ese reply port para que la respuesta de B llegue a A mientras tu privileged request está siendo parseada.

Estos requieren crafting de mensajes mach de bajo nivel para el bootstrap de XPC y los formatos de mensaje; revisa las páginas introductorias de mach/XPC de esta sección para consultar los packet layouts y flags exactos.

## Herramientas útiles

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) puede ayudar a enumerar connections y observar el tráfico para validar configuraciones multi-sender y el timing. Ejemplo: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing para libxpc: haz interpose sobre `xpc_connection_send_message*` y `xpc_connection_get_audit_token` para registrar los call sites y stacks durante las pruebas black-box.



## Referencias

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
