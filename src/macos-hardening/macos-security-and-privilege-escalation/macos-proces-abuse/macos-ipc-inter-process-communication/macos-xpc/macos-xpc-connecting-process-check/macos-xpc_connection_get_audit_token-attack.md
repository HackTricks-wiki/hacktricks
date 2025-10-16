# macOS xpc_connection_get_audit_token Ataque

{{#include ../../../../../../banners/hacktricks-training.md}}

**For further information check the original post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). This is a summary:

## Información básica sobre Mach Messages

If you don't know what Mach Messages are start checking this page:


{{#ref}}
../../
{{#endref}}

Por ahora recuerda que ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages are sent over a _mach port_, which is a **single receiver, multiple sender communication** channel built into the mach kernel. **Multiple processes can send messages** to a mach port, but at any point **only a single process can read from it**. Just like file descriptors and sockets, mach ports are allocated and managed by the kernel and processes only see an integer, which they can use to indicate to the kernel which of their mach ports they want to use.

## Conexión XPC

If you don't know how a XPC connection is established check:


{{#ref}}
../
{{#endref}}

## Resumen de la vulnerabilidad

Lo que es importante saber es que **la abstracción de XPC es una conexión uno-a-uno**, pero está construida sobre una tecnología que **puede tener múltiples remitentes, por lo que:**

- Mach ports son de receptor único, **múltiples remitentes**.
- El audit token de una conexión XPC es el audit token **copiado del mensaje recibido más recientemente**.
- Obtener el **audit token** de una conexión XPC es crítico para muchas **comprobaciones de seguridad**.

Aunque lo anterior suena prometedor hay algunos escenarios donde esto no va a causar problemas ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Los audit tokens a menudo se usan para una comprobación de autorización para decidir si aceptar una conexión. Como esto ocurre usando un mensaje al puerto del servicio, **no hay conexión establecida aún**. Más mensajes en este puerto solo serán tratados como solicitudes adicionales de conexión. Por tanto, **las comprobaciones antes de aceptar una conexión no son vulnerables** (esto también significa que dentro de `-listener:shouldAcceptNewConnection:` el audit token es seguro). Por ello **buscamos conexiones XPC que verifiquen acciones específicas**.
- Los event handlers de XPC son manejados de forma síncrona. Esto significa que el event handler para un mensaje debe completarse antes de invocarlo para el siguiente, incluso en colas de despacho concurrentes. Así que dentro de un **XPC event handler el audit token no puede ser sobrescrito** por otros mensajes normales (¡no-reply!).

Dos métodos diferentes en los que esto podría ser explotable:

1. Variant1:
- **Exploit** **connects** to service **A** and service **B**
- Service **B** can call a **privileged functionality** in service A that the user cannot
- Service **A** calls **`xpc_connection_get_audit_token`** while _**not**_ inside the **event handler** for a connection in a **`dispatch_async`**.
- So a **different** message could **overwrite the Audit Token** because it's being dispatched asynchronously outside of the event handler.
- The exploit passes to **service B the SEND right to service A**.
- So svc **B** will be actually **sending** the **messages** to service **A**.
- The **exploit** tries to **call** the **privileged action.** In a RC svc **A** **checks** the authorization of this **action** while **svc B overwrote the Audit token** (giving the exploit access to call the privileged action).
2. Variant 2:
- Service **B** can call a **privileged functionality** in service A that the user cannot
- Exploit connects with **service A** which **sends** the exploit a **message expecting a response** in a specific **replay** **port**.
- Exploit sends **service** B a message passing **that reply port**.
- When service **B** replies, it s**ends the message to service A**, **while** the **exploit** sends a different **message to service A** trying to **reach a privileged functionality** and expecting that the reply from service B will overwrite the Audit token in the perfect moment (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Escenario:

- Two mach services **`A`** and **`B`** that we can both connect to (based on the sandbox profile and the authorization checks before accepting the connection).
- _**A**_ must have an **authorization check** for a specific action that **`B`** can pass (but our app can’t).
- For example, if B has some **entitlements** or is running as **root**, it might allow him to ask A to perform a privileged action.
- For this authorization check, **`A`** obtains the audit token asynchronously, for example by calling `xpc_connection_get_audit_token` from **`dispatch_async`**.

> [!CAUTION]
> In this case an attacker could trigger a **Race Condition** making a **exploit** that **asks A to perform an action** several times while making **B send messages to `A`**. When the RC is **successful**, the **audit token** of **B** will be copied in memory **while** the request of our **exploit** is being **handled** by A, giving it **access to the privilege action only B could request**.

Esto ocurrió con **`A`** como `smd` y **`B`** como `diagnosticd`. The function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) from smb an be used to install a new privileged helper toot (as **root**). If a **process running as root contact** **smd**, no other checks will be performed.

Therefore, the service **B** is **`diagnosticd`** because it runs as **root** and can be used to **monitor** a process, so once monitoring has started, it will **send multiple messages per second.**

Para realizar el ataque:

1. Initiate a **connection** to the service named `smd` using the standard XPC protocol.
2. Form a secondary **connection** to `diagnosticd`. Contrary to normal procedure, rather than creating and sending two new mach ports, the client port send right is substituted with a duplicate of the **send right** associated with the `smd` connection.
3. As a result, XPC messages can be dispatched to `diagnosticd`, but responses from `diagnosticd` are rerouted to `smd`. To `smd`, it appears as though the messages from both the user and `diagnosticd` are originating from the same connection.

![Imagen que representa el proceso del exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. The next step involves instructing `diagnosticd` to initiate monitoring of a chosen process (potentially the user's own). Concurrently, a flood of routine 1004 messages is sent to `smd`. The intent here is to install a tool with elevated privileges.
5. This action triggers a race condition within the `handle_bless` function. The timing is critical: the `xpc_connection_get_pid` function call must return the PID of the user's process (as the privileged tool resides in the user's app bundle). However, the `xpc_connection_get_audit_token` function, specifically within the `connection_is_authorized` subroutine, must reference the audit token belonging to `diagnosticd`.

## Variante 2: reply forwarding

In an XPC (Cross-Process Communication) environment, although event handlers don't execute concurrently, the handling of reply messages has a unique behavior. Specifically, two distinct methods exist for sending messages that expect a reply:

1. **`xpc_connection_send_message_with_reply`**: Here, the XPC message is received and processed on a designated queue.
2. **`xpc_connection_send_message_with_reply_sync`**: Conversely, in this method, the XPC message is received and processed on the current dispatch queue.

This distinction is crucial because it allows for the possibility of **reply packets being parsed concurrently with the execution of an XPC event handler**. Notably, while `_xpc_connection_set_creds` does implement locking to safeguard against the partial overwrite of the audit token, it does not extend this protection to the entire connection object. Consequently, this creates a vulnerability where the audit token can be replaced during the interval between the parsing of a packet and the execution of its event handler.

To exploit this vulnerability, the following setup is required:

- Two mach services, referred to as **`A`** and **`B`**, both of which can establish a connection.
- Service **`A`** should include an authorization check for a specific action that only **`B`** can perform (the user's application cannot).
- Service **`A`** should send a message that anticipates a reply.
- The user can send a message to **`B`** that it will respond to.

The exploitation process involves the following steps:

1. Wait for service **`A`** to send a message that expects a reply.
2. Instead of replying directly to **`A`**, the reply port is hijacked and used to send a message to service **`B`**.
3. Subsequently, a message involving the forbidden action is dispatched, with the expectation that it will be processed concurrently with the reply from **`B`**.

Below is a visual representation of the described attack scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas de descubrimiento

- **Difficulties in Locating Instances**: Searching for instances of `xpc_connection_get_audit_token` usage was challenging, both statically and dynamically.
- **Methodology**: Frida was employed to hook the `xpc_connection_get_audit_token` function, filtering calls not originating from event handlers. However, this method was limited to the hooked process and required active usage.
- **Analysis Tooling**: Tools like IDA/Ghidra were used for examining reachable mach services, but the process was time-consuming, complicated by calls involving the dyld shared cache.
- **Scripting Limitations**: Attempts to script the analysis for calls to `xpc_connection_get_audit_token` from `dispatch_async` blocks were hindered by complexities in parsing blocks and interactions with the dyld shared cache.

## La corrección <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: A report was submitted to Apple detailing the general and specific issues found within `smd`.
- **Apple's Response**: Apple addressed the issue in `smd` by substituting `xpc_connection_get_audit_token` with `xpc_dictionary_get_audit_token`.
- **Nature of the Fix**: The `xpc_dictionary_get_audit_token` function is considered secure as it retrieves the audit token directly from the mach message tied to the received XPC message. However, it's not part of the public API, similar to `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: It remains unclear why Apple didn't implement a more comprehensive fix, such as discarding messages not aligning with the saved audit token of the connection. The possibility of legitimate audit token changes in certain scenarios (e.g., `setuid` usage) might be a factor.
- **Current Status**: The issue persists in iOS 17 and macOS 14, posing a challenge for those seeking to identify and understand it.

## Encontrando rutas de código vulnerables en la práctica (2024–2025)

When auditing XPC services for this bug class, focus on authorization performed outside the message’s event handler or concurrently with reply processing.

Pistas para triage estático:
- Search for calls to `xpc_connection_get_audit_token` reachable from blocks queued via `dispatch_async`/`dispatch_after` or other worker queues that run outside the message handler.
- Look for authorization helpers that mix per-connection and per-message state (e.g., fetch PID from `xpc_connection_get_pid` but audit token from `xpc_connection_get_audit_token`).
- In NSXPC code, verify that checks are done in `-listener:shouldAcceptNewConnection:` or, for per-message checks, that the implementation uses a per-message audit token (e.g., the message’s dictionary via `xpc_dictionary_get_audit_token` in lower-level code).

Triage dinámico:
- Hook `xpc_connection_get_audit_token` and flag invocations whose user stack does not include the event-delivery path (e.g., `_xpc_connection_mach_event`). Ejemplo de hook de Frida:
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
- En macOS, instrumentar protected/Apple binaries puede requerir SIP desactivado o un entorno de desarrollo; prefiere probar tus propias builds o userland services.
- Para reply-forwarding races (Variant 2), monitoriza el análisis concurrente de paquetes de respuesta mediante fuzzing de los tiempos de `xpc_connection_send_message_with_reply` frente a solicitudes normales, y verifica si el token de auditoría efectivo usado durante la autorización puede ser influenciado.

## Primitivas de explotación que probablemente necesitarás

- Multi-sender setup (Variant 1): crea conexiones a A y B; duplica el send right del client port de A y úsalo como client port de B para que las replies de B se entreguen a A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): captura el send-once right de la solicitud pendiente de A (reply port), luego envía un mensaje manipulado a B usando ese reply port para que la respuesta de B llegue a A mientras se está procesando tu solicitud privilegiada.

Estos requieren la creación de mensajes mach a bajo nivel para el bootstrap de XPC y los formatos de mensaje; revisa las páginas introductorias mach/XPC en esta sección para la estructura exacta de los paquetes y las flags.

## Herramientas útiles

- XPC sniffing/dynamic inspection: gxpc (sniffer XPC de código abierto) puede ayudar a enumerar conexiones y observar el tráfico para validar configuraciones multi-sender y la sincronización. Example: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interponer en `xpc_connection_send_message*` y `xpc_connection_get_audit_token` para registrar los sitios de llamada y las trazas de pila durante pruebas black-box.



## Referencias

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
