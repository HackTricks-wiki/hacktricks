# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Información Básica

**Grand Central Dispatch (GCD),** también conocido como **libdispatch** (`libdispatch.dyld`), está disponible tanto en macOS como en iOS. Es una tecnología desarrollada por Apple para optimizar el soporte de aplicaciones para la ejecución concurrente (multihilo) en hardware de múltiples núcleos.

**GCD** proporciona y gestiona **colas FIFO** a las que tu aplicación puede **enviar tareas** en forma de **objetos de bloque**. Los bloques enviados a las colas de despacho son **ejecutados en un grupo de hilos** completamente gestionados por el sistema. GCD crea automáticamente hilos para ejecutar las tareas en las colas de despacho y programa esas tareas para que se ejecuten en los núcleos disponibles.

> [!TIP]
> En resumen, para ejecutar código en **paralelo**, los procesos pueden enviar **bloques de código a GCD**, que se encargará de su ejecución. Por lo tanto, los procesos no crean nuevos hilos; **GCD ejecuta el código dado con su propio grupo de hilos** (que puede aumentar o disminuir según sea necesario).

Esto es muy útil para gestionar la ejecución paralela con éxito, reduciendo en gran medida el número de hilos que los procesos crean y optimizando la ejecución paralela. Esto es ideal para tareas que requieren **gran paralelismo** (¿fuerza bruta?) o para tareas que no deberían bloquear el hilo principal: Por ejemplo, el hilo principal en iOS maneja interacciones de UI, por lo que cualquier otra funcionalidad que podría hacer que la aplicación se congele (buscar, acceder a la web, leer un archivo...) se gestiona de esta manera.

### Bloques

Un bloque es una **sección de código autocontenida** (como una función con argumentos que devuelve un valor) y también puede especificar variables vinculadas.\
Sin embargo, a nivel de compilador, los bloques no existen, son `os_object`s. Cada uno de estos objetos está formado por dos estructuras:

- **literal de bloque**:&#x20;
- Comienza por el campo **`isa`**, que apunta a la clase del bloque:
- `NSConcreteGlobalBlock` (bloques de `__DATA.__const`)
- `NSConcreteMallocBlock` (bloques en el heap)
- `NSConcreateStackBlock` (bloques en la pila)
- Tiene **`flags`** (indicando campos presentes en el descriptor del bloque) y algunos bytes reservados
- El puntero de función a llamar
- Un puntero al descriptor del bloque
- Variables importadas del bloque (si las hay)
- **descriptor de bloque**: Su tamaño depende de los datos que están presentes (como se indica en los flags anteriores)
- Tiene algunos bytes reservados
- Su tamaño
- Usualmente tendrá un puntero a una firma de estilo Objective-C para saber cuánto espacio se necesita para los parámetros (flag `BLOCK_HAS_SIGNATURE`)
- Si se hacen referencia a variables, este bloque también tendrá punteros a un ayudante de copia (copiando el valor al principio) y un ayudante de eliminación (liberándolo).

### Colas

Una cola de despacho es un objeto nombrado que proporciona un orden FIFO de bloques para ejecuciones.

Los bloques se establecen en colas para ser ejecutados, y estas soportan 2 modos: `DISPATCH_QUEUE_SERIAL` y `DISPATCH_QUEUE_CONCURRENT`. Por supuesto, la **serial** no **tendrá problemas de condiciones de carrera** ya que un bloque no se ejecutará hasta que el anterior haya terminado. Pero **el otro tipo de cola podría tenerlo**.

Colas predeterminadas:

- `.main-thread`: Desde `dispatch_get_main_queue()`
- `.libdispatch-manager`: Gestor de colas de GCD
- `.root.libdispatch-manager`: Gestor de colas de GCD
- `.root.maintenance-qos`: Tareas de menor prioridad
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Disponible como `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Disponible como `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Disponible como `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Disponible como `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Mayor prioridad
- `.root.background-qos.overcommit`

Ten en cuenta que será el sistema quien decida **qué hilos manejan qué colas en cada momento** (múltiples hilos pueden trabajar en la misma cola o el mismo hilo puede trabajar en diferentes colas en algún momento)

#### Atributos

Al crear una cola con **`dispatch_queue_create`**, el tercer argumento es un `dispatch_queue_attr_t`, que generalmente es `DISPATCH_QUEUE_SERIAL` (que en realidad es NULL) o `DISPATCH_QUEUE_CONCURRENT`, que es un puntero a una estructura `dispatch_queue_attr_t` que permite controlar algunos parámetros de la cola.

### Objetos de Despacho

Hay varios objetos que libdispatch utiliza y las colas y bloques son solo 2 de ellos. Es posible crear estos objetos con `dispatch_object_create`:

- `block`
- `data`: Bloques de datos
- `group`: Grupo de bloques
- `io`: Solicitudes de I/O asíncronas
- `mach`: Puertos Mach
- `mach_msg`: Mensajes Mach
- `pthread_root_queue`: Una cola con un grupo de hilos pthread y no colas de trabajo
- `queue`
- `semaphore`
- `source`: Fuente de eventos

## Objective-C

En Objective-C hay diferentes funciones para enviar un bloque para ser ejecutado en paralelo:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Envía un bloque para ejecución asíncrona en una cola de despacho y devuelve inmediatamente.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Envía un objeto de bloque para ejecución y devuelve después de que ese bloque termine de ejecutarse.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Ejecuta un objeto de bloque solo una vez durante la vida de una aplicación.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Envía un elemento de trabajo para ejecución y devuelve solo después de que termine de ejecutarse. A diferencia de [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), esta función respeta todos los atributos de la cola cuando ejecuta el bloque.

Estas funciones esperan estos parámetros: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Esta es la **estructura de un Bloque**:
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
Y este es un ejemplo de usar **parallelism** con **`dispatch_async`**:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** es una biblioteca que proporciona **enlaces de Swift** al marco Grand Central Dispatch (GCD) que fue escrito originalmente en C.\
La biblioteca **`libswiftDispatch`** envuelve las API de C GCD en una interfaz más amigable para Swift, facilitando y haciendo más intuitivo para los desarrolladores de Swift trabajar con GCD.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Ejemplo de código**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

El siguiente script de Frida se puede utilizar para **interceptar varias funciones `dispatch`** y extraer el nombre de la cola, la traza de la pila y el bloque: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Actualmente, Ghidra no entiende ni la estructura **`dispatch_block_t`** de ObjectiveC, ni la **`swift_dispatch_block`**.

Así que si quieres que las entienda, podrías **declararlas**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Luego, encuentra un lugar en el código donde se **utilicen**:

> [!TIP]
> Nota todas las referencias hechas a "block" para entender cómo podrías deducir que se está utilizando la estructura.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Haz clic derecho en la variable -> Retype Variable y selecciona en este caso **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra reescribirá automáticamente todo:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
