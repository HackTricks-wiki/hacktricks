# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Información básica

**Grand Central Dispatch (GCD),** también conocido como **libdispatch** (`libdispatch.dyld`), está disponible tanto en macOS como en iOS. Es una tecnología desarrollada por Apple para optimizar la compatibilidad de las aplicaciones con la ejecución concurrente (multithreaded) en hardware multinúcleo.<sup>[[4]](#references)</sup>

**GCD** proporciona y gestiona **colas FIFO** a las que tu aplicación puede **enviar tareas** en forma de **block objects**. Los bloques enviados a las dispatch queues se **ejecutan en un grupo de threads** totalmente gestionado por el sistema. GCD crea automáticamente threads para ejecutar las tareas de las dispatch queues y planifica dichas tareas para que se ejecuten en los cores disponibles.<sup>[[1]](#references)</sup>

> [!TIP]
> En resumen, para ejecutar código **en paralelo**, los procesos pueden enviar **bloques de código a GCD**, que se encargará de su ejecución. Por tanto, los procesos no crean nuevos threads; **GCD ejecuta el código proporcionado con su propio grupo de threads** (que puede aumentar o disminuir según sea necesario).

Esto resulta muy útil para gestionar correctamente la ejecución en paralelo, reduciendo considerablemente el número de threads que crean los procesos y optimizando la ejecución paralela. Es ideal para tareas que requieren **un gran paralelismo** (¿brute-forcing?) o para tareas que no deberían bloquear el thread principal: por ejemplo, el thread principal en iOS gestiona las interacciones de la UI, por lo que cualquier otra funcionalidad que pudiera hacer que la aplicación se bloquee (buscar, acceder a la web, leer un archivo...) se gestiona de esta forma.

### Blocks

Un block es una **sección de código autocontenida** (como una función con argumentos que devuelve un valor) y también puede especificar variables enlazadas.\
Sin embargo, a nivel del compilador los blocks no existen, sino que son `os_object`s. Cada uno de estos objetos está formado por dos estructuras:

- **block literal**:
- Comienza con el campo **`isa`**, que apunta a la clase del block:
- `NSConcreteGlobalBlock` (blocks de `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks en el heap)
- `NSConcreateStackBlock` (blocks en el stack)
- Tiene **`flags`** (que indican los campos presentes en el block descriptor) y algunos bytes reservados
- El puntero a la función que se debe llamar
- Un puntero al block descriptor
- Variables importadas por el block (si las hay)
- **block descriptor**: Su tamaño depende de los datos presentes (como indican los flags anteriores)
- Tiene algunos bytes reservados
- Su tamaño
- Normalmente tendrá un puntero a una signature de estilo Objective-C para saber cuánto espacio se necesita para los parámetros (flag `BLOCK_HAS_SIGNATURE`)
- Si se hace referencia a variables, este block también tendrá punteros a un copy helper (que copia el valor al principio) y a un dispose helper (que lo libera).

### Queues

Una dispatch queue es un objeto con nombre que proporciona un orden FIFO para la ejecución de blocks.<sup>[[3]](#references)</sup>

Los blocks se establecen en queues para ser ejecutados, y estas admiten 2 modos: `DISPATCH_QUEUE_SERIAL` y `DISPATCH_QUEUE_CONCURRENT`. Por supuesto, la **serial** **no tendrá** problemas de race condition, ya que un block no se ejecutará hasta que el anterior haya terminado. Pero **el otro tipo de queue podría tenerlos**.

Queues predeterminadas:

- `.main-thread`: De `dispatch_get_main_queue()`
- `.libdispatch-manager`: Gestor de queues de GCD
- `.root.libdispatch-manager`: Gestor de queues de GCD
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
- `.root.user-interactive-qos`: Prioridad más alta
- `.root.background-qos.overcommit`

Ten en cuenta que será el sistema quien decida **qué threads gestionan qué queues en cada momento** (varios threads pueden trabajar en la misma queue o el mismo thread puede trabajar en distintas queues en algún momento).

#### Atributos

Al crear una queue con **`dispatch_queue_create`**, el tercer argumento es un `dispatch_queue_attr_t`, que normalmente es `DISPATCH_QUEUE_SERIAL` (que en realidad es NULL) o `DISPATCH_QUEUE_CONCURRENT`, que es un puntero a una estructura `dispatch_queue_attr_t` que permite controlar algunos parámetros de la queue.

### Dispatch objects

Hay varios objetos que libdispatch utiliza, y las queues y los blocks son solo 2 de ellos. Es posible crear estos objetos con `dispatch_object_create`:<sup>[[1]](#references)[[2]](#references)</sup>

- `block`
- `data`: Data blocks
- `group`: Grupo de blocks
- `io`: Solicitudes de I/O asíncronas
- `mach`: Mach ports
- `mach_msg`: Mach messages
- `pthread_root_queue`:Una queue con un grupo de threads pthread y no workqueues
- `queue`
- `semaphore`
- `source`: Fuente de eventos

## Objective-C

En Objective-C hay distintas funciones para enviar un block que se ejecutará en paralelo:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Envía un block para su ejecución asíncrona en una dispatch queue y devuelve el control inmediatamente.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Envía un block object para su ejecución y devuelve el control después de que dicho block termine de ejecutarse.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Ejecuta un block object una sola vez durante el ciclo de vida de una aplicación.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Envía un work item para su ejecución y devuelve el control únicamente después de que termine de ejecutarse. A diferencia de [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), esta función respeta todos los atributos de la queue al ejecutar el block.

Estas funciones esperan estos parámetros: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Este es el **struct de un Block**:
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
Y este es un ejemplo de uso de **parallelism** con **`dispatch_async`**:
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

**`libswiftDispatch`** es una library que proporciona **Swift bindings** para el framework Grand Central Dispatch (GCD), escrito originalmente en C.\
La library **`libswiftDispatch`** encapsula las APIs de GCD de C en una interfaz más compatible con Swift, lo que facilita y hace más intuitivo para los desarrolladores de Swift trabajar con GCD.

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

El siguiente script de Frida puede utilizarse para **interceptar varias funciones de `dispatch`** y extraer el nombre de la cola, el backtrace y el bloque: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Actualmente Ghidra no entiende ni la estructura de ObjectiveC **`dispatch_block_t`**, ni la de **`swift_dispatch_block`**.

Por lo tanto, si quieres que las entienda, simplemente podrías **declararlas**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Después, busca un lugar en el código donde se **utilicen**:

> [!TIP]
> Observa todas las referencias a "block" para entender cómo podrías determinar que se está utilizando la estructura.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Haz clic derecho en la variable -> Retype Variable y selecciona, en este caso, **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra reescribirá todo automáticamente:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencias

- [1] [libdispatch — `src/queue.c` (implementación de queue/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (API pública de queue)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
