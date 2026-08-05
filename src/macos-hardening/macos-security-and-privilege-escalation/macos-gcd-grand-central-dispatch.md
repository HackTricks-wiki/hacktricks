# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Información básica

**Grand Central Dispatch (GCD),** también conocido como **libdispatch** (`libdispatch.dyld`), está disponible tanto en macOS como en iOS. Es una tecnología desarrollada por Apple para optimizar la compatibilidad de las aplicaciones con la ejecución concurrente (multithreaded) en hardware multinúcleo.

**GCD** proporciona y gestiona **colas FIFO** a las que tu aplicación puede **enviar tareas** en forma de **objetos block**. Los bloques enviados a las colas de dispatch se **ejecutan en un pool de threads** completamente gestionado por el sistema. GCD crea automáticamente threads para ejecutar las tareas de las colas de dispatch y programa dichas tareas para que se ejecuten en los núcleos disponibles.

> [!TIP]
> En resumen, para ejecutar código **en paralelo**, los procesos pueden enviar **bloques de código a GCD**, que se encargará de su ejecución. Por tanto, los procesos no crean nuevos threads; **GCD ejecuta el código proporcionado con su propio pool de threads** (que puede aumentar o disminuir según sea necesario).

Esto resulta muy útil para gestionar correctamente la ejecución en paralelo, reduciendo considerablemente el número de threads que crean los procesos y optimizando la ejecución paralela. Es ideal para tareas que requieren **un gran paralelismo** (¿brute-forcing?) o para tareas que no deberían bloquear el thread principal: Por ejemplo, el thread principal en iOS gestiona las interacciones de la interfaz de usuario, por lo que cualquier otra funcionalidad que pueda hacer que la aplicación se bloquee (buscar, acceder a la web, leer un archivo...) se gestiona de esta forma.

### Bloques

Un bloque es una **sección de código autocontenida** (como una función con argumentos que devuelve un valor) y también puede especificar variables vinculadas.\
Sin embargo, a nivel del compilador los bloques no existen, sino que son `os_object`s. Cada uno de estos objetos está formado por dos estructuras:

- **block literal**:
- Comienza con el campo **`isa`**, que apunta a la clase del bloque:
- `NSConcreteGlobalBlock` (bloques de `__DATA.__const`)
- `NSConcreteMallocBlock` (bloques en el heap)
- `NSConcreateStackBlock` (bloques en el stack)
- Tiene **`flags`** (que indican los campos presentes en el descriptor del bloque) y algunos bytes reservados
- El puntero a la función que se debe llamar
- Un puntero al descriptor del bloque
- Variables importadas por el bloque (si las hay)
- **block descriptor**: Su tamaño depende de los datos presentes (como indican los flags anteriores)
- Tiene algunos bytes reservados
- Su tamaño
- Normalmente tendrá un puntero a una signature de estilo Objective-C para saber cuánto espacio se necesita para los parámetros (flag `BLOCK_HAS_SIGNATURE`)
- Si se hace referencia a variables, este bloque también tendrá punteros a un helper de copia (que copia el valor al principio) y a un helper de eliminación (que lo libera).

### Colas

Una cola de dispatch es un objeto con nombre que proporciona un ordenamiento FIFO de bloques para su ejecución.

Los bloques se configuran en colas para ser ejecutados, y estas admiten 2 modos: `DISPATCH_QUEUE_SERIAL` y `DISPATCH_QUEUE_CONCURRENT`. Por supuesto, la cola **serial** **no tendrá problemas de race condition**, ya que un bloque no se ejecutará hasta que el anterior haya terminado. Pero **el otro tipo de cola podría tenerlos**.

Colas predeterminadas:

- `.main-thread`: De `dispatch_get_main_queue()`
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
- `.root.user-interactive-qos`: Prioridad más alta
- `.root.background-qos.overcommit`

Ten en cuenta que será el sistema quien decida **qué threads gestionan qué colas en cada momento** (varios threads pueden trabajar en la misma cola o el mismo thread puede trabajar en diferentes colas en algún momento).

#### Atributos

Al crear una cola con **`dispatch_queue_create`**, el tercer argumento es un `dispatch_queue_attr_t`, que normalmente es `DISPATCH_QUEUE_SERIAL` (que en realidad es NULL) o `DISPATCH_QUEUE_CONCURRENT`, que es un puntero a una estructura `dispatch_queue_attr_t` que permite controlar algunos parámetros de la cola.

### Objetos de dispatch

Hay varios objetos que libdispatch utiliza, y las colas y los bloques son solo 2 de ellos. Es posible crear estos objetos con `dispatch_object_create`:

- `block`
- `data`: Bloques de datos
- `group`: Grupo de bloques
- `io`: Solicitudes de I/O asíncronas
- `mach`: Puertos Mach
- `mach_msg`: Mensajes Mach
- `pthread_root_queue`:Una cola con un pool de threads pthread y sin workqueues
- `queue`
- `semaphore`
- `source`: Fuente de eventos

## Objective-C

En Objetive-C hay diferentes funciones para enviar un bloque para que se ejecute en paralelo:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Envía un bloque para su ejecución asíncrona en una cola de dispatch y retorna inmediatamente.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Envía un objeto block para su ejecución y retorna después de que dicho bloque termina de ejecutarse.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Ejecuta un objeto block una sola vez durante la vida de una aplicación.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Envía un work item para su ejecución y retorna únicamente después de que este termina de ejecutarse. A diferencia de [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), esta función respeta todos los atributos de la cola al ejecutar el bloque.

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
Y este es un ejemplo para usar **paralelismo** con **`dispatch_async`**:
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

**`libswiftDispatch`** es una biblioteca que proporciona **bindings de Swift** para el framework Grand Central Dispatch (GCD), escrito originalmente en C.\
La biblioteca **`libswiftDispatch`** envuelve las API de GCD de C en una interfaz más compatible con Swift, lo que facilita y hace más intuitivo que los desarrolladores de Swift trabajen con GCD.

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

El siguiente script de Frida puede utilizarse para **hookear varias funciones `dispatch`** y extraer el nombre de la queue, el backtrace y el block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Actualmente, Ghidra no entiende ni la estructura de ObjectiveC **`dispatch_block_t`** ni la de **`swift_dispatch_block`**.

Así que, si quieres que las entienda, simplemente puedes **declararlas**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Después, busca un lugar en el código donde se **utilicen**:

> [!TIP]
> Observa todas las referencias hechas a "block" para entender cómo podrías deducir que se está utilizando la estructura.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Haz clic derecho en la variable -> Retype Variable y selecciona, en este caso, **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra lo reescribirá todo automáticamente:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Referencias

- [1] [libdispatch — `src/queue.c` (implementación de queue/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (API pública de queue)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
