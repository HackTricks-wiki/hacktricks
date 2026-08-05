# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

**Grand Central Dispatch (GCD),** noto anche come **libdispatch** (`libdispatch.dyld`), è disponibile sia in macOS che in iOS. È una tecnologia sviluppata da Apple per ottimizzare il supporto delle applicazioni all'esecuzione concorrente (multithread) su hardware multicore.

**GCD** fornisce e gestisce **code FIFO** alle quali l'applicazione può **inviare task** sotto forma di **block objects**. I blocchi inviati alle dispatch queue vengono **eseguiti in un pool di thread** completamente gestito dal sistema. GCD crea automaticamente i thread per eseguire i task nelle dispatch queue e pianifica l'esecuzione di tali task sui core disponibili.

> [!TIP]
> In sintesi, per eseguire codice **in parallelo**, i processi possono inviare **blocchi di codice a GCD**, che si occuperà della loro esecuzione. Pertanto, i processi non creano nuovi thread; **GCD esegue il codice fornito utilizzando il proprio pool di thread** (che può aumentare o diminuire secondo necessità).

Questo è molto utile per gestire correttamente l'esecuzione parallela, riducendo notevolmente il numero di thread creati dai processi e ottimizzando l'esecuzione parallela. È ideale per i task che richiedono **un elevato parallelismo** (brute-forcing?) o per i task che non dovrebbero bloccare il thread principale: ad esempio, il thread principale su iOS gestisce le interazioni con la UI, quindi qualsiasi altra funzionalità che potrebbe causare il blocco dell'app (ricerca, accesso al web, lettura di un file...) viene gestita in questo modo.

### Blocchi

Un block è una **sezione di codice autonoma** (come una funzione con argomenti che restituisce un valore) e può anche specificare variabili associate.\
Tuttavia, a livello di compilatore i blocchi non esistono: sono `os_object`s. Ognuno di questi oggetti è costituito da due strutture:

- **block literal**:
- Inizia con il campo **`isa`**, che punta alla classe del blocco:
- `NSConcreteGlobalBlock` (blocchi da `__DATA.__const`)
- `NSConcreteMallocBlock` (blocchi nell'heap)
- `NSConcreateStackBlock` (blocchi nello stack)
- Contiene **`flags`** (che indicano i campi presenti nel block descriptor) e alcuni byte riservati
- Il function pointer da chiamare
- Un puntatore al block descriptor
- Le variabili importate dal blocco (se presenti)
- **block descriptor**: la sua dimensione dipende dai dati presenti (come indicato nei flags precedenti)
- Contiene alcuni byte riservati
- La sua dimensione
- Di solito contiene un puntatore a una signature in stile Objective-C per sapere quanto spazio è necessario per i parametri (flag `BLOCK_HAS_SIGNATURE`)
- Se vengono referenziate variabili, questo blocco conterrà anche puntatori a un copy helper (che copia il valore all'inizio) e a un dispose helper (che lo libera).

### Code

Una dispatch queue è un oggetto denominato che fornisce un ordinamento FIFO dei blocchi da eseguire.

I blocchi vengono inseriti nelle queue per essere eseguiti, e queste supportano 2 modalità: `DISPATCH_QUEUE_SERIAL` e `DISPATCH_QUEUE_CONCURRENT`. Naturalmente, quella **seriale** **non avrà problemi di race condition**, poiché un blocco non verrà eseguito finché quello precedente non sarà terminato. Ma **l'altro tipo di queue potrebbe averne**.

Code predefinite:

- `.main-thread`: Da `dispatch_get_main_queue()`
- `.libdispatch-manager`: Queue manager di GCD
- `.root.libdispatch-manager`: Queue manager di GCD
- `.root.maintenance-qos`: Task con la priorità più bassa
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Disponibile come `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Disponibile come `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Disponibile come `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Disponibile come `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Priorità massima
- `.root.background-qos.overcommit`

Si noti che sarà il sistema a decidere **quali thread gestiscono quali queue in ogni momento** (più thread potrebbero lavorare sulla stessa queue, oppure lo stesso thread potrebbe lavorare su queue diverse in un determinato momento).

#### Attributi

Quando si crea una queue con **`dispatch_queue_create`**, il terzo argomento è un `dispatch_queue_attr_t`, che solitamente è `DISPATCH_QUEUE_SERIAL` (che in realtà è NULL) oppure `DISPATCH_QUEUE_CONCURRENT`, che è un puntatore a una struct `dispatch_queue_attr_t` che consente di controllare alcuni parametri della queue.

### Dispatch objects

Esistono diversi oggetti utilizzati da libdispatch; queue e blocchi sono solo 2 di questi. È possibile creare questi oggetti con `dispatch_object_create`:

- `block`
- `data`: Blocchi di dati
- `group`: Gruppo di blocchi
- `io`: Richieste di I/O asincrone
- `mach`: Porte Mach
- `mach_msg`: Messaggi Mach
- `pthread_root_queue`: Una queue con un pool di thread pthread e senza workqueue
- `queue`
- `semaphore`
- `source`: Sorgente di eventi

## Objective-C

In Objective-C esistono diverse funzioni per inviare un blocco da eseguire in parallelo:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Invia un blocco per l'esecuzione asincrona su una dispatch queue e restituisce immediatamente.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Invia un block object per l'esecuzione e restituisce il controllo dopo che il blocco ha terminato l'esecuzione.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Esegue un block object una sola volta durante la vita di un'applicazione.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Invia un work item per l'esecuzione e restituisce il controllo solo dopo che questo ha terminato l'esecuzione. A differenza di [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), questa funzione rispetta tutti gli attributi della queue quando esegue il blocco.

Queste funzioni richiedono i seguenti parametri: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Questa è la **struct di un Block**:
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
E questo è un esempio di utilizzo del **parallelismo** con **`dispatch_async`**:
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

**`libswiftDispatch`** è una libreria che fornisce **Swift bindings** per il framework Grand Central Dispatch (GCD), originariamente scritto in C.\
La libreria **`libswiftDispatch`** avvolge le API C di GCD in un'interfaccia più adatta a Swift, rendendo più semplice e intuitivo per gli sviluppatori Swift lavorare con GCD.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Esempio di codice**:
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

Il seguente script Frida può essere utilizzato per fare **hook su diverse** funzioni `dispatch` ed estrarre il nome della queue, il backtrace e il block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Attualmente Ghidra non comprende né la struttura ObjectiveC **`dispatch_block_t`**, né quella **`swift_dispatch_block`**.

Quindi, se vuoi che le comprenda, puoi semplicemente **dichiararle**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Poi, trova un punto nel codice in cui vengono **utilizzate**:

> [!TIP]
> Prendi nota di tutti i riferimenti a "block" per capire come determinare che la struct viene utilizzata.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Fai clic con il pulsante destro del mouse sulla variabile -> Retype Variable e seleziona, in questo caso, **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra riscriverà automaticamente tutto:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Riferimenti

- [1] [libdispatch — `src/queue.c` (implementazione di queue/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (API pubblica di queue)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
