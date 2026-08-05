# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**Grand Central Dispatch (GCD),** auch bekannt als **libdispatch** (`libdispatch.dyld`), ist sowohl in macOS als auch in iOS verfügbar. Es handelt sich um eine von Apple entwickelte Technologie zur Optimierung der Anwendungsunterstützung für die gleichzeitige (multithreaded) Ausführung auf Hardware mit mehreren Kernen.

**GCD** stellt **FIFO queues** bereit und verwaltet diese. In ihnen kann deine Anwendung **tasks** in Form von **block objects** einreihen. An dispatch queues übergebene Blocks werden **in einem vom System vollständig verwalteten Thread-Pool ausgeführt**. GCD erstellt automatisch Threads zur Ausführung der tasks in den dispatch queues und plant diese tasks auf den verfügbaren Kernen ein.

> [!TIP]
> Zusammengefasst können Prozesse zur Ausführung von Code **parallel** **code blocks an GCD senden**, das sich um deren Ausführung kümmert. Prozesse erstellen daher keine neuen Threads; **GCD führt den übergebenen Code mit seinem eigenen Thread-Pool aus** (dessen Größe je nach Bedarf erhöht oder verringert werden kann).

Dies ist sehr hilfreich, um die parallele Ausführung zuverlässig zu verwalten. Dabei wird die Anzahl der von Prozessen erstellten Threads erheblich reduziert und die parallele Ausführung optimiert. Dies ist ideal für tasks, die **starke Parallelisierung** erfordern (Brute-Forcing?), oder für tasks, die den Main Thread nicht blockieren sollten: Der Main Thread unter iOS verarbeitet beispielsweise UI-Interaktionen. Daher werden alle anderen Funktionen, die die App zum Hängen bringen könnten (Suchen, Zugriff auf das Web, Lesen einer Datei...), auf diese Weise verwaltet.

### Blocks

Ein Block ist ein **in sich geschlossener Codeabschnitt** (wie eine Funktion mit Argumenten, die einen Wert zurückgibt) und kann außerdem gebundene Variablen angeben.\
Auf Compiler-Ebene existieren Blocks jedoch nicht, sondern sie sind `os_object`s. Jedes dieser Objekte besteht aus zwei Strukturen:

- **block literal**:
- Es beginnt mit dem Feld **`isa`**, das auf die Klasse des Blocks zeigt:
- `NSConcreteGlobalBlock` (Blocks aus `__DATA.__const`)
- `NSConcreteMallocBlock` (Blocks auf dem Heap)
- `NSConcreateStackBlock` (Blocks auf dem Stack)
- Es enthält **`flags`** (die angeben, welche Felder im Block-Deskriptor vorhanden sind) sowie einige reservierte Bytes
- Der Function Pointer, der aufgerufen werden soll
- Einen Pointer auf den Block-Deskriptor
- Vom Block importierte Variablen (falls vorhanden)
- **block descriptor**: Seine Größe hängt von den vorhandenen Daten ab (wie durch die vorherigen Flags angegeben)
- Er enthält einige reservierte Bytes
- Seine Größe
- Normalerweise enthält er einen Pointer auf eine Signatur im Objective-C-Stil, um zu bestimmen, wie viel Speicher für die Parameter benötigt wird (Flag `BLOCK_HAS_SIGNATURE`)
- Wenn Variablen referenziert werden, enthält dieser Block außerdem Pointer auf einen Copy Helper (der den Wert am Anfang kopiert) und einen Dispose Helper (der ihn freigibt).

### Queues

Eine Dispatch Queue ist ein benanntes Objekt, das die FIFO-Reihenfolge der auszuführenden Blocks bereitstellt.

Blocks werden zur Ausführung in Queues eingereiht. Diese unterstützen zwei Modi: `DISPATCH_QUEUE_SERIAL` und `DISPATCH_QUEUE_CONCURRENT`. Die **serielle** Queue hat natürlich **keine Race-Condition**-Probleme, da ein Block erst ausgeführt wird, wenn der vorherige beendet wurde. Der **andere Queue-Typ kann jedoch davon betroffen sein**.

Standard-Queues:

- `.main-thread`: Von `dispatch_get_main_queue()`
- `.libdispatch-manager`: Queue-Manager von GCD
- `.root.libdispatch-manager`: Queue-Manager von GCD
- `.root.maintenance-qos`: Tasks mit der niedrigsten Priorität
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Verfügbar als `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Verfügbar als `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Verfügbar als `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Verfügbar als `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Höchste Priorität
- `.root.background-qos.overcommit`

Beachte, dass das System entscheidet, **welche Threads zu welchem Zeitpunkt welche Queues verarbeiten** (mehrere Threads können in derselben Queue arbeiten, oder derselbe Thread kann zu einem bestimmten Zeitpunkt in verschiedenen Queues arbeiten).

#### Attribute

Beim Erstellen einer Queue mit **`dispatch_queue_create`** ist das dritte Argument ein `dispatch_queue_attr_t`, das normalerweise entweder `DISPATCH_QUEUE_SERIAL` (tatsächlich NULL) oder `DISPATCH_QUEUE_CONCURRENT` ist. Letzteres ist ein Pointer auf eine `dispatch_queue_attr_t`-Struktur, mit der sich einige Parameter der Queue steuern lassen.

### Dispatch objects

libdispatch verwendet mehrere Objekte; Queues und Blocks sind nur zwei davon. Diese Objekte können mit `dispatch_object_create` erstellt werden:

- `block`
- `data`: Data Blocks
- `group`: Gruppe von Blocks
- `io`: Asynchrone I/O-Anforderungen
- `mach`: Mach Ports
- `mach_msg`: Mach Messages
- `pthread_root_queue`: Eine Queue mit einem pthread Thread-Pool und ohne Workqueues
- `queue`
- `semaphore`
- `source`: Event Source

## Objective-C

In Objective-C gibt es verschiedene Funktionen, um einen Block zur parallelen Ausführung zu senden:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Übermittelt einen Block zur asynchronen Ausführung an eine Dispatch Queue und kehrt sofort zurück.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Übermittelt ein Block-Objekt zur Ausführung und kehrt zurück, nachdem die Ausführung dieses Blocks beendet ist.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Führt ein Block-Objekt während der gesamten Lebensdauer einer Anwendung nur einmal aus.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Übermittelt ein Work Item zur Ausführung und kehrt erst zurück, nachdem dessen Ausführung beendet ist. Anders als [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) berücksichtigt diese Funktion bei der Ausführung des Blocks alle Attribute der Queue.

Diese Funktionen erwarten folgende Parameter: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Dies ist die **struct eines Blocks**:
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
Und dies ist ein Beispiel für **Parallelität** mit **`dispatch_async`**:
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

**`libswiftDispatch`** ist eine Bibliothek, die **Swift-Bindings** für das ursprünglich in C geschriebene Grand Central Dispatch (GCD)-Framework bereitstellt.\
Die **`libswiftDispatch`**-Bibliothek kapselt die C-GCD-APIs in einer stärker an Swift orientierten Schnittstelle und erleichtert Swift-Entwicklern dadurch die Arbeit mit GCD und macht sie intuitiver.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Codebeispiel**:
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

Das folgende Frida-Script kann verwendet werden, um sich in mehrere **dispatch**-Funktionen einzuhaken und den Queue-Namen, den Backtrace sowie den Block zu extrahieren: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
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

Derzeit versteht Ghidra weder die ObjectiveC-**`dispatch_block_t`**-Struktur noch die **`swift_dispatch_block`**-Struktur.

Wenn Ghidra sie verstehen soll, könntest du sie einfach **deklarieren**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Suche anschließend eine Stelle im Code, an der sie **verwendet** werden:

> [!TIP]
> Beachte alle Referenzen auf „block“, um zu verstehen, wie du feststellen kannst, dass die Struktur verwendet wird.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Klicke mit der rechten Maustaste auf die Variable -> Retype Variable und wähle in diesem Fall **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra schreibt automatisch alles neu:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Referenzen

- [1] [libdispatch — `src/queue.c` (Implementierung von Queue und Thread-Pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (dispatch sources)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (öffentliche Queue-API)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
