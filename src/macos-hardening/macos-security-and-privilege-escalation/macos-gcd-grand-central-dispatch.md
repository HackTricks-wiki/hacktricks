# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Grundinformationen

**Grand Central Dispatch (GCD),** auch bekannt als **libdispatch** (`libdispatch.dyld`), ist sowohl in macOS als auch in iOS verfügbar. Es ist eine von Apple entwickelte Technologie zur Optimierung der Anwendungsunterstützung für parallele (multithreaded) Ausführung auf Multicore-Hardware.

**GCD** stellt **FIFO-Warteschlangen** bereit und verwaltet diese, in die Ihre Anwendung **Aufgaben** in Form von **Blockobjekten** einreichen kann. Blöcke, die an Dispatch-Warteschlangen übergeben werden, werden **auf einem Pool von Threads** ausgeführt, der vollständig vom System verwaltet wird. GCD erstellt automatisch Threads zur Ausführung der Aufgaben in den Dispatch-Warteschlangen und plant diese Aufgaben zur Ausführung auf den verfügbaren Kernen.

> [!TIP]
> Zusammenfassend lässt sich sagen, dass Prozesse **Code parallel ausführen** können, indem sie **Codeblöcke an GCD senden**, das sich um deren Ausführung kümmert. Daher erstellen Prozesse keine neuen Threads; **GCD führt den gegebenen Code mit seinem eigenen Pool von Threads aus** (der je nach Bedarf erhöht oder verringert werden kann).

Dies ist sehr hilfreich, um die parallele Ausführung erfolgreich zu verwalten, da die Anzahl der Threads, die Prozesse erstellen, erheblich reduziert und die parallele Ausführung optimiert wird. Dies ist ideal für Aufgaben, die **große Parallelität** erfordern (Brute-Forcing?) oder für Aufgaben, die den Hauptthread nicht blockieren sollten: Zum Beispiel verarbeitet der Hauptthread in iOS UI-Interaktionen, sodass jede andere Funktionalität, die die App zum Hängen bringen könnte (Suchen, Zugriff auf das Web, Lesen einer Datei...), auf diese Weise verwaltet wird.

### Blöcke

Ein Block ist ein **selbstständiger Abschnitt von Code** (wie eine Funktion mit Argumenten, die einen Wert zurückgibt) und kann auch gebundene Variablen angeben.\
Auf Compiler-Ebene existieren Blöcke jedoch nicht, sie sind `os_object`s. Jedes dieser Objekte besteht aus zwei Strukturen:

- **Blockliteral**:&#x20;
- Es beginnt mit dem **`isa`**-Feld, das auf die Klasse des Blocks zeigt:
- `NSConcreteGlobalBlock` (Blöcke aus `__DATA.__const`)
- `NSConcreteMallocBlock` (Blöcke im Heap)
- `NSConcreateStackBlock` (Blöcke im Stack)
- Es hat **`flags`** (die Felder im Block-Descriptor anzeigen) und einige reservierte Bytes
- Der Funktionszeiger zum Aufruf
- Ein Zeiger auf den Block-Descriptor
- Importierte Blockvariablen (falls vorhanden)
- **Block-Descriptor**: Die Größe hängt von den vorhandenen Daten ab (wie in den vorherigen Flags angegeben)
- Es hat einige reservierte Bytes
- Die Größe davon
- Es wird normalerweise einen Zeiger auf eine Objective-C-Stil-Signatur haben, um zu wissen, wie viel Platz für die Parameter benötigt wird (Flag `BLOCK_HAS_SIGNATURE`)
- Wenn Variablen referenziert werden, hat dieser Block auch Zeiger auf einen Kopierhelfer (der den Wert zu Beginn kopiert) und einen Entsorgungshelfer (der ihn freigibt).

### Warteschlangen

Eine Dispatch-Warteschlange ist ein benanntes Objekt, das FIFO-Reihenfolge von Blöcken für die Ausführung bereitstellt.

Blöcke werden in Warteschlangen gesetzt, um ausgeführt zu werden, und diese unterstützen 2 Modi: `DISPATCH_QUEUE_SERIAL` und `DISPATCH_QUEUE_CONCURRENT`. Natürlich hat die **serielle** Warteschlange **keine Probleme mit Race Conditions**, da ein Block nicht ausgeführt wird, bis der vorherige abgeschlossen ist. Aber **die andere Art von Warteschlange könnte dies haben**.

Standardwarteschlangen:

- `.main-thread`: Von `dispatch_get_main_queue()`
- `.libdispatch-manager`: GCDs Warteschlangenmanager
- `.root.libdispatch-manager`: GCDs Warteschlangenmanager
- `.root.maintenance-qos`: Aufgaben mit der niedrigsten Priorität
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

Beachten Sie, dass das System entscheiden wird, **welche Threads zu welchem Zeitpunkt welche Warteschlangen bearbeiten** (mehrere Threads können in derselben Warteschlange arbeiten oder derselbe Thread kann zu einem bestimmten Zeitpunkt in verschiedenen Warteschlangen arbeiten).

#### Attribute

Beim Erstellen einer Warteschlange mit **`dispatch_queue_create`** ist das dritte Argument ein `dispatch_queue_attr_t`, das normalerweise entweder `DISPATCH_QUEUE_SERIAL` (was tatsächlich NULL ist) oder `DISPATCH_QUEUE_CONCURRENT` ist, was ein Zeiger auf eine `dispatch_queue_attr_t`-Struktur ist, die es ermöglicht, einige Parameter der Warteschlange zu steuern.

### Dispatch-Objekte

Es gibt mehrere Objekte, die libdispatch verwendet, und Warteschlangen und Blöcke sind nur 2 davon. Es ist möglich, diese Objekte mit `dispatch_object_create` zu erstellen:

- `block`
- `data`: Datenblöcke
- `group`: Gruppe von Blöcken
- `io`: Asynchrone I/O-Anfragen
- `mach`: Mach-Ports
- `mach_msg`: Mach-Nachrichten
- `pthread_root_queue`: Eine Warteschlange mit einem pthread-Thread-Pool und nicht Arbeitswarteschlangen
- `queue`
- `semaphore`
- `source`: Ereignisquelle

## Objective-C

In Objective-C gibt es verschiedene Funktionen, um einen Block zur parallelen Ausführung zu senden:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Reicht einen Block zur asynchronen Ausführung in einer Dispatch-Warteschlange ein und gibt sofort zurück.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Reicht ein Blockobjekt zur Ausführung ein und gibt zurück, nachdem dieser Block die Ausführung abgeschlossen hat.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Führt ein Blockobjekt nur einmal während der Lebensdauer einer Anwendung aus.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Reicht ein Arbeitsobjekt zur Ausführung ein und gibt nur zurück, nachdem es die Ausführung abgeschlossen hat. Im Gegensatz zu [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) respektiert diese Funktion alle Attribute der Warteschlange, wenn sie den Block ausführt.

Diese Funktionen erwarten diese Parameter: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Dies ist die **Struktur eines Blocks**:
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
Und dies ist ein Beispiel, um **Parallelismus** mit **`dispatch_async`** zu verwenden:
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

**`libswiftDispatch`** ist eine Bibliothek, die **Swift-Bindings** für das Grand Central Dispatch (GCD) Framework bereitstellt, das ursprünglich in C geschrieben wurde.\
Die **`libswiftDispatch`** Bibliothek umschließt die C GCD APIs in einer benutzerfreundlicheren Swift-Schnittstelle, was es für Swift-Entwickler einfacher und intuitiver macht, mit GCD zu arbeiten.

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

Das folgende Frida-Skript kann verwendet werden, um **in mehrere `dispatch`** Funktionen einzuhaken und den Warteschafennamen, den Backtrace und den Block zu extrahieren: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Derzeit versteht Ghidra weder die ObjectiveC **`dispatch_block_t`** Struktur noch die **`swift_dispatch_block`**.

Wenn Sie möchten, dass es sie versteht, könnten Sie sie einfach **deklarieren**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Suchen Sie dann einen Ort im Code, an dem sie **verwendet** werden:

> [!TIP]
> Beachten Sie alle Verweise auf "block", um zu verstehen, wie Sie herausfinden können, dass die Struktur verwendet wird.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Rechtsklick auf die Variable -> Variable umbenennen und in diesem Fall **`swift_dispatch_block`** auswählen:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra wird automatisch alles umschreiben:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
