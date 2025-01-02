# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Zunächst wird die **`task_threads()`**-Funktion auf dem Task-Port aufgerufen, um eine Thread-Liste vom Remote-Task zu erhalten. Ein Thread wird zum Hijacking ausgewählt. Dieser Ansatz weicht von herkömmlichen Code-Injektionsmethoden ab, da das Erstellen eines neuen Remote-Threads aufgrund der neuen Minderung, die `thread_create_running()` blockiert, verboten ist.

Um den Thread zu steuern, wird **`thread_suspend()`** aufgerufen, um seine Ausführung zu stoppen.

Die einzigen Operationen, die auf dem Remote-Thread erlaubt sind, beinhalten **Stoppen** und **Starten**, **Abrufen** und **Ändern** seiner Registerwerte. Remote-Funktionsaufrufe werden initiiert, indem die Register `x0` bis `x7` auf die **Argumente** gesetzt, **`pc`** auf die gewünschte Funktion konfiguriert und der Thread aktiviert wird. Um sicherzustellen, dass der Thread nach der Rückkehr nicht abstürzt, ist es notwendig, die Rückkehr zu erkennen.

Eine Strategie besteht darin, einen **Ausnahmebehandler** für den Remote-Thread mit `thread_set_exception_ports()` zu registrieren, wobei das `lr`-Register vor dem Funktionsaufruf auf eine ungültige Adresse gesetzt wird. Dies löst eine Ausnahme nach der Funktionsausführung aus, die eine Nachricht an den Ausnahmeport sendet und eine Zustandsinspektion des Threads ermöglicht, um den Rückgabewert wiederherzustellen. Alternativ, wie im Triple-Fetch-Exploit von Ian Beer übernommen, wird `lr` so gesetzt, dass es unendlich schleift. Die Register des Threads werden dann kontinuierlich überwacht, bis **`pc` auf diese Anweisung zeigt**.

## 2. Mach ports for communication

Die nächste Phase besteht darin, Mach-Ports einzurichten, um die Kommunikation mit dem Remote-Thread zu erleichtern. Diese Ports sind entscheidend für den Transfer beliebiger Sende- und Empfangsrechte zwischen Tasks.

Für die bidirektionale Kommunikation werden zwei Mach-Empfangsrechte erstellt: eines im lokalen und das andere im Remote-Task. Anschließend wird ein Senderecht für jeden Port an den entsprechenden Task übertragen, um den Nachrichtenaustausch zu ermöglichen.

Fokussiert auf den lokalen Port, wird das Empfangsrecht vom lokalen Task gehalten. Der Port wird mit `mach_port_allocate()` erstellt. Die Herausforderung besteht darin, ein Senderecht für diesen Port in den Remote-Task zu übertragen.

Eine Strategie besteht darin, `thread_set_special_port()` zu nutzen, um ein Senderecht für den lokalen Port im `THREAD_KERNEL_PORT` des Remote-Threads zu platzieren. Dann wird der Remote-Thread angewiesen, `mach_thread_self()` aufzurufen, um das Senderecht abzurufen.

Für den Remote-Port wird der Prozess im Wesentlichen umgekehrt. Der Remote-Thread wird angewiesen, einen Mach-Port über `mach_reply_port()` zu generieren (da `mach_port_allocate()` aufgrund seines Rückgabemechanismus ungeeignet ist). Nach der Port-Erstellung wird `mach_port_insert_right()` im Remote-Thread aufgerufen, um ein Senderecht einzurichten. Dieses Recht wird dann im Kernel mit `thread_set_special_port()` gespeichert. Im lokalen Task wird `thread_get_special_port()` auf dem Remote-Thread verwendet, um ein Senderecht für den neu zugewiesenen Mach-Port im Remote-Task zu erwerben.

Der Abschluss dieser Schritte führt zur Einrichtung von Mach-Ports, die die Grundlage für die bidirektionale Kommunikation legen.

## 3. Basic Memory Read/Write Primitives

In diesem Abschnitt liegt der Fokus auf der Nutzung des Execute-Primitivs, um grundlegende Speicher-Lese- und Schreibprimitive zu etablieren. Diese ersten Schritte sind entscheidend, um mehr Kontrolle über den Remote-Prozess zu erlangen, obwohl die Primitiven in diesem Stadium nicht viele Zwecke erfüllen werden. Bald werden sie auf fortgeschrittenere Versionen aktualisiert.

### Memory Reading and Writing Using Execute Primitive

Das Ziel ist es, Speicher zu lesen und zu schreiben, indem spezifische Funktionen verwendet werden. Zum Lesen von Speicher werden Funktionen verwendet, die einer folgenden Struktur ähneln:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Und zum Schreiben in den Speicher werden Funktionen verwendet, die einer ähnlichen Struktur folgen:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Diese Funktionen entsprechen den angegebenen Assemblierungsanweisungen:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifying Suitable Functions

Ein Scan gängiger Bibliotheken hat geeignete Kandidaten für diese Operationen ergeben:

1. **Reading Memory:**
Die Funktion `property_getName()` aus der [Objective-C-Laufzeitbibliothek](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) wird als geeignete Funktion zum Lesen von Speicher identifiziert. Die Funktion wird unten beschrieben:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Diese Funktion wirkt effektiv wie die `read_func`, indem sie das erste Feld von `objc_property_t` zurückgibt.

2. **Speicher schreiben:**
Eine vorgefertigte Funktion zum Schreiben von Speicher zu finden, ist herausfordernder. Die Funktion `_xpc_int64_set_value()` aus libxpc ist jedoch ein geeigneter Kandidat mit der folgenden Disassemblierung:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Um einen 64-Bit-Schreibvorgang an einer bestimmten Adresse durchzuführen, wird der Remote-Call wie folgt strukturiert:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Mit diesen Primitiven etabliert, ist die Bühne für die Erstellung von gemeinsamem Speicher bereitet, was einen bedeutenden Fortschritt in der Kontrolle des Remote-Prozesses darstellt.

## 4. Einrichtung des gemeinsamen Speichers

Das Ziel ist es, gemeinsamen Speicher zwischen lokalen und Remote-Aufgaben einzurichten, um den Datentransfer zu vereinfachen und das Aufrufen von Funktionen mit mehreren Argumenten zu erleichtern. Der Ansatz besteht darin, `libxpc` und seinen `OS_xpc_shmem` Objekttyp zu nutzen, der auf Mach-Speichereinträgen basiert.

### Prozessübersicht:

1. **Speicherzuweisung**:

- Weisen Sie den Speicher für die gemeinsame Nutzung mit `mach_vm_allocate()` zu.
- Verwenden Sie `xpc_shmem_create()`, um ein `OS_xpc_shmem` Objekt für den zugewiesenen Speicherbereich zu erstellen. Diese Funktion verwaltet die Erstellung des Mach-Speichereintrags und speichert das Mach-Sende-Recht an Offset `0x18` des `OS_xpc_shmem` Objekts.

2. **Erstellung des gemeinsamen Speichers im Remote-Prozess**:

- Weisen Sie Speicher für das `OS_xpc_shmem` Objekt im Remote-Prozess mit einem Remote-Aufruf von `malloc()` zu.
- Kopieren Sie den Inhalt des lokalen `OS_xpc_shmem` Objekts in den Remote-Prozess. Diese erste Kopie wird jedoch falsche Mach-Speichereintragsnamen an Offset `0x18` haben.

3. **Korrektur des Mach-Speichereintrags**:

- Nutzen Sie die Methode `thread_set_special_port()`, um ein Sende-Recht für den Mach-Speichereintrag in die Remote-Aufgabe einzufügen.
- Korrigieren Sie das Mach-Speichereintrag-Feld an Offset `0x18`, indem Sie es mit dem Namen des Remote-Speichereintrags überschreiben.

4. **Abschluss der Einrichtung des gemeinsamen Speichers**:
- Validieren Sie das Remote `OS_xpc_shmem` Objekt.
- Stellen Sie die gemeinsame Speicherzuordnung mit einem Remote-Aufruf von `xpc_shmem_remote()` her.

Durch das Befolgen dieser Schritte wird der gemeinsame Speicher zwischen den lokalen und Remote-Aufgaben effizient eingerichtet, was einen unkomplizierten Datentransfer und die Ausführung von Funktionen ermöglicht, die mehrere Argumente erfordern.

## Zusätzliche Code-Snippets

Für die Speicherzuweisung und die Erstellung des gemeinsamen Speicherobjekts:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Um das gemeinsam genutzte Speicherobjekt im Remote-Prozess zu erstellen und zu korrigieren:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Denken Sie daran, die Details von Mach-Ports und Speicher-Eintragsnamen korrekt zu behandeln, um sicherzustellen, dass die gemeinsame Speicher-Einrichtung ordnungsgemäß funktioniert.

## 5. Vollständige Kontrolle erreichen

Nach dem erfolgreichen Einrichten des gemeinsamen Speichers und dem Erlangen von beliebigen Ausführungsfähigkeiten haben wir im Wesentlichen die vollständige Kontrolle über den Zielprozess erlangt. Die Schlüssel-Funktionalitäten, die diese Kontrolle ermöglichen, sind:

1. **Beliebige Speicheroperationen**:

- Führen Sie beliebige Speicherlesevorgänge durch, indem Sie `memcpy()` aufrufen, um Daten aus dem gemeinsamen Bereich zu kopieren.
- Führen Sie beliebige Schreibvorgänge im Speicher durch, indem Sie `memcpy()` verwenden, um Daten in den gemeinsamen Bereich zu übertragen.

2. **Behandlung von Funktionsaufrufen mit mehreren Argumenten**:

- Für Funktionen, die mehr als 8 Argumente erfordern, ordnen Sie die zusätzlichen Argumente auf dem Stack gemäß der Aufrufkonvention an.

3. **Mach-Port-Übertragung**:

- Übertragen Sie Mach-Ports zwischen Aufgaben über Mach-Nachrichten über zuvor eingerichtete Ports.

4. **Dateideskriptor-Übertragung**:
- Übertragen Sie Dateideskriptoren zwischen Prozessen unter Verwendung von Fileports, einer Technik, die von Ian Beer in `triple_fetch` hervorgehoben wird.

Diese umfassende Kontrolle ist in der [threadexec](https://github.com/bazad/threadexec) Bibliothek zusammengefasst, die eine detaillierte Implementierung und eine benutzerfreundliche API für die Interaktion mit dem Opferprozess bietet.

## Wichtige Überlegungen:

- Stellen Sie sicher, dass `memcpy()` für Speicher-Lese-/Schreiboperationen ordnungsgemäß verwendet wird, um die Systemstabilität und Datenintegrität zu gewährleisten.
- Befolgen Sie beim Übertragen von Mach-Ports oder Dateideskriptoren die richtigen Protokolle und gehen Sie verantwortungsbewusst mit Ressourcen um, um Lecks oder unbeabsichtigten Zugriff zu verhindern.

Durch die Einhaltung dieser Richtlinien und die Nutzung der `threadexec` Bibliothek kann man Prozesse effizient verwalten und auf granularer Ebene interagieren, um die vollständige Kontrolle über den Zielprozess zu erreichen.

## Referenzen

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{{#include ../../../../banners/hacktricks-training.md}}
