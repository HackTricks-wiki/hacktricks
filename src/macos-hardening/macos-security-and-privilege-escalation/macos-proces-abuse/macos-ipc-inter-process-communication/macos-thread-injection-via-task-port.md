# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Zunächst wird die Funktion `task_threads()` auf dem task port aufgerufen, um eine thread-Liste vom remote task abzurufen. Ein thread wird für das Hijacking ausgewählt. Dieser Ansatz weicht von herkömmlichen Code-injection-Methoden ab, da das Erstellen eines neuen remote thread aufgrund der Mitigation, die `thread_create_running()` blockiert, nicht zulässig ist.<sup>[[1]](#references)</sup>

Um den thread zu kontrollieren, wird `thread_suspend()` aufgerufen, wodurch seine Ausführung angehalten wird.<sup>[[1]](#references)</sup>

Die einzigen zulässigen Operationen auf dem remote thread bestehen darin, ihn zu **stoppen** und zu **starten** sowie seine Registerwerte abzurufen und zu **ändern**. Remote function calls werden initiiert, indem die Register `x0` bis `x7` auf die **Argumente** gesetzt, `pc` auf die gewünschte Funktion konfiguriert und der thread fortgesetzt wird. Damit der thread nach der Rückkehr nicht abstürzt, muss die Rückkehr erkannt werden.<sup>[[1]](#references)</sup>

Eine Strategie besteht darin, mithilfe von `thread_set_exception_ports()` einen **exception handler** für den remote thread zu registrieren und das `lr`-Register vor dem function call auf eine ungültige Adresse zu setzen. Dadurch wird nach der Funktionsausführung eine Exception ausgelöst und eine Nachricht an den exception port gesendet, wodurch eine Untersuchung des thread-Zustands ermöglicht wird, um den Rückgabewert abzurufen. Alternativ wird, wie bei Ian Beers *triple_fetch*-Exploit, `lr` auf eine Endlosschleife gesetzt; anschließend werden die Register des threads kontinuierlich überwacht, bis `pc` auf diese Instruktion zeigt.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

In der folgenden Phase werden Mach ports eingerichtet, um die Kommunikation mit dem remote thread zu ermöglichen. Diese ports sind entscheidend für die Übertragung beliebiger Send-/Receive-Rechte zwischen tasks.<sup>[[1]](#references)</sup>

Für die bidirektionale Kommunikation werden zwei Mach receive rights erstellt: einer im lokalen und der andere im remote task. Anschließend wird für jeden port ein send right an den jeweils anderen task übertragen, wodurch der Austausch von Nachrichten ermöglicht wird.<sup>[[1]](#references)</sup>

Beim lokalen port wird das receive right vom lokalen task gehalten. Der port wird mit `mach_port_allocate()` erstellt. Die Herausforderung besteht darin, ein send right für diesen port in den remote task zu übertragen.<sup>[[1]](#references)</sup>

Eine Strategie besteht darin, `thread_set_special_port()` zu verwenden, um ein send right für den lokalen port im `THREAD_KERNEL_PORT` des remote threads zu platzieren. Anschließend wird der remote thread angewiesen, `mach_thread_self()` aufzurufen, um das send right abzurufen.<sup>[[1]](#references)</sup>

Beim remote port wird der Prozess im Wesentlichen umgekehrt. Der remote thread wird angewiesen, über `mach_reply_port()` einen Mach port zu erzeugen, da `mach_port_allocate()` aufgrund seines Rückgabemechanismus ungeeignet ist. Nach der Erstellung des ports wird `mach_port_insert_right()` im remote thread aufgerufen, um ein send right einzurichten. Dieses right wird anschließend mithilfe von `thread_set_special_port()` im Kernel hinterlegt. Zurück im lokalen task wird `thread_get_special_port()` auf dem remote thread verwendet, um ein send right für den neu zugewiesenen Mach port im remote task zu erhalten.<sup>[[1]](#references)</sup>

Nach Abschluss dieser Schritte sind die Mach ports eingerichtet und bilden die Grundlage für die bidirektionale Kommunikation.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

In diesem Abschnitt liegt der Fokus auf der Verwendung des execute primitive, um grundlegende Memory read/write primitives einzurichten. Diese ersten Schritte sind entscheidend, um eine bessere Kontrolle über den remote process zu erlangen, auch wenn die primitives in dieser Phase noch nicht viele Einsatzmöglichkeiten bieten. Bald werden sie zu fortgeschritteneren Versionen erweitert.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Das Ziel besteht darin, mithilfe bestimmter Funktionen Memory reading und writing durchzuführen. Für **das Lesen des Speichers**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Zum **Schreiben in den Speicher**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Diese Funktionen entsprechen der folgenden Assembly:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Geeignete Funktionen identifizieren

Eine Untersuchung gängiger Bibliotheken ergab geeignete Kandidaten für diese Operationen:<sup>[[1]](#references)</sup>

1. **Speicher lesen – `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Schreiben in den Speicher — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Um einen 64-Bit-Schreibvorgang an einer beliebigen Adresse durchzuführen:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Mit diesen etablierten Primitiven ist die Grundlage für die Erstellung von Shared Memory geschaffen, was einen bedeutenden Fortschritt bei der Kontrolle des entfernten Prozesses darstellt.<sup>[[1]](#references)</sup>

## 4. Einrichtung des Shared Memory

Ziel ist es, Shared Memory zwischen lokalen und entfernten Tasks einzurichten, um die Datenübertragung zu vereinfachen und den Aufruf von Funktionen mit mehreren Argumenten zu ermöglichen. Der Ansatz nutzt `libxpc` und dessen Objekttyp `OS_xpc_shmem`, der auf Mach memory entries basiert.<sup>[[1]](#references)</sup>

### Prozessübersicht

1. **Speicherzuweisung**
* Speicher für die gemeinsame Nutzung mit `mach_vm_allocate()` zuweisen.
* `xpc_shmem_create()` verwenden, um ein `OS_xpc_shmem`-Objekt für den zugewiesenen Bereich zu erstellen.
2. **Erstellen des Shared Memory im entfernten Prozess**
* Speicher für das `OS_xpc_shmem`-Objekt im entfernten Prozess zuweisen (`remote_malloc`).
* Das lokale Template-Objekt kopieren; ein Fix-up des eingebetteten Mach send right am Offset `0x18` ist weiterhin erforderlich.
3. **Korrigieren des Mach memory entry**
* Mit `thread_set_special_port()` ein send right einfügen und das Feld `0x18` mit dem Namen des remote entry überschreiben.
4. **Abschluss**
* Das entfernte Objekt validieren und mit einem remote call an `xpc_shmem_remote()` mappen.

## 5. Vollständige Kontrolle erlangen

Sobald arbitrary execution und ein Shared-Memory-Backchannel verfügbar sind, besitzt du den Zielprozess effektiv:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — `memcpy()` zwischen lokalen und gemeinsam genutzten Bereichen verwenden.
* **Funktionsaufrufe mit > 8 Argumenten** — die zusätzlichen Argumente gemäß der arm64 calling convention auf dem Stack ablegen.
* **Mach port transfer** — Rechte über Mach messages mithilfe der eingerichteten Ports übertragen.
* **File-descriptor transfer** — fileports nutzen (siehe *triple_fetch*).

All dies ist für die einfache Wiederverwendung in der Bibliothek [`threadexec`](https://github.com/bazad/threadexec) gekapselt.

---

## 6. Besonderheiten von Apple Silicon (arm64e)

Auf Apple-Silicon-Geräten (arm64e) schützen **Pointer Authentication Codes (PAC)** alle Rücksprungadressen und viele Funktionszeiger. Thread-hijacking-Techniken, die *vorhandenen Code wiederverwenden*, funktionieren weiterhin, da die ursprünglichen Werte in `lr`/`pc` bereits gültige PAC-Signaturen tragen. Probleme treten auf, wenn du versuchst, zu angreiferkontrolliertem Speicher zu springen:

1. Ausführbaren Speicher innerhalb des Ziels zuweisen (entferntes `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Deine Payload kopieren.
3. Den Pointer innerhalb des *entfernten* Prozesses signieren:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Setze `pc = ptr` im Zustand des hijacked thread.

Alternativ kannst du PAC-konform bleiben, indem du vorhandene Gadgets/Funktionen verkettst (traditionelles ROP).

## 7. Erkennung & Hardening mit EndpointSecurity

Das **EndpointSecurity (ES)**-Framework stellt Kernel-Ereignisse bereit, mit denen Defender Thread-Injection-Versuche beobachten oder blockieren können:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – wird ausgelöst, wenn ein Prozess den Port des Tasks eines anderen Prozesses anfordert (z. B. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – wird ausgegeben, sobald ein Thread in einem *anderen* Task erstellt wird.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (in macOS 14 Sonoma hinzugefügt) – zeigt die Manipulation von Registern eines bestehenden Threads an.

Minimaler Swift-Client, der Ereignisse zu Remote-Threads ausgibt:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
Abfragen mit **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Überlegungen zur Hardened Runtime

Das Verteilen Ihrer Anwendung **ohne** das Entitlement `com.apple.security.get-task-allow` verhindert, dass nicht als root ausgeführte Angreifer ihren task-port erhalten. System Integrity Protection (SIP) blockiert weiterhin den Zugriff auf viele Apple-Binaries, Drittanbieter-Software muss jedoch ausdrücklich darauf verzichten.

## 8. Aktuelle öffentliche Tools (2023-2025)

| Tool | Jahr | Anmerkungen |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompakter PoC, der PAC-aware Thread-Hijacking auf Ventura/Sonoma demonstriert |
| `remote_thread_es` | 2024 | EndpointSecurity-Hilfsprogramm, das von mehreren EDR-Anbietern verwendet wird, um `REMOTE_THREAD_CREATE`-Events sichtbar zu machen |

> Das Lesen des Quellcodes dieser Projekte ist hilfreich, um API-Änderungen in macOS 13/14 zu verstehen und die Kompatibilität zwischen Intel und Apple Silicon aufrechtzuerhalten.

## Referenzen

- [1] [Umgehen von Platform-Binary-Einschränkungen mit task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
