# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Zunächst wird die Funktion `task_threads()` auf dem Task-Port aufgerufen, um eine Thread-Liste vom remote Task abzurufen. Ein Thread wird für das Hijacking ausgewählt. Dieser Ansatz weicht von herkömmlichen Code-Injection-Methoden ab, da das Erstellen eines neuen remote Threads aufgrund der Mitigation, die `thread_create_running()` blockiert, nicht zulässig ist.<sup>[1]</sup>

Um den Thread zu kontrollieren, wird `thread_suspend()` aufgerufen, wodurch dessen Ausführung angehalten wird.<sup>[1]</sup>

Die einzigen zulässigen Operationen auf dem remote Thread bestehen darin, ihn **anzuhalten** und **zu starten** sowie seine Registerwerte **abzurufen**/**zu ändern**. Remote function calls werden initiiert, indem die Register `x0` bis `x7` auf die **Argumente** gesetzt, `pc` auf die gewünschte Funktion konfiguriert und der Thread fortgesetzt wird. Damit der Thread nach der Rückkehr nicht abstürzt, muss die Rückkehr erkannt werden.<sup>[1]</sup>

Eine Möglichkeit besteht darin, mithilfe von `thread_set_exception_ports()` einen **exception handler** für den remote Thread zu registrieren und das `lr`-Register vor dem function call auf eine ungültige Adresse zu setzen. Dadurch wird nach der Funktionsausführung eine Exception ausgelöst und eine Nachricht an den Exception-Port gesendet, wodurch eine Untersuchung des Thread-Zustands ermöglicht wird, um den Rückgabewert abzurufen. Alternativ wird, wie aus Ian Beers *triple_fetch*-Exploit übernommen, `lr` auf eine Endlosschleife gesetzt. Anschließend werden die Register des Threads kontinuierlich überwacht, bis `pc` auf diese Instruktion zeigt.<sup>[1]</sup>

## 2. Mach ports for communication

In der anschließenden Phase werden Mach ports eingerichtet, um die Kommunikation mit dem remote Thread zu ermöglichen. Diese Ports dienen der Übertragung beliebiger Send-/Receive-Rechte zwischen Tasks.<sup>[1]</sup>

Für die bidirektionale Kommunikation werden zwei Mach receive rights erstellt: einer im lokalen und der andere im remote Task. Anschließend wird für jeden Port ein send right an den jeweils anderen Task übertragen, wodurch der Nachrichtenaustausch ermöglicht wird.<sup>[1]</sup>

Beim lokalen Port wird das receive right vom lokalen Task gehalten. Der Port wird mit `mach_port_allocate()` erstellt. Die Herausforderung besteht darin, ein send right für diesen Port in den remote Task zu übertragen.<sup>[1]</sup>

Eine Strategie besteht darin, `thread_set_special_port()` zu verwenden, um ein send right für den lokalen Port im `THREAD_KERNEL_PORT` des remote Threads abzulegen. Anschließend wird der remote Thread angewiesen, `mach_thread_self()` aufzurufen, um das send right abzurufen.<sup>[1]</sup>

Beim remote Port wird der Vorgang im Wesentlichen umgekehrt. Der remote Thread wird angewiesen, über `mach_reply_port()` einen Mach-Port zu erzeugen, da `mach_port_allocate()` aufgrund seines Rückgabemechanismus ungeeignet ist. Nach der Erstellung des Ports wird im remote Thread `mach_port_insert_right()` aufgerufen, um ein send right einzurichten. Dieses Recht wird anschließend mithilfe von `thread_set_special_port()` im Kernel abgelegt. Zurück im lokalen Task wird `thread_get_special_port()` für den remote Thread verwendet, um ein send right für den neu zugewiesenen Mach-Port im remote Task zu erhalten.<sup>[1]</sup>

Durch den Abschluss dieser Schritte werden Mach ports eingerichtet und damit die Grundlage für die bidirektionale Kommunikation geschaffen.<sup>[1]</sup>

## 3. Basic Memory Read/Write Primitives

In diesem Abschnitt liegt der Fokus auf der Verwendung des execute primitive zur Einrichtung grundlegender Memory read/write primitives. Diese ersten Schritte sind entscheidend, um mehr Kontrolle über den remote Prozess zu erlangen, auch wenn die primitives in dieser Phase noch nicht viele Einsatzmöglichkeiten bieten. Bald werden sie auf fortgeschrittenere Versionen aktualisiert.<sup>[1]</sup>

### Memory reading and writing using the execute primitive

Das Ziel besteht darin, mithilfe bestimmter Funktionen Memory reading und writing durchzuführen. Für **reading memory**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Für das **Schreiben in den Speicher**:
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

Eine Untersuchung gängiger Libraries ergab geeignete Kandidaten für diese Operationen:<sup>[1]</sup>

1. **Speicher lesen — `property_getName()`** (libobjc):
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
Mit diesen etablierten Primitiven ist die Grundlage für die Erstellung von Shared Memory geschaffen, was einen bedeutenden Fortschritt bei der Kontrolle des remote Prozesses darstellt.<sup>[1]</sup>

## 4. Einrichtung von Shared Memory

Das Ziel besteht darin, Shared Memory zwischen lokalen und remote Tasks einzurichten, um die Datenübertragung zu vereinfachen und den Aufruf von Funktionen mit mehreren Argumenten zu ermöglichen. Der Ansatz nutzt `libxpc` und dessen `OS_xpc_shmem`-Objekttyp, der auf Mach memory entries basiert.<sup>[1]</sup>

### Prozessübersicht

1. **Speicherzuweisung**
* Speicher für die gemeinsame Nutzung mit `mach_vm_allocate()` zuweisen.
* Mit `xpc_shmem_create()` ein `OS_xpc_shmem`-Objekt für den zugewiesenen Bereich erstellen.
2. **Erstellen von Shared Memory im remote Prozess**
* Speicher für das `OS_xpc_shmem`-Objekt im remote Prozess zuweisen (`remote_malloc`).
* Das lokale Template-Objekt kopieren; eine Korrektur des eingebetteten Mach send right am Offset `0x18` ist weiterhin erforderlich.
3. **Korrigieren des Mach memory entry**
* Mit `thread_set_special_port()` ein send right einfügen und das Feld `0x18` mit dem Namen des remote entry überschreiben.
4. **Abschluss**
* Das remote Objekt validieren und mit einem remote Aufruf von `xpc_shmem_remote()` mappen.

## 5. Vollständige Kontrolle erlangen

Sobald arbitrary execution und ein Shared-Memory-Backchannel verfügbar sind, besitzt du den Zielprozess effektiv:<sup>[1]</sup>

* **Arbitrary memory R/W** — `memcpy()` zwischen lokalen und Shared-Regionen verwenden.
* **Funktionsaufrufe mit > 8 Argumenten** — die zusätzlichen Argumente gemäß der arm64 calling convention auf dem Stack platzieren.
* **Mach port transfer** — Rights in Mach messages über die eingerichteten Ports übertragen.
* **File-descriptor transfer** — fileports nutzen (siehe *triple_fetch*).

All dies ist in der [`threadexec`](https://github.com/bazad/threadexec)-Bibliothek gekapselt und kann einfach wiederverwendet werden.

---

## 6. Apple-Silicon-(arm64e)-Besonderheiten

Auf Apple-Silicon-Geräten (arm64e) schützen **Pointer Authentication Codes (PAC)** alle return addresses und viele function pointers. Thread-hijacking-Techniken, die vorhandenen Code *wiederverwenden*, funktionieren weiterhin, da die ursprünglichen Werte in `lr`/`pc` bereits gültige PAC-Signaturen enthalten. Probleme treten auf, wenn versucht wird, zu von einem Angreifer kontrolliertem Speicher zu springen:

1. Ausführbaren Speicher innerhalb des Ziels zuweisen (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Die Payload kopieren.
3. Den Pointer innerhalb des *remote* Prozesses signieren:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Setze `pc = ptr` im Zustand des hijacked Threads.

Alternativ kannst du PAC-konform bleiben, indem du vorhandene Gadgets/Funktionen verkettst (traditionelles ROP).

## 7. Erkennung und Hardening mit EndpointSecurity

Das **EndpointSecurity (ES)**-Framework stellt Kernel-Ereignisse bereit, mit denen Defender Versuche zur Thread-Injection überwachen oder blockieren können:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – wird ausgelöst, wenn ein Prozess den Port eines anderen Tasks anfordert (z. B. durch `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – wird ausgegeben, sobald ein Thread in einem *anderen* Task erstellt wird.<sup>[3]</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (in macOS 14 Sonoma hinzugefügt) – weist auf die Manipulation von Registern eines vorhandenen Threads hin.

Minimaler Swift-Client, der Ereignisse für entfernte Threads ausgibt:
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
Abfrage mit **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Überlegungen zur Hardened Runtime

Die Verteilung Ihrer Anwendung **ohne** das Entitlement `com.apple.security.get-task-allow` verhindert, dass Angreifer ohne Root-Rechte ihren task-port erhalten. System Integrity Protection (SIP) blockiert weiterhin den Zugriff auf viele Apple-Binärdateien, aber Software von Drittanbietern muss sich ausdrücklich abmelden.

## 8. Aktuelle öffentliche Tools (2023-2025)

| Tool | Jahr | Anmerkungen |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompakter PoC, der PAC-aware thread hijacking auf Ventura/Sonoma demonstriert |
| `remote_thread_es` | 2024 | EndpointSecurity helper, der von mehreren EDR-Anbietern verwendet wird, um `REMOTE_THREAD_CREATE`-Ereignisse sichtbar zu machen |

> Das Lesen des Quellcodes dieser Projekte ist hilfreich, um API-Änderungen in macOS 13/14 zu verstehen und die Kompatibilität zwischen Intel und Apple Silicon aufrechtzuerhalten.

## Referenzen

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
