# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Zunächst wird die Funktion `task_threads()` auf dem Task-Port aufgerufen, um eine Thread-Liste vom Remote-Task zu erhalten. Ein Thread wird zum Hijacking ausgewählt. Dieser Ansatz weicht von herkömmlichen Code-Injection-Methoden ab, da das Erstellen eines neuen Remote-Threads aufgrund der Minderung, die `thread_create_running()` blockiert, verboten ist.

Um den Thread zu steuern, wird `thread_suspend()` aufgerufen, um seine Ausführung zu stoppen.

Die einzigen Operationen, die auf dem Remote-Thread erlaubt sind, beinhalten **Stoppen** und **Starten** sowie **Abrufen**/**Ändern** seiner Registerwerte. Remote-Funktionsaufrufe werden initiiert, indem die Register `x0` bis `x7` auf die **Argumente** gesetzt, `pc` auf die gewünschte Funktion konfiguriert und der Thread fortgesetzt wird. Um sicherzustellen, dass der Thread nach der Rückkehr nicht abstürzt, ist es notwendig, die Rückkehr zu erkennen.

Eine Strategie besteht darin, einen **Ausnahmebehandler** für den Remote-Thread mit `thread_set_exception_ports()` zu registrieren und das Register `lr` vor dem Funktionsaufruf auf eine ungültige Adresse zu setzen. Dies löst nach der Funktionsausführung eine Ausnahme aus, die eine Nachricht an den Ausnahmeport sendet, wodurch eine Zustandsinspektion des Threads ermöglicht wird, um den Rückgabewert zu ermitteln. Alternativ, wie im *triple_fetch*-Exploit von Ian Beer übernommen, wird `lr` so gesetzt, dass es unendlich schleift; die Register des Threads werden dann kontinuierlich überwacht, bis `pc` auf diese Anweisung zeigt.

## 2. Mach ports for communication

Die nächste Phase besteht darin, Mach-Ports einzurichten, um die Kommunikation mit dem Remote-Thread zu erleichtern. Diese Ports sind entscheidend für den Transfer beliebiger Send/Receive-Rechte zwischen Tasks.

Für die bidirektionale Kommunikation werden zwei Mach-Receive-Rechte erstellt: eines im lokalen und das andere im Remote-Task. Anschließend wird ein Senderecht für jeden Port an den entsprechenden Task übertragen, um den Nachrichtenaustausch zu ermöglichen.

Fokussiert auf den lokalen Port, wird das Receive-Recht vom lokalen Task gehalten. Der Port wird mit `mach_port_allocate()` erstellt. Die Herausforderung besteht darin, ein Senderecht für diesen Port in den Remote-Task zu übertragen.

Eine Strategie besteht darin, `thread_set_special_port()` zu nutzen, um ein Senderecht für den lokalen Port im `THREAD_KERNEL_PORT` des Remote-Threads zu platzieren. Dann wird der Remote-Thread angewiesen, `mach_thread_self()` aufzurufen, um das Senderecht abzurufen.

Für den Remote-Port wird der Prozess im Wesentlichen umgekehrt. Der Remote-Thread wird angewiesen, einen Mach-Port über `mach_reply_port()` zu generieren (da `mach_port_allocate()` aufgrund seines Rückgabemechanismus ungeeignet ist). Nach der Port-Erstellung wird `mach_port_insert_right()` im Remote-Thread aufgerufen, um ein Senderecht einzurichten. Dieses Recht wird dann im Kernel mit `thread_set_special_port()` gespeichert. Im lokalen Task wird `thread_get_special_port()` auf dem Remote-Thread verwendet, um ein Senderecht für den neu zugewiesenen Mach-Port im Remote-Task zu erwerben.

Der Abschluss dieser Schritte führt zur Einrichtung von Mach-Ports, die die Grundlage für die bidirektionale Kommunikation legen.

## 3. Basic Memory Read/Write Primitives

In diesem Abschnitt liegt der Fokus auf der Nutzung des Execute-Primitivs, um grundlegende Speicher-Lese-/Schreib-Primitiven zu etablieren. Diese ersten Schritte sind entscheidend, um mehr Kontrolle über den Remote-Prozess zu erlangen, obwohl die Primitiven in diesem Stadium nicht viele Zwecke erfüllen werden. Bald werden sie auf fortgeschrittenere Versionen aktualisiert.

### Memory reading and writing using the execute primitive

Das Ziel ist es, Speicher zu lesen und zu schreiben, indem spezifische Funktionen verwendet werden. Für **Speicher lesen**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Für **Speicher schreiben**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Diese Funktionen entsprechen der folgenden Assemblierung:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifizierung geeigneter Funktionen

Ein Scan gängiger Bibliotheken ergab geeignete Kandidaten für diese Operationen:

1. **Speicher lesen — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Speichern von Speicher — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Um einen 64-Bit-Schreibvorgang an einer beliebigen Adresse durchzuführen:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Mit diesen Primitiven ist die Bühne für die Erstellung von gemeinsamem Speicher bereitet, was einen bedeutenden Fortschritt bei der Kontrolle des Remote-Prozesses darstellt.

## 4. Einrichtung des gemeinsamen Speichers

Das Ziel ist es, gemeinsamen Speicher zwischen lokalen und Remote-Aufgaben einzurichten, um den Datentransfer zu vereinfachen und das Aufrufen von Funktionen mit mehreren Argumenten zu erleichtern. Der Ansatz nutzt `libxpc` und seinen `OS_xpc_shmem` Objekttyp, der auf Mach-Speichereinträgen basiert.

### Prozessübersicht

1. **Speicherzuweisung**
* Weisen Sie Speicher für die gemeinsame Nutzung mit `mach_vm_allocate()` zu.
* Verwenden Sie `xpc_shmem_create()`, um ein `OS_xpc_shmem` Objekt für den zugewiesenen Bereich zu erstellen.
2. **Erstellung des gemeinsamen Speichers im Remote-Prozess**
* Weisen Sie Speicher für das `OS_xpc_shmem` Objekt im Remote-Prozess (`remote_malloc`) zu.
* Kopieren Sie das lokale Template-Objekt; eine Anpassung des eingebetteten Mach-Sende-Rechts bei Offset `0x18` ist weiterhin erforderlich.
3. **Korrektur des Mach-Speichereintrags**
* Fügen Sie ein Sende-Recht mit `thread_set_special_port()` ein und überschreiben Sie das Feld `0x18` mit dem Namen des Remote-Eintrags.
4. **Abschluss**
* Validieren Sie das Remote-Objekt und mappen Sie es mit einem Remote-Aufruf von `xpc_shmem_remote()`.

## 5. Vollständige Kontrolle erreichen

Sobald willkürliche Ausführung und ein gemeinsamer Speicher-Backchannel verfügbar sind, besitzen Sie effektiv den Zielprozess:

* **Willkürlicher Speicher R/W** — verwenden Sie `memcpy()` zwischen lokalen und gemeinsamen Regionen.
* **Funktionsaufrufe mit > 8 Argumenten** — platzieren Sie die zusätzlichen Argumente auf dem Stack gemäß der arm64 Aufrufkonvention.
* **Mach-Port-Übertragung** — übergeben Sie Rechte in Mach-Nachrichten über die etablierten Ports.
* **Dateideskriptor-Übertragung** — nutzen Sie Fileports (siehe *triple_fetch*).

All dies ist in der [`threadexec`](https://github.com/bazad/threadexec) Bibliothek für eine einfache Wiederverwendung verpackt.

---

## 6. Apple Silicon (arm64e) Nuancen

Auf Apple Silicon Geräten (arm64e) schützen **Pointer Authentication Codes (PAC)** alle Rückgabewerte und viele Funktionszeiger. Techniken zum Thread-Hijacking, die *vorhandenen Code wiederverwenden*, funktionieren weiterhin, da die ursprünglichen Werte in `lr`/`pc` bereits gültige PAC-Signaturen tragen. Probleme treten auf, wenn Sie versuchen, zu speicher, der vom Angreifer kontrolliert wird:

1. Weisen Sie ausführbaren Speicher innerhalb des Ziels zu (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Kopieren Sie Ihr Payload.
3. Signieren Sie den Zeiger im *Remote*-Prozess:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Setze `pc = ptr` im gehijackten Thread-Zustand.

Alternativ bleibe PAC-konform, indem du vorhandene Gadgets/Funktionen verkettest (traditionelles ROP).

## 7. Erkennung & Härtung mit EndpointSecurity

Das **EndpointSecurity (ES)**-Framework gibt Kernelereignisse frei, die es Verteidigern ermöglichen, Thread-Injektionsversuche zu beobachten oder zu blockieren:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – wird ausgelöst, wenn ein Prozess den Port eines anderen Tasks anfordert (z. B. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – wird ausgegeben, wann immer ein Thread in einem *anderen* Task erstellt wird.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (hinzugefügt in macOS 14 Sonoma) – zeigt die Registermanipulation eines bestehenden Threads an.

Minimaler Swift-Client, der Remote-Thread-Ereignisse ausgibt:
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
### Überlegungen zur gehärteten Laufzeit

Die Verteilung Ihrer Anwendung **ohne** das `com.apple.security.get-task-allow` Entitlement verhindert, dass Angreifer ohne Root-Rechte auf ihren Task-Port zugreifen können. Der System Integrity Protection (SIP) blockiert weiterhin den Zugriff auf viele Apple-Binärdateien, aber Drittanbieter-Software muss sich ausdrücklich abmelden.

## 8. Neueste öffentliche Werkzeuge (2023-2025)

| Werkzeug | Jahr | Anmerkungen |
|---------|------|-------------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompakte PoC, die das PAC-bewusste Thread-Hijacking auf Ventura/Sonoma demonstriert |
| `remote_thread_es` | 2024 | EndpointSecurity-Helfer, der von mehreren EDR-Anbietern verwendet wird, um `REMOTE_THREAD_CREATE`-Ereignisse anzuzeigen |

> Das Lesen des Quellcodes dieser Projekte ist nützlich, um die in macOS 13/14 eingeführten API-Änderungen zu verstehen und um die Kompatibilität zwischen Intel ↔ Apple Silicon aufrechtzuerhalten.

## Referenzen

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
