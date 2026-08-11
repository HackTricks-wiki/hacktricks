# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Kode

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Aanvanklik word die `task_threads()`-funksie op die task port aangeroep om ’n thread list van die remote task te verkry. ’n Thread word vir hijacking gekies. Hierdie benadering verskil van konvensionele code-injection-metodes, aangesien die skep van ’n nuwe remote thread verbied word weens die mitigation wat `thread_create_running()` blokkeer.<sup>[[1]](#references)</sup>

Om die thread te beheer, word `thread_suspend()` aangeroep, wat die uitvoering daarvan stop.<sup>[[1]](#references)</sup>

Die enigste bewerkings wat op die remote thread toegelaat word, behels om dit te **stop** en te **start**, asook om sy registerwaardes te **verkry**/**wysig**. Remote function calls word geïnisieer deur registers `x0` tot `x7` op die **arguments** te stel, `pc` te konfigureer om na die verlangde funksie te wys, en die thread te hervat. Om te verseker dat die thread nie ná die return crash nie, moet die return opgespoor word.<sup>[[1]](#references)</sup>

Een strategie behels die registrasie van ’n **exception handler** vir die remote thread deur `thread_set_exception_ports()` te gebruik, en om die `lr`-register voor die function call op ’n ongeldige adres te stel. Dit veroorsaak ’n exception ná die funksie-uitvoering, wat ’n boodskap na die exception port stuur en dit moontlik maak om die toestand van die thread te inspekteer om die return value te herstel. Alternatiewelik, soos oorgeneem uit Ian Beer se *triple_fetch*-exploit, word `lr` gestel om oneindig te loop; die thread se registers word dan voortdurend gemonitor totdat `pc` na daardie instruksie wys.<sup>[[1]](#references)</sup>

## 2. Mach ports vir kommunikasie

Die volgende fase behels die opstel van Mach ports om kommunikasie met die remote thread moontlik te maak. Hierdie ports is instrumenteel om arbitrêre send/receive rights tussen tasks oor te dra.<sup>[[1]](#references)</sup>

Vir bidirectional communication word twee Mach receive rights geskep: een in die local task en die ander in die remote task. Vervolgens word ’n send right vir elke port na die ooreenstemmende task oorgedra, wat message exchange moontlik maak.<sup>[[1]](#references)</sup>

Met fokus op die local port word die receive right deur die local task gehou. Die port word met `mach_port_allocate()` geskep. Die uitdaging lê daarin om ’n send right na hierdie port in die remote task oor te dra.<sup>[[1]](#references)</sup>

Een strategie behels die gebruik van `thread_set_special_port()` om ’n send right na die local port in die remote thread se `THREAD_KERNEL_PORT` te plaas. Die remote thread word dan opdrag gegee om `mach_thread_self()` aan te roep om die send right te verkry.<sup>[[1]](#references)</sup>

Vir die remote port word die proses in wese omgekeer. Die remote thread word opdrag gegee om ’n Mach port deur middel van `mach_reply_port()` te genereer (`mach_port_allocate()` is ongeskik weens sy return-meganisme). Nadat die port geskep is, word `mach_port_insert_right()` in die remote thread aangeroep om ’n send right te skep. Hierdie right word dan in die kernel gestoor deur `thread_set_special_port()` te gebruik. Terug in die local task word `thread_get_special_port()` op die remote thread gebruik om ’n send right na die nuut toegekende Mach port in die remote task te verkry.<sup>[[1]](#references)</sup>

Die voltooiing van hierdie stappe lei tot die vestiging van Mach ports, wat die grondslag vir bidirectional communication lê.<sup>[[1]](#references)</sup>

## 3. Basiese Memory Read/Write Primitives

In hierdie afdeling val die fokus op die gebruik van die execute primitive om basiese memory read/write primitives te vestig. Hierdie aanvanklike stappe is noodsaaklik om meer beheer oor die remote process te verkry, hoewel die primitives op hierdie stadium nie veel doel sal dien nie. Binnekort sal hulle na meer gevorderde weergawes opgegradeer word.<sup>[[1]](#references)</sup>

### Memory reading en writing met behulp van die execute primitive

Die doel is om memory reading en writing met behulp van spesifieke funksies uit te voer. Vir **reading memory**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Vir **skryf na geheue**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Hierdie funksies stem ooreen met die volgende assembly:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifisering van geskikte funksies

'n Skandering van algemene libraries het geskikte kandidate vir hierdie bewerkings onthul:<sup>[[1]](#references)</sup>

1. **Geheue lees — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Skryf na geheue — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Om ’n 64-bis-skrywing by ’n arbitrêre adres uit te voer:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Met hierdie primitives gevestig, is die weg nou gebaan vir die skep van shared memory, wat ’n belangrike vordering in die beheer van die remote process verteenwoordig.<sup>[[1]](#references)</sup>

## 4. Opstelling van Shared Memory

Die doel is om shared memory tussen plaaslike en remote tasks te vestig, wat data-oordrag vereenvoudig en die aanroep van functions met veelvuldige arguments moontlik maak. Die benadering gebruik `libxpc` en sy `OS_xpc_shmem`-objecttipe, wat op Mach memory entries gebou is.<sup>[[1]](#references)</sup>

### Oorsig van die process

1. **Geheue-allokasie**
* Allokeer geheue vir sharing met `mach_vm_allocate()`.
* Gebruik `xpc_shmem_create()` om ’n `OS_xpc_shmem`-object vir die geallokeerde area te skep.
2. **Skep van shared memory in die remote process**
* Allokeer geheue vir die `OS_xpc_shmem`-object in die remote process (`remote_malloc`).
* Kopieer die plaaslike template-object; fix-up van die ingebedde Mach send right by offset `0x18` word steeds vereis.
3. **Korrigering van die Mach memory entry**
* Voeg ’n send right met `thread_set_special_port()` in en oorskryf die `0x18`-veld met die naam van die remote entry.
4. **Finalisering**
* Valideer die remote object en map dit met ’n remote call na `xpc_shmem_remote()`.

## 5. Bereiking van Volledige Beheer

Sodra arbitrary execution en ’n shared-memory back-channel beskikbaar is, besit jy die target process effektief:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — gebruik `memcpy()` tussen plaaslike en shared regions.
* **Function calls met > 8 args** — plaas die ekstra arguments op die stack volgens die arm64 calling convention.
* **Mach port transfer** — stuur rights in Mach messages via die gevestigde ports.
* **File-descriptor transfer** — gebruik fileports (sien *triple_fetch*).

Dit alles is in die [`threadexec`](https://github.com/bazad/threadexec)-library verpak vir maklike hergebruik.

---

## 6. Apple Silicon (arm64e)-nuanses

Op Apple Silicon-devices (arm64e) beskerm **Pointer Authentication Codes (PAC)** alle return addresses en baie function pointers. Thread-hijacking-tegnieke wat *bestaande code hergebruik*, werk steeds omdat die oorspronklike waardes in `lr`/`pc` reeds geldige PAC-signatures bevat. Probleme ontstaan wanneer jy probeer om na attacker-controlled memory te spring:

1. Allokeer executable memory binne die target (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Kopieer jou payload.
3. Sign die pointer binne die *remote* process:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Stel `pc = ptr` in die state van die gekaapte thread.

Alternatiewelik, bly PAC-compliant deur bestaande gadgets/functions aan mekaar te skakel (tradisionele ROP).

## 7. Opsporing & Versterking met EndpointSecurity

Die **EndpointSecurity (ES)** framework stel kernel-events bloot wat defenders in staat stel om thread-injection-pogings waar te neem of te blokkeer:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – word geaktiveer wanneer ’n proses ’n ander task se port versoek (bv. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – word gegenereer wanneer ’n thread in ’n *ander* task geskep word.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (bygevoeg in macOS 14 Sonoma) – dui op registermanipulasie van ’n bestaande thread.

Minimale Swift-client wat remote-thread-events druk:
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
Navraag doen met **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Oorwegings vir hardened-runtime

Die verspreiding van jou toepassing **sonder** die `com.apple.security.get-task-allow` entitlement voorkom dat nie-root aanvallers sy task-port bekom. System Integrity Protection (SIP) blokkeer steeds toegang tot baie Apple binaries, maar third-party software moet uitdruklik opt-out.

## 8. Onlangse publieke Tooling (2023-2025)

| Tool | Jaar | Opmerkings |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompakte PoC wat PAC-aware thread hijacking op Ventura/Sonoma demonstreer<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | EndpointSecurity-helper wat deur verskeie EDR vendors gebruik word om `REMOTE_THREAD_CREATE`-events sigbaar te maak |

> Dit is nuttig om die bronkode van hierdie projekte te lees om API-veranderinge wat in macOS 13/14 ingestel is, te verstaan en versoenbaarheid oor Intel ↔ Apple Silicon heen te behou.

## References

- [1] [Om platform binary restrictions met task_threads() te omseil - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
