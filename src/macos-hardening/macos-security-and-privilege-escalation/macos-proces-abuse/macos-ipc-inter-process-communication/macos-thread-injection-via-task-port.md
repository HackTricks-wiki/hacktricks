# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Aanvanklik word die `task_threads()` funksie op die taakpoort aangeroep om 'n draadlys van die afstandlike taak te verkry. 'n Draad word gekies vir kaap. Hierdie benadering verskil van konvensionele kode-inspuitingsmetodes aangesien die skep van 'n nuwe afstandlike draad verbied word weens die versagting wat `thread_create_running()` blokkeer.

Om die draad te beheer, word `thread_suspend()` aangeroep, wat die uitvoering stop.

Die enigste operasies wat op die afstandlike draad toegelaat word, behels **stop** en **begin** dit en **herwin**/**wysig** sy registerwaardes. Afstandlike funksie-oproepe word geïnisieer deur registers `x0` tot `x7` op die **argumente** in te stel, `pc` te konfigureer om die gewenste funksie te teiken, en die draad te hervat. Om te verseker dat die draad nie cras nadat die terugkeer plaasvind nie, is dit nodig om die terugkeer te detecteer.

Een strategie behels die registrasie van 'n **uitzonderinghandler** vir die afstandlike draad met behulp van `thread_set_exception_ports()`, wat die `lr` register op 'n ongeldige adres stel voor die funksie-oproep. Dit veroorsaak 'n uitzondering na die funksie-uitvoering, wat 'n boodskap na die uitzonderingpoort stuur, wat staatinspeksie van die draad moontlik maak om die terugkeerwaarde te herstel. Alternatiewelik, soos aangeneem van Ian Beer se *triple_fetch* uitbuiting, word `lr` op oneindig gesirkuleer; die draad se registers word dan voortdurend gemonitor totdat `pc` na daardie instruksie wys.

## 2. Mach ports for communication

Die volgende fase behels die vestiging van Mach-poorte om kommunikasie met die afstandlike draad te fasiliteer. Hierdie poorte is noodsaaklik vir die oordrag van arbitrêre stuur/ontvang regte tussen take.

Vir bidireksionele kommunikasie word twee Mach ontvang regte geskep: een in die plaaslike en die ander in die afstandlike taak. Daarna word 'n stuurreg vir elke poort na die teenhanger-taak oorgedra, wat boodskapuitruiling moontlik maak.

Fokus op die plaaslike poort, die ontvang regte word deur die plaaslike taak gehou. Die poort word geskep met `mach_port_allocate()`. Die uitdaging lê in die oordrag van 'n stuurreg na hierdie poort in die afstandlike taak.

'n Strategie behels die benutting van `thread_set_special_port()` om 'n stuurreg na die plaaslike poort in die afstandlike draad se `THREAD_KERNEL_PORT` te plaas. Dan word die afstandlike draad aangesê om `mach_thread_self()` aan te roep om die stuurreg te verkry.

Vir die afstandlike poort is die proses basies omgekeerd. Die afstandlike draad word aangestuur om 'n Mach-poort te genereer via `mach_reply_port()` (aangesien `mach_port_allocate()` onvanpas is weens sy terugkeermeganisme). Na poortskepping word `mach_port_insert_right()` in die afstandlike draad aangeroep om 'n stuurreg te vestig. Hierdie reg word dan in die kern gestoor met `thread_set_special_port()`. Terug in die plaaslike taak, word `thread_get_special_port()` op die afstandlike draad gebruik om 'n stuurreg na die nuut toegeken Mach-poort in die afstandlike taak te verkry.

Die voltooiing van hierdie stappe lei tot die vestiging van Mach-poorte, wat die grondslag lê vir bidireksionele kommunikasie.

## 3. Basic Memory Read/Write Primitives

In hierdie afdeling is die fokus op die benutting van die uitvoerprimitive om basiese geheue lees/skryf primitiewe te vestig. Hierdie aanvanklike stappe is noodsaaklik om meer beheer oor die afstandlike proses te verkry, alhoewel die primitiewe op hierdie stadium nie baie doeleindes sal dien nie. Binnekort sal hulle opgegradeer word na meer gevorderde weergawes.

### Memory reading and writing using the execute primitive

Die doel is om geheue te lees en te skryf met behulp van spesifieke funksies. Vir **geheue lees**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Vir **skryf van geheue**:
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

'n Skandering van algemene biblioteke het geskikte kandidate vir hierdie operasies onthul:

1. **Lees geheue — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Skryf geheue — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Om 'n 64-bis skrywe op 'n arbitrêre adres uit te voer:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Met hierdie primitiewe gevestig, is die verhoog gereed om gedeelde geheue te skep, wat 'n beduidende vordering in die beheer van die afstandsproses aandui.

## 4. Gedeelde Geheue Opstelling

Die doel is om gedeelde geheue tussen plaaslike en afstands take te vestig, wat dataverskuiwing vereenvoudig en die oproep van funksies met meerdere argumente fasiliteer. Die benadering benut `libxpc` en sy `OS_xpc_shmem` objektipe, wat gebou is op Mach geheue-invoere.

### Proses oorsig

1. **Geheue toewysing**
* Toewys geheue vir deel met `mach_vm_allocate()`.
* Gebruik `xpc_shmem_create()` om 'n `OS_xpc_shmem` objek vir die toegewyde streek te skep.
2. **Skep gedeelde geheue in die afstandsproses**
* Toewys geheue vir die `OS_xpc_shmem` objek in die afstandsproses (`remote_malloc`).
* Kopieer die plaaslike sjabloon objek; regstelling van die ingebedde Mach stuurreg op offset `0x18` is steeds nodig.
3. **Regstelling van die Mach geheue-invoer**
* Voeg 'n stuurreg in met `thread_set_special_port()` en oorskryf die `0x18` veld met die naam van die afstands invoer.
4. **Finalisering**
* Valideer die afstands objek en kaart dit met 'n afstands oproep na `xpc_shmem_remote()`.

## 5. Bereik Volle Beheer

Sodra arbitrêre uitvoering en 'n gedeelde-geheue terug-kanaal beskikbaar is, besit jy effektief die teiken proses:

* **Arbitrêre geheue R/W** — gebruik `memcpy()` tussen plaaslike & gedeelde streke.
* **Funksie oproepe met > 8 args** — plaas die ekstra argumente op die stapel volgens die arm64 oproepkonvensie.
* **Mach port oordrag** — gee regte in Mach boodskappe deur die gevestigde poorte.
* **Lêer-descriptor oordrag** — benut fileports (sien *triple_fetch*).

Al hierdie is ingepak in die [`threadexec`](https://github.com/bazad/threadexec) biblioteek vir maklike hergebruik.

---

## 6. Apple Silicon (arm64e) Nuanses

Op Apple Silicon toestelle (arm64e) **Pointer Authentication Codes (PAC)** beskerm alle terugadresse en baie funksie punte. Draad-hijacking tegnieke wat *bestaande kode hergebruik* voortgaan om te werk omdat die oorspronklike waardes in `lr`/`pc` reeds geldige PAC-handtekeninge dra. Probleme ontstaan wanneer jy probeer om na aanvaller-beheerde geheue te spring:

1. Toewys uitvoerbare geheue binne die teiken (afstand `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Kopieer jou payload.
3. Binne die *afstand* proses teken die pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Stel `pc = ptr` in die gehuurde draadtoestand.

Alternatiewelik, bly PAC-nakoming deur bestaande gadgets/funksies te ketting (tradisionele ROP).

## 7. Opsporing & Versterking met EndpointSecurity

Die **EndpointSecurity (ES)** raamwerk stel kerngebeurtenisse bloot wat verdedigers toelaat om draad-inspuitpogings waar te neem of te blokkeer:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – geaktiveer wanneer 'n proses 'n ander taak se poort versoek (bv. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – uitgegee wanneer 'n draad in 'n *ander* taak geskep word.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (bygevoeg in macOS 14 Sonoma) – dui registermanipulasie van 'n bestaande draad aan.

Minimale Swift-kliënt wat afstand-draadgebeurtenisse druk:
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
Querying met **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Versterkte-runtime oorwegings

Die verspreiding van jou aansoek **sonder** die `com.apple.security.get-task-allow` regte voorkom dat nie-root aanvallers toegang tot sy taak-port verkry. Stelselintegriteitsbeskerming (SIP) blokkeer steeds toegang tot baie Apple binaries, maar derdeparty-sagteware moet eksplisiet opt-out.

## 8. Onlangse Publieke Gereedskap (2023-2025)

| Gereedskap | Jaar | Opmerkings |
|------------|------|------------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompakte PoC wat PAC-bewuste draad-hijacking op Ventura/Sonoma demonstreer |
| `remote_thread_es` | 2024 | EndpointSecurity helper wat deur verskeie EDR verskaffers gebruik word om `REMOTE_THREAD_CREATE` gebeurtenisse te vertoon |

> Om die bronkode van hierdie projekte te lees, is nuttig om API-wijzigings wat in macOS 13/14 bekendgestel is, te verstaan en om versoenbaar te bly oor Intel ↔ Apple Silicon.

## Verwysings

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
