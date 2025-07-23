# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

U početku, `task_threads()` funkcija se poziva na task port da bi se dobila lista niti iz udaljenog taska. Niti se bira za preuzimanje. Ovaj pristup se razlikuje od konvencionalnih metoda injekcije koda jer je kreiranje nove udaljene niti zabranjeno zbog mitigacije koja blokira `thread_create_running()`.

Da bi se kontrolisala nit, poziva se `thread_suspend()`, zaustavljajući njeno izvršavanje.

Jedine operacije dozvoljene na udaljenoj niti uključuju **zaustavljanje** i **pokretanje** nje i **dobijanje**/**modifikovanje** njenih registarskih vrednosti. Udaljeni pozivi funkcija se iniciraju postavljanjem registara `x0` do `x7` na **argumente**, konfigurišući `pc` da cilja željenu funkciju, i nastavljajući nit. Osiguranje da nit ne sruši nakon povratka zahteva detekciju povratka.

Jedna strategija uključuje registraciju **handler-a za izuzetke** za udaljenu nit koristeći `thread_set_exception_ports()`, postavljajući `lr` registar na nevalidnu adresu pre poziva funkcije. Ovo izaziva izuzetak nakon izvršenja funkcije, šaljući poruku na port izuzetaka, omogućavajući inspekciju stanja niti da se povrati povratna vrednost. Alternativno, kao što je preuzeto iz *triple_fetch* eksploita Iana Beera, `lr` se postavlja da beskonačno petlja; registri niti se zatim kontinuirano prate dok `pc` ne ukazuje na tu instrukciju.

## 2. Mach ports for communication

Sledeća faza uključuje uspostavljanje Mach portova za olakšavanje komunikacije sa udaljenom niti. Ovi portovi su ključni za prenos proizvoljnih prava slanja/primanja između taskova.

Za dvosmernu komunikaciju, kreiraju se dva Mach prava za primanje: jedno u lokalnom i drugo u udaljenom tasku. Nakon toga, pravo slanja za svaki port se prenosi u odgovarajući task, omogućavajući razmenu poruka.

Fokusirajući se na lokalni port, pravo za primanje drži lokalni task. Port se kreira pomoću `mach_port_allocate()`. Izazov leži u prenosu prava slanja na ovaj port u udaljeni task.

Strategija uključuje korišćenje `thread_set_special_port()` da se postavi pravo slanja na lokalni port u `THREAD_KERNEL_PORT` udaljene niti. Zatim, udaljenoj niti se naređuje da pozove `mach_thread_self()` da bi dobila pravo slanja.

Za udaljeni port, proces je suštinski obrnut. Udaljenoj niti se naređuje da generiše Mach port putem `mach_reply_port()` (jer `mach_port_allocate()` nije prikladan zbog svog mehanizma vraćanja). Nakon kreiranja porta, `mach_port_insert_right()` se poziva u udaljenoj niti da bi se uspostavilo pravo slanja. Ovo pravo se zatim čuva u kernelu koristeći `thread_set_special_port()`. Ponovo u lokalnom tasku, `thread_get_special_port()` se koristi na udaljenoj niti da bi se steklo pravo slanja na novokreirani Mach port u udaljenom tasku.

Završetak ovih koraka rezultira uspostavljanjem Mach portova, postavljajući temelje za dvosmernu komunikaciju.

## 3. Basic Memory Read/Write Primitives

U ovom odeljku, fokus je na korišćenju izvršnog primitiva za uspostavljanje osnovnih primitiva za čitanje/pisanje u memoriju. Ovi inicijalni koraci su ključni za sticanje veće kontrole nad udaljenim procesom, iako primitivi u ovoj fazi neće služiti mnogim svrhama. Ubrzo će biti unapređeni na naprednije verzije.

### Memory reading and writing using the execute primitive

Cilj je izvršiti čitanje i pisanje u memoriju koristeći specifične funkcije. Za **čitanje memorije**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Za **pisanje u memoriju**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Ove funkcije odgovaraju sledećem asembleru:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifikacija pogodnih funkcija

Skeniranje uobičajenih biblioteka otkrilo je odgovarajuće kandidate za ove operacije:

1. **Čitanje memorije — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Pisanje u memoriju — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Da biste izvršili 64-bitno pisanje na proizvoljnu adresu:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Sa ovim postavljenim primitivima, postavljena je scena za kreiranje deljene memorije, što predstavlja značajan napredak u kontroli udaljenog procesa.

## 4. Postavljanje deljene memorije

Cilj je uspostaviti deljenu memoriju između lokalnih i udaljenih zadataka, pojednostavljujući prenos podataka i olakšavajući pozivanje funkcija sa više argumenata. Pristup koristi `libxpc` i njegov `OS_xpc_shmem` tip objekta, koji se zasniva na Mach memorijskim unosima.

### Pregled procesa

1. **Alokacija memorije**
* Alocirajte memoriju za deljenje koristeći `mach_vm_allocate()`.
* Koristite `xpc_shmem_create()` za kreiranje `OS_xpc_shmem` objekta za alociranu oblast.
2. **Kreiranje deljene memorije u udaljenom procesu**
* Alocirajte memoriju za `OS_xpc_shmem` objekat u udaljenom procesu (`remote_malloc`).
* Kopirajte lokalni šablon objekta; ispravka ugrađenog Mach prava slanja na offsetu `0x18` je još uvek potrebna.
3. **Ispravljanje Mach memorijskog unosa**
* Umetnite pravo slanja sa `thread_set_special_port()` i prepišite polje `0x18` imenom udaljenog unosa.
4. **Finalizacija**
* Validirajte udaljeni objekat i mapirajte ga sa udaljenim pozivom na `xpc_shmem_remote()`.

## 5. Postizanje potpune kontrole

Kada su dostupne proizvoljne izvršne i deljene memorijske povratne veze, efikasno posedujete ciljni proces:

* **Proizvoljno čitanje/pisanje memorije** — koristite `memcpy()` između lokalnih i deljenih oblasti.
* **Pozivi funkcija sa > 8 argumenata** — stavite dodatne argumente na stek prema arm64 konvenciji pozivanja.
* **Prenos Mach portova** — prosledite prava u Mach porukama putem uspostavljenih portova.
* **Prenos deskriptora datoteka** — iskoristite fileports (vidi *triple_fetch*).

Sve ovo je obavijeno u [`threadexec`](https://github.com/bazad/threadexec) biblioteci za laku ponovnu upotrebu.

---

## 6. Nuance Apple Silicon (arm64e)

Na Apple Silicon uređajima (arm64e) **Kodovi za autentifikaciju pokazivača (PAC)** štite sve adrese povratka i mnoge pokazivače funkcija. Tehnike preuzimanja niti koje *ponovo koriste postojeći kod* nastavljaju da funkcionišu jer originalne vrednosti u `lr`/`pc` već nose važeće PAC potpise. Problemi se javljaju kada pokušate da skočite na memoriju pod kontrolom napadača:

1. Alocirajte izvršnu memoriju unutar cilja (udaljeni `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Kopirajte svoj payload.
3. Unutar *udaljenog* procesa potpišite pokazivač:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Postavite `pc = ptr` u stanju otete niti.

Alternativno, ostanite PAC-usaglasni povezivanjem postojećih gadgeta/funkcija (tradicionalni ROP).

## 7. Detekcija i Ojačavanje sa EndpointSecurity

**EndpointSecurity (ES)** okvir izlaže kernel događaje koji omogućavaju odbrambenim snagama da posmatraju ili blokiraju pokušaje injekcije niti:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – aktivira se kada proces zatraži port druge niti (npr. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emituje se svaki put kada se niti kreira u *drugom* zadatku.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (dodato u macOS 14 Sonoma) – ukazuje na manipulaciju registrima postojeće niti.

Minimalni Swift klijent koji ispisuje događaje udaljenih niti:
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
Upit sa **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Razmatranja o ojačanom izvršavanju

Distribucija vaše aplikacije **bez** `com.apple.security.get-task-allow` prava sprečava napadače koji nisu root da dobiju njen task-port. Sistem zaštite integriteta (SIP) i dalje blokira pristup mnogim Apple binarnim datotekama, ali softver trećih strana mora eksplicitno da se isključi.

## 8. Nedavni javni alati (2023-2025)

| Alat | Godina | Napomene |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompaktni PoC koji demonstrira PAC-svesti preuzimanje niti na Ventura/Sonoma |
| `remote_thread_es` | 2024 | EndpointSecurity pomoćnik koji koriste nekoliko EDR dobavljača za prikazivanje `REMOTE_THREAD_CREATE` događaja |

> Čitanje izvornog koda ovih projekata je korisno za razumevanje promena API-ja uvedenih u macOS 13/14 i za održavanje kompatibilnosti između Intel ↔ Apple Silicon.

## Reference

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
