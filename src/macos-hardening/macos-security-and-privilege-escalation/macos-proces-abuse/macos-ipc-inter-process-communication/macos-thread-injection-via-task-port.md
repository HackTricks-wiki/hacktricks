# macOS Thread Injection putem Task porta

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Na početku se funkcija `task_threads()` poziva nad task port-om kako bi se dobila lista thread-ova iz udaljenog task-a. Zatim se bira thread za hijacking. Ovaj pristup se razlikuje od konvencionalnih metoda code injection-a, jer je kreiranje novog udaljenog thread-a onemogućeno mitigacijom koja blokira `thread_create_running()`.<sup>[[1]](#references)</sup>

Da bi se preuzela kontrola nad thread-om, poziva se `thread_suspend()`, čime se zaustavlja njegovo izvršavanje.<sup>[[1]](#references)</sup>

Jedine dozvoljene operacije nad udaljenim thread-om obuhvataju njegovo **zaustavljanje** i **pokretanje**, kao i **dohvatanje**/**izmenu** vrednosti njegovih registara. Pozivi udaljenih funkcija pokreću se postavljanjem registara `x0` do `x7` na **argumente**, konfigurisanjem registra `pc` tako da pokazuje na željenu funkciju i nastavljanjem izvršavanja thread-a. Da bi se sprečilo rušenje thread-a nakon povratka iz funkcije, neophodno je detektovati povratak.<sup>[[1]](#references)</sup>

Jedna strategija podrazumeva registrovanje **exception handler-a** za udaljeni thread pomoću `thread_set_exception_ports()`, uz postavljanje registra `lr` na nevažeću adresu pre poziva funkcije. Ovo pokreće exception nakon izvršavanja funkcije i šalje poruku na exception port, čime se omogućava inspekcija stanja thread-a i preuzimanje povratne vrednosti. Alternativno, kao u exploitu *triple_fetch* autora Ian Beer-a, `lr` se postavlja tako da izvršavanje ide u beskonačnu petlju; registri thread-a se zatim neprekidno nadgledaju sve dok `pc` ne pokaže na tu instrukciju.<sup>[[1]](#references)</sup>

## 2. Mach port-ovi za komunikaciju

Sledeća faza obuhvata uspostavljanje Mach port-ova radi omogućavanja komunikacije sa udaljenim thread-om. Ovi port-ovi služe za prenos proizvoljnih send/receive prava između task-ova.<sup>[[1]](#references)</sup>

Za dvosmernu komunikaciju kreiraju se dva Mach receive prava: jedno u lokalnom, a drugo u udaljenom task-u. Zatim se send pravo za svaki port prenosi suprotnom task-u, čime se omogućava razmena poruka.<sup>[[1]](#references)</sup>

Kada je reč o lokalnom port-u, receive pravo poseduje lokalni task. Port se kreira pomoću `mach_port_allocate()`. Izazov je preneti send pravo na ovaj port u udaljeni task.<sup>[[1]](#references)</sup>

Jedna strategija podrazumeva korišćenje `thread_set_special_port()` za postavljanje send prava na lokalni port u `THREAD_KERNEL_PORT` udaljenog thread-a. Zatim se udaljenom thread-u nalaže da pozove `mach_thread_self()` kako bi preuzeo send pravo.<sup>[[1]](#references)</sup>

Za udaljeni port postupak je praktično obrnut. Udaljenom thread-u se nalaže da generiše Mach port pomoću `mach_reply_port()` (pošto `mach_port_allocate()` nije pogodan zbog načina na koji vraća rezultat). Nakon kreiranja port-a, u udaljenom thread-u se poziva `mach_port_insert_right()` kako bi se uspostavilo send pravo. Ovo pravo se zatim skladišti u kernelu pomoću `thread_set_special_port()`. U lokalnom task-u se potom nad udaljenim thread-om koristi `thread_get_special_port()` za preuzimanje send prava na novoalocirani Mach port u udaljenom task-u.<sup>[[1]](#references)</sup>

Završetak ovih koraka rezultira uspostavljanjem Mach port-ova i postavlja osnovu za dvosmernu komunikaciju.<sup>[[1]](#references)</sup>

## 3. Osnovni primitivi za čitanje/upis memorije

U ovom odeljku fokus je na korišćenju execute primitive-a za uspostavljanje osnovnih primitive-a za čitanje/upis memorije. Ovi početni koraci su ključni za sticanje veće kontrole nad udaljenim procesom, iako primitivi u ovoj fazi neće imati mnogo praktične koristi. Uskoro će biti unapređeni u naprednije verzije.<sup>[[1]](#references)</sup>

### Čitanje i upis memorije pomoću execute primitive-a

Cilj je obavljati čitanje i upis memorije pomoću određenih funkcija. Za **čitanje memorije**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Za **upisivanje u memoriju**:
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
### Identifikovanje odgovarajućih funkcija

Skeniranje uobičajenih biblioteka otkrilo je odgovarajuće kandidate za ove operacije:<sup>[[1]](#references)</sup>

1. **Čitanje memorije — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Upisivanje u memoriju — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Da biste izvršili 64-bitni upis na proizvoljnoj adresi:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Sa uspostavljenim ovim primitivama, stvoreni su uslovi za kreiranje deljene memorije, što predstavlja značajan napredak u kontroli udaljenog procesa.<sup>[[1]](#references)</sup>

## 4. Podešavanje deljene memorije

Cilj je uspostaviti deljenu memoriju između lokalnih i udaljenih taskova, čime se pojednostavljuje prenos podataka i omogućava pozivanje funkcija sa više argumenata. Pristup koristi `libxpc` i njegov tip objekta `OS_xpc_shmem`, koji je zasnovan na Mach memory entries.<sup>[[1]](#references)</sup>

### Pregled procesa

1. **Alokacija memorije**
* Alocirajte memoriju za deljenje pomoću `mach_vm_allocate()`.
* Koristite `xpc_shmem_create()` za kreiranje objekta `OS_xpc_shmem` za alocirani region.
2. **Kreiranje deljene memorije u udaljenom procesu**
* Alocirajte memoriju za objekat `OS_xpc_shmem` u udaljenom procesu (`remote_malloc`).
* Kopirajte lokalni template objekat; i dalje je potrebno izvršiti fix-up ugrađenog Mach send right-a na offsetu `0x18`.
3. **Ispravljanje Mach memory entry-ja**
* Umetnite send right pomoću `thread_set_special_port()` i prepišite polje `0x18` imenom udaljenog entry-ja.
4. **Finalizacija**
* Validirajte udaljeni objekat i mapirajte ga udaljenim pozivom ka `xpc_shmem_remote()`.

## 5. Postizanje potpune kontrole

Kada su dostupni proizvoljno izvršavanje i back-channel putem deljene memorije, praktično posedujete ciljni proces:<sup>[[1]](#references)</sup>

* **Proizvoljni memory R/W** — koristite `memcpy()` između lokalnih i deljenih regiona.
* **Pozivi funkcija sa > 8 argumenata** — smestite dodatne argumente na stack u skladu sa arm64 calling convention-om.
* **Prenos Mach portova** — prosleđujte prava u Mach porukama putem uspostavljenih portova.
* **Prenos file descriptor-a** — koristite fileports (pogledajte *triple_fetch*).

Sve ovo je upakovano u biblioteku [`threadexec`](https://github.com/bazad/threadexec) radi jednostavne ponovne upotrebe.

---

## 6. Specifičnosti Apple Silicon-a (arm64e)

Na Apple Silicon uređajima (arm64e), **Pointer Authentication Codes (PAC)** štite sve return address-e i mnoge function pointer-e. Tehnike preuzimanja niti koje *ponovo koriste postojeći code* i dalje funkcionišu, jer originalne vrednosti u `lr`/`pc` već sadrže važeće PAC potpise. Problemi nastaju kada pokušate da skočite na memory pod kontrolom napadača:

1. Alocirajte izvršnu memoriju unutar cilja (udaljeni `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Kopirajte svoj payload.
3. Unutar *udaljenog* procesa potpišite pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Postavite `pc = ptr` u stanje preotete niti.

Alternativno, ostanite usklađeni sa PAC-om tako što ćete ulančati postojeće gadgets/funkcije (tradicionalni ROP).

## 7. Detekcija i ojačavanje bezbednosti pomoću EndpointSecurity-ja

Framework **EndpointSecurity (ES)** izlaže kernel događaje koji defenderima omogućavaju da nadgledaju ili blokiraju pokušaje thread-injection-a:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – aktivira se kada proces zatraži port drugog task-a (npr. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – generiše se svaki put kada se thread kreira u *drugom* task-u.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (dodat u macOS 14 Sonoma) – ukazuje na manipulaciju registrima postojeće niti.

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
Upitovanje pomoću **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Razmatranja u vezi sa hardened-runtime

Distribuiranje vaše aplikacije **bez** entitilementa `com.apple.security.get-task-allow` sprečava napadače koji nisu root da pribave njen task-port. System Integrity Protection (SIP) i dalje blokira pristup mnogim Apple binarnim datotekama, ali third-party softver mora izričito da se isključi iz ove zaštite.

## 8. Nedavni javno dostupni alati (2023-2025)

| Alat | Godina | Napomene |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompaktan PoC koji demonstrira PAC-aware thread hijacking na sistemima Ventura/Sonoma |
| `remote_thread_es` | 2024 | EndpointSecurity pomoćni alat koji nekoliko EDR proizvođača koristi za detekciju događaja `REMOTE_THREAD_CREATE` |

> Čitanje izvornog koda ovih projekata korisno je za razumevanje promena u API-ju uvedenih u macOS 13/14 i za održavanje kompatibilnosti između Intel ↔ Apple Silicon platformi.

## Reference

- [1] [Zaobilaženje ograničenja platformskih binarnih datoteka pomoću task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
