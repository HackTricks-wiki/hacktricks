# Thread Injection putem Task porta u macOS-u

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Najpre se funkcija `task_threads()` poziva na task portu kako bi se dobila lista thread-ova iz udaljenog task-a. Zatim se bira thread za hijacking. Ovaj pristup se razlikuje od konvencionalnih metoda code injection-a, jer je kreiranje novog remote thread-a zabranjeno mitigacijom koja blokira `thread_create_running()`.<sup>[[1]](#references)</sup>

Za kontrolu thread-a poziva se `thread_suspend()`, čime se zaustavlja njegovo izvršavanje.<sup>[[1]](#references)</sup>

Jedine dozvoljene operacije nad remote thread-om obuhvataju njegovo **zaustavljanje** i **pokretanje**, kao i **dohvatanje**/**izmenu** vrednosti njegovih registara. Remote function calls se pokreću postavljanjem registara `x0` do `x7` na **argumente**, konfigurisanjem registra `pc` da pokazuje na željenu funkciju i nastavljanjem izvršavanja thread-a. Da bi se sprečilo rušenje thread-a nakon povratka iz funkcije, neophodno je detektovati povratak.<sup>[[1]](#references)</sup>

Jedna strategija podrazumeva registrovanje **exception handler-a** za remote thread pomoću `thread_set_exception_ports()`, uz postavljanje registra `lr` na nevažeću adresu pre poziva funkcije. To izaziva exception nakon izvršavanja funkcije, pri čemu se poruka šalje na exception port, što omogućava pregled stanja thread-a i preuzimanje povratne vrednosti. Druga mogućnost, preuzeta iz exploit-a *triple_fetch* autora Ian Beer-a, jeste postavljanje registra `lr` tako da izvršavanje ide u beskonačnu petlju; registri thread-a se zatim neprekidno nadgledaju sve dok `pc` ne pokaže na tu instrukciju.<sup>[[1]](#references)</sup>

## 2. Mach ports za komunikaciju

Sledeća faza obuhvata uspostavljanje Mach port-ova radi omogućavanja komunikacije sa remote thread-om. Ovi port-ovi služe za prenos proizvoljnih send/receive prava između task-ova.<sup>[[1]](#references)</sup>

Za dvosmernu komunikaciju kreiraju se dva Mach receive right-a: jedan u lokalnom, a drugi u remote task-u. Zatim se send right za svaki port prenosi odgovarajućem task-u, čime se omogućava razmena poruka.<sup>[[1]](#references)</sup>

Kada je reč o lokalnom port-u, receive right poseduje lokalni task. Port se kreira pomoću `mach_port_allocate()`. Izazov predstavlja prenos send right-a za ovaj port u remote task.<sup>[[1]](#references)</sup>

Jedna strategija podrazumeva korišćenje `thread_set_special_port()` za smeštanje send right-a za lokalni port u `THREAD_KERNEL_PORT` remote thread-a. Zatim se remote thread-u nalaže da pozove `mach_thread_self()` kako bi preuzeo send right.<sup>[[1]](#references)</sup>

Za remote port postupak je praktično obrnut. Remote thread-u se nalaže da generiše Mach port pomoću `mach_reply_port()` (pošto `mach_port_allocate()` nije pogodan zbog načina na koji vraća rezultat). Nakon kreiranja port-a, u remote thread-u se poziva `mach_port_insert_right()` radi uspostavljanja send right-a. Ovo pravo se zatim smešta u kernel pomoću `thread_set_special_port()`. U lokalnom task-u se nad remote thread-om koristi `thread_get_special_port()` kako bi se preuzeo send right za novokreirani Mach port u remote task-u.<sup>[[1]](#references)</sup>

Završetak ovih koraka rezultuje uspostavljanjem Mach port-ova, čime se postavljaju temelji za dvosmernu komunikaciju.<sup>[[1]](#references)</sup>

## 3. Osnovni primitivni mehanizmi za čitanje/upis u memoriju

U ovom odeljku fokus je na korišćenju execute primitive-a za uspostavljanje osnovnih primitivnih mehanizama za čitanje/upis u memoriju. Ovi početni koraci su ključni za sticanje veće kontrole nad remote procesom, iako primitivni mehanizmi u ovoj fazi nemaju mnogo namena. Uskoro će biti unapređeni u naprednije verzije.<sup>[[1]](#references)</sup>

### Čitanje i upis u memoriju pomoću execute primitive-a

Cilj je obavljati čitanje i upis u memoriju pomoću određenih funkcija. Za **čitanje memorije**:
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
Ove funkcije odgovaraju sledećem asemblerskom kodu:
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
Sa ovim utvrđenim primitivima, stvoreni su uslovi za kreiranje deljene memorije, što predstavlja značajan napredak u kontroli udaljenog procesa.<sup>[[1]](#references)</sup>

## 4. Podešavanje deljene memorije

Cilj je uspostaviti deljenu memoriju između lokalnih i udaljenih taskova, čime se pojednostavljuje prenos podataka i omogućava pozivanje funkcija sa više argumenata. Ovaj pristup koristi `libxpc` i njegov tip objekta `OS_xpc_shmem`, koji je izgrađen na Mach memory entries.<sup>[[1]](#references)</sup>

### Pregled procesa

1. **Alokacija memorije**
* Alocirajte memoriju za deljenje pomoću `mach_vm_allocate()`.
* Koristite `xpc_shmem_create()` za kreiranje `OS_xpc_shmem` objekta za alocirani region.
2. **Kreiranje deljene memorije u udaljenom procesu**
* Alocirajte memoriju za `OS_xpc_shmem` objekat u udaljenom procesu (`remote_malloc`).
* Kopirajte lokalni template objekat; i dalje je potreban fix-up ugrađenog Mach send right-a na offsetu `0x18`.
3. **Ispravljanje Mach memory entry-ja**
* Umetnite send right pomoću `thread_set_special_port()` i prepišite polje `0x18` imenom udaljenog entry-ja.
4. **Završetak**
* Validirajte udaljeni objekat i mapirajte ga udaljenim pozivom ka `xpc_shmem_remote()`.

## 5. Postizanje potpune kontrole

Kada su dostupni proizvoljno izvršavanje i back-channel putem deljene memorije, praktično posedujete ciljni proces:<sup>[[1]](#references)</sup>

* **Proizvoljni memory R/W** — koristite `memcpy()` između lokalnih i deljenih regiona.
* **Pozivi funkcija sa više od 8 argumenata** — postavite dodatne argumente na stek u skladu sa arm64 calling convention-om.
* **Prenos Mach portova** — prosleđujte prava u Mach porukama putem uspostavljenih portova.
* **Prenos file descriptor-a** — koristite fileports (pogledajte *triple_fetch*).

Sve ovo je obuhvaćeno bibliotekom [`threadexec`](https://github.com/bazad/threadexec) radi jednostavne ponovne upotrebe.

---

## 6. Specifičnosti Apple Silicon-a (arm64e)

Na Apple Silicon uređajima (arm64e), **Pointer Authentication Codes (PAC)** štite sve povratne adrese i mnoge pokazivače na funkcije. Thread-hijacking tehnike koje *ponovo koriste postojeći code* i dalje funkcionišu jer originalne vrednosti u `lr`/`pc` već sadrže važeće PAC potpise. Problemi nastaju kada pokušate da skočite na memoriju pod kontrolom napadača:

1. Alocirajte izvršnu memoriju unutar cilja (udaljeni `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Kopirajte svoj payload.
3. Unutar *udaljenog* procesa potpišite pokazivač:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Postavite `pc = ptr` u stanju otetog thread-a.

Alternativno, ostanite PAC-compliant ulančavanjem postojećih gadgets/functions (tradicionalni ROP).

## 7. Detekcija i hardening uz EndpointSecurity

**EndpointSecurity (ES)** framework izlaže kernel događaje koji defenderima omogućavaju da posmatraju ili blokiraju pokušaje thread-injection-a:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – aktivira se kada proces zatraži port drugog task-a (npr. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emituje se svaki put kada se thread kreira u *drugom task-u*.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (dodat u macOS 14 Sonoma) – ukazuje na manipulaciju registrima postojećeg thread-a.

Minimalni Swift klijent koji ispisuje događaje udaljenih thread-ova:
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
Upit pomoću **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Razmatranja u vezi sa hardened runtime-om

Distribuiranje vaše aplikacije **bez** entitlement-a `com.apple.security.get-task-allow` sprečava non-root napadače da pribave njen task-port. System Integrity Protection (SIP) i dalje blokira pristup mnogim Apple binarnim datotekama, ali third-party software mora izričito da se odrekne zaštite.

## 8. Nedavni javno dostupni alati (2023-2025)

| Alat | Godina | Napomene |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Kompaktan PoC koji demonstrira PAC-aware thread hijacking na Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | EndpointSecurity pomoćni alat koji nekoliko EDR vendora koristi za otkrivanje događaja `REMOTE_THREAD_CREATE` |

> Čitanje izvornog koda ovih projekata korisno je za razumevanje promena API-ja uvedenih u macOS 13/14 i za održavanje kompatibilnosti između Intel ↔ Apple Silicon.

## References

- [1] [Zaobilaženje ograničenja platformskih binarnih datoteka pomoću task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
