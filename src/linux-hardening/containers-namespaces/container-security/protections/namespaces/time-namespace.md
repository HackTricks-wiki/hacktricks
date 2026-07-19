# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Time namespace virtuelizuje odabrane satove monotonic-style umesto sistemskog sata hosta. U praksi, to znači privatne pomake za **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**, kao i za povezane prikaze **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** i **`CLOCK_BOOTTIME_ALARM`**. Ne virtuelizuje **`CLOCK_REALTIME`**, pa `date` i logika za istek sertifikata i dalje posmatraju sistemski sat hosta, osim ako neki drugi mehanizam ne utiče na to.

Osnovna svrha je da procesu omogući posmatranje kontrolisanih pomaka proteklog vremena bez menjanja globalnog prikaza vremena na hostu. Ovo je korisno za checkpoint/restore workflows, determinističko testiranje i napredno ponašanje runtime-a. Obično nije primarna kontrola izolacije na isti način kao mount ili user namespaces, ali i dalje doprinosi tome da okruženje procesa bude samostalnije.

Iz ofanzivne perspektive, ovaj namespace je obično relevantniji za **reconnaissance, timer skew i razumevanje runtime-a** nego za direktan breakout. Ipak, važan je zato što sve veći broj container runtime-ova i checkpoint/restore workflows sada može eksplicitno da ga zatraži.

## Lab

Ako ga kernel hosta i userspace podržavaju, namespace možete ispitati pomoću:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Podrška varira u zavisnosti od verzije kernela i alata, pa je ova stranica više namenjena razumevanju mehanizma nego očekivanju da će on biti vidljiv u svakom lab okruženju. Važno zapažanje je da `date` i dalje treba da odražava wall clock hosta, dok su vrednosti zasnovane na monotonic/boottime mehanizmima one koje se menjaju kada se konfigurišu nenulti offset-i.

### Specifičnosti kreiranja

Time namespaces su pomalo neuobičajeni u poređenju sa mount, PID ili network namespaces:

- `unshare(CLONE_NEWTIME)` kreira novi time namespace za **buduću decu**.
- Pozivajući task ostaje u svom trenutnom time namespace-u.
- Zbog toga je `/proc/<pid>/ns/time_for_children>` često interesantniji od `/proc/<pid>/ns/time` kada se analizira podešavanje runtime-a.

Prozor za upis je takođe specifičan. Offset-i u `/proc/<pid>/timens_offsets` moraju biti upisani pre nego što se novi time namespace u potpunosti popuni taskovima koji se izvršavaju; u praksi runtime-i to rade tokom uskog prozora za podešavanje između kreiranja namespace-a i pokretanja finalnog payload-a. Kada je task već pokrenut unutar njega, kasniji upisi neuspešno se završavaju greškom `EACCES`. Zbog toga low-level runtime-i podešavanje time namespace-a obrađuju kao rani bootstrap korak, umesto da pokušavaju da izmene offset-e iz već pokrenutog container procesa.

### Vremenski offset-i

Linux time namespaces izlažu offset-e specifične za namespace putem `/proc/<pid>/timens_offsets`. Format je skup naziva ili ID-jeva clock-ova, zajedno sa delta-vrednostima u sekundama i nanosekundama u odnosu na initial time namespace.

U praksi je najpouzdaniji workflow namenjen korisniku da prepusti alatu `unshare` da upiše te offset-e:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Važna stvar nije tačna sintaksa komande, već ponašanje: container može da posmatra drugačiji prikaz sličan uptime-u bez menjanja host wall clock-a.

### `unshare` pomoćne zastavice

Novije verzije alata `util-linux` pružaju praktične zastavice koje automatski upisuju offset-e tokom kreiranja namespace-a:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ove zastavice su uglavnom poboljšanje upotrebljivosti, ali takođe olakšavaju prepoznavanje ove funkcionalnosti u dokumentaciji, test harness-ima i runtime wrapper-ima.

## Upotreba tokom izvršavanja

Time namespaces su noviji i ređe se univerzalno koriste od mount ili PID namespaces. OCI Runtime Specification v1.1 dodala je eksplicitnu podršku za `time` namespace i polje `linux.timeOffsets`, a moderni runtime-i mogu mapirati te podatke u kernel bootstrap tok. Minimalni OCI fragment izgleda ovako:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Ovo je važno zato što pretvara time namespacing iz usko specijalizovanog kernel primitive-a u nešto što runtime-i mogu prenosivo da zahtevaju. Takođe objašnjava zašto interne komponente runtime-a zahtevaju eksplicitan korak sinhronizacije: offset mora biti upisan u `/proc/<pid>/timens_offsets` pre nego što payload kontejnera u potpunosti uđe u novi namespace.

Stack-ovi za checkpoint/restore, kao što je CRIU, jedan su od glavnih praktičnih razloga zbog kojih ovo uopšte postoji. Bez time namespaces-a, vraćanje pauziranog workload-a izazvalo bi skok monotonic i boot-time satova za iznos vremena tokom kog je workload bio suspendovan.

## Uticaj na bezbednost

Postoji manje klasičnih breakout priča usmerenih na time namespace nego na druge tipove namespace-a. Rizik ovde obično nije u tome što time namespace direktno omogućava escape, već u tome što ga čitaoci potpuno zanemare i zato ne uoče kako napredni runtime-i mogu oblikovati ponašanje procesa.

U specijalizovanim okruženjima, izmenjeni prikazi monotonic ili boottime satova mogu uticati na:

- ponašanje timeout-a i retry-ja
- watchdog-e i lease logiku
- ponašanje `timerfd`, `nanosleep` i `clock_nanosleep`
- forenziku checkpoint/restore procesa
- telemetriju proteklog vremena i heuristike zasnovane na uptime-u

Dakle, iako je ovo retko prvi namespace koji ćete abuse-ovati, on apsolutno može objasniti „nemoguće“ ponašanje vremena tokom assessment-a.

## Abuse

Ovde obično ne postoji direktan breakout primitive, ali izmenjeno ponašanje satova i dalje može biti korisno za razumevanje execution environment-a, identifikovanje naprednih funkcija runtime-a i pronalaženje logike zasnovane na timer-ima koja se meri u odnosu na monotonic satove, a ne na wall clock time:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Ako poredite dva procesa, razlike ovde mogu pomoći u objašnjavanju neobičnog ponašanja vezanog za vreme, artefakata checkpoint/restore procesa ili nepodudaranja u logging-u specifičnih za okruženje.

Praktično relevantni aspekti za napadača:

- zbuniti backoff, sleep ili watchdog logiku implementiranu pomoću monotonic clocks
- objasniti zašto se `/proc/uptime` i ponašanje zasnovano na timer-ima ne slažu sa očekivanjima wall-clock vremena na hostu
- prepoznati CRIU/checkpoint-restore workflow-e i druge napredne runtime funkcije
- uočiti okruženja u kojima pridruživanje target time namespace-u pomoću `nsenter -T -t <pid> -- ...` može reprodukovati ponašanje timer-a lokalno u container-u radi debug-ovanja ili post-exploitation aktivnosti

Uticaj:

- gotovo uvek reconnaissance ili razumevanje okruženja
- korisno za objašnjavanje anomalija u logging-u, uptime-u ili checkpoint/restore procesu
- korisno za analizu sleep-ova, retry-ja i timer-a zasnovanih na monotonic time-u
- obično nije direktan mehanizam za container escape sam po sebi

Važna nijansa u vezi sa abuse-om jeste da time namespaces ne virtualizuju `CLOCK_REALTIME`, pa sami po sebi ne omogućavaju napadaču da falsifikuje wall clock na hostu niti da direktno pokvari provere isteka sertifikata na nivou celog sistema. Njihova vrednost uglavnom se ogleda u zbunjivanju logike zasnovane na monotonic time-u, reprodukovanju bug-ova specifičnih za okruženje ili razumevanju naprednog runtime ponašanja.

## Provere

Ove provere se uglavnom odnose na potvrđivanje da li runtime uopšte koristi privatni time namespace i da li je zaista postavio nenulte offset-e.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Šta je ovde zanimljivo:

- U mnogim okruženjima ove vrednosti neće odmah ukazati na bezbednosni nalaz, ali vam govore da li je aktivna specijalizovana runtime funkcija.
- Ako se `time_for_children` razlikuje od `time`, pozivalac je možda pripremio time namespace namenjen samo deci procesa, ali sam nije ušao u njega.
- Ako se `date` poklapa sa hostom, ali se vrednosti zasnovane na monotonic/boottime ne poklapaju, verovatno posmatrate time namespacing, a ne menjanje wall-clock vremena.
- Ako poredite dva procesa, razlike ovde mogu objasniti zbunjujuće ponašanje u vezi sa vremenom ili checkpoint/restore funkcionalnošću.

Kod većine container breakout scenarija, time namespace nije prva kontrola koju ćete ispitivati. Ipak, kompletna sekcija o container security treba da ga pomene jer je deo modernog modela kernela i povremeno je važan u naprednim runtime scenarijima.

## Reference

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
