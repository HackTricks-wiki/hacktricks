# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Time namespace virtualizuje odabrane satove monotonic-style umesto sistemskog sata hosta. U praksi to znači privatne offsete za **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**, kao i povezane prikaze **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** i **`CLOCK_BOOTTIME_ALARM`**. Ne virtualizuje **`CLOCK_REALTIME`**, tako da `date` i logika isteka sertifikata i dalje očitavaju sistemski sat hosta, osim ako neki drugi mehanizam ne interveniše.<sup>[[1]](#references)</sup>

Glavna svrha je da procesu omogući očitavanje kontrolisanih offseta proteklog vremena bez menjanja globalnog prikaza vremena na hostu. Ovo je korisno za checkpoint/restore workflows, determinističko testiranje i napredno ponašanje runtime-a. Obično nije primarna isolation kontrola na isti način kao mount ili user namespaces, ali i dalje doprinosi tome da okruženje procesa bude samostalnije.

Iz offensive perspektive, ovaj namespace je obično relevantniji za **reconnaissance, timer skew i razumevanje runtime-a** nego za direktan breakout. Ipak, važan je zato što sve veći broj container runtime-ova i checkpoint/restore workflows sada može eksplicitno da ga zatraži.

## Laboratorija

Ako ga kernel hosta i userspace podržavaju, namespace možete proveriti pomoću:
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
Podrška se razlikuje u zavisnosti od verzija kernela i alata, pa je ova stranica više namenjena razumevanju mehanizma nego očekivanju da će on biti vidljiv u svakom lab okruženju. Važno zapažanje je da `date` i dalje treba da odražava wall clock hosta, dok su vrednosti zasnovane na monotonic/boottime clock-u one koje se menjaju kada se konfigurišu nenulte vrednosti pomaka.

### Specifičnosti kreiranja

Time namespaces su donekle neuobičajeni u poređenju sa mount, PID ili network namespaces:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` kreira novi time namespace za **buduću decu**.
- Pozivajući task ostaje u svom trenutnom time namespace-u.
- `/proc/<pid>/ns/time_for_children` je zato često zanimljiviji od `/proc/<pid>/ns/time` prilikom debug-ovanja runtime setup-a.

Prozor za upis je takođe specifičan. Pomaci u `/proc/<pid>/timens_offsets` moraju biti upisani pre nego što se novi time namespace u potpunosti popuni taskovima koji se izvršavaju; u praksi runtime-i to rade tokom uskog setup prozora između kreiranja namespace-a i pokretanja finalnog payload-a. Kada task već radi u njemu, kasniji upisi ne uspevaju sa greškom `EACCES`. Zato low-level runtime-i tretiraju setup time namespace-a kao rani bootstrap korak, umesto da pokušavaju da izmene pomake iz već pokrenutog procesa unutar kontejnera.<sup>[[1]](#references)</sup>

### Vremenski pomaci

Linux time namespaces izlažu pomake specifične za namespace kroz `/proc/<pid>/timens_offsets`. Format je skup imena ili ID-jeva clock-ova, zajedno sa delta-vrednostima u sekundama i nanosekundama u odnosu na početni time namespace.<sup>[[1]](#references)</sup>

U praksi je najpouzdaniji workflow namenjen korisniku da prepusti alatu `unshare` upis tih pomaka:
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
Važna je suština, a ne tačna sintaksa komande: container može da vidi drugačiji prikaz nalik uptime-u, bez menjanja sistemskog sata hosta.

### `unshare` Helper Flags

Novije verzije `util-linux` pružaju praktične flags koji automatski upisuju offsete tokom kreiranja namespace-a:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ove flags su uglavnom poboljšanje upotrebljivosti, ali takođe olakšavaju prepoznavanje ove funkcije u dokumentaciji, test harnesses i runtime wrapperima.

## Runtime Usage

Time namespaces su noviji i ređe se univerzalno koriste od mount ili PID namespaces. OCI Runtime Specification v1.1 dodala je eksplicitnu podršku za `time` namespace i polje `linux.timeOffsets`, a moderni runtimes mogu da preslikaju te podatke u kernel bootstrap tok. Minimalni OCI fragment izgleda ovako:
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
Ovo je važno zato što time namespacing pretvara time namespace iz usko specijalizovanog kernel primitiva u nešto što runtime-i mogu portabilno da zahtevaju. Ovo takođe objašnjava zašto interne komponente runtime-a zahtevaju eksplicitan korak sinhronizacije: offset mora biti upisan u `/proc/<pid>/timens_offsets` pre nego što payload kontejnera u potpunosti uđe u novi namespace.

Stack-ovi za checkpoint/restore, kao što je CRIU, jedan su od glavnih razloga iz stvarnog sveta zbog kojih ovo uopšte postoji. Bez time namespace-ova, obnavljanje pauziranog workload-a izazvalo bi skok monotonic i boot-time clock-ova za onoliko vremena koliko je workload proveo suspendovan.<sup>[[2]](#references)</sup>

## Uticaj na bezbednost

Postoji manje klasičnih breakout priča usmerenih na time namespace nego na druge tipove namespace-ova. Rizik ovde obično nije u tome što time namespace direktno omogućava escape, već u tome što ga čitaoci potpuno ignorišu i zato ne uočavaju kako napredni runtime-i mogu oblikovati ponašanje procesa.

U specijalizovanim okruženjima, izmenjeni monotonic ili boottime prikazi mogu uticati na:

- ponašanje timeout-a i retry-ja
- watchdog-e i lease logiku
- ponašanje `timerfd`, `nanosleep` i `clock_nanosleep`
- forenziku checkpoint/restore procesa
- telemetry proteklog vremena i heuristike zasnovane na uptime-u

Dakle, iako je ovo retko prvi namespace koji ćete abuse-ovati, može apsolutno objasniti "nemoguće" ponašanje vezano za vreme tokom procene.

## Abuse

Ovde obično ne postoji direktan breakout primitive, ali izmenjeno ponašanje clock-a i dalje može biti korisno za razumevanje execution okruženja, identifikovanje naprednih funkcija runtime-a i uočavanje logike zasnovane na timer-ima koja se meri u odnosu na monotonic clock-ove, umesto na wall clock time:
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
Ako poredite dva procesa, razlike ovde mogu pomoći da se objasne neobično ponašanje u vezi sa vremenom, artefakti checkpoint/restore procesa ili neslaganja u logging-u specifična za okruženje.

Praktični aspekti relevantni za napadače:

- zbuniti logiku za backoff, sleep ili watchdog implementiranu pomoću monotonic clocks
- objasniti zašto se `/proc/uptime` i ponašanje zasnovano na timer-ima ne slažu sa očekivanjima wall-clock vremena na hostu
- prepoznati CRIU/checkpoint-restore workflow-e i druge napredne runtime funkcije
- uočiti okruženja u kojima pridruživanje target time namespace-u pomoću `nsenter -T -t <pid> -- ...` može reprodukovati ponašanje container-local timer-a radi debugging-a ili post-exploitation aktivnosti

Uticaj:

- gotovo uvek reconnaissance ili razumevanje okruženja
- korisno za objašnjavanje anomalija u logging-u, uptime-u ili checkpoint/restore procesima
- korisno za analizu sleep-ova, retry-ja i timer-a zasnovanih na monotonic time-u
- obično nije direktan mehanizam za container escape sam po sebi

Važna nijansa u vezi sa abuse-om jeste da time namespaces ne virtualizuju `CLOCK_REALTIME`, pa sami po sebi ne omogućavaju napadaču da falsifikuje wall clock na hostu ili direktno pokvari provere isteka sertifikata na nivou celog sistema. Njihova vrednost uglavnom je u zbunjivanju logike zasnovane na monotonic time-u, reprodukovanju bug-ova specifičnih za okruženje ili razumevanju naprednog runtime ponašanja.

## Provere

Ove provere se uglavnom odnose na potvrđivanje toga da li runtime uopšte koristi privatni time namespace i da li je zaista postavio nenulte offset-e.
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

- U mnogim okruženjima ove vrednosti neće odmah ukazati na bezbednosni problem, ali vam govore da li je aktivna specijalizovana runtime funkcija.
- Ako se `time_for_children` razlikuje od `time`, pozivalac je možda pripremio time namespace namenjen samo podređenim procesima, ali sam nije ušao u njega.
- Ako se `date` poklapa sa hostom, ali se vrednosti zasnovane na monotonic/boottime ne poklapaju, verovatno posmatrate time namespacing, a ne neovlašćeno menjanje wall-clock vremena.
- Ako poredite dva procesa, razlike ovde mogu objasniti zbunjujuće ponašanje u vezi sa vremenom ili checkpoint/restore funkcionalnošću.

Kod većine container breakout scenarija, time namespace neće biti prva kontrola koju ćete ispitivati. Ipak, kompletan odeljak o container-security treba da ga pomene jer je deo savremenog kernel modela i povremeno je važan u naprednim runtime scenarijima.

## Reference

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
