# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

time namespace virtualizuje izabrane monotonic-style satove umesto host wall clock-a. U praksi to znači privatne offsete za **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**, plus blisko povezane prikaze **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** i **`CLOCK_BOOTTIME_ALARM`**. Ono ne virtualizuje **`CLOCK_REALTIME`**, tako da `date` i logika isteka sertifikata i dalje vide host wall clock osim ako neki drugi mehanizam ne ometa.

Glavna svrha je da omogući procesu da posmatra kontrolisane elapsed-time offsete bez menjanja globalnog time view-a hosta. Ovo je korisno za checkpoint/restore workflows, deterministic testing i napredno runtime ponašanje. Obično nije glavna isolation kontrola kao mount ili user namespaces, ali i dalje doprinosi tome da procesno okruženje bude samostalnije.

Sa ofanzivne tačke gledišta, ovaj namespace je obično relevantniji za **reconnaissance, timer skew i runtime understanding** nego za direktan breakout. Ipak, važan je jer sve više container runtimes i checkpoint/restore workflows sada mogu da ga zatraže eksplicitno.

## Lab

Ako host kernel i userspace podržavaju to, možete da pregledate namespace sa:
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
Podrška zavisi od verzije kernela i alata, tako da je ova stranica više o razumevanju mehanizma nego o očekivanju da će biti vidljiv u svakom lab okruženju. Važno zapažanje je da `date` i dalje treba da odražava host wall clock, dok su vrednosti zasnovane na monotonic/boottime one koje se menjaju kada su konfigurisani nenulti offsets.

### Creation Nuance

Time namespaces su malo neobični u poređenju sa mount, PID ili network namespaces:

- `unshare(CLONE_NEWTIME)` kreira novi time namespace za **buduću decu**.
- Pozvani task ostaje u svom trenutnom time namespace-u.
- `/proc/<pid>/ns/time_for_children` je zato često zanimljiviji od `/proc/<pid>/ns/time` pri debagovanju runtime setup-a.

Prozor za upis je takođe specijalan. Offsets u `/proc/<pid>/timens_offsets` moraju biti upisani pre nego što je novi time namespace u potpunosti popunjen running tasks; u praksi runtimes to rade tokom uskog setup prozora između kreiranja namespace-a i pokretanja finalnog payload-a. Jednom kada task već radi tamo, kasniji upisi padaju sa `EACCES`. Zato low-level runtimes tretiraju time-namespace setup kao rani bootstrap korak umesto da pokušavaju da patch-uju offsets iz već pokrenutog container procesa.

### Time Offsets

Linux time namespaces izlažu per-namespace offsets kroz `/proc/<pid>/timens_offsets`. Format je skup clock naziva ili ID-ova plus second/nanosecond delte u odnosu na initial time namespace.

U praksi, najpouzdaniji user-facing workflow je da pustite `unshare` da upiše te offsets umesto vas:
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
Važna stvar nije tačna sintaksa komande, već ponašanje: container može da posmatra drugačiji uptime-like prikaz bez menjanja host wall clock-a.

### `unshare` Helper Flags

Nedavne `util-linux` verzije pružaju convenience flags koji automatski upisuju offset-e tokom kreiranja namespace-a:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ovi flagovi su uglavnom poboljšanje upotrebljivosti, ali takođe olakšavaju prepoznavanje ove funkcije u dokumentaciji, test harnesses i runtime wrapper-ima.

## Runtime Usage

Time namespaces su noviji i manje univerzalno korišćeni od mount ili PID namespaces. OCI Runtime Specification v1.1 je dodao eksplicitnu podršku za `time` namespace i polje `linux.timeOffsets`, a moderni runtimes mogu da mapiraju te podatke u kernel bootstrap flow. Minimalni OCI fragment izgleda ovako:
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
Ovo je važno zato što pretvara time namespacing iz nišne kernel primitive u nešto što runtimes mogu portabilno da zahtevaju. Takođe objašnjava zašto internim delovima runtime-a treba eksplicitni korak sinhronizacije: offset mora da se upiše u `/proc/<pid>/timens_offsets` pre nego što container payload u potpunosti uđe u novi namespace.

Checkpoint/restore stackovi kao što je CRIU jedan su od glavnih praktičnih razloga što ovo uopšte postoji. Bez time namespaces, vraćanje pauziranog workload-a bi nateralo monotonic i boot-time clock-ove da skoče za iznos vremena tokom kog je workload bio suspendovan.

## Security Impact

Postoji manje klasičnih breakout priča fokusiranih na time namespace nego na druge tipove namespace-a. Rizik ovde obično nije u tome da time namespace direktno omogućava escape, već u tome što ga čitaoci potpuno ignorišu i time propuštaju kako napredni runtimes mogu da oblikuju ponašanje procesa.

U specijalizovanim okruženjima, izmenjeni monotonic ili boottime prikazi mogu uticati na:

- timeout i retry ponašanje
- watchdogs i lease logiku
- `timerfd`, `nanosleep`, i `clock_nanosleep` ponašanje
- checkpoint/restore forensics
- elapsed-time telemetry i heuristike zasnovane na uptime-u

Dakle, iako ovo retko predstavlja prvi namespace koji ćete abuse-ovati, može potpuno da objasni "nemoguće" timing ponašanje tokom procene.

## Abuse

Obično nema direktne breakout primitive ovde, ali izmenjeno ponašanje clock-ova i dalje može biti korisno za razumevanje execution environment-a, identifikovanje naprednih runtime features, i uočavanje timer-based logike koja se meri prema monotonic clock-ovima umesto prema wall clock vremenu:
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
Ako upoređujete dva procesa, razlike ovde mogu pomoći da se objasni čudno ponašanje tajminga, artifacts checkpoint/restore, ili neusklađenosti u logovanju specifične za okruženje.

Praktični uglovi relevantni za napadača:

- zbuniti backoff, sleep, ili watchdog logiku implementiranu pomoću monotonic clocks
- objasniti zašto se `/proc/uptime` i ponašanje vođeno timerima ne slažu sa očekivanjima wall-clock vremena sa host strane
- prepoznati CRIU/checkpoint-restore workflows i druge napredne runtime funkcije
- uočiti okruženja gde pridruživanje target time namespace-u pomoću `nsenter -T -t <pid> -- ...` može reprodukovati container-local timer ponašanje radi debugovanja ili post-exploitation

Uticaj:

- gotovo uvek reconnaissance ili razumevanje okruženja
- korisno za objašnjavanje logovanja, uptime-a, ili checkpoint/restore anomalija
- korisno za analiziranje sleep, retries, i timer-a zasnovanih na monotonic-time
- obično nije direktan container-escape mehanizam sam po sebi

Važna nijansa zloupotrebe je da time namespaces ne virtualizuju `CLOCK_REALTIME`, pa sami po sebi ne dozvoljavaju napadaču da falsifikuje host wall clock ili direktno pokvari provere isteka sertifikata na nivou celog sistema. Njihova vrednost je uglavnom u zbunjivanju logike zasnovane na monotonic-time, reprodukovanju bugova specifičnih za okruženje, ili razumevanju naprednog runtime ponašanja.

## Checks

Ove provere se uglavnom odnose na potvrdu da li runtime uopšte koristi private time namespace i da li je zaista postavio ne-nulte offsets.
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
Šta je zanimljivo ovde:

- U mnogim okruženjima ove vrednosti neće dovesti do trenutnog security nalaza, ali ipak otkrivaju da je u upotrebi specijalizovana runtime funkcija.
- Ako se `time_for_children` razlikuje od `time`, caller je možda pripremio child-only time namespace u koji sam nije ušao.
- Ako se `date` poklapa sa hostom, ali monotonic/boottime-based vrednosti ne, verovatno gledate time namespacing, a ne wall-clock tampering.
- Ako poredite dva procesa, razlike ovde mogu objasniti zbunjujuće timing ili checkpoint/restore ponašanje.

Za većinu container breakouts, time namespace nije prva kontrola koju ćete istražiti. Ipak, kompletan container-security odeljak bi trebalo da ga pomene jer je deo modernog kernel modela i povremeno je bitan u naprednim runtime scenarijima.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
