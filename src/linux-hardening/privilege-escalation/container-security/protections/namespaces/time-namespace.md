# Vremenski namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Time namespace virtualizuje odabrane satove, posebno **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**. To je noviji i specijalizovaniji namespace u odnosu na mount, PID, network ili user namespaces, i retko je prvo na šta operater pomisli kada se govori o container hardening. Ipak, deo je moderne porodice namespaces i vredi ga konceptualno razumeti.

Glavna svrha je omogućiti procesu da posmatra kontrolisane offset-e za određene satove bez menjanja globalnog prikaza vremena na hostu. Ovo je korisno za checkpoint/restore workflows, deterministic testing, i neka napredna runtime ponašanja. Obično nije glavna kontrola izolacije na isti način kao mount ili user namespaces, ali i dalje doprinosi tome da procesno okruženje bude više samo-sadržajno.

## Lab

Ako host kernel i userspace to podržavaju, možete da pregledate namespace pomoću:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Support varies by kernel and tool versions, so this page is more about understanding the mechanism than expecting it to be visible in every lab environment.

### Vremenski pomaci

Linux time namespaces virtualizuju pomake za `CLOCK_MONOTONIC` i `CLOCK_BOOTTIME`. Trenutni pomaci po namespace-u su izloženi putem `/proc/<pid>/timens_offsets`, a na kernel-ima koji to podržavaju taj fajl može da izmeni proces koji poseduje `CAP_SYS_TIME` unutar odgovarajućeg namespace-a:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Datoteka sadrži nanosekundne razlike. Pomeranje `monotonic` za dva dana menja zapažanja slična uptime-u unutar tog namespace-a bez promene sistemskog sata (wall clock) hosta.

### `unshare` Pomoćne zastavice

Novije verzije `util-linux` pružaju praktične zastavice koje automatski upisuju pomake:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Ove zastavice su pretežno poboljšanje upotrebljivosti, ali takođe olakšavaju prepoznavanje funkcije u dokumentaciji i pri testiranju.

## Korišćenje za vreme izvršavanja

Time namespaces su noviji i ređe se koriste u poređenju sa mount ili PID namespaces. OCI Runtime Specification v1.1 je dodao eksplicitnu podršku za `time` namespace i polje `linux.timeOffsets`, a novije `runc` verzije implementiraju taj deo modela. Minimalni OCI fragment izgleda ovako:
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
Ovo je važno zato što time namespacing pretvara iz nišnog kernel primitiva u nešto što runtimes mogu prenosivo da zatraže.

## Bezbednosni uticaj

Postoji manje klasičnih breakout priča usmerenih na time namespace nego na druge tipove namespace-ova. Rizik ovde obično nije da time namespace direktno omogućava escape, već da čitaoci u potpunosti ignorišu tu mogućnost i zbog toga ne primete kako napredni runtimes mogu oblikovati ponašanje procesa. U specijalizovanim okruženjima, promenjeni prikazi sata mogu uticati na checkpoint/restore, observability, ili forenzičke pretpostavke.

## Zloupotreba

Obično ovde nema direktne breakout primitive, ali promenjeno ponašanje sata i dalje može biti korisno za razumevanje izvršnog okruženja i identifikovanje naprednih funkcionalnosti runtima:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Ako upoređujete dva procesa, razlike ovde mogu pomoći da se objasni neobično ponašanje u vezi sa vremenom, artefakti pri checkpoint/restore, ili neusaglašenosti u logging-u specifičnom za okruženje.

Impact:

- skoro uvek reconnaissance ili razumevanje okruženja
- korisno za objašnjenje logging-a, uptime-a, ili anomalija pri checkpoint/restore
- obično nije direktan container-escape mehanizam sam po sebi

Važna nijansa zloupotrebe je da time namespaces ne virtualizuju `CLOCK_REALTIME`, tako da same po sebi ne dozvoljavaju napadaču da falsifikuje host wall clock ili direktno pokvari provere isteka sertifikata na nivou sistema. Njihova vrednost je uglavnom u zbunjivanju logike zasnovane na monotonic-time, reprodukovanju bug-ova specifičnih za okruženje, ili razumevanju naprednog runtime ponašanja.

## Checks

Ove provere uglavnom potvrđuju da li runtime uopšte koristi privatni time namespace.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Šta je ovde zanimljivo:

- U mnogim okruženjima ove vrednosti neće dovesti do neposrednog sigurnosnog nalaza, ali pokazuju da li je aktivirana neka specijalizovana runtime funkcija.
- Ako upoređujete dva procesa, razlike ovde mogu objasniti zbunjujuće vremensko ponašanje ili ponašanje pri checkpoint/restore.

Za većinu container breakouts, time namespace nije prva kontrola koju ćete istražiti. Ipak, kompletna container-security sekcija treba da ga pomene jer je deo modernog kernel modela i povremeno je važna u naprednim runtime scenarijima.
