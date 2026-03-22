# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Time namespace virtualizuje odabrane časovnike, posebno **`CLOCK_MONOTONIC`** i **`CLOCK_BOOTTIME`**. To je noviji i specijalizovaniji namespace u odnosu na mount, PID, network, ili user namespaces, i retko je prva stvar o kojoj operator razmišlja kada se govori o container hardening. Ipak, deo je moderne porodice namespace-ova i vredi ga konceptualno razumeti.

Glavna svrha je omogućiti procesu da posmatra kontrolisane pomake za određene časovnike bez menjanja globalnog prikaza vremena na hostu. Ovo je korisno za checkpoint/restore tokove rada, deterministic testing, i neka napredna runtime ponašanja. Obično nije glavna mera izolacije na isti način kao mount ili user namespaces, ali i dalje doprinosi tome da okruženje procesa bude samostalnije.

## Lab

Ako host kernel i userspace to podržavaju, možete pregledati namespace pomoću:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Podrška zavisi od verzije kernela i alata, zato je ova stranica više o razumevanju mehanizma nego o očekivanju da će biti vidljiva u svakom lab okruženju.

### Vremenski pomaci

Linux time namespaces virtualizuju pomake za `CLOCK_MONOTONIC` i `CLOCK_BOOTTIME`. Trenutni pomaci po namespace-u izloženi su kroz `/proc/<pid>/timens_offsets`, koje na kernelima koji to podržavaju takođe može da izmeni proces koji poseduje `CAP_SYS_TIME` unutar odgovarajućeg namespace-a:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Fajl sadrži nanosekundne razlike. Pomeranje `monotonic` za dva dana menja posmatranja slična uptime-u unutar tog namespace-a bez promene host wall clock.

### `unshare` pomoćne zastavice

Novije verzije `util-linux` obezbeđuju pomoćne zastavice koje automatski upisuju pomake:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Ove zastavice su većinom poboljšanje upotrebljivosti, ali такође олакшавају препознавање функције у документацији и током тестирања.

## Runtime Usage

Time namespaces су новије и мање универзално коришћене него mount или PID namespaces. OCI Runtime Specification v1.1 додала је експлицитну подршку за `time` namespace и поље `linux.timeOffsets`, а новије `runc` верзије имплементирају тај део модела. Минимални OCI фрагмент изгледа овако:
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
Ovo je važno zato što time namespacing pretvara iz nišnog kernel primitiva u nešto što runtimes mogu prenosivo zahtevati.

## Sigurnosni uticaj

Postoji manje klasičnih slučajeva bekstva fokusiranih na time namespace nego na druge tipove namespace-a. Rizik ovde obično nije da time namespace direktno omogućava escape, već da ga čitaoci potpuno ignorišu i zbog toga propuste kako napredni runtimes mogu oblikovati ponašanje procesa. U specijalizovanim okruženjima, izmenjeni prikazi vremena mogu uticati na checkpoint/restore, observability ili forenzičke pretpostavke.

## Zloupotreba

Obično ovde nema direktnog primitiva za bekstvo, ali izmenjeno ponašanje sata može i dalje biti korisno za razumevanje izvršnog okruženja i identifikovanje naprednih funkcija runtime-a:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Ako upoređujete dva procesa, razlike ovde mogu pomoći da objasne čudno ponašanje u pogledu vremena, artefakte checkpoint/restore, ili neusaglašenosti u logovanju specifičnom za okruženje.

Impact:

- gotovo uvek reconnaissance ili razumevanje okruženja
- korisno za objašnjavanje anomalija u logovanju, uptime-a, ili checkpoint/restore anomalija
- obično nije direktan container-escape mehanizam sam po sebi

Važna nijansa zloupotrebe je da time namespaces ne virtualizuju `CLOCK_REALTIME`, pa same po sebi ne omogućavaju napadaču da falsifikuje sistemski sat hosta ili direktno pokvari sistemske provere isteka sertifikata. Njihova vrednost uglavnom leži u zbunjivanju logike zasnovane na monotoničkom vremenu, reprodukovanju grešaka specifičnih za okruženje, ili razumevanju naprednog ponašanja runtime-a.

## Checks

Ove provere uglavnom služe da potvrde da li runtime uopšte koristi privatni time namespace.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Šta je ovde interesantno:

- U mnogim okruženjima ove vrednosti neće dovesti do neposrednog sigurnosnog nalaza, ali vam govore da li je u upotrebi specijalizovana runtime funkcija.
- Ako upoređujete dva procesa, razlike ovde mogu objasniti zbunjujuće ponašanje u vezi sa tajmingom ili checkpoint/restore ponašanjem.

Za većinu container breakouts, time namespace nije prvi kontrolni mehanizam koji ćete istraživati. Ipak, kompletan container-security odeljak treba da ga pomene jer je deo modernog kernel modela i povremeno je bitan u naprednim runtime scenarijima.
{{#include ../../../../../banners/hacktricks-training.md}}
