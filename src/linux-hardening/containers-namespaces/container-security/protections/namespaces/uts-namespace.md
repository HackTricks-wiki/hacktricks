# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

UTS namespace izoluje **hostname** i **NIS domain name** koje proces vidi. Na prvi pogled ovo može delovati beznačajno u poređenju sa mount, PID ili user namespaces, ali je deo onoga što omogućava da container izgleda kao zaseban host. Unutar namespace-a, workload može da vidi i ponekad promeni hostname koji je lokalni za taj namespace, a ne globalan za mašinu.

Sam po sebi, ovaj mehanizam obično nije središnji deo breakout scenarija. Međutim, kada se host UTS namespace deli, dovoljno privilegovan proces može uticati na podešavanja povezana sa identitetom hosta, što može biti operativno važno, a povremeno i značajno za security.

## Lab

UTS namespace možete kreirati pomoću:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Promena hostname-a ostaje lokalna za taj namespace i ne menja globalni hostname hosta. Ovo je jednostavna, ali efikasna demonstracija svojstva izolacije.

## Upotreba tokom izvršavanja

Uobičajeni container-i dobijaju izolovani UTS namespace. Docker i Podman mogu da se pridruže UTS namespace-u hosta pomoću `--uts=host`, a slični obrasci deljenja hosta mogu se pojaviti i u drugim runtime-ovima i orchestration sistemima. Međutim, privatna UTS izolacija je najčešće jednostavno deo standardnog podešavanja container-a i zahteva malo pažnje operatora.

## Bezbednosni uticaj

Iako UTS namespace obično nije namespace čije je deljenje najopasnije, on i dalje doprinosi integritetu granice container-a. Ako je UTS namespace hosta izložen i proces ima potrebne privilegije, može biti u mogućnosti da izmeni informacije povezane sa hostname-om hosta. To može uticati na monitoring, logging, operativne pretpostavke ili skripte koje donose odluke o poverenju na osnovu podataka o identitetu hosta.

## Zloupotreba

Ako se UTS namespace hosta deli, praktično pitanje je da li proces može da menja podešavanja identiteta hosta, a ne samo da ih čita:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Ako kontejner takođe ima potrebnu privilegiju, proverite da li je moguće promeniti hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Ovo je prvenstveno problem integriteta i operativnog uticaja, a ne potpuni escape, ali i dalje pokazuje da kontejner može direktno da utiče na globalno svojstvo hosta.

Uticaj:

- neovlašćena izmena identiteta hosta
- zbunjujući logovi, monitoring ili automatizacija koji veruju hostname-u
- obično nije potpuni escape sam po sebi, osim ako se kombinuje sa drugim slabostima

U Docker okruženjima, koristan obrazac za detekciju sa strane hosta je:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontejneri sa `UTSMode=host` dele UTS namespace sa hostom i treba ih pažljivije pregledati ako takođe imaju capabilities koje im omogućavaju da pozovu `sethostname()` ili `setdomainname()`.

## Provere

Ove komande su dovoljne da se utvrdi da li workload ima sopstveni prikaz hostname-a ili deli UTS namespace sa hostom.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Šta je ovde interesantno:

- Podudarni identifikatori namespace-a sa host procesom mogu ukazivati na deljenje host UTS namespace-a.
- Ako promena hostname-a utiče na nešto više od samog kontejnera, workload ima veći uticaj na identitet hosta nego što bi trebalo.
- Ovo je obično nalaz nižeg prioriteta u odnosu na probleme sa PID, mount ili user namespace-om, ali i dalje potvrđuje koliko je proces zaista izolovan.

U većini okruženja, UTS namespace je najbolje posmatrati kao pomoćni sloj izolacije. Retko je prva stvar koju istražujete tokom breakout-a, ali je i dalje deo ukupne konzistentnosti i bezbednosti prikaza kontejnera.
{{#include ../../../../../banners/hacktricks-training.md}}
