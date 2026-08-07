# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

UTS namespace izoluje **hostname** i **NIS domain name** koje proces vidi. Na prvi pogled ovo može delovati trivijalno u poređenju sa mount, PID ili user namespaces, ali predstavlja deo onoga što omogućava da container izgleda kao zaseban host. Unutar namespace-a, workload može da vidi i ponekad promeni hostname koji je lokalni za taj namespace, a ne globalni za mašinu.

Sam po sebi, ovo obično nije centralni deo breakout scenarija. Međutim, kada se host UTS namespace deli, dovoljno privilegovan proces može uticati na podešavanja povezana sa identitetom hosta, što može biti operativno značajno, a povremeno i bezbednosno relevantno.

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

Normalni kontejneri dobijaju izolovani UTS namespace. Docker i Podman mogu da se pridruže UTS namespace-u hosta pomoću `--uts=host`, a slični obrasci deljenja hosta mogu se pojaviti u drugim runtime-ovima i orchestration sistemima. Međutim, privatna UTS izolacija je najčešće jednostavno deo uobičajenog podešavanja kontejnera i zahteva malo pažnje operatora.

## Bezbednosni uticaj

Iako UTS namespace obično nije namespace koji je najopasnije deliti, on i dalje doprinosi integritetu granice kontejnera. Ako je UTS namespace hosta izložen i proces ima neophodne privilegije, možda će moći da menja informacije povezane sa hostname-om hosta. To može uticati na monitoring, logging, operativne pretpostavke ili skripte koje donose odluke o poverenju na osnovu podataka o identitetu hosta.

## Zloupotreba

Ako se UTS namespace hosta deli, praktično pitanje je da li proces može da menja podešavanja identiteta hosta, a ne samo da ih čita:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Ako kontejner takođe ima neophodnu privilegiju, testirajte da li hostname može da se promeni:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Ovo je pre svega problem integriteta i operativnog uticaja, a ne full escape, ali ipak pokazuje da kontejner može direktno da utiče na svojstvo globalno za host.

Uticaj:

- neovlašćena izmena identiteta hosta
- zbunjujući logovi, monitoring ili automatizacija koji veruju hostname-u
- obično nije full escape sam po sebi, osim ako se ne kombinuje sa drugim slabostima

U Docker-style okruženjima, koristan obrazac detekcije na hostu je:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontejneri sa `UTSMode=host` dele UTS namespace hosta i treba ih pažljivije pregledati ako imaju i capabilities koje im omogućavaju pozivanje `sethostname()` ili `setdomainname()`.

## Provere

Ove komande su dovoljne da se utvrdi da li workload ima sopstveni prikaz hostname-a ili deli UTS namespace hosta.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Šta je ovde zanimljivo:

- Poklapanje identifikatora namespace-a sa procesom hosta može ukazivati na deljenje UTS namespace-a sa hostom.
- Ako promena hostname-a utiče na više od samog kontejnera, workload ima veći uticaj na identitet hosta nego što bi trebalo.
- Ovo je obično nalaz nižeg prioriteta u odnosu na probleme sa PID, mount ili user namespace-ovima, ali i dalje potvrđuje koliko je proces zaista izolovan.

U većini okruženja, na UTS namespace je najbolje gledati kao na pomoćni sloj izolacije. Retko je prva stvar koju istražujete tokom breakout-a, ali je i dalje deo ukupne konzistentnosti i bezbednosti prikaza kontejnera.

{{#include ../../../../../banners/hacktricks-training.md}}
