# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

UTS namespace izoluje **hostname** i **NIS domain name** koje proces vidi. Na prvi pogled ovo može delovati trivijalno u poređenju sa mount, PID ili user namespaces, ali je deo onoga što čini da container izgleda kao sopstveni host. Unutar namespace-a, workload može videti i ponekad promeniti hostname koji je lokalni za taj namespace, umesto globalnog za mašinu.

Na sopstvenu ruku, ovo obično nije centralni deo priče o breakout-u. Međutim, kada se host UTS namespace podeli, proces sa dovoljno privilegija može uticati na podešavanja vezana za identitet hosta, što može biti važno operativno, a povremeno i sa aspekta bezbednosti.

## Laboratorija

Možete kreirati UTS namespace pomoću:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Promena hostname-a ostaje lokalna za taj namespace i ne menja globalni hostname hosta. Ovo je jednostavan, ali efektivan primer svojstva izolacije.

## Runtime Usage

Normalni container-i dobijaju izolovan UTS namespace. Docker i Podman mogu da se priključe host UTS namespace-u pomoću `--uts=host`, i slični obrasci deljenja hosta se mogu pojaviti i u drugim runtime-ovima i orchestration sistemima. Većinom, međutim, privatna UTS izolacija je jednostavno deo normalnog podešavanja container-a i zahteva malo pažnje operatera.

## Security Impact

Iako UTS namespace obično nije najopasniji za deljenje, on i dalje doprinosi integritetu granice containera. Ako je host UTS namespace izložen i proces ima potrebne privilegije, može biti u mogućnosti da izmeni informacije vezane za hostname hosta. To može uticati na monitoring, logging, operativne pretpostavke ili skripte koje donose odluke o poverenju zasnovane na podacima o identitetu hosta.

## Abuse

Ako je host UTS namespace deljen, praktično pitanje je da li proces može da modifikuje podešavanja identiteta hosta, a ne samo da ih čita:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Ako kontejner takođe ima potrebne privilegije, testirajte da li se hostname može promeniti:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Ovo je prvenstveno problem integriteta i operativnog uticaja, a ne potpuni escape, ali i dalje pokazuje da container može direktno da utiče na host-global property.

Uticaj:

- manipulacija identitetom hosta
- zbunjivanje logova, monitoringa ili automatizacije koja se oslanja na hostname
- obično nije potpuni escape sam po sebi, osim ako nije kombinovan sa drugim slabostima

U Docker-style okruženjima, koristan obrazac detekcije na strani hosta je:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontejneri koji imaju `UTSMode=host` dele host UTS namespace i treba ih pažljivije pregledati ako takođe nose capabilities koje im omogućavaju da pozovu `sethostname()` ili `setdomainname()`.

## Checks

Ove komande su dovoljne da se utvrdi da li workload ima sopstveni prikaz hostname-a ili deli host UTS namespace.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Šta je ovde zanimljivo:

- Poklapanje identifikatora namespace-a sa host procesom može ukazivati na deljenje UTS-a sa hostom.
- Ako promena hostname-a utiče na više od samog container-a, workload ima veći uticaj na identitet hosta nego što bi trebalo.
- Ovo je obično nalaz nižeg prioriteta u odnosu na probleme sa PID, mount ili user namespace-om, ali i dalje potvrđuje koliko je proces zaista izolovan.

U većini okruženja, UTS namespace treba posmatrati kao pomoćni sloj izolacije. Retko je to prva stvar koju jurite u breakout-u, ali je i dalje deo ukupne konzistentnosti i bezbednosti container view-a.
{{#include ../../../../../banners/hacktricks-training.md}}
