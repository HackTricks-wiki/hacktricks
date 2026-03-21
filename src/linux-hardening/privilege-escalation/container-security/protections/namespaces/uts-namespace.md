# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

UTS namespace izoluje **hostname** i **NIS domain name** koje proces vidi. Na prvi pogled ovo može delovati trivijalno u poređenju sa mount, PID ili user namespaces, ali je deo onoga što čini da container izgleda kao sopstveni host. Unutar namespace-a, workload može videti i ponekad promeniti hostname koji je lokalni za taj namespace umesto globalnog za mašinu.

Samo po sebi, ovo obično nije centralni deo priče o breakout-u. Međutim, kada se host UTS namespace podeli, proces sa dovoljnim privilegijama može uticati na podešavanja vezana za identitet hosta, što može biti važno operativno i povremeno u smislu bezbednosti.

## Lab

Možete kreirati UTS namespace sa:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Promena hostname-a ostaje lokalna za taj namespace i ne menja globalni hostname hosta. Ovo je jednostavan ali efektivan prikaz svojstva izolacije.

## Runtime Usage

Normalni containeri dobijaju izolovan UTS namespace. Docker i Podman mogu da se pridruže host UTS namespace-u preko `--uts=host`, a slični obrasci deljenja hosta mogu se pojaviti i u drugim runtime-ovima i orchestration sistemima. Većinu vremena, međutim, privatna UTS izolacija je jednostavno deo standardne container konfiguracije i zahteva malo pažnje od operatera.

## Security Impact

Iako UTS namespace obično nije najozbiljniji za deljenje, on i dalje doprinosi integritetu granice container-a. Ako je host UTS namespace izložen i proces ima potrebne privilegije, mogao bi promeniti informacije vezane za hostname hosta. To može uticati na nadgledanje, logovanje, operativne pretpostavke ili skripte koje donose odluke o poverenju na osnovu podataka o identitetu hosta.

## Abuse

Ako je host UTS namespace podeljen, praktično pitanje je da li proces može izmeniti podešavanja identiteta hosta, a ne samo da ih čita:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Ako kontejner takođe ima potrebnu privilegiju, testirajte da li se hostname može promeniti:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Ovo je prvenstveno pitanje integriteta i operativnog uticaja, a ne potpuni escape, ali ipak pokazuje da kontejner može direktno uticati na globalno svojstvo hosta.

Uticaj:

- manipulacija identitetom hosta
- zbunjivanje logova, monitoringa ili automatizacije koja se oslanja na ime hosta
- obično nije potpuni escape sam po sebi osim ako nije kombinovan sa drugim slabostima

U Docker-style okruženjima, koristan obrazac za detekciju na strani hosta je:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontejneri koji prikazuju `UTSMode=host` dele host UTS namespace i treba ih pažljivije pregledati ako takođe imaju capabilities koje im omogućavaju da pozovu `sethostname()` ili `setdomainname()`.

## Provere

Ove komande su dovoljne da se vidi da li workload ima sopstveni prikaz hostname-a ili deli host UTS namespace.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- Poklapanje identifikatora namespace-a sa procesom na hostu može ukazivati na deljenje host UTS-a.
- Ako promena hostname-a utiče na više od samog container-a, workload ima veću kontrolu nad identitetom hosta nego što bi trebalo.
- Ovo je obično nalaz nižeg prioriteta nego problemi sa PID, mount ili user namespace-om, ali i dalje potvrđuje koliko je proces zaista izolovan.

U većini okruženja, UTS namespace je najbolje posmatrati kao pomoćni sloj izolacije. Retko je prvo što ćete progoniti u breakout-u, ali je i dalje deo ukupne konzistentnosti i bezbednosti prikaza container-a.
