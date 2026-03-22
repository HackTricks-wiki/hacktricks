# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces ni sifa ya kernel inayofanya container ihisi kama "its own machine" ingawa kwa kweli ni mti wa michakato kwenye host. Haziumbii kernel mpya na hazivirualize kila kitu, lakini zinamruhusu kernel kuwasilisha mitazamo tofauti ya rasilimali zilizochaguliwa kwa vikundi tofauti vya michakato. Hii ndiyo kiini cha udanganyifu wa container: mzigo wa kazi unaona filesystem, process table, network stack, hostname, IPC resources, na mfano wa utambulisho wa user/group unaoonekana kuwa local, ingawa mfumo wa msingi unashirikiwa.

Hivyo namespaces ndizo dhana ya kwanza watu wengi wanakutana nayo wanapojifunza jinsi containers zinavyofanya kazi. Wakati huo huo, ni mojawapo ya dhana zinazokosewa ufahamu kwa sababu wasomaji mara nyingi hufikiria kwamba "has namespaces" inamaanisha "is safely isolated". Kwa kweli, namespace inatenganisha tu daraja maalum la rasilimali iliyoundwa kwa ajili yake. Mchakato unaweza kuwa na private PID namespace na bado kuwa hatari kwa sababu una writable host bind mount. Unaweza kuwa na private network namespace na bado kuwa hatari kwa sababu inadumisha `CAP_SYS_ADMIN` na inaendeshwa bila seccomp. Namespaces ni msingi, lakini ni safu moja tu katika kizuizi cha mwisho.

## Namespace Types

Linux containers mara nyingi hutegemea aina kadhaa za namespace kwa wakati mmoja. The **mount namespace** huwapa mchakato jedwali la mount tofauti na kwa hivyo mtazamo udhibitiwa wa filesystem. The **PID namespace** hubadilisha kuonekana na nambari za michakato ili mzigo wa kazi uone mti wake wa michakato. The **network namespace** inatenganisha interfaces, routes, sockets, na state ya firewall. The **IPC namespace** inatenganisha SysV IPC na POSIX message queues. The **UTS namespace** inatenganisha hostname na NIS domain name. The **user namespace** inaremap user na group IDs ili root ndani ya container haimaanishi lazima root kwenye host. The **cgroup namespace** inavirtualize hierarki ya cgroup inayoonekana, na the **time namespace** inavirtualize baadhi ya saa katika kernels mpya.

Kila moja ya namespaces hizi inatatua tatizo tofauti. Hii ndiyo sababu uchambuzi wa vitendo wa usalama wa container mara nyingi hupungua kwa kuchunguza **ni namespaces zipi zimekutengwa** na **zipi zimegawiwa kwa makusudi na host**.

## Host Namespace Sharing

Mengi ya container breakouts hazianzi kwa udhaifu wa kernel. Huanza na operator anayepunguza kwa makusudi mfano wa kutenganisha. Mifano `--pid=host`, `--network=host`, na `--userns=host` ni **Docker/Podman-style CLI flags** zinazotumika hapa kama mifano halisi ya kushiriki namespace ya host. Runtimes nyingine zinaelezea wazo hilo kwa njia tofauti. In Kubernetes the equivalents usually appear as Pod settings such as `hostPID: true`, `hostNetwork: true`, or `hostIPC: true`. Katika runtime stacks za ngazi ya chini kama containerd au CRI-O, tabia ile ile mara nyingi inafikiwa kupitia generated OCI runtime configuration badala ya kupitia flag inayomuonekana mtumiaji yenye jina lile lile. Katika kesi zote hizi, matokeo ni sawa: mzigo wa kazi haipuzi tena mtazamo wa default isolated namespace.

Hii ndiyo sababu hakiki za namespace hazipaswi kuishia kwenye "the process is in some namespace". Swali muhimu ni kuwa je namespace ni private kwa container, imegawiana na container wenzake, au imeunganishwa moja kwa moja na host. In Kubernetes wazo hili linaonekana tena na flags kama `hostPID`, `hostNetwork`, na `hostIPC`. Majina hubadilika kati ya platform, lakini muundo wa hatari uko sawa: shared host namespace huifanya privileges zilizobaki za container na state ya host inayoweza kufikiwa kuwa na maana zaidi.

## Inspection

Muhtasari rahisi ni:
```bash
ls -l /proc/self/ns
```
Kila kipengee ni symbolic link yenye kitambulisho kinachofanana na inode. Ikiwa processes mbili zinaelekeza kwa kitambulisho cha namespace sawa, ziko kwenye namespace sawa ya aina hiyo. Hii inafanya `/proc` kuwa mahali muhimu sana kulinganisha process ya sasa na processes nyingine zinazoonekana kuvutia kwenye mashine.

Hizi amri za haraka mara nyingi zinatosha kuanza:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Kutoka hapo, hatua inayofuata ni kulinganisha mchakato wa container na michakato ya mwenyeji au jirani na kubainisha ikiwa namespace ni binafsi au la.

### Kuhesabu Matukio ya Namespace Kutoka kwenye Mwenyeji

Unapokuwa tayari na upatikanaji wa mwenyeji na unataka kuelewa ni namespaces ngapi tofauti za aina fulani zipo, `/proc` hutoa orodha ya haraka:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Ikiwa unataka kupata ni michakato gani inayohusiana na kitambulisho maalum cha namespace, badilisha kutoka `readlink` hadi `ls -l` na tumia grep kutafuta nambari ya namespace inayolengwa:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Amri hizi ni muhimu kwa sababu zinakuwezesha kujua kama host inaendesha workload moja iliyotengwa, workloads nyingi zilizotengwa, au mchanganyiko wa matukio ya namespace yalioshirikiwa na binafsi.

### Kuingia kwenye Namespace ya lengo

Wakati muombaji ana ruhusa za kutosha, `nsenter` ni njia ya kawaida ya kujiunga na namespace ya mchakato mwingine:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Lengo la kuorodhesha aina hizi pamoja si kwamba kila tathmini inahitaji zote, bali kwamba post-exploitation maalum kwa namespace mara nyingi inakuwa rahisi zaidi mara mwendeshaji anapojua syntax sahihi ya kuingia badala ya kukumbuka tu fomu ya all-namespaces.

## Pages

The following pages explain each namespace in more detail:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Unapozisoma, kumbuka mawazo mawili. Kwanza, kila namespace inatenga tu aina moja ya mtazamo. Pili, namespace binafsi ni ya manufaa tu ikiwa sehemu nyingine ya mfumo wa vibali bado inafanya kutengwa hicho kuwa na maana.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Namespaces mpya za mount, PID, network, IPC, na UTS kwa chaguo-msingi; user namespaces zinapatikana lakini hazijawezeshwa kwa chaguo-msingi katika mipangilio ya kawaida ya rootful | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Namespaces mpya kwa chaguo-msingi; rootless Podman hujiendesha kwa kutumia user namespace moja kwa moja; chaguo-msingi cha cgroup namespace hutegemea toleo la cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods hazishiriki host PID, network, au IPC kwa chaguo-msingi; Pod networking ni binafsi kwa Pod, si kwa kila container binafsi; user namespaces ni opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Kawaida hufuata chaguo-msingi za Kubernetes Pod | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Sheria kuu ya uhamaji ni rahisi: the **concept** of host namespace sharing is common across runtimes, but the **syntax** is runtime-specific.
{{#include ../../../../../banners/hacktricks-training.md}}
