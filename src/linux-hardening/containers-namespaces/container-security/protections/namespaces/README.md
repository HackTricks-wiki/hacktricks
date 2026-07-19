# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces ni feature ya kernel inayofanya container ionekane kama "mashine yake yenyewe", ingawa kwa kweli ni mti wa process wa host. Hazitengenezi kernel mpya wala ku-virtualize kila kitu, lakini zinawezesha kernel kuwasilisha mitazamo tofauti ya resources zilizochaguliwa kwa makundi tofauti ya processes. Huu ndio msingi wa taswira ya container: workload huona filesystem, process table, network stack, hostname, IPC resources, na mfumo wa utambulisho wa user/group unaoonekana kuwa wa ndani, ingawa mfumo wa msingi unashirikiwa.

Hii ndiyo sababu namespaces ni concept ya kwanza ambayo watu wengi hukutana nayo wanapojifunza jinsi containers zinavyofanya kazi. Wakati huohuo, ni miongoni mwa concepts zinazoeleweka vibaya zaidi kwa sababu wasomaji mara nyingi hudhani kwamba "ina namespaces" inamaanisha "imeisoleshwa kwa usalama". Kwa uhalisia, namespace hutenganisha tu aina maalum ya resources ambayo iliundwa kushughulikia. Process inaweza kuwa na private PID namespace na bado ikawa hatari kwa sababu ina writable host bind mount. Inaweza kuwa na private network namespace na bado ikawa hatari kwa sababu bado ina `CAP_SYS_ADMIN` na inaendesha bila seccomp. Namespaces ni msingi, lakini ni layer moja tu katika boundary ya mwisho.

## Namespace Types

Linux containers kwa kawaida hutegemea aina kadhaa za namespaces kwa wakati mmoja. **Mount namespace** huipa process mount table tofauti na hivyo filesystem view inayodhibitiwa. **PID namespace** hubadilisha process visibility na numbering ili workload ione mti wake wa processes. **Network namespace** hutenganisha interfaces, routes, sockets, na firewall state. **IPC namespace** hutenganisha SysV IPC na POSIX message queues. **UTS namespace** hutenganisha hostname na NIS domain name. **User namespace** hubadilisha user na group IDs ili root ndani ya container asiwe lazima awe root kwenye host. **Cgroup namespace** hu-virtualize cgroup hierarchy inayoonekana, na **time namespace** hu-virtualize clocks zilizochaguliwa katika kernels mpya zaidi.

Kila moja ya namespaces hizi hutatua tatizo tofauti. Ndiyo sababu practical container security analysis mara nyingi hujikita katika kuangalia **ni namespaces zipi zimeisoleshwa** na **ni zipi ambazo zimeshirikishwa kwa makusudi na host**.

## Host Namespace Sharing

Breakouts nyingi za containers hazianzi na kernel vulnerability. Huanzia kwa operator kudhoofisha kwa makusudi isolation model. Mifano ya `--pid=host`, `--network=host`, na `--userns=host` ni **Docker/Podman-style CLI flags** zinazotumika hapa kama mifano halisi ya host namespace sharing. Runtimes nyingine huonyesha wazo hilo kwa njia tofauti. Katika Kubernetes, equivalents kwa kawaida huonekana kama Pod settings kama `hostPID: true`, `hostNetwork: true`, au `hostIPC: true`. Katika runtime stacks za kiwango cha chini kama containerd au CRI-O, tabia hiyo hiyo mara nyingi hupatikana kupitia generated OCI runtime configuration badala ya flag inayoonyeshwa kwa mtumiaji yenye jina hilohilo. Katika hali hizi zote, matokeo yanafanana: workload haipokei tena default isolated namespace view.

Ndiyo sababu namespace reviews hazipaswi kuishia kwenye "process iko katika namespace fulani". Swali muhimu ni kama namespace ni private kwa container, inashirikishwa na sibling containers, au imeunganishwa moja kwa moja na host. Katika Kubernetes, wazo hilohilo huonekana kupitia flags kama `hostPID`, `hostNetwork`, na `hostIPC`. Majina hubadilika kati ya platforms, lakini risk pattern ni ileile: shared host namespace hufanya privileges zilizobaki za container na host state inayoweza kufikiwa kuwa na umuhimu mkubwa zaidi.

## Inspection

Muhtasari rahisi zaidi ni:
```bash
ls -l /proc/self/ns
```
Kila ingizo ni symbolic link yenye kitambulisho kinachofanana na inode. Ikiwa processes mbili zinaelekeza kwenye kitambulisho sawa cha namespace, ziko kwenye namespace moja ya aina hiyo. Hivyo, `/proc` ni mahali muhimu sana pa kulinganisha process ya sasa na processes nyingine zinazovutia kwenye mashine.

Amri hizi fupi mara nyingi zinatosha kuanza:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Kutoka hapo, hatua inayofuata ni kulinganisha process ya container na process za host au zilizo karibu, kisha kubaini ikiwa namespace ni private kweli au la.

### Kuhesabu Namespace Instances Kutoka Kwenye Host

Unapokuwa tayari una ufikiaji wa host na unataka kuelewa ni namespace ngapi tofauti za aina fulani zipo, `/proc` hutoa orodha ya haraka ya kufanya inventory:
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
Ikiwa unataka kujua ni michakato ipi inayohusishwa na kitambulisho mahususi cha namespace, badilisha kutoka `readlink` hadi `ls -l` na utumie grep kutafuta nambari ya namespace lengwa:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Amri hizi ni muhimu kwa sababu zinakuwezesha kujibu ikiwa host inaendesha workload moja iliyotengwa, workloads nyingi zilizotengwa, au mchanganyiko wa instances za namespace zilizoshirikiwa na za kibinafsi.

### Kuingia Kwenye Namespace ya Target

Caller anapokuwa na privilege ya kutosha, `nsenter` ndiyo njia ya kawaida ya kujiunga na namespace ya process nyingine:
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
Hoja ya kuorodhesha fomu hizi pamoja si kwamba kila assessment inahitaji zote, bali kwamba post-exploitation inayolenga namespace fulani mara nyingi huwa rahisi zaidi operator anapojua syntax kamili ya kuingia badala ya kukumbuka tu fomu ya all-namespaces.

## Kurasa

Kurasa zifuatazo zinaeleza kila namespace kwa undani zaidi:

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

Unapozisoma, zingatia mawazo mawili. Kwanza, kila namespace hutenga aina moja tu ya mtazamo. Pili, namespace ya private huwa na manufaa tu ikiwa sehemu nyingine ya privilege model bado inafanya utengaji huo uwe na maana.

## Mipangilio ya Kawaida ya Runtime

| Runtime / platform | Mkao wa kawaida wa namespace | Udhoofishaji wa kawaida wa mkono |
| --- | --- | --- |
| Docker Engine | Huunda mount, PID, network, IPC, na UTS namespaces mpya kwa default; user namespaces zinapatikana lakini hazijawezeshwa kwa default katika setups za kawaida za rootful | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Huunda namespaces mpya kwa default; rootless Podman hutumia user namespace moja kwa moja; default ya cgroup namespace hutegemea toleo la cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods **hazishiriki** host PID, network, au IPC kwa default; Pod networking ni private kwa Pod, si kwa kila container mmoja mmoja; user namespaces huwezeshwa kwa hiari kupitia `spec.hostUsers: false` kwenye clusters zinazotumika | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / kutoweka user-namespace opt-in, mipangilio ya privileged workload |
| containerd / CRI-O under Kubernetes | Kwa kawaida hufuata default za Kubernetes Pod | sawa na safu ya Kubernetes; specs za moja kwa moja za CRI/OCI pia zinaweza kuomba kujiunga na host namespaces |

Kanuni kuu ya portability ni rahisi: **dhana** ya kushiriki host namespace ni ya kawaida katika runtimes, lakini **syntax** hutegemea runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
