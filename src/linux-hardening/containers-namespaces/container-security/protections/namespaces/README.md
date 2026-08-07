# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces ni feature ya kernel inayofanya container ionekane kama "mashine yake yenyewe", ingawa kwa kweli ni mti wa processes wa host. Hazitengenezi kernel mpya wala hazivirtualize kila kitu, lakini huwezesha kernel kuwasilisha mitazamo tofauti ya resources zilizochaguliwa kwa makundi tofauti ya processes. Huu ndio msingi wa container illusion: workload huona filesystem, process table, network stack, hostname, resources za IPC, na mfumo wa utambulisho wa user/group unaoonekana kuwa wa ndani, ingawa mfumo wa msingi unashirikiwa.

Hii ndiyo sababu namespaces huwa dhana ya kwanza ambayo watu wengi hukutana nayo wanapojifunza jinsi containers zinavyofanya kazi. Wakati huohuo, ni miongoni mwa dhana zinazoeleweka vibaya zaidi kwa sababu wasomaji mara nyingi hudhani kwamba "ina namespaces" inamaanisha "imetengwa kwa usalama". Kwa uhalisia, namespace hutenga tu aina maalum ya resources ambayo iliundwa kwa ajili yake. Process inaweza kuwa na private PID namespace na bado ikawa hatari kwa sababu ina writable host bind mount. Inaweza kuwa na private network namespace na bado ikawa hatari kwa sababu inahifadhi `CAP_SYS_ADMIN` na inaendesha bila seccomp. Namespaces ni msingi, lakini ni layer moja tu katika boundary ya mwisho.

## Aina za Namespace

Linux containers kwa kawaida hutegemea aina kadhaa za namespaces kwa wakati mmoja. **Mount namespace** huipa process mount table tofauti na hivyo filesystem view inayodhibitiwa. **PID namespace** hubadilisha process visibility na numbering ili workload ione mti wake wa processes. **Network namespace** hutenga interfaces, routes, sockets, na firewall state. **IPC namespace** hutenga SysV IPC na POSIX message queues. **UTS namespace** hutenga hostname na NIS domain name. **User namespace** hubadilisha user na group IDs ili root ndani ya container asiwe lazima awe root kwenye host. **Cgroup namespace** hu-virtualize cgroup hierarchy inayoonekana, na **time namespace** hu-virtualize clocks zilizochaguliwa katika kernels mpya zaidi.

Kila moja ya namespaces hizi hutatua tatizo tofauti. Ndiyo sababu practical container security analysis mara nyingi huhusisha kukagua **ni namespaces zipi zimetengwa** na **ni zipi zimeshirikishwa kwa makusudi na host**.

## Kushiriki Host Namespace

Container breakouts nyingi hazianzi na kernel vulnerability. Huanzia kwa operator kudhoofisha kwa makusudi isolation model. Mifano `--pid=host`, `--network=host`, na `--userns=host` ni **Docker/Podman-style CLI flags** zinazotumiwa hapa kama mifano halisi ya host namespace sharing. Runtimes nyingine huonyesha wazo hilo kwa njia tofauti. Katika Kubernetes, equivalents kwa kawaida huonekana kama Pod settings kama `hostPID: true`, `hostNetwork: true`, au `hostIPC: true`. Katika lower-level runtime stacks kama containerd au CRI-O, tabia hiyo hiyo mara nyingi hupatikana kupitia generated OCI runtime configuration badala ya user-facing flag yenye jina hilo hilo. Katika hali hizi zote, matokeo yanafanana: workload haipokei tena default isolated namespace view.

Hii ndiyo sababu namespace reviews hazipaswi kuishia kwenye "process iko katika namespace fulani". Swali muhimu ni kama namespace ni private kwa container, inashirikiwa na sibling containers, au imeunganishwa moja kwa moja na host. Katika Kubernetes, wazo hilo hilo huonekana kupitia flags kama `hostPID`, `hostNetwork`, na `hostIPC`. Majina hubadilika kati ya platforms, lakini risk pattern ni ileile: shared host namespace hufanya privileges zilizobaki za container na host state inayoweza kufikiwa kuwa muhimu zaidi.

## Ukaguzi

Muhtasari rahisi zaidi ni:
```bash
ls -l /proc/self/ns
```
Kila ingizo ni symbolic link yenye kitambulisho kinachofanana na inode. Ikiwa processes mbili zinaelekeza kwenye kitambulisho kimoja cha namespace, ziko kwenye namespace moja ya aina hiyo. Hivyo, `/proc` ni mahali muhimu sana pa kulinganisha process ya sasa na processes nyingine zinazovutia kwenye mashine.

Amri hizi fupi mara nyingi zinatosha kuanza:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Kutoka hapo, hatua inayofuata ni kulinganisha container process na host au neighboring processes na kubaini ikiwa namespace ni private kweli au la.

### Kuhesabu Namespace Instances Kutoka Kwa Host

Unapokuwa tayari una host access na unataka kuelewa ni namespace ngapi tofauti za aina fulani zipo, `/proc` hutoa inventory ya haraka:
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
Ikiwa unataka kubaini ni processes zipi zinahusishwa na kitambulisho kimoja mahususi cha namespace, badilisha kutoka `readlink` hadi `ls -l` kisha tumia `grep` kutafuta nambari ya namespace lengwa:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Amri hizi ni muhimu kwa sababu zinakuruhusu kubaini ikiwa host inaendesha workload moja iliyotengwa, workloads nyingi zilizotengwa, au mchanganyiko wa instances za namespace zinazoshirikiwa na za faragha.

### Kuingia kwenye Namespace ya Lengo

Mwaitaji anapokuwa na privilege za kutosha, `nsenter` ndiyo njia ya kawaida ya kujiunga na namespace ya process nyingine:
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
Hoja ya kuorodhesha aina hizi pamoja si kwamba kila assessment inahitaji zote, bali ni kwamba post-exploitation inayolenga namespace fulani mara nyingi huwa rahisi zaidi operator anapojua syntax halisi ya kuingia, badala ya kukumbuka tu fomu ya all-namespaces.

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

Unapozisoma, zingatia mawazo mawili. Kwanza, kila namespace hutenga aina moja tu ya mwonekano. Pili, namespace ya private huwa na manufaa tu ikiwa sehemu nyingine ya privilege model bado inafanya utengaji huo uwe na maana.

## Mipangilio ya Kawaida ya Runtime

| Runtime / platform | Mkao wa namespace kwa default | Udhoofishaji wa kawaida wa manual |
| --- | --- | --- |
| Docker Engine | Namespace mpya za mount, PID, network, IPC, na UTS kwa default; user namespaces zinapatikana lakini hazijawezeshwa kwa default katika mipangilio ya kawaida ya rootful | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Namespace mpya kwa default; rootless Podman hutumia user namespace moja kwa moja; default za cgroup namespace hutegemea toleo la cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods **hazishiriki** PID, network, au IPC ya host kwa default; Pod networking ni private kwa Pod, si kwa kila container binafsi; user namespaces huwezeshwa kwa hiari kupitia `spec.hostUsers: false` kwenye clusters zinazotumika | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / kutoweka user-namespace opt-in, mipangilio ya privileged workload |
| containerd / CRI-O under Kubernetes | Kwa kawaida hufuata default za Kubernetes Pod | sawa na safu ya Kubernetes; specs za moja kwa moja za CRI/OCI pia zinaweza kuomba kujiunga na host namespaces |

Kanuni kuu ya portability ni rahisi: **dhana** ya host namespace sharing ni ya kawaida katika runtimes, lakini **syntax** hutofautiana kulingana na runtime.

{{#include ../../../../../banners/hacktricks-training.md}}
