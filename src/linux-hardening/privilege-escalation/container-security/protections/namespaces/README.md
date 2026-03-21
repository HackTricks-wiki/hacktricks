# Majina ya Nafasi

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces ni kipengele cha kernel kinachofanya container ihisi kama "mashine yake yenyewe" ingawa kwa kweli ni mti wa mchakato wa host. Haileti kernel mpya na haiwalitishi vitu vyote, lakini inaruhusu kernel kuonyesha mitazamo tofauti ya rasilimali zilizochaguliwa kwa vikundi tofauti vya michakato. Hii ndilo msingi wa udanganyifu wa container: mzigo wa kazi unaona mfumo wa faili, jedwali la mchakato, msururu/stack wa mtandao, jina la mwenyeji, rasilimali za IPC, na mfumo wa utambulisho wa mtumiaji/kikundi ambao yanaonekana kuwa ya ndani, ingawa mfumo wa msingi unashirikiwa.

Hii ndiyo sababu namespaces ndizo dhana ya kwanza watu wengi wanakutana nayo wanapoanza kujifunza jinsi containers zinavyofanya kazi. Wakati huo huo, ni mojawapo ya dhana zinazokosewa kueleweka kwa sababu wasomaji mara nyingi hufikiri kwamba "ina namespaces" inamaanisha "imegawika salama". Kweli, namespace inatangaza tu aina maalumu ya rasilimali iliyoundwa kwake. Mchakato unaweza kuwa na private PID namespace na bado kuwa hatari kwa sababu una writable host bind mount. Unaweza kuwa na private network namespace na bado kuwa hatari kwa sababu unabaki na `CAP_SYS_ADMIN` na unaendesha bila `seccomp`. Namespaces ni msingi, lakini ni safu moja tu katika mpaka wa mwisho.

## Aina za Namespace

Containers za Linux mara nyingi hutegemea aina kadhaa za namespace kwa wakati mmoja. **mount namespace** hutoa mchakato jedwali la mount tofauti na kwa hivyo mtazamo wa filesystem uliozimwa. **PID namespace** hubadilisha uonekano na nambari za mchakato ili mzigo wa kazi uone mti wake wa mchakato. **network namespace** inagawanya interfaces, routes, sockets, na hali ya firewall. **IPC namespace** inagawanya SysV IPC na POSIX message queues. **UTS namespace** inagawanya hostname na jina la NIS domain. **user namespace** ina remap user na group IDs ili root ndani ya container si lazima maana yake root kwenye host. **cgroup namespace** inavyirtualize hierarki ya cgroup inayoonekana, na **time namespace** inavyirtualize saa zilizochaguliwa katika kernels mpya.

Kila moja ya namespaces hizi inatatua tatizo tofauti. Hii ndiyo sababu uchambuzi wa usalama wa container kwa vitendo mara nyingi unapungua hadi kuangalia **ni namespaces gani zimezaguliwa** na **ni zipi zimegawanywa kwa makusudi na host**.

## Kushirikiana kwa Namespace za Host

Mafunzo mengi ya kuvunja container hayaendi kwa kuanzia na udhaifu wa kernel. Huanzia na operator anayewekewa kwa makusudi udhaifu katika modeli ya kutenganisha. Mifano `--pid=host`, `--network=host`, na `--userns=host` ni **Docker/Podman-style CLI flags** zinazotumika hapa kama mifano halisi ya kushirikiana kwa host namespace. Runtimes zingine zinaonyesha wazo lile kwa njia tofauti. Katika Kubernetes sawa kawaida zinaonekana kama settings za Pod kama `hostPID: true`, `hostNetwork: true`, au `hostIPC: true`. Katika stacks za runtime za kiwango cha chini kama containerd au CRI-O, tabia ile ile mara nyingi inafikiwa kupitia OCI runtime configuration iliyotengenezwa badala ya kupitia flag inayomuonekanao mtumiaji yenye jina lile. Katika kesi zote hizi, matokeo ni sawa: mzigo wa kazi haubaki kupokea mtazamo wa default isolated namespace.

Hii ndiyo sababu mapitio ya namespace hayapaswi kusimama kwa "mchakato uko katika namespace fulani". Swali muhimu ni kama namespace ni binafsi kwa container, imegawanywa na containers wenzake, au imeunganishwa moja kwa moja na host. Katika Kubernetes wazo lile linaonekana kwa flags kama `hostPID`, `hostNetwork`, na `hostIPC`. Majina hubadilika kati ya platform, lakini muundo wa hatari ni ule ule: host namespace iliyoshirikiwa inafanya vibali vilivyobaki vya container na hali ya host inayofikiwa kuwa muhimu zaidi.

## Uchunguzi

Muhtasari rahisi ni:
```bash
ls -l /proc/self/ns
```
Kila kipengee ni kiungo cha kielelezo (symbolic link) chenye kitambulisho kinachofanana na inode. Ikiwa michakato miwili inaonyesha kitambulisho sawa cha namespace, basi ziko katika namespace ya aina hiyo. Hii inafanya `/proc` kuwa mahali muhimu sana pa kulinganisha mchakato wa sasa na michakato mingine ya kuvutia kwenye mashine.

Amri hizi za haraka mara nyingi zinafaa kuanza:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Kutoka hapo, hatua inayofuata ni kulinganisha mchakato wa container na michakato ya host au michakato jirani ili kubaini ikiwa namespace ni binafsi au la.

### Kuorodhesha instances za namespace kutoka kwa host

Unapokuwa tayari una host access na unataka kuelewa ni namespaces ngapi tofauti za aina fulani zipo, `/proc` inatoa orodha ya haraka:
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
Ikiwa unataka kupata ni mchakato gani yanayomilikiwa na kitambulisho kimoja cha namespace, badilisha kutoka `readlink` kwenda `ls -l` na grep kwa nambari ya namespace inayolengwa:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Amri hizi ni muhimu kwa sababu zinakuwezesha kujua ikiwa host inaendesha isolated workload moja, isolated workloads nyingi, au mchanganyiko wa shared na private namespace instances.

### Kuingia kwenye Namespace ya Lengo

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
Madhumuni ya kuorodhesha aina hizi pamoja si kwamba tathmini zote zinahitaji zote, bali kwamba namespace-specific post-exploitation mara nyingi inakuwa rahisi zaidi mara operator anapojua syntax sahihi ya kuingia badala ya kukumbuka tu all-namespaces form.

## Kurasa

Kurasa zifuatazo zinaelezea kila namespace kwa undani zaidi:

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

Unapovisoma, kumbuka mawazo mawili. Kwanza, kila namespace hutoa kutenganisha aina moja tu ya mtazamo. Pili, namespace binafsi ina manufaa tu ikiwa sehemu nyingine za mfumo wa vibali bado zinafanya kutenganishwa kuwa na maana.

## Chaguo-msingi za Runtime

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Mount, PID, network, IPC, na UTS namespaces mpya kwa chaguo-msingi; user namespaces zinapatikana lakini hazijawezeshwa kwa chaguo-msingi katika setup za rootful za kawaida | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Namespaces mpya kwa chaguo-msingi; rootless Podman kwa moja kwa moja hutumia user namespace; mipangilio ya default ya cgroup namespace inategemea toleo la cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods hazishiriki host PID, network, au IPC kwa chaguo-msingi; Pod networking ni binafsi kwa Pod, si kwa kila container binafsi; user namespaces ni opt-in kupitia `spec.hostUsers: false` kwenye clusters zinazounga mkono | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Kawaida hufuata chaguo-msingi za Kubernetes Pod | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Sheria kuu ya uhamaji ni rahisi: the **concept** ya host namespace sharing ni ya kawaida kwa runtimes, lakini the **syntax** ni maalum kwa runtime.
