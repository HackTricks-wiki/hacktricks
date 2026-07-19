# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

PID namespace hudhibiti jinsi processes zinavyopangiwa nambari na ni processes zipi zinazoonekana. Hii ndiyo sababu container inaweza kuwa na PID 1 yake yenyewe ingawa si mashine halisi. Ndani ya namespace, workload huona kile kinachoonekana kuwa process tree ya ndani. Nje ya namespace, host bado huona PIDs halisi za host na mandhari kamili ya processes.

Kwa mtazamo wa security, PID namespace ni muhimu kwa sababu uwezo wa kuona processes una thamani kubwa. Mara workload inapoweza kuona processes za host, inaweza kuweza kuona majina ya services, command-line arguments, secrets zilizopitishwa kwenye process arguments, hali inayotokana na environment kupitia `/proc`, na targets zinazoweza kutumiwa kuingia kwenye namespaces. Ikiwa inaweza kufanya zaidi ya kuziona processes hizo, kwa mfano kutuma signals au kutumia ptrace chini ya masharti yanayofaa, tatizo huwa kubwa zaidi.

## Uendeshaji

PID namespace mpya huanza ikiwa na mfumo wake wa ndani wa kuhesabu processes. Process ya kwanza inayoundwa ndani yake huwa PID 1 kwa mtazamo wa namespace hiyo, jambo ambalo pia humaanisha kwamba hupata semantics maalum zinazofanana na init kwa children waliobaki yatima na tabia ya signals. Hii inaeleza mambo mengi yasiyo ya kawaida kwenye containers kuhusu init processes, zombie reaping, na kwa nini wrappers ndogo za init wakati mwingine hutumika kwenye containers.

Somo muhimu la security ni kwamba process inaweza kuonekana kuwa imetengwa kwa sababu huona PID tree yake pekee, lakini utengaji huo unaweza kuondolewa kwa makusudi. Docker hufichua uwezo huu kupitia `--pid=host`, huku Kubernetes ikifanya hivyo kupitia `hostPID: true`. Mara container inapojiunga na PID namespace ya host, workload huona processes za host moja kwa moja, na attack paths nyingi zinazofuata huwa halisi zaidi.

## Maabara

Kuunda PID namespace manually:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sasa inaona mtazamo binafsi wa michakato. Flag ya `--mount-proc` ni muhimu kwa sababu ina-mount instance ya procfs inayolingana na PID namespace mpya, hivyo orodha ya michakato huwa na uwiano kutoka ndani.

Kulinganisha tabia ya container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Tofauti hiyo inaonekana mara moja na ni rahisi kuelewa, ndiyo maana hii ni labu nzuri ya kwanza kwa wasomaji.

## Matumizi ya Runtime

Containers za kawaida katika Docker, Podman, containerd, na CRI-O hupata PID namespace yao wenyewe. Kubernetes Pods kwa kawaida pia hupokea mtazamo wa PID uliotengwa isipokuwa workload iombe wazi kushiriki host PID. Mazingira ya LXC/Incus hutegemea kernel primitive hiyo hiyo, ingawa matumizi ya system-container yanaweza kuonyesha process trees ngumu zaidi na kuhimiza shortcuts zaidi za debugging.

Kanuni hiyo hiyo inatumika kila mahali: ikiwa runtime ilichagua kutotenga PID namespace, huo ni upunguzaji wa makusudi wa mpaka wa container.

## Mipangilio Isiyo Sahihi

Mdatinganyiko wa kawaida zaidi ni kushiriki host PID. Teams mara nyingi huhalalisha hili kwa sababu za debugging, monitoring, au urahisi wa service-management, lakini linapaswa kuchukuliwa kila wakati kama security exception yenye umuhimu. Hata kama container haina write primitive ya haraka dhidi ya host processes, visibility pekee inaweza kufichua mengi kuhusu mfumo. Mara capabilities kama `CAP_SYS_PTRACE` au procfs access yenye manufaa zinapoongezwa, risk huongezeka kwa kiasi kikubwa.

Kosa lingine ni kudhani kwamba kwa sababu workload haiwezi kill au ptrace host processes kwa default, basi kushiriki host PID hakuna madhara. Hitimisho hilo linapuuza thamani ya enumeration, upatikanaji wa namespace-entry targets, na jinsi PID visibility inavyoungana na controls nyingine zilizodhoofishwa.

## Matumizi Mabaya

Ikiwa host PID namespace inashirikiwa, attacker anaweza kukagua host processes, kuvuna process arguments, kutambua services zinazovutia, kupata candidate PIDs za `nsenter`, au kuunganisha process visibility na privilege inayohusiana na ptrace ili kuingilia host au neighboring workloads. Katika baadhi ya hali, kuona tu process sahihi inayotumika kwa muda mrefu kunatosha kubadilisha mpango uliobaki wa attack.

Hatua ya kwanza ya vitendo daima ni kuthibitisha kwamba host processes zinaonekana kweli:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Mara tu host PIDs zinapoonekana, arguments za process na targets za namespace-entry mara nyingi huwa chanzo muhimu zaidi cha taarifa:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ikiwa `nsenter` inapatikana na privilege ya kutosha ipo, jaribu ikiwa process inayoonekana ya host inaweza kutumika kama namespace bridge:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Hata entry inapozuiwa, kushiriki host PID bado kuna thamani kwa sababu hufichua mpangilio wa services, vipengele vya runtime, na processes zenye privilege zinazoweza kuwa shabaha inayofuata.

Mwonekano wa host PID pia hufanya matumizi mabaya ya file descriptors yawe halisi zaidi. Ikiwa process yenye privilege kwenye host au workload jirani ina file au socket nyeti iliyofunguliwa, attacker anaweza kukagua `/proc/<pid>/fd/` na kutumia tena handle hiyo, kutegemea ownership, chaguo za mount za procfs, na model ya service inayolengwa.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Amri hizi ni muhimu kwa sababu zinajibu ikiwa `hidepid=1` au `hidepid=2` inapunguza mwonekano kati ya process na ikiwa descriptors zinazovutia waziwazi, kama vile files za siri zilizo wazi, logs, au Unix sockets, zinaonekana kabisa.

### Mfano Kamili: host PID + `nsenter`

Kushiriki host PID huwa host escape ya moja kwa moja wakati process pia ina privilege ya kutosha kujiunga na host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ikiwa amri itafaulu, container process sasa inatekelezwa katika mount, UTS, network, IPC, na PID namespaces za host. Athari yake ni kuathiri host moja kwa moja.

Hata wakati `nsenter` yenyewe haipo, matokeo hayo hayo yanaweza kupatikana kupitia binary ya host ikiwa filesystem ya host ime-mountiwa:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Vidokezo vya Hivi Karibuni vya Runtime

Baadhi ya attacks zinazohusiana na PID namespace si `hostPID: true` misconfigurations za kawaida, bali ni bugs za utekelezaji wa runtime zinazohusu jinsi protections za procfs zinavyotumika wakati wa container setup.

#### `maskedPaths` race hadi host procfs

Katika versions zilizo hatarini za `runc`, attackers wanaoweza kudhibiti container image au workload ya `runc exec` wanaweza kufanya race katika masking phase kwa kubadilisha container-side `/dev/null` kuwa symlink inayoelekeza kwenye procfs path nyeti kama `/proc/sys/kernel/core_pattern`. Ikiwa race itafaulu, masked-path bind mount inaweza kuwekwa kwenye target isiyo sahihi na kufichua procfs knobs za host-global kwa container mpya.

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Hii ni muhimu kwa sababu athari ya mwisho inaweza kuwa sawa na kufichuliwa moja kwa moja kwa procfs: `core_pattern` au `sysrq-trigger` inayoweza kuandikwa, ikifuatiwa na utekelezaji wa code kwenye host au denial of service.

#### Namespace injection with `insject`

Zana za Namespace injection kama `insject` zinaonyesha kuwa mwingiliano na PID-namespace hauhitaji kila mara kuingia kwenye namespace lengwa kabla ya kuunda mchakato. Helper inaweza kujiunga baadaye, kutumia `setns()`, na kutekeleza huku ikiendelea kuona nafasi ya PID lengwa:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Aina hii ya technique ni muhimu hasa kwa advanced debugging, offensive tooling, na post-exploitation workflows ambapo namespace context lazima iunganishwe baada ya runtime kuanzisha workload.

### Mifumo Husika ya FD Abuse

Mifumo miwili inafaa kutajwa wazi wakati host PIDs zinaonekana. Kwanza, privileged process inaweza kuendelea kuweka sensitive file descriptor ikiwa wazi wakati wa `execve()` kwa sababu haikuwekewa `O_CLOEXEC`. Pili, services zinaweza kutuma file descriptors kupitia Unix sockets kwa kutumia `SCM_RIGHTS`. Katika hali zote mbili, object muhimu si pathname tena, bali handle iliyokwisha kufunguliwa ambayo lower-privilege process inaweza kurithi au kupokea.

Hili ni muhimu katika container work kwa sababu handle inaweza kuelekeza kwenye `docker.sock`, privileged log, host secret file, au object nyingine yenye thamani kubwa, hata wakati path yenyewe haipatikani moja kwa moja kutoka kwenye container filesystem.

## Ukaguzi

Madhumuni ya commands hizi ni kubaini ikiwa process ina private PID view au inaweza tayari kuorodhesha process landscape pana zaidi.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Kinachovutia hapa:

- Ikiwa orodha ya processes ina huduma dhahiri za host, huenda host PID sharing tayari inatumika.
- Kuona tree ndogo ya container-local pekee ndiyo baseline ya kawaida; kuona `systemd`, `dockerd`, au daemons zisizohusiana si kawaida.
- PIDs za host zinapoonekana, hata taarifa za processes za kusoma tu huwa reconnaissance yenye manufaa.

Ukigundua container inayoendesha ikiwa na host PID sharing, usichukulie hili kama tofauti ya mwonekano tu. Ni mabadiliko makubwa katika kile ambacho workload inaweza kuona na uwezekano wa kuathiri.
{{#include ../../../../../banners/hacktricks-training.md}}
