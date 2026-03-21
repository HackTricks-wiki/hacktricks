# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

**seccomp** वह तंत्र है जो kernel को उस फ़िल्टर को लागू करने देता है जो किसी process द्वारा invoke किए जा सकने वाले syscalls पर लग सकता है। containerized environments में, seccomp सामान्यतः filter mode में उपयोग होता है ताकि process को सिर्फ़ एक अस्पष्ट अर्थ में "restricted" के रूप में चिह्नित न किया जाए, बल्कि वह एक ठोस syscall नीति के अधीन हो। इसका महत्व इसलिए है क्योंकि कई container breakouts के लिए बहुत विशिष्ट kernel interfaces तक पहुँच आवश्यक होती है। यदि process संबंधित syscalls को सफलतापूर्वक invoke नहीं कर सकता, तो एक बड़ा वर्ग के attacks namespace या capability के किसी भी सूक्ष्म अंतर प्रासंगिक होने से पहले ही समाप्त हो जाते हैं।

मुख्य मानसिक मॉडल सरल है: namespaces तय करते हैं **कि process क्या देख सकता है**, capabilities तय करते हैं **कि process किस नाममात्र रूप में अनुमत privileged actions को प्रयास करने के लिए सक्षम है**, और seccomp तय करता है **कि kernel उस प्रयास किए गए action के लिए syscall entry point को स्वीकार करेगा भी या नहीं**। इसी कारण से seccomp अक्सर उन हमलों को रोक देता है जो केवल capabilities के आधार पर संभावित दिखाई देते होंगे।

## सुरक्षा प्रभाव

खतरनाक kernel surface का बहुत बड़ा हिस्सा केवल अपेक्षाकृत छोटे syscalls सेट के माध्यम से ही पहुंच योग्य होता है। container hardening में बार‑बार महत्वपूर्ण उदाहरणों में `mount`, `unshare`, `clone` or `clone3` with particular flags, `bpf`, `ptrace`, `keyctl`, और `perf_event_open` शामिल हैं। जो attacker उन syscalls तक पहुँच सकता है वह नए namespaces बना सकता है, kernel subsystems को manipulate कर सकता है, या उस attack surface के साथ interact कर सकता है जिसकी सामान्य application container को बिल्कुल आवश्यकता नहीं है।

इसीलिए default runtime seccomp profiles इतने महत्वपूर्ण होते हैं। वे केवल "अतिरिक्त रक्षा" नहीं हैं। कई वातावरणों में वे उस अंतर का निर्धारण करते हैं कि कौन‑सा container kernel की व्यापक कार्यक्षमता का अभ्यास कर पाएगा और कौन‑सा container उस syscall surface तक सीमित रहेगा जो वास्तव में आवेदन को चाहिए।

## मोड और फ़िल्टर निर्माण

seccomp ऐतिहासिक रूप से एक strict mode रखता था जिसमें केवल एक छोटा सा syscall सेट उपलब्ध रहता था, लेकिन आधुनिक container runtimes के लिए प्रासंगिक मोड seccomp filter mode है, जिसे अक्सर **seccomp-bpf** कहा जाता है। इस मॉडल में, kernel एक फ़िल्टर प्रोग्राम का मूल्यांकन करता है जो निर्धारित करता है कि किसी syscall को allow किया जाना चाहिए, errno के साथ deny किया जाना चाहिए, trapped किया जाना चाहिए, logged किया जाना चाहिए, या process को kill कर देना चाहिए। Container runtimes इस तंत्र का उपयोग इसलिए करते हैं क्योंकि यह सामान्य application व्यवहार की अनुमति देते हुए खतरनाक syscalls के व्यापक वर्गों को ब्लॉक करने के लिए पर्याप्त अभिव्यक्तिपूर्ण है।

दो low-level उदाहरण उपयोगी हैं क्योंकि वे तंत्र को जादुई नहीं बल्कि ठोस बनाते हैं। Strict mode पुराना "केवल एक न्यूनतम syscall सेट बचता है" मॉडल प्रदर्शित करता है:
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
अंतिम `open` प्रक्रिया को मार देता है क्योंकि यह strict mode के न्यूनतम सेट का हिस्सा नहीं है।

एक libseccomp फ़िल्टर उदाहरण आधुनिक पॉलिसी मॉडल को अधिक स्पष्ट रूप से दिखाता है:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
जब अधिकांश पाठक runtime seccomp profiles के बारे में सोचते हैं, तो वे इस प्रकार की नीति की कल्पना करते हैं।

## प्रयोगशाला

किसी container में seccomp सक्रिय है यह पुष्टि करने का एक सरल तरीका है:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
आप एक ऐसा ऑपरेशन भी आजमा सकते हैं जिसे default profiles आमतौर पर प्रतिबंधित करते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
यदि कंटेनर सामान्य डिफ़ॉल्ट seccomp प्रोफ़ाइल के तहत चल रहा है, तो `unshare`-style ऑपरेशन्स अक्सर ब्लॉक हो जाते हैं। यह एक उपयोगी प्रदर्शन है क्योंकि यह दिखाता है कि भले ही userspace टूल इमेज के अंदर मौजूद हो, जिस kernel पथ की उसे आवश्यकता है वह अभी भी अनुपलब्ध हो सकता है।
यदि कंटेनर सामान्य डिफ़ॉल्ट seccomp प्रोफ़ाइल के तहत चल रहा है, तो `unshare`-style ऑपरेशन्स अक्सर ब्लॉक हो जाते हैं भले ही userspace टूल इमेज के अंदर मौजूद हो।

प्रोसेस की स्थिति को सामान्य रूप से निरीक्षण करने के लिए, चलाएँ:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## रनटाइम उपयोग

Docker डिफ़ॉल्ट और कस्टम seccomp प्रोफाइल दोनों का समर्थन करता है और प्रशासकों को उन्हें `--security-opt seccomp=unconfined` के साथ अक्षम करने की अनुमति देता है। Podman में समान समर्थन होता है और अक्सर seccomp को rootless execution के साथ जोड़कर एक बहुत समझदार डिफ़ॉल्ट स्थिति बनाता है। Kubernetes workload configuration के माध्यम से seccomp को एक्सपोज़ करता है, जहाँ `RuntimeDefault` आम तौर पर एक समझदारी भरा बेसलाइन होता है और `Unconfined` को सुविधा के तौर पर टॉगल के बजाय एक अपवाद मानकर उसकी तार्किक वजह माँगी जानी चाहिए।

In containerd और CRI-O आधारित वातावरणों में, सटीक मार्ग अधिक स्तरित होता है, लेकिन सिद्धांत समान है: उच्च-स्तरीय engine या orchestrator यह तय करता है कि क्या होना चाहिए, और runtime अंततः container प्रक्रिया के लिए उत्पन्न seccomp नीति इंस्टॉल करता है। परिणाम अभी भी उस अंतिम runtime कॉन्फ़िगरेशन पर निर्भर करता है जो kernel तक पहुँचता है।

### कस्टम पॉलिसी उदाहरण

Docker और समान engines JSON से एक कस्टम seccomp प्रोफ़ाइल लोड कर सकते हैं। एक न्यूनतम उदाहरण जो `chmod` को अस्वीकार करता है जबकि बाकी सब कुछ की अनुमति देता है, इस तरह दिखता है:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
के साथ लागू किया गया:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
कमान्ड `Operation not permitted` के साथ विफल होता है, जो दर्शाता है कि प्रतिबंध साधारण फ़ाइल अनुमतियों के बजाय syscall नीति से आ रहा है। वास्तविक hardening में, allowlists आमतौर पर permissive defaults और छोटी blacklist की तुलना में अधिक सख्त होते हैं।

## गलत कॉन्फ़िगरेशन

सबसे भारी भूल यह है कि seccomp को **unconfined** सेट कर देना क्योंकि कोई एप्लिकेशन default policy के तहत विफल हुआ। यह troubleshooting के दौरान सामान्य है और स्थायी समाधान के रूप में बहुत खतरनाक है। एक बार filter हट जाने पर, कई syscall-आधारित breakout primitives फिर से पहुँच योग्य हो जाते हैं, खासकर जब powerful capabilities या host namespace sharing भी मौजूद हों।

एक और आम समस्या है कि किसी ब्लॉग या आंतरिक workaround से कॉपी किया गया **custom permissive profile** बिना सावधानीपूर्वक समीक्षा किए उपयोग में ले लिया जाता है। टीमें कभी‑कभी लगभग सभी dangerous syscalls को बरकरार रख देती हैं केवल इसलिए कि profile "stop the app from breaking" के इर्द‑गिर्द बनाया गया था न कि "grant only what the app actually needs" के। तीसरी भ्रांति यह मानना है कि non-root containers के लिए seccomp कम महत्वपूर्ण है। वास्तविकता में, बहुत सा kernel attack surface तब भी प्रासंगिक रहता है जब प्रक्रिया UID 0 नहीं होती।

## दुरुपयोग

यदि seccomp अनुपस्थित है या बहुत कमजोर किया गया है, तो एक attacker namespace-creation syscalls को invoke कर सकता है, `bpf` या `perf_event_open` के माध्यम से पहुँच योग्य kernel attack surface का विस्तार कर सकता है, `keyctl` का दुरुपयोग कर सकता है, या उन syscall पाथ्स को dangerous capabilities जैसे `CAP_SYS_ADMIN` के साथ जोड़ सकता है। कई वास्तविक हमलों में, seccomp अकेला missing control नहीं होता, लेकिन इसकी अनुपस्थिति exploit path को नाटकीय रूप से छोटा कर देती है क्योंकि यह उन कुछ बचावों में से एक को हटा देती है जो risky syscall को रोक सकते हैं इससे पहले कि privilege model का बाकी हिस्सा प्रभाव में आये।

सबसे उपयोगी व्यावहारिक टेस्ट यह है कि उन्हीं exact syscall families को आज़माया जाए जिन्हें default profiles आमतौर पर block करते हैं। अगर वे अचानक काम करने लगते हैं, तो container posture बहुत बदल गया है:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
यदि `CAP_SYS_ADMIN` या कोई अन्य मजबूत capability मौजूद है, तो यह जाँचें कि seccomp mount-based abuse से पहले केवल एकमात्र बाधा है:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
कुछ लक्ष्यों पर, तात्कालिक महत्व पूरा escape हासिल करना नहीं बल्कि information gathering और kernel attack-surface expansion करना होता है। ये कमांड यह निर्धारित करने में मदद करते हैं कि क्या विशेष रूप से संवेदनशील syscall paths पहुँच योग्य हैं:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
यदि seccomp अनुपस्थित है और container अन्य तरीकों से भी privileged है, तो यही वह समय है जब legacy container-escape pages में पहले से दस्तावेजीकृत अधिक specific breakout techniques की ओर pivot करना अर्थपूर्ण होगा।

### पूरा उदाहरण: seccomp ही एकमात्र चीज़ थी जो `unshare` को ब्लॉक कर रही थी

कई लक्ष्यों पर, seccomp हटाने का व्यावहारिक प्रभाव यह होता है कि namespace-creation या mount syscalls अचानक काम करना शुरू कर देते हैं। यदि container के पास `CAP_SYS_ADMIN` भी मौजूद है, तो निम्नलिखित क्रम संभव हो सकता है:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
अपने आप में यह अभी तक एक host escape नहीं है, लेकिन यह दर्शाता है कि seccomp mount-related exploitation को रोकने वाली बाधा था।

### पूर्ण उदाहरण: seccomp निष्क्रिय + cgroup v1 `release_agent`

यदि seccomp निष्क्रिय है और कंटेनर cgroup v1 hierarchies को mount कर सकता है, तो cgroups सेक्शन से `release_agent` तकनीक पहुँच योग्य हो जाती है:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
यह एक seccomp-only exploit नहीं है। मुद्दा यह है कि एक बार seccomp अप्रतिबंधित हो जाने पर, पहले ब्लॉक किए गए syscall-heavy breakout chains ठीक वैसे ही काम करना शुरू कर सकते हैं जैसा लिखा गया है।

## जांच

इन जांचों का उद्देश्य यह निर्धारित करना है कि क्या seccomp बिल्कुल सक्रिय है, क्या यह `no_new_privs` के साथ है, और क्या रनटाइम कॉन्फ़िगरेशन में स्पष्ट रूप से seccomp को निष्क्रिय दिखाया गया है।
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
What is interesting here:

- A non-zero `Seccomp` value means filtering is active; `0` usually means no seccomp protection.
- If the runtime security options include `seccomp=unconfined`, the workload has lost one of its most useful syscall-level defenses.
- `NoNewPrivs` is not seccomp itself, but seeing both together usually indicates a more careful hardening posture than seeing neither.

If a container already has suspicious mounts, broad capabilities, or shared host namespaces, and seccomp is also unconfined, that combination should be treated as a major escalation signal. The container may still not be trivially breakable, but the number of kernel entry points available to the attacker has increased sharply.

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | आम तौर पर डिफ़ॉल्ट रूप से सक्षम | यदि ओवरराइड नहीं किया गया हो तो Docker के इन-बिल्ट डिफ़ॉल्ट `seccomp` प्रोफ़ाइल का उपयोग करता है | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | आम तौर पर डिफ़ॉल्ट रूप से सक्षम | यदि ओवरराइड नहीं किया गया हो तो runtime के डिफ़ॉल्ट `seccomp` प्रोफ़ाइल को लागू करता है | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **डिफ़ॉल्ट रूप से गारंटीकृत नहीं** | यदि `securityContext.seccompProfile` सेट नहीं है, तो डिफ़ॉल्ट `Unconfined` होता है जब तक कि kubelet `--seccomp-default` सक्षम न करे; अन्यथा `RuntimeDefault` या `Localhost` को स्पष्ट रूप से सेट किया जाना चाहिए | `securityContext.seccompProfile.type: Unconfined`, उन क्लस्टरों पर जहाँ `seccompDefault` नहीं है `seccomp` को अनसेट छोड़ना, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes node और Pod सेटिंग्स का पालन करता है | जब Kubernetes `RuntimeDefault` का अनुरोध करता है या जब kubelet seccomp defaulting सक्षम होता है तो runtime प्रोफ़ाइल का उपयोग किया जाता है | Kubernetes पंक्ति के समान; सीधे CRI/OCI कॉन्फ़िगरेशन भी पूरी तरह से `seccomp` को छोड़ सकता है |

Kubernetes व्यवहार ऐसा है जो सबसे अधिक ऑपरेटरों को चौंकाता है। कई क्लस्टरों में, `seccomp` अभी भी अनुपस्थित होता है जब तक कि Pod इसे अनुरोध न करे या kubelet को `RuntimeDefault` पर डिफ़ॉल्ट करने के लिए कॉन्फ़िगर न किया गया हो।
