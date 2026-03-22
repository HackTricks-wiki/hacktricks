# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

**seccomp** वह mechanism है जो kernel को किसी process द्वारा invoke किए जाने वाले syscalls पर filter लागू करने देता है। containerized environments में, seccomp आम तौर पर filter mode में उपयोग किया जाता है ताकि process को सिर्फ़ एक अस्पष्ट "restricted" लेबल न दिया जाए, बल्कि उसे एक ठोस syscall policy के अधीन रखा जाए। यह महत्वपूर्ण है क्योंकि कई container breakouts के लिए बहुत specific kernel interfaces तक पहुंचना ज़रूरी होता है। अगर process सम्बंधित syscalls को सफलतापूर्वक invoke नहीं कर पाता, तो एक बड़ी श्रेणी के attacks उस चरण तक पहुँचने से पहले ही समाप्त हो जाते हैं, इससे पहले कि कोई namespace या capability का कोई नाज़ुक अंतर मायने रखे।

मुख्य मानसिक मॉडल सरल है: namespaces तय करते हैं **what the process can see**, capabilities तय करते हैं **which privileged actions the process is nominally allowed to attempt**, और seccomp तय करता है **whether the kernel will even accept the syscall entry point for the attempted action**। इसलिए seccomp अक्सर उन attacks को रोक देता है जो केवल capabilities के आधार पर संभव दिखते हैं।

## Security Impact

कई खतरनाक kernel surface सिर्फ़ एक अपेक्षाकृत छोटी syscall सूची के माध्यम से ही पहुँचा जा सकता है। container hardening में बार-बार महत्वपूर्ण उदाहरणों में `mount`, `unshare`, `clone` या `clone3` with particular flags, `bpf`, `ptrace`, `keyctl`, और `perf_event_open` शामिल हैं। एक attacker जो उन syscalls तक पहुँच बना लेता है, वह नए namespaces बना सकता है, kernel subsystems को manipulate कर सकता है, या ऐसे attack surface के साथ interact कर सकता है जिसकी सामान्य application container को बिल्कुल भी ज़रूरत नहीं होती।

इसीलिए default runtime seccomp profiles बहुत महत्वपूर्ण होते हैं। वे केवल "extra defense" नहीं हैं। कई environments में वे उस अंतर को तय करते हैं कि कोई container kernel functionality के एक व्यापक हिस्से का उपयोग कर सकता है या वह केवल उन syscalls तक सीमित है जो वास्तविक में application को चाहिए।

## Modes And Filter Construction

seccomp historically had a strict mode in which only a tiny syscall set remained available, but the mode relevant to modern container runtimes is seccomp filter mode, often called **seccomp-bpf**। इस मॉडल में, kernel एक filter program का मूल्यांकन करता है जो तय करता है कि किसी syscall को allow किया जाए, errno के साथ deny किया जाए, trapped किया जाए, logged किया जाए, या process को kill कर दिया जाए। Container runtimes इस mechanism का उपयोग इसलिए करते हैं क्योंकि यह खतरनाक syscalls के व्यापक वर्गों को ब्लॉक करने के लिए पर्याप्त expressive है जबकि सामान्य application behavior को अनुमति देता है।

दो low-level उदाहरण उपयोगी हैं क्योंकि वे इस mechanism को जादुई नहीं बल्कि ठोस बनाते हैं। Strict mode पुराने "only a minimal syscall set survives" मॉडल को दर्शाता है:
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
अंतिम `open` प्रक्रिया को समाप्त कर देता है क्योंकि यह strict mode के न्यूनतम सेट का हिस्सा नहीं है।

एक libseccomp फ़िल्टर उदाहरण आधुनिक नीति मॉडल को और स्पष्ट रूप से दिखाता है:
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
यह नीति की इस शैली को अधिकांश पाठक तब कल्पना करते हैं जब वे runtime seccomp profiles के बारे में सोचते हैं।

## लैब

किसी container में seccomp सक्रिय है यह पुष्टि करने का एक सरल तरीका है:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
आप एक ऐसा ऑपरेशन भी आज़मा सकते हैं जिसे default profiles आमतौर पर प्रतिबंधित करते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
यदि container सामान्य default seccomp profile के अंतर्गत चल रहा है, तो `unshare`-style ऑपरेशन्स अक्सर ब्लॉक हो जाते हैं। यह एक उपयोगी प्रदर्शन है क्योंकि यह दिखाता है कि भले ही userspace tool image के अंदर मौजूद हो, फिर भी उसे आवश्यक kernel path उपलब्ध नहीं हो सकता।

यदि container सामान्य default seccomp profile के अंतर्गत चल रहा है, तो `unshare`-style ऑपरेशन्स अक्सर ब्लॉक हो जाते हैं भले ही userspace tool image के अंदर मौजूद हो।

प्रोसेस स्थिति को सामान्य रूप से जांचने के लिए, चलाएँ:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## रनटाइम उपयोग

Docker डिफ़ॉल्ट और कस्टम seccomp प्रोफ़ाइल दोनों को सपोर्ट करता है और प्रशासकों को इन्हें `--security-opt seccomp=unconfined` के साथ अक्षम करने की अनुमति देता है। Podman में समान सपोर्ट है और अक्सर seccomp को rootless execution के साथ जोड़ा जाता है, जो एक बहुत समझदारी भरा डिफ़ॉल्ट रुख होता है। Kubernetes workload configuration के माध्यम से seccomp को प्रदर्शित करता है, जहाँ `RuntimeDefault` आमतौर पर सबसे समझदारी भरा बेसलाइन होता है और `Unconfined` को सुविधा के टॉगल के रूप में लेने के बजाय एक अपवाद माना जाना चाहिए जिसकी औचित्यपूर्ण व्याख्या आवश्यक हो।

containerd और CRI-O आधारित परिवेशों में, सटीक पथ अधिक परतदार होता है, लेकिन सिद्धांत वही रहता है: उच्च-स्तरीय engine या orchestrator तय करता है कि क्या होना चाहिए, और runtime अंततः container process के लिए परिणामी seccomp नीति स्थापित करता है। अंतिम परिणाम अभी भी उस अंतिम रनटाइम कॉन्फ़िगरेशन पर निर्भर करता है जो kernel तक पहुँचता है।

### कस्टम पॉलिसी उदाहरण

Docker और समान engines JSON से कस्टम seccomp प्रोफ़ाइल लोड कर सकते हैं। एक न्यूनतम उदाहरण जो `chmod` को अस्वीकार करता है जबकि बाकी सब कुछ अनुमति देता है, इस प्रकार दिखता है:
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
I don't have the file contents. Please paste the markdown from src/linux-hardening/privilege-escalation/container-security/protections/seccomp.md that you want translated to Hindi, and I'll translate it preserving all tags, links, code and markdown syntax.
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
The command fails with `Operation not permitted`, demonstrating that the restriction comes from the syscall policy rather than from ordinary file permissions alone. In real hardening, allowlists are generally stronger than permissive defaults with a small blacklist.

## गलत कॉन्फ़िगरेशन

सबसे बुरी गलती यह है कि किसी एप्लिकेशन के default policy के तहत फेल होने पर seccomp को **unconfined** सेट कर दिया जाए। यह समस्या निवारण के दौरान आम है और स्थायी समाधान के रूप में बेहद खतरनाक है। एक बार filter हट जाने पर, कई syscall-आधारित breakout primitives फिर से पहुँच योग्य हो जाते हैं, खासकर जब शक्तिशाली capabilities या host namespace sharing भी मौजूद हों।

एक और सामान्य समस्या यह है कि कोई **custom permissive profile** उपयोग किया जाता है जिसे किसी ब्लॉग या आंतरिक workaround से बिना ध्यान से समीक्षा किए कॉपी किया गया हो। टीमें कभी-कभी लगभग सभी खतरनाक syscalls को बनाए रख देती हैं सिर्फ इसलिए कि profile "ऐप के टूटने को रोकना" के इर्द-गिर्द बनाया गया था, बजाय इसके कि "ऐप को वास्तव में जो चाहिए वही देना"। तीसरी गलतफ़हमी यह है कि non-root containers के लिए seccomp कम महत्वपूर्ण है। असल में, बहुत सा kernel attack surface तब भी प्रासंगिक रहता है जब प्रक्रिया UID 0 नहीं होती।

## दुरुपयोग

यदि seccomp अनुपस्थित है या बहुत कमजोर कर दिया गया है, तो एक attacker namespace-creation syscalls को invoke कर सकता है, `bpf` या `perf_event_open` के माध्यम से पहुँच योग्य kernel attack surface का विस्तार कर सकता है, `keyctl` का दुरुपयोग कर सकता है, या इन syscall पाथ्स को `CAP_SYS_ADMIN` जैसे खतरनाक capabilities के साथ जोड़ सकता है। कई वास्तविक हमलों में, seccomp ही एकमात्र कमी नहीं होती, लेकिन इसकी अनुपस्थिति exploit path को नाटकीय रूप से छोटा कर देती है क्योंकि यह कुछ उन कम सुरक्षा-रक्षाओं में से एक को हटा देती है जो जोखिम भरे syscall को रोक सकती हैं इससे पहले कि privilege मॉडल के बाकी हिस्से काम में आएं।

सबसे उपयोगी व्यावहारिक परीक्षण यह है कि उन्हीं syscall परिवारों को आज़माया जाएं जिन्हें default profiles आम तौर पर ब्लॉक करते हैं। यदि वे अचानक काम करने लगते हैं, तो container posture बहुत बदल गया है:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
यदि `CAP_SYS_ADMIN` या कोई अन्य मजबूत capability मौजूद है, तो यह परीक्षण करें कि क्या seccomp mount-based abuse से पहले एकमात्र अनुपस्थित बाधा है:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
कुछ लक्ष्यों पर, तत्काल लाभ पूरा एस्केप नहीं बल्कि information gathering और kernel attack-surface expansion होता है। ये कमांड यह तय करने में मदद करते हैं कि क्या विशेष रूप से संवेदनशील syscall paths पहुँच योग्य हैं:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
If seccomp is absent and the container is also privileged in other ways, that is when it makes sense to pivot into the more specific breakout techniques already documented in the legacy container-escape pages.

### पूरा उदाहरण: seccomp ही एकमात्र चीज़ थी जो `unshare` को ब्लॉक कर रही थी

कई लक्ष्यों पर, seccomp को हटाने का व्यावहारिक प्रभाव यह होता है कि namespace-creation या mount syscalls अचानक काम करना शुरू कर देते हैं। अगर container के पास `CAP_SYS_ADMIN` भी है, तो निम्नलिखित क्रम संभव हो सकता है:
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
यह अपने आप में अभी तक host escape नहीं है, लेकिन यह दर्शाता है कि seccomp mount-related exploitation को रोकने वाली बाधा था।

### पूर्ण उदाहरण: seccomp अक्षम + cgroup v1 `release_agent`

यदि seccomp अक्षम है और container cgroup v1 hierarchies को mount कर सकता है, तो cgroups सेक्शन की `release_agent` technique पहुँच योग्य हो जाता है:
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
यह seccomp-only exploit नहीं है। मुद्दा यह है कि एक बार seccomp अनकन्फाइन्ड हो जाने पर, पहले ब्लॉक किए गए syscall-heavy breakout chains बिलकुल वैसे ही काम करना शुरू कर सकती हैं जैसे वे लिखे गए थे।

## जांच

इन जाँचों का उद्देश्य यह निर्धारित करना है कि seccomp सक्रिय है या नहीं, क्या `no_new_privs` इसके साथ मौजूद है, और क्या रनटाइम कॉन्फ़िगरेशन में seccomp को स्पष्ट रूप से निष्क्रिय दिखाया गया है।
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
What is interesting here:

- शून्य नहीं `Seccomp` मान का मतलब है कि फ़िल्टरिंग सक्रिय है; `0` आम तौर पर कोई seccomp सुरक्षा नहीं दिखाता।
- यदि runtime security options में `seccomp=unconfined` शामिल है, तो workload ने syscall-स्तर की सबसे उपयोगी रक्षा में से एक खो दी है।
- `NoNewPrivs` स्वयं seccomp नहीं है, लेकिन दोनों को एक साथ देखकर आमतौर पर यह संकेत मिलता है कि हार्डनिंग की स्थिति दोनों के न होने की तुलना में अधिक सावधानीपूर्ण है।

यदि किसी container में पहले से ही suspicious mounts, broad capabilities, या shared host namespaces हैं, और seccomp भी unconfined है, तो इस संयोजन को एक प्रमुख escalation संकेत माना जाना चाहिए। container अभी भी तुरंत टूटने योग्य न हो, लेकिन हमलावर के लिए उपलब्ध kernel entry points की संख्या तीव्र रूप से बढ़ सकती है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **डिफ़ॉल्ट के रूप में गारंटीकृत नहीं** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes node और Pod सेटिंग्स का पालन करता है | Runtime profile तब उपयोग होता है जब Kubernetes `RuntimeDefault` का अनुरोध करता है या जब kubelet seccomp defaulting सक्षम होता है | Kubernetes पंक्ति के समान; सीधे CRI/OCI कॉन्फ़िगरेशन भी seccomp को पूरी तरह छोड़ सकता है |

Kubernetes का व्यवहार वह है जो अक्सर ऑपरेटरों को आश्चर्यचकित कर देता है। कई क्लस्टरों में, seccomp तब तक अनुपस्थित रहता है जब तक Pod इसे अनुरोध न करे या kubelet को `RuntimeDefault` पर डिफ़ॉल्ट करने के लिए कॉन्फ़िगर न किया गया हो।
{{#include ../../../../banners/hacktricks-training.md}}
