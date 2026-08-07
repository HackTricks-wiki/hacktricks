# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

**seccomp** वह mechanism है जो kernel को उन syscalls पर filter लागू करने देता है जिन्हें कोई process invoke कर सकता है। Containerized environments में seccomp का उपयोग सामान्यतः filter mode में किया जाता है, ताकि process को केवल अस्पष्ट अर्थ में "restricted" चिह्नित न किया जाए, बल्कि उसे एक ठोस syscall policy के अधीन रखा जाए। यह महत्वपूर्ण है क्योंकि कई container breakouts के लिए बहुत विशिष्ट kernel interfaces तक पहुंच आवश्यक होती है। यदि process संबंधित syscalls को सफलतापूर्वक invoke नहीं कर सकता, तो namespace या capability की किसी भी बारीकी के प्रासंगिक होने से पहले ही attacks की एक बड़ी श्रेणी समाप्त हो जाती है।

मुख्य mental model सरल है: namespaces तय करते हैं कि **process क्या देख सकता है**, capabilities तय करती हैं कि **process को nominally कौन-सी privileged actions करने का प्रयास करने की अनुमति है**, और seccomp तय करता है कि **kernel प्रयास की गई action के लिए syscall entry point को स्वीकार भी करेगा या नहीं**। इसी कारण seccomp अक्सर उन attacks को रोकता है जो केवल capabilities के आधार पर संभव प्रतीत होते।

## Security Impact

काफी खतरनाक kernel surface तक पहुंच अपेक्षाकृत कम syscalls के एक छोटे set के माध्यम से ही संभव होती है। Container hardening में बार-बार महत्वपूर्ण होने वाले examples में `mount`, `unshare`, विशेष flags के साथ `clone` या `clone3`, `bpf`, `ptrace`, `keyctl`, और `perf_event_open` शामिल हैं। जो attacker इन syscalls तक पहुंच सकता है, वह नए namespaces बनाने, kernel subsystems में बदलाव करने, या ऐसे attack surface के साथ interact करने में सक्षम हो सकता है जिसकी किसी सामान्य application container को बिल्कुल आवश्यकता नहीं होती।

इसीलिए default runtime seccomp profiles इतने महत्वपूर्ण हैं। वे केवल "extra defense" नहीं हैं। कई environments में यही उस container के बीच का अंतर होते हैं जो kernel functionality के बड़े हिस्से का उपयोग कर सकता है और उस container के बीच जो syscall surface तक सीमित होता है, जो application की वास्तविक आवश्यकताओं के अधिक करीब है।

## Modes And Filter Construction

seccomp में ऐतिहासिक रूप से एक strict mode था, जिसमें केवल बहुत छोटा syscall set उपलब्ध रहता था, लेकिन modern container runtimes के लिए प्रासंगिक mode seccomp filter mode है, जिसे अक्सर **seccomp-bpf** कहा जाता है। इस model में kernel एक filter program को evaluate करता है, जो तय करता है कि किसी syscall को allow किया जाना चाहिए, errno के साथ deny किया जाना चाहिए, trap किया जाना चाहिए, log किया जाना चाहिए, या process को kill किया जाना चाहिए।<sup>[[1]](#references)</sup> Container runtimes इस mechanism का उपयोग करते हैं क्योंकि यह normal application behavior की अनुमति देते हुए dangerous syscalls की व्यापक classes को block करने के लिए पर्याप्त expressive है।

दो low-level examples उपयोगी हैं क्योंकि वे mechanism को किसी जादुई प्रक्रिया के बजाय ठोस रूप में स्पष्ट करते हैं। Strict mode पुराने "केवल एक minimal syscall set बचता है" model को प्रदर्शित करता है:
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
अंतिम `open` के कारण process kill हो जाता है क्योंकि यह strict mode के minimal set का हिस्सा नहीं है।

libseccomp filter का एक उदाहरण modern policy model को अधिक स्पष्ट रूप से दिखाता है:
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
इस प्रकार की policy वह है जिसकी अधिकांश readers को runtime seccomp profiles के बारे में सोचते समय कल्पना करनी चाहिए।

## Lab

किसी container में seccomp के active होने की पुष्टि करने का एक सरल तरीका है:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
आप एक ऐसा operation भी आज़मा सकते हैं, जिसे default profiles आमतौर पर प्रतिबंधित करते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
यदि कंटेनर सामान्य default seccomp profile के अंतर्गत चल रहा है, तो `unshare`-style operations अक्सर block हो जाते हैं। यह एक उपयोगी demonstration है, क्योंकि इससे पता चलता है कि image के अंदर userspace tool मौजूद होने पर भी, kernel path जिसकी उसे आवश्यकता है, उपलब्ध नहीं हो सकता।

यदि कंटेनर सामान्य default seccomp profile के अंतर्गत चल रहा है, तो image के अंदर userspace tool मौजूद होने पर भी `unshare`-style operations अक्सर block हो जाते हैं।

Process status का अधिक सामान्य रूप से निरीक्षण करने के लिए, चलाएँ:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime का उपयोग

Docker default और custom seccomp profiles, दोनों को support करता है और administrators को `--security-opt seccomp=unconfined` के साथ इन्हें disable करने की अनुमति देता है।<sup>[[2]](#references)</sup> Podman में भी ऐसा ही support है और यह अक्सर rootless execution के साथ एक बहुत sensible default posture में seccomp का उपयोग करता है। Kubernetes workload configuration के माध्यम से seccomp उपलब्ध कराता है, जहाँ `RuntimeDefault` आमतौर पर sane baseline होता है और `Unconfined` को convenience toggle के बजाय justification की आवश्यकता वाले exception के रूप में माना जाना चाहिए।<sup>[[3]](#references)</sup>

containerd और CRI-O आधारित environments में exact path अधिक layered होता है, लेकिन principle वही रहता है: higher-level engine या orchestrator तय करता है कि क्या होना चाहिए, और runtime अंततः container process के लिए परिणामी seccomp policy install करता है। Outcome अभी भी kernel तक पहुँचने वाली final runtime configuration पर निर्भर करता है।

### Custom Policy का उदाहरण

Docker और similar engines JSON से custom seccomp profile load कर सकते हैं। एक minimal example, जो `chmod` को deny करता है और बाकी सबकी अनुमति देता है, इस प्रकार है:
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
इसके साथ लागू किया गया:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
कमांड `Operation not permitted` के साथ विफल होता है, जो दर्शाता है कि प्रतिबंध केवल सामान्य file permissions से नहीं, बल्कि syscall policy से लागू हो रहा है। वास्तविक hardening में, permissive defaults के साथ छोटी blacklist की तुलना में allowlists आम तौर पर अधिक मजबूत होती हैं।

## Misconfigurations

सबसे सीधी गलती यह है कि default policy के अंतर्गत application विफल होने पर seccomp को **unconfined** सेट कर दिया जाए। Troubleshooting के दौरान यह आम है और स्थायी समाधान के रूप में बहुत खतरनाक है। Filter हटते ही, syscall-based breakout primitives फिर से पहुंच योग्य हो जाते हैं, विशेष रूप से तब जब powerful capabilities या host namespace sharing भी मौजूद हों।

एक अन्य सामान्य समस्या **custom permissive profile** का उपयोग है, जिसे किसी blog या internal workaround से copy किया गया हो और सावधानीपूर्वक review न किया गया हो। Teams कभी-कभी लगभग सभी dangerous syscalls को केवल इसलिए बनाए रखते हैं क्योंकि profile को "app को टूटने से रोकने" के आधार पर बनाया गया था, न कि "app को वास्तव में जितना चाहिए उतना ही grant करने" के आधार पर। एक तीसरी गलत धारणा यह है कि non-root containers के लिए seccomp कम महत्वपूर्ण है। वास्तव में, process के UID 0 न होने पर भी kernel attack surface का एक बड़ा हिस्सा relevant रहता है।

## Abuse

यदि seccomp अनुपस्थित हो या बुरी तरह कमजोर कर दिया गया हो, तो attacker namespace-creation syscalls invoke करने, `bpf` या `perf_event_open` के माध्यम से reachable kernel attack surface बढ़ाने, `keyctl` का दुरुपयोग करने, या इन syscall paths को `CAP_SYS_ADMIN` जैसी dangerous capabilities के साथ combine करने में सक्षम हो सकता है। कई वास्तविक attacks में seccomp ही एकमात्र missing control नहीं होता, लेकिन इसकी अनुपस्थिति exploit path को काफी छोटा कर देती है, क्योंकि यह उन कुछ defenses में से एक को हटा देती है जो privilege model के बाकी हिस्से के लागू होने से पहले ही किसी risky syscall को रोक सकते हैं।

सबसे उपयोगी practical test यह है कि उन exact syscall families को आजमाया जाए जिन्हें default profiles आम तौर पर block करते हैं। यदि वे अचानक काम करने लगें, तो container posture में बड़ा बदलाव आ चुका है:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
यदि `CAP_SYS_ADMIN` या कोई अन्य strong capability मौजूद है, तो mount-based abuse से पहले जांचें कि seccomp ही एकमात्र missing barrier है या नहीं:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
कुछ targets पर, immediate value full escape नहीं, बल्कि information gathering और kernel attack-surface expansion होता है। ये commands यह निर्धारित करने में सहायता करते हैं कि विशेष रूप से संवेदनशील syscall paths तक पहुंच संभव है या नहीं:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
यदि seccomp मौजूद नहीं है और container अन्य तरीकों से भी privileged है, तभी पहले से documented legacy container-escape pages में दी गई अधिक specific breakout techniques पर pivot करना उचित होता है।

### Full Example: seccomp Was The Only Thing Blocking `unshare`

कई targets पर seccomp हटाने का व्यावहारिक प्रभाव यह होता है कि namespace-creation या mount syscalls अचानक काम करने लगते हैं। यदि container में `CAP_SYS_ADMIN` भी है, तो निम्न sequence संभव हो सकता है:
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
अपने आप में यह अभी host escape नहीं है, लेकिन यह दर्शाता है कि mount-संबंधित exploitation को रोकने वाली बाधा seccomp थी।

### पूर्ण उदाहरण: seccomp Disabled + cgroup v1 `release_agent`

यदि seccomp Disabled है और container cgroup v1 hierarchies को mount कर सकता है, तो cgroups section में दी गई `release_agent` technique तक पहुंच संभव हो जाती है:
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
यह seccomp-only exploit नहीं है। मुद्दा यह है कि जब seccomp unconfined हो जाता है, तो syscall-heavy breakout chains, जिन्हें पहले ब्लॉक किया गया था, ठीक उसी तरह काम करना शुरू कर सकती हैं जैसा वे लिखी गई हैं।

## जाँच

इन जाँचों का उद्देश्य यह निर्धारित करना है कि seccomp बिल्कुल सक्रिय है या नहीं, क्या `no_new_privs` इसके साथ मौजूद है, और क्या runtime configuration में seccomp को स्पष्ट रूप से disabled दिखाया गया है।
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
यहाँ क्या महत्वपूर्ण है:

- गैर-शून्य `Seccomp` मान का अर्थ है कि filtering सक्रिय है; `0` का आमतौर पर अर्थ है कि कोई seccomp protection नहीं है।
- यदि runtime security options में `seccomp=unconfined` शामिल है, तो workload ने अपनी सबसे उपयोगी syscall-level defenses में से एक खो दी है।
- `NoNewPrivs` स्वयं seccomp नहीं है, लेकिन दोनों को साथ देखना आमतौर पर किसी को भी न देखने की तुलना में अधिक सावधानीपूर्ण hardening posture का संकेत देता है।

यदि किसी container में पहले से suspicious mounts, broad capabilities, या shared host namespaces हैं और seccomp भी unconfined है, तो इस combination को major escalation signal माना जाना चाहिए। Container अभी भी आसानी से breakable न हो सकता है, लेकिन attacker के लिए उपलब्ध kernel entry points की संख्या तेज़ी से बढ़ गई है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | आमतौर पर default रूप से enabled | Override न किए जाने पर Docker के built-in default seccomp profile का उपयोग करता है | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | आमतौर पर default रूप से enabled | Override न किए जाने पर runtime default seccomp profile लागू करता है | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Default रूप से guaranteed नहीं** | यदि `securityContext.seccompProfile` unset है, तो default `Unconfined` होता है, जब तक kubelet `--seccomp-default` enable न करे; अन्यथा `RuntimeDefault` या `Localhost` को explicitly set करना होगा | `securityContext.seccompProfile.type: Unconfined`, `seccompDefault` के बिना clusters पर seccomp को unset छोड़ना, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes node और Pod settings का पालन करता है | Kubernetes द्वारा `RuntimeDefault` अनुरोध किए जाने पर या kubelet seccomp defaulting enabled होने पर runtime profile का उपयोग किया जाता है | Kubernetes row के समान; direct CRI/OCI configuration भी seccomp को पूरी तरह omit कर सकती है |

Kubernetes का behavior operators को सबसे अधिक चौंकाता है। कई clusters में seccomp अभी भी absent होता है, जब तक कि Pod इसे request न करे या kubelet को `RuntimeDefault` पर default करने के लिए configure न किया गया हो।<sup>[[3]](#references)</sup>

## References

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
