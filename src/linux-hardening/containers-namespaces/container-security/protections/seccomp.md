# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Security Impact

**seccomp** वह mechanism है जिससे kernel उन syscalls पर filter लागू कर सकता है जिन्हें कोई process invoke कर सकता है। Containerized environments में seccomp का उपयोग सामान्यतः filter mode में किया जाता है, ताकि process को केवल अस्पष्ट अर्थ में "restricted" चिह्नित न किया जाए, बल्कि उस पर एक ठोस syscall policy लागू हो। यह महत्वपूर्ण है क्योंकि कई container breakouts के लिए बहुत विशिष्ट kernel interfaces तक पहुंचना आवश्यक होता है। यदि process संबंधित syscalls को सफलतापूर्वक invoke नहीं कर सकता, तो namespace या capability से जुड़ी बारीकियां प्रासंगिक होने से पहले ही attacks का एक बड़ा वर्ग समाप्त हो जाता है।

मुख्य mental model सरल है: namespaces तय करते हैं कि **process क्या देख सकता है**, capabilities तय करती हैं कि **process को nominally कौन-सी privileged actions करने का प्रयास करने की अनुमति है**, और seccomp तय करता है कि **kernel प्रयास की गई action के syscall entry point को स्वीकार भी करेगा या नहीं**। यही कारण है कि seccomp अक्सर उन attacks को रोक देता है जो केवल capabilities के आधार पर संभव दिखाई दे सकते थे।

## Security Impact

खतरनाक kernel surface का बड़ा हिस्सा केवल syscalls के अपेक्षाकृत छोटे set के माध्यम से accessible होता है। Container hardening में बार-बार महत्वपूर्ण होने वाले examples में `mount`, `unshare`, particular flags के साथ `clone` या `clone3`, `bpf`, `ptrace`, `keyctl`, और `perf_event_open` शामिल हैं। ऐसा attacker जो उन syscalls तक पहुंच सकता है, नए namespaces बनाने, kernel subsystems में बदलाव करने, या ऐसे attack surface के साथ interact करने में सक्षम हो सकता है जिसकी किसी normal application container को बिल्कुल आवश्यकता नहीं होती।

यही कारण है कि default runtime seccomp profiles इतने महत्वपूर्ण हैं। वे केवल "extra defense" नहीं हैं। कई environments में वे उस container के बीच का अंतर होते हैं जो kernel functionality के बड़े हिस्से का उपयोग कर सकता है और उस container के बीच का, जो ऐसे syscall surface तक सीमित होता है जो application की वास्तविक आवश्यकताओं के अधिक करीब है।

## Modes And Filter Construction

seccomp में ऐतिहासिक रूप से एक strict mode था जिसमें केवल एक बहुत छोटा syscall set उपलब्ध रहता था, लेकिन modern container runtimes के लिए प्रासंगिक mode seccomp filter mode है, जिसे अक्सर **seccomp-bpf** कहा जाता है। इस model में kernel एक filter program evaluate करता है, जो तय करता है कि किसी syscall को allow किया जाना चाहिए, errno के साथ deny किया जाना चाहिए, trap किया जाना चाहिए, log किया जाना चाहिए, या process को kill करना चाहिए। Container runtimes इस mechanism का उपयोग करते हैं क्योंकि यह normal application behavior को allow करते हुए dangerous syscalls के व्यापक classes को block करने के लिए पर्याप्त expressive है।

दो low-level examples उपयोगी हैं क्योंकि वे mechanism को किसी magical चीज के बजाय concrete बनाते हैं। Strict mode पुराने "केवल एक minimal syscall set बचा रहता है" model को दर्शाता है:
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

libseccomp filter का एक उदाहरण आधुनिक policy model को अधिक स्पष्ट रूप से दिखाता है:
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
इस प्रकार की policy वह है जिसकी कल्पना अधिकांश readers को runtime seccomp profiles के बारे में सोचते समय करनी चाहिए।

## Lab

किसी container में seccomp सक्रिय है या नहीं, इसकी पुष्टि करने का एक सरल तरीका है:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
आप ऐसा operation भी आज़मा सकते हैं जिसे default profiles आम तौर पर प्रतिबंधित करती हैं:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
यदि container एक सामान्य default seccomp profile के अंतर्गत चल रहा है, तो `unshare`-style operations अक्सर blocked होती हैं। यह एक उपयोगी demonstration है, क्योंकि इससे पता चलता है कि image के अंदर userspace tool मौजूद होने पर भी, kernel path जिसकी उसे आवश्यकता है, उपलब्ध नहीं हो सकता।

यदि container एक सामान्य default seccomp profile के अंतर्गत चल रहा है, तो image के अंदर userspace tool मौजूद होने पर भी `unshare`-style operations अक्सर blocked रहती हैं।

Process status को अधिक सामान्य रूप से inspect करने के लिए, चलाएँ:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime Usage

Docker default और custom seccomp profiles, दोनों को support करता है और administrators को `--security-opt seccomp=unconfined` के माध्यम से इन्हें disable करने की अनुमति देता है। Podman में भी ऐसा ही support है और यह अक्सर rootless execution के साथ एक बहुत sensible default posture में काम करता है। Kubernetes workload configuration के माध्यम से seccomp expose करता है, जहाँ `RuntimeDefault` आमतौर पर sane baseline होता है और `Unconfined` को convenience toggle के बजाय justification की आवश्यकता वाले exception के रूप में माना जाना चाहिए।

containerd और CRI-O आधारित environments में exact path अधिक layered होता है, लेकिन principle वही रहता है: higher-level engine या orchestrator तय करता है कि क्या होना चाहिए, और runtime अंततः container process के लिए resulting seccomp policy install करता है। Outcome अभी भी kernel तक पहुँचने वाली final runtime configuration पर निर्भर करता है।

### Custom Policy Example

Docker और similar engines JSON से custom seccomp profile load कर सकते हैं। एक minimal example, जो `chmod` को deny करता है और बाकी सभी operations को allow करता है, इस प्रकार दिखता है:
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
कमांड `Operation not permitted` के साथ विफल होती है, जिससे स्पष्ट होता है कि प्रतिबंध केवल सामान्य file permissions से नहीं, बल्कि syscall policy से आता है। वास्तविक hardening में, permissive defaults के साथ छोटी blacklist की तुलना में allowlists आम तौर पर अधिक मजबूत होती हैं।

## Misconfigurations

सबसे स्पष्ट गलती यह है कि default policy के अंतर्गत application विफल होने पर seccomp को **unconfined** पर सेट कर दिया जाए। Troubleshooting के दौरान यह आम है और स्थायी fix के रूप में बहुत खतरनाक है। Filter हटते ही, syscall-आधारित कई breakout primitives फिर से reachable हो जाते हैं, खासकर तब जब powerful capabilities या host namespace sharing भी मौजूद हों।

एक और आम समस्या **custom permissive profile** का उपयोग है, जिसे किसी blog या internal workaround से कॉपी किया गया हो और जिसकी सावधानीपूर्वक समीक्षा न की गई हो। Teams कभी-कभी लगभग सभी dangerous syscalls को केवल इसलिए बनाए रखती हैं क्योंकि profile को "app को breaking से रोकने" के आधार पर बनाया गया था, न कि "app को वास्तव में जितनी आवश्यकता है केवल उतना grant करने" के आधार पर। एक तीसरी गलत धारणा यह है कि non-root containers के लिए seccomp कम महत्वपूर्ण है। वास्तविकता में, process के UID 0 न होने पर भी kernel attack surface का काफी हिस्सा relevant रहता है।

## Abuse

यदि seccomp अनुपस्थित हो या बुरी तरह weakened हो, तो attacker namespace-creation syscalls invoke करने, `bpf` या `perf_event_open` के माध्यम से reachable kernel attack surface बढ़ाने, `keyctl` का abuse करने, या इन syscall paths को `CAP_SYS_ADMIN` जैसी dangerous capabilities के साथ combine करने में सक्षम हो सकता है। कई वास्तविक attacks में seccomp ही एकमात्र missing control नहीं होता, लेकिन इसकी अनुपस्थिति exploit path को काफी छोटा कर देती है, क्योंकि यह उन कुछ defenses में से एक को हटा देती है जो privilege model के बाकी हिस्से के सक्रिय होने से पहले ही किसी risky syscall को रोक सकती हैं।

सबसे उपयोगी practical test उन exact syscall families को आज़माना है जिन्हें default profiles आम तौर पर block करते हैं। यदि वे अचानक काम करने लगें, तो container posture में काफी बदलाव आ गया है:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
यदि `CAP_SYS_ADMIN` या कोई अन्य strong capability मौजूद हो, तो mount-based abuse से पहले जाँचें कि क्या seccomp ही एकमात्र अनुपस्थित बाधा है:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
कुछ targets पर तात्कालिक उद्देश्य full escape नहीं, बल्कि information gathering और kernel attack-surface expansion होता है। ये commands यह निर्धारित करने में सहायता करती हैं कि विशेष रूप से sensitive syscall paths तक पहुँचना संभव है या नहीं:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
यदि seccomp अनुपस्थित है और container अन्य तरीकों से भी privileged है, तो legacy container-escape pages में पहले से documented अधिक specific breakout techniques की ओर pivot करना उचित होता है।

### पूर्ण उदाहरण: `unshare` को रोकने वाली एकमात्र चीज़ seccomp थी

कई targets पर seccomp हटाने का practical प्रभाव यह होता है कि namespace-creation या mount syscalls अचानक काम करने लगती हैं। यदि container में `CAP_SYS_ADMIN` भी हो, तो निम्न sequence संभव हो सकता है:
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
अपने आप में यह अभी host escape नहीं है, लेकिन यह दर्शाता है कि mount-related exploitation को रोकने वाली बाधा seccomp थी।

### पूर्ण उदाहरण: seccomp Disabled + cgroup v1 `release_agent`

यदि seccomp Disabled है और container cgroup v1 hierarchies को mount कर सकता है, तो cgroups section की `release_agent` technique उपलब्ध हो जाती है:
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
यह केवल seccomp exploit नहीं है। मुद्दा यह है कि एक बार seccomp unconfined हो जाए, तो syscall-heavy breakout chains, जो पहले blocked थीं, ठीक वैसे ही काम करना शुरू कर सकती हैं जैसा लिखा गया है।

## जाँच

इन जाँचों का उद्देश्य यह निर्धारित करना है कि seccomp बिल्कुल active है या नहीं, क्या `no_new_privs` इसके साथ मौजूद है, और क्या runtime configuration में seccomp को explicitly disabled दिखाया गया है।
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
यहाँ क्या महत्वपूर्ण है:

- गैर-शून्य `Seccomp` मान का अर्थ है कि filtering सक्रिय है; `0` का आमतौर पर अर्थ है कि कोई seccomp protection नहीं है।
- यदि runtime security options में `seccomp=unconfined` शामिल है, तो workload ने syscall-level की अपनी सबसे उपयोगी defenses में से एक खो दी है।
- `NoNewPrivs` स्वयं seccomp नहीं है, लेकिन दोनों को साथ देखना आमतौर पर इनमें से किसी को भी न देखने की तुलना में अधिक सावधानीपूर्ण hardening posture का संकेत देता है।

यदि किसी container में पहले से suspicious mounts, broad capabilities या shared host namespaces हैं और seccomp भी unconfined है, तो इस combination को major escalation signal माना जाना चाहिए। Container अभी भी आसानी से breakable न हो सकता है, लेकिन attacker के लिए उपलब्ध kernel entry points की संख्या तेज़ी से बढ़ गई है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | आमतौर पर default रूप से enabled | Override न किए जाने पर Docker के built-in default seccomp profile का उपयोग करता है | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | आमतौर पर default रूप से enabled | Override न किए जाने पर runtime default seccomp profile लागू करता है | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Default रूप से guaranteed नहीं** | यदि `securityContext.seccompProfile` unset है, तो `--seccomp-default` enable होने तक default `Unconfined` होता है; अन्यथा `RuntimeDefault` या `Localhost` को explicitly set करना आवश्यक है | `securityContext.seccompProfile.type: Unconfined`, `seccompDefault` के बिना clusters पर seccomp को unset छोड़ना, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes node और Pod settings का पालन करता है | Kubernetes द्वारा `RuntimeDefault` का अनुरोध करने पर या kubelet seccomp defaulting enabled होने पर runtime profile का उपयोग किया जाता है | Kubernetes row जैसा ही; direct CRI/OCI configuration भी seccomp को पूरी तरह omit कर सकती है |

Kubernetes का behavior operators को सबसे अधिक आश्चर्यचकित करता है। कई clusters में seccomp अभी भी absent होता है, जब तक कि Pod इसका अनुरोध न करे या kubelet को `RuntimeDefault` पर default करने के लिए configure न किया गया हो।
{{#include ../../../../banners/hacktricks-training.md}}
