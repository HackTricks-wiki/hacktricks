# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` एक kernel hardening feature है, जो किसी process को `execve()` के दौरान अधिक privilege प्राप्त करने से रोकता है। व्यावहारिक रूप से, एक बार flag set हो जाने पर, किसी setuid binary, setgid binary या Linux file capabilities वाली file को execute करने से process को उसकी मौजूदा privilege से अधिक privilege नहीं मिलता। Containerized environments में यह महत्वपूर्ण है, क्योंकि कई privilege-escalation chains image के अंदर ऐसे executable को खोजने पर निर्भर करती हैं, जो launch होने पर privilege बदल देता है।

Defensive दृष्टिकोण से, `no_new_privs`, namespaces, seccomp या capability dropping का विकल्प नहीं है। यह एक reinforcement layer है। यह code execution प्राप्त हो जाने के बाद होने वाली एक specific class की follow-up escalation को block करता है। इसलिए यह उन environments में विशेष रूप से उपयोगी है जहाँ images में helper binaries, package-manager artifacts या legacy tools मौजूद होते हैं, जो partial compromise के साथ मिलकर अन्यथा खतरनाक हो सकते हैं।

## Operation

इस behavior के पीछे kernel flag `PR_SET_NO_NEW_PRIVS` है। एक बार किसी process के लिए यह set हो जाने पर, बाद की `execve()` calls privilege को बढ़ा नहीं सकतीं। महत्वपूर्ण बात यह है कि process अभी भी binaries चला सकता है; वह केवल उन binaries का उपयोग करके उस privilege boundary को पार नहीं कर सकता, जिसे kernel अन्यथा allow करता।

Kernel behavior **inherited and irreversible** भी है: एक बार कोई task `no_new_privs` set कर दे, तो bit `fork()`, `clone()` और `execve()` के दौरान inherited रहती है और बाद में unset नहीं की जा सकती। Assessments में यह उपयोगी है, क्योंकि container process पर एक single `NoNewPrivs: 1` का सामान्यतः अर्थ होता है कि descendants को भी इसी mode में रहना चाहिए, जब तक कि आप पूरी तरह अलग process tree को न देख रहे हों।

Kubernetes-oriented environments में, `allowPrivilegeEscalation: false` container process के लिए इसी behavior को map करता है। Docker और Podman style runtimes में, equivalent आमतौर पर security option के माध्यम से explicitly enabled किया जाता है। OCI layer पर यही concept `process.noNewPrivileges` के रूप में दिखाई देता है।

## Important Nuances

`no_new_privs` **exec-time** privilege gain को block करता है, हर privilege change को नहीं। विशेष रूप से:

- setuid और setgid transitions `execve()` के दौरान काम करना बंद कर देते हैं
- file capabilities `execve()` पर permitted set में add नहीं होतीं
- AppArmor या SELinux जैसे LSMs `execve()` के बाद constraints को relax नहीं करते
- जो privilege पहले से मौजूद है, वह पहले से मौजूद privilege ही रहता है

यह अंतिम बिंदु operational रूप से महत्वपूर्ण है। यदि process पहले से root के रूप में चल रहा है, पहले से कोई dangerous capability रखता है, या पहले से किसी powerful runtime API अथवा writable host mount तक access रखता है, तो `no_new_privs` set करने से वे exposures neutralize नहीं होते। यह privilege-escalation chain में केवल एक सामान्य **next step** को हटाता है।

यह भी ध्यान दें कि flag उन privilege changes को block नहीं करता, जो `execve()` पर निर्भर नहीं होते। उदाहरण के लिए, कोई task जो पहले से पर्याप्त privileged है, सीधे `setuid(2)` call कर सकता है या Unix socket के माध्यम से privileged file descriptor प्राप्त कर सकता है। इसी कारण `no_new_privs` को standalone answer के रूप में देखने के बजाय [seccomp](seccomp.md), capability sets और namespace exposure के साथ पढ़ना चाहिए।

## Lab

Current process state inspect करें:
```bash
grep NoNewPrivs /proc/self/status
```
इसकी तुलना उस container से करें जिसमें runtime flag enable करता है:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
एक hardened workload पर परिणाम में `NoNewPrivs: 1` दिखाई देना चाहिए।

आप setuid binary के विरुद्ध वास्तविक प्रभाव भी प्रदर्शित कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
इस तुलना का उद्देश्य यह नहीं है कि `su` सार्वभौमिक रूप से exploitable है। उद्देश्य यह है कि वही image इस बात पर निर्भर करते हुए बहुत अलग व्यवहार कर सकती है कि `execve()` को privilege boundary पार करने की अनुमति अभी भी है या नहीं।

## Security Impact

यदि `no_new_privs` मौजूद नहीं है, तो container के भीतर मौजूद foothold को setuid helpers या file capabilities वाली binaries के माध्यम से अभी भी upgrade किया जा सकता है। यदि यह मौजूद है, तो exec के बाद होने वाले privilege changes रोक दिए जाते हैं। इसका प्रभाव विशेष रूप से broad base images में महत्वपूर्ण है, जिनमें कई ऐसी utilities शामिल होती हैं जिनकी application को वास्तव में कभी आवश्यकता नहीं थी।

seccomp के साथ भी एक महत्वपूर्ण interaction है। Unprivileged tasks को आम तौर पर filter mode में seccomp filter install करने से पहले `no_new_privs` set करना आवश्यक होता है। यही एक कारण है कि hardened containers में अक्सर `Seccomp` और `NoNewPrivs` दोनों एक साथ enabled दिखाई देते हैं। Attacker के दृष्टिकोण से, दोनों का मौजूद होना आम तौर पर यह दर्शाता है कि environment को जानबूझकर configure किया गया था, न कि यह गलती से हुआ।

## Misconfigurations

सबसे आम समस्या यह है कि उन environments में control को enable ही नहीं किया जाता जहाँ यह compatible होता। Kubernetes में `allowPrivilegeEscalation` को enabled छोड़ देना अक्सर default operational mistake होती है। Docker और Podman में संबंधित security option को omit करने का भी यही प्रभाव होता है। एक और बार-बार होने वाली failure mode यह मान लेना है कि क्योंकि कोई container "not privileged" है, इसलिए exec-time privilege transitions अपने-आप irrelevant हैं।

Kubernetes की एक अधिक subtle pitfall यह है कि `allowPrivilegeEscalation: false` को उस तरह **honor नहीं किया जाता जैसा लोग अपेक्षा करते हैं**, जब container `privileged` हो या उसके पास `CAP_SYS_ADMIN` हो। Kubernetes API documents करता है कि इन स्थितियों में `allowPrivilegeEscalation` प्रभावी रूप से हमेशा true होता है। व्यवहार में, इसका अर्थ है कि field को final posture में केवल एक signal माना जाना चाहिए, न कि इस बात की guarantee कि runtime में अंततः `NoNewPrivs: 1` set हुआ।

## Abuse

यदि `no_new_privs` set नहीं है, तो पहला प्रश्न यह है कि क्या image में ऐसी binaries मौजूद हैं जो अभी भी privilege बढ़ा सकती हैं:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
रोचक परिणामों में शामिल हैं:

- `NoNewPrivs: 0`
- `su`, `mount`, `passwd`, या distribution-specific admin tools जैसे setuid helpers
- ऐसी binaries जिनकी file capabilities network या filesystem privileges प्रदान करती हैं

वास्तविक assessment में, ये findings अपने-आप में working escalation सिद्ध नहीं करतीं, लेकिन ये ठीक उन binaries की पहचान करती हैं जिनका अगली बार परीक्षण किया जाना चाहिए।

Kubernetes में यह भी सत्यापित करें कि YAML में व्यक्त intent kernel reality से मेल खाता है:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
दिलचस्प संयोजनों में शामिल हैं:

- Pod spec में `allowPrivilegeEscalation: false`, लेकिन container में `NoNewPrivs: 0`
- `cap_sys_admin` मौजूद होना, जिससे Kubernetes field पर भरोसा काफी कम हो जाता है
- `Seccomp: 0` और `NoNewPrivs: 0`, जो आमतौर पर किसी एक अलग-थलग गलती के बजाय व्यापक रूप से कमजोर runtime posture का संकेत देता है

### Full Example: setuid के माध्यम से In-Container Privilege Escalation

यह control आमतौर पर सीधे host escape के बजाय **in-container privilege escalation** को रोकता है। यदि `NoNewPrivs` `0` है और कोई setuid helper मौजूद है, तो इसका स्पष्ट रूप से परीक्षण करें:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
यदि कोई ज्ञात setuid binary मौजूद और कार्यशील है, तो उसे इस तरह लॉन्च करने का प्रयास करें कि privilege transition बना रहे:
```bash
/bin/su -c id 2>/dev/null
```
यह अपने आप container से बाहर escape नहीं करता, लेकिन यह container के अंदर एक low-privilege foothold को container-root में बदल सकता है, जो अक्सर mounts, runtime sockets या kernel-facing interfaces के माध्यम से बाद में host escape के लिए prerequisite बन जाता है।

## Checks

इन checks का लक्ष्य यह निर्धारित करना है कि exec-time privilege gain को block किया गया है या नहीं, और image में अभी भी ऐसे helpers मौजूद हैं या नहीं जो इसके block न होने पर महत्वपूर्ण हो सकते हैं।
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
यहाँ क्या महत्वपूर्ण है:

- `NoNewPrivs: 1` आमतौर पर अधिक सुरक्षित परिणाम है।
- `NoNewPrivs: 0` का अर्थ है कि setuid और file-cap आधारित escalation paths अभी भी प्रासंगिक हैं।
- `NoNewPrivs: 1` के साथ `Seccomp: 2` अधिक जानबूझकर अपनाई गई hardening posture का सामान्य संकेत है।
- Kubernetes manifest में `allowPrivilegeEscalation: false` लिखा होना उपयोगी है, लेकिन kernel status ही ground truth है।
- कम या बिना setuid/file-cap binaries वाली minimal image attacker को कम post-exploitation options देती है, भले ही `no_new_privs` मौजूद न हो।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से enabled नहीं | `--security-opt no-new-privileges=true` के साथ explicitly enabled; daemon-wide default `dockerd --no-new-privileges` के माध्यम से भी उपलब्ध है | flag को छोड़ देना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से enabled नहीं | `--security-opt no-new-privileges` या equivalent security configuration के साथ explicitly enabled | option को छोड़ देना, `--privileged` |
| Kubernetes | workload policy द्वारा नियंत्रित | `allowPrivilegeEscalation: false` इस effect का अनुरोध करता है, लेकिन `privileged: true` और `CAP_SYS_ADMIN` इसे effectively true रखते हैं | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` जोड़ना |
| containerd / CRI-O under Kubernetes | Kubernetes workload settings / OCI `process.noNewPrivileges` का अनुसरण करता है | आमतौर पर Pod security context से inherited होकर OCI runtime config में translated होता है | Kubernetes row जैसा ही |

यह protection अक्सर केवल इसलिए absent होती है क्योंकि किसी ने इसे enabled नहीं किया, न कि इसलिए कि runtime में इसका support नहीं है।

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
