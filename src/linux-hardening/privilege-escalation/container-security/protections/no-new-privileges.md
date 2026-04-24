# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` एक kernel hardening feature है जो किसी process को `execve()` के across अधिक privilege पाने से रोकता है। Practical terms में, once flag set हो जाए, setuid binary, setgid binary, या Linux file capabilities वाला file execute करने पर process को उसकी मौजूदा privilege से extra privilege नहीं मिलता। containerized environments में यह important है, क्योंकि कई privilege-escalation chains इस बात पर निर्भर करते हैं कि image के अंदर ऐसा executable मिले जो launch होने पर privilege बदल दे।

Defensive point of view से, `no_new_privs` namespaces, seccomp, या capability dropping का substitute नहीं है। यह एक reinforcement layer है। यह code execution already हासिल होने के बाद follow-up escalation की एक specific class को block करता है। इसलिए यह उन environments में खास तौर पर valuable है जहाँ images में helper binaries, package-manager artifacts, या legacy tools हों, जो partial compromise के साथ मिलकर dangerous हो सकते हैं।

## Operation

इस behavior के पीछे kernel flag `PR_SET_NO_NEW_PRIVS` है। एक बार किसी process के लिए यह set हो जाए, तो बाद के `execve()` calls privilege को increase नहीं कर सकते। Important detail यह है कि process अभी भी binaries चला सकता है; बस वह उन binaries का use करके privilege boundary cross नहीं कर सकता जिसे kernel otherwise honor करता।

Kernel behavior **inherited and irreversible** भी है: एक बार task `no_new_privs` set कर दे, तो bit `fork()`, `clone()`, और `execve()` के across inherit हो जाता है, और बाद में unset नहीं किया जा सकता। Assessments में यह useful है, क्योंकि container process पर सिर्फ `NoNewPrivs: 1` आमतौर पर मतलब होता है कि descendants भी उसी mode में रहने चाहिए, जब तक कि आप पूरी तरह अलग process tree न देख रहे हों।

Kubernetes-oriented environments में, `allowPrivilegeEscalation: false` container process के लिए इसी behavior को map करता है। Docker और Podman style runtimes में, equivalent आमतौर पर security option के through explicitly enabled किया जाता है। OCI layer पर, यही concept `process.noNewPrivileges` के रूप में दिखता है।

## Important Nuances

`no_new_privs` **exec-time** privilege gain को block करता है, हर privilege change को नहीं। खास तौर पर:

- setuid और setgid transitions `execve()` के across काम करना बंद कर देते हैं
- file capabilities `execve()` पर permitted set में add नहीं होतीं
- AppArmor या SELinux जैसे LSMs `execve()` के बाद constraints को relax नहीं करते
- पहले से मौजूद privilege, पहले से मौजूद ही रहता है

यह आखिरी point operationally important है। अगर process पहले से root चल रहा है, पहले से कोई dangerous capability रखता है, या पहले से किसी powerful runtime API या writable host mount तक access रखता है, तो `no_new_privs` उन exposures को neutralize नहीं करता। यह सिर्फ privilege-escalation chain में एक common **next step** को हटाता है।

यह भी ध्यान दें कि यह flag उन privilege changes को block नहीं करता जो `execve()` पर depend नहीं करतीं। उदाहरण के लिए, जो task पहले से पर्याप्त privileged है, वह अभी भी सीधे `setuid(2)` call कर सकता है या Unix socket के जरिए privileged file descriptor प्राप्त कर सकता है। इसलिए `no_new_privs` को [seccomp](seccomp.md), capability sets, और namespace exposure के साथ पढ़ना चाहिए, न कि standalone answer के रूप में।

## Lab

Current process state inspect करें:
```bash
grep NoNewPrivs /proc/self/status
```
उसकी तुलना एक ऐसे container से करें जहाँ runtime यह flag enable करता है:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
एक hardened workload पर, परिणाम में `NoNewPrivs: 1` दिखना चाहिए।

आप setuid binary के खिलाफ वास्तविक प्रभाव भी दिखा सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
इस तुलना का उद्देश्य यह नहीं है कि `su` सार्वभौमिक रूप से exploitable है। उद्देश्य यह है कि वही image बहुत अलग तरीके से behave कर सकती है, यह इस पर निर्भर करता है कि `execve()` अभी भी privilege boundary को cross करने की अनुमति रखता है या नहीं।

## Security Impact

अगर `no_new_privs` absent है, तो container के अंदर बना foothold अभी भी setuid helpers या file capabilities वाले binaries के जरिए upgraded हो सकता है। अगर यह present है, तो exec के बाद होने वाले ये privilege changes रोक दिए जाते हैं। यह effect खास तौर पर उन broad base images में relevant है जो कई utilities ship करती हैं, जिनकी application को शुरू से जरूरत ही नहीं थी।

एक महत्वपूर्ण seccomp interaction भी है। Unprivileged tasks को आम तौर पर filter mode में seccomp filter install करने से पहले `no_new_privs` set करना पड़ता है। यही एक कारण है कि hardened containers में अक्सर `Seccomp` और `NoNewPrivs` दोनों साथ में enabled दिखते हैं। attacker के नजरिए से, दोनों को देखना आम तौर पर यह संकेत देता है कि environment accidentally नहीं, बल्कि deliberately configure किया गया था।

## Misconfigurations

सबसे आम problem बस यही है कि उन environments में control enable नहीं किया जाता जहाँ यह compatible होता। Kubernetes में `allowPrivilegeEscalation` को enabled छोड़ देना अक्सर default operational mistake होता है। Docker और Podman में, relevant security option को omit करने का वही effect होता है। एक और recurring failure mode यह मान लेना है कि क्योंकि container "not privileged" है, इसलिए exec-time privilege transitions automatically irrelevant हैं।

Kubernetes की एक और subtle pitfall यह है कि `allowPrivilegeEscalation: false` को लोगों की उम्मीद के मुताबिक honor नहीं किया जाता जब container `privileged` हो या जब उसके पास `CAP_SYS_ADMIN` हो। Kubernetes API document करता है कि उन cases में `allowPrivilegeEscalation` effectively हमेशा true होता है। Practical तौर पर, इसका मतलब है कि field को final posture में एक signal की तरह देखना चाहिए, न कि इस guarantee की तरह कि runtime ने अंततः `NoNewPrivs: 1` set किया होगा।

## Abuse

अगर `no_new_privs` set नहीं है, तो पहला सवाल यह है कि क्या image में ऐसे binaries हैं जो अभी भी privilege बढ़ा सकते हैं:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
दिलचस्प परिणामों में शामिल हैं:

- `NoNewPrivs: 0`
- setuid helpers जैसे `su`, `mount`, `passwd`, या distribution-specific admin tools
- file capabilities वाले binaries जो network या filesystem privileges grant करते हैं

एक real assessment में, ये findings अपने-आप में working escalation prove नहीं करते, लेकिन ये exactly वही binaries identify करते हैं जिन्हें आगे test करना चाहिए।

Kubernetes में, यह भी verify करें कि YAML intent kernel reality से match करता है:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
दिलचस्प संयोजन में शामिल हैं:

- Pod spec में `allowPrivilegeEscalation: false` लेकिन container में `NoNewPrivs: 0`
- `cap_sys_admin` मौजूद है, जो Kubernetes field को काफी कम भरोसेमंद बनाता है
- `Seccomp: 0` और `NoNewPrivs: 0`, जो आमतौर पर एक अकेली अलग गलती के बजाय broadly कमजोर runtime posture का संकेत देता है

### Full Example: setuid के Through In-Container Privilege Escalation

यह control आमतौर पर सीधे host escape के बजाय **in-container privilege escalation** को रोकता है। अगर `NoNewPrivs` `0` है और कोई setuid helper मौजूद है, तो इसे explicitly test करें:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
यदि कोई known setuid binary मौजूद हो और functional हो, तो उसे इस तरह launch करने की कोशिश करें कि privilege transition preserve रहे:
```bash
/bin/su -c id 2>/dev/null
```
यह अपने आप में container से escape नहीं करता, लेकिन यह container के अंदर low-privilege foothold को container-root में बदल सकता है, जो अक्सर mounts, runtime sockets, या kernel-facing interfaces के जरिए बाद में host escape के लिए prerequisite बन जाता है।

## Checks

इन checks का goal यह स्थापित करना है कि exec-time privilege gain blocked है या नहीं और क्या image में अभी भी ऐसे helpers मौजूद हैं जो, अगर यह blocked नहीं है, तो महत्वपूर्ण होंगे।
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
What is interesting here:

- `NoNewPrivs: 1` आमतौर पर safer result है।
- `NoNewPrivs: 0` का मतलब है कि setuid और file-cap आधारित escalation paths अभी भी relevant हैं।
- `NoNewPrivs: 1` plus `Seccomp: 2` अक्सर अधिक intentional hardening posture का संकेत होता है।
- एक Kubernetes manifest जो `allowPrivilegeEscalation: false` कहता है, उपयोगी है, लेकिन kernel status ही ground truth है।
- कम setuid/file-cap binaries वाला minimal image attacker को कम post-exploitation options देता है, even when `no_new_privs` missing हो।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | By default enabled नहीं | `--security-opt no-new-privileges=true` के साथ explicitly enabled; daemon-wide default `dockerd --no-new-privileges` से भी मौजूद है | flag छोड़ देना, `--privileged` |
| Podman | By default enabled नहीं | `--security-opt no-new-privileges` या equivalent security configuration के साथ explicitly enabled | option छोड़ देना, `--privileged` |
| Kubernetes | workload policy द्वारा controlled | `allowPrivilegeEscalation: false` effect request करता है, लेकिन `privileged: true` और `CAP_SYS_ADMIN` इसे effectively true रखते हैं | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` जोड़ना |
| containerd / CRI-O under Kubernetes | Kubernetes workload settings / OCI `process.noNewPrivileges` follow करता है | Usually Pod security context से inherited होता है और OCI runtime config में translated होता है | same as Kubernetes row |

यह protection अक्सर सिर्फ इसलिए absent होती है क्योंकि किसी ने इसे on नहीं किया, न कि इसलिए कि runtime इसमें support नहीं करता।

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
