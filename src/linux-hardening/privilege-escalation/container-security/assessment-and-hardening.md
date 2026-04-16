# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

एक अच्छा container assessment दो समानांतर प्रश्नों का उत्तर देना चाहिए। पहला, current workload से attacker क्या कर सकता है? दूसरा, कौन-से operator choices ने यह संभव बनाया? Enumeration tools पहले प्रश्न में मदद करते हैं, और hardening guidance दूसरे में। दोनों को एक ही पेज पर रखने से यह section सिर्फ escape tricks की catalog की बजाय field reference के रूप में अधिक उपयोगी बन जाता है।

Modern environments के लिए एक व्यावहारिक update यह है कि कई पुराने container writeups चुपचाप एक **rootful runtime**, **no user namespace isolation**, और अक्सर **cgroup v1** मान लेते हैं। ये assumptions अब सुरक्षित नहीं हैं। पुराने escape primitives पर समय लगाने से पहले, पहले confirm करें कि workload rootless है या userns-remapped, host cgroup v2 इस्तेमाल कर रहा है या नहीं, और क्या Kubernetes या runtime अब default seccomp और AppArmor profiles लागू कर रहा है। ये details अक्सर तय करती हैं कि कोई प्रसिद्ध breakout अभी भी लागू होता है या नहीं।

## Enumeration Tools

Container environment को जल्दी से characterize करने के लिए कई tools उपयोगी रहते हैं:

- `linpeas` कई container indicators, mounted sockets, capability sets, dangerous filesystems, और breakout hints पहचान सकता है।
- `CDK` विशेष रूप से container environments पर केंद्रित है और इसमें enumeration के साथ कुछ automated escape checks भी शामिल हैं।
- `amicontained` हल्का है और container restrictions, capabilities, namespace exposure, और संभावित breakout classes की पहचान के लिए उपयोगी है।
- `deepce` एक और container-focused enumerator है जिसमें breakout-oriented checks हैं।
- `grype` तब उपयोगी है जब assessment में केवल runtime escape analysis नहीं बल्कि image-package vulnerability review भी शामिल हो।
- `Tracee` तब उपयोगी है जब आपको केवल static posture नहीं बल्कि **runtime evidence** चाहिए, खासकर suspicious process execution, file access, और container-aware event collection के लिए।
- `Inspektor Gadget` Kubernetes और Linux-host investigations में उपयोगी है जब आपको pods, containers, namespaces, और अन्य higher-level concepts से जुड़ी eBPF-backed visibility चाहिए।

इन tools का value speed और coverage है, certainty नहीं। ये rough posture को जल्दी उजागर करने में मदद करते हैं, लेकिन interesting findings को अभी भी actual runtime, namespace, capability, और mount model के विरुद्ध manual interpretation की जरूरत होती है।

## Hardening Priorities

सबसे महत्वपूर्ण hardening principles conceptually सरल हैं, भले ही उनका implementation platform के अनुसार अलग हो। Privileged containers से बचें। Mounted runtime sockets से बचें। जब तक बहुत विशिष्ट कारण न हो, containers को writable host paths न दें। संभव हो तो user namespaces या rootless execution का उपयोग करें। सभी capabilities drop करें और केवल वही वापस जोड़ें जो workload को वास्तव में चाहिए। Application compatibility problems को ठीक करने के लिए उन्हें disable करने के बजाय seccomp, AppArmor, और SELinux enabled रखें। Resources limit करें ताकि compromised container host पर trivially deny of service न कर सके।

Image और build hygiene runtime posture जितने ही महत्वपूर्ण हैं। Minimal images का उपयोग करें, बार-बार rebuild करें, उन्हें scan करें, जहाँ practical हो provenance require करें, और secrets को layers से बाहर रखें। Non-root के रूप में चलने वाला container, छोटे image और narrow syscall तथा capability surface के साथ, उस बड़े convenience image की तुलना में बहुत आसान है जिसे host-equivalent root के रूप में चलाया जा रहा हो और जिसमें debugging tools पहले से installed हों।

Kubernetes के लिए, current hardening baselines कई operators की धारणा से अधिक opinionated हैं। Built-in **Pod Security Standards** `restricted` को "current best practice" profile के रूप में treat करते हैं: `allowPrivilegeEscalation` `false` होना चाहिए, workloads non-root के रूप में चलने चाहिए, seccomp को स्पष्ट रूप से `RuntimeDefault` या `Localhost` पर set किया जाना चाहिए, और capability sets को aggressively drop किया जाना चाहिए। Assessment के दौरान यह महत्वपूर्ण है, क्योंकि जो cluster केवल `warn` या `audit` labels का उपयोग कर रहा है, वह paper पर hardened दिख सकता है जबकि व्यवहार में अभी भी risky pods स्वीकार कर रहा हो।

## Modern Triage Questions

Escape-specific pages में जाने से पहले, इन quick questions के उत्तर दें:

1. क्या workload **rootful**, **rootless**, या **userns-remapped** है?
2. क्या node **cgroup v1** या **cgroup v2** उपयोग कर रहा है?
3. क्या **seccomp** और **AppArmor/SELinux** explicitly configured हैं, या उपलब्ध होने पर केवल inherited हैं?
4. Kubernetes में, क्या namespace वास्तव में `baseline` या `restricted` को **enforcing** कर रहा है, या केवल warning/auditing कर रहा है?

Useful checks:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
यहाँ क्या दिलचस्प है:

- यदि `/proc/self/uid_map` दिखाता है कि container root एक **high host UID range** पर mapped है, तो कई पुराने host-root writeups अब कम relevant हो जाते हैं, क्योंकि container में root अब host-root equivalent नहीं है।
- यदि `/sys/fs/cgroup` `cgroup2fs` है, तो पुराने **cgroup v1**-specific writeups जैसे `release_agent` abuse अब आपका पहला guess नहीं होना चाहिए।
- यदि seccomp और AppArmor केवल implicitly inherited हैं, तो portability defenders की उम्मीद से कमजोर हो सकती है। Kubernetes में, स्पष्ट रूप से `RuntimeDefault` सेट करना अक्सर node defaults पर silently rely करने से अधिक strong होता है।
- यदि `supplementalGroupsPolicy` `Strict` पर set है, तो pod को image के अंदर `/etc/group` से extra group memberships silently inherit करने से बचना चाहिए, जिससे group-based volume और file access behavior अधिक predictable हो जाता है।
- `pod-security.kubernetes.io/enforce=restricted` जैसे namespace labels को सीधे check करना worth है। `warn` और `audit` useful हैं, लेकिन वे risky pod को create होने से नहीं रोकते।

## Resource-Exhaustion Examples

Resource controls glamorous नहीं होते, लेकिन वे container security का हिस्सा हैं क्योंकि वे compromise के blast radius को सीमित करते हैं। बिना memory, CPU, या PID limits के, एक simple shell host या neighboring workloads को degrade करने के लिए काफी हो सकता है।

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
ये उदाहरण उपयोगी हैं क्योंकि ये दिखाते हैं कि हर खतरनाक container परिणाम एक साफ़ "escape" नहीं होता। कमजोर cgroup limits फिर भी code execution को वास्तविक operational impact में बदल सकते हैं।

Kubernetes-backed environments में, DoS को सैद्धांतिक मानने से पहले यह भी जांचें कि resource controls मौजूद हैं या नहीं:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Docker-केंद्रित environments के लिए, `docker-bench-security` एक उपयोगी host-side audit baseline बना रहता है क्योंकि यह common configuration issues को widely recognized benchmark guidance के against check करता है:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
The tool थ्रेट मॉडलिंग का विकल्प नहीं है, लेकिन यह फिर भी careless daemon, mount, network, और runtime defaults को ढूंढने के लिए उपयोगी है, जो समय के साथ जमा हो जाते हैं।

Kubernetes और runtime-heavy environments के लिए, static checks को runtime visibility के साथ pair करें:

- `Tracee` container-aware runtime detection और quick forensics के लिए उपयोगी है जब आपको यह confirm करना हो कि एक compromised workload ने वास्तव में किस चीज़ को touch किया।
- `Inspektor Gadget` तब उपयोगी है जब assessment को kernel-level telemetry की ज़रूरत हो जिसे pods, containers, DNS activity, file execution, या network behavior से map किया जा सके।

## Checks

Assessment के दौरान इन्हें quick first-pass commands के रूप में उपयोग करें:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
यहाँ क्या interesting है:

- Broad capabilities और `Seccomp: 0` वाला root process तुरंत ध्यान देने योग्य है।
- जो root process साथ में **1:1 UID map** भी रखता है, वह properly isolated user namespace के अंदर "root" की तुलना में कहीं अधिक interesting है।
- `cgroup2fs` आम तौर पर बताता है कि कई पुराने **cgroup v1** escape chains आपका best starting point नहीं हैं, जबकि `memory.max` या `pids.max` का missing होना अभी भी weak blast-radius controls की ओर इशारा करता है।
- Suspicious mounts और runtime sockets अक्सर किसी भी kernel exploit की तुलना में impact तक तेज़ रास्ता देते हैं।
- Weak runtime posture और weak resource limits का combination आमतौर पर एक single isolated mistake के बजाय generally permissive container environment को दर्शाता है।

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
