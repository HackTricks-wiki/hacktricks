# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

एक अच्छा container assessment दो समानांतर प्रश्नों का उत्तर देना चाहिए। पहला, मौजूदा workload से attacker क्या कर सकता है? दूसरा, कौन-से operator choices ने इसे संभव बनाया? Enumeration tools पहले प्रश्न में मदद करते हैं, और hardening guidance दूसरे में। दोनों को एक ही पेज पर रखने से यह section केवल escape tricks की catalog के बजाय field reference के रूप में अधिक उपयोगी बनता है।

आधुनिक environments के लिए एक व्यावहारिक update यह है कि कई पुराने container writeups चुपचाप **rootful runtime**, **no user namespace isolation**, और अक्सर **cgroup v1** मान लेते हैं। अब ये assumptions सुरक्षित नहीं हैं। पुराने escape primitives पर समय लगाने से पहले यह confirm करें कि workload rootless या userns-remapped है या नहीं, host cgroup v2 का उपयोग कर रहा है या नहीं, और Kubernetes या runtime अब default seccomp और AppArmor profiles लागू कर रहा है या नहीं। ये विवरण अक्सर तय करते हैं कि कोई प्रसिद्ध breakout अभी भी लागू होता है या नहीं।

## Enumeration Tools

Container environment को तुरंत characterize करने के लिए कई tools अभी भी उपयोगी हैं:

- `linpeas` कई container indicators, mounted sockets, capability sets, dangerous filesystems और breakout hints की पहचान कर सकता है।
- `CDK` विशेष रूप से container environments पर केंद्रित है और इसमें enumeration के साथ कुछ automated escape checks भी शामिल हैं।
- `amicontained` lightweight है और container restrictions, capabilities, namespace exposure और संभावित breakout classes की पहचान करने के लिए उपयोगी है।
- `deepce` एक अन्य container-focused enumerator है, जिसमें breakout-oriented checks शामिल हैं।
- `grype` तब उपयोगी है जब assessment में केवल runtime escape analysis के बजाय image-package vulnerability review भी शामिल हो।
- `Tracee` तब उपयोगी है जब आपको केवल static posture के बजाय **runtime evidence** चाहिए, विशेष रूप से suspicious process execution, file access और container-aware event collection के लिए।
- `Inspektor Gadget` Kubernetes और Linux-host investigations में उपयोगी है, जब आपको pods, containers, namespaces और अन्य higher-level concepts से जुड़ी eBPF-backed visibility चाहिए।

इन tools का मूल्य speed और coverage है, certainty नहीं। वे rough posture को जल्दी उजागर करने में मदद करते हैं, लेकिन महत्वपूर्ण findings की actual runtime, namespace, capability और mount model के संदर्भ में manual interpretation अभी भी आवश्यक होती है।

## Hardening Priorities

सबसे महत्वपूर्ण hardening principles वैचारिक रूप से सरल हैं, भले ही उनका implementation platform के अनुसार अलग हो। Privileged containers से बचें। Mounted runtime sockets से बचें। Containers को writable host paths न दें, जब तक इसका कोई बहुत specific reason न हो। जहाँ संभव हो, user namespaces या rootless execution का उपयोग करें। सभी capabilities drop करें और केवल वही वापस add करें जिनकी workload को वास्तव में आवश्यकता है। Application compatibility problems ठीक करने के लिए seccomp, AppArmor और SELinux को disable करने के बजाय enabled रखें। Resources को limit करें, ताकि compromised container host को आसानी से deny service न कर सके।

Image और build hygiene runtime posture जितने ही महत्वपूर्ण हैं। Minimal images का उपयोग करें, उन्हें frequently rebuild करें, scan करें, जहाँ practical हो provenance require करें, और secrets को layers से बाहर रखें। Non-root के रूप में चलने वाला container, जिसमें छोटी image और narrow syscall तथा capability surface हो, उस बड़े convenience image की तुलना में defend करना काफी आसान है जो host-equivalent root के रूप में चलता हो और जिसमें debugging tools पहले से installed हों।

Kubernetes के लिए current hardening baselines कई operators की अब भी मौजूद assumptions से अधिक opinionated हैं। Built-in **Pod Security Standards** `restricted` को "current best practice" profile मानते हैं: `allowPrivilegeEscalation` को `false` होना चाहिए, workloads को non-root के रूप में चलना चाहिए, seccomp को explicitly `RuntimeDefault` या `Localhost` पर set किया जाना चाहिए, और capability sets को aggressively drop किया जाना चाहिए। Assessment के दौरान यह महत्वपूर्ण है, क्योंकि केवल `warn` या `audit` labels का उपयोग करने वाला cluster कागज़ पर hardened दिख सकता है, जबकि व्यवहार में अभी भी risky pods को admit कर रहा हो।<sup>[[1]](#references)</sup>

## Modern Triage Questions

Escape-specific pages पर जाने से पहले इन quick questions के उत्तर दें:

1. क्या workload **rootful**, **rootless**, या **userns-remapped** है?
2. क्या node **cgroup v1** या **cgroup v2** का उपयोग कर रहा है?
3. क्या **seccomp** और **AppArmor/SELinux** explicitly configured हैं, या केवल उपलब्ध होने पर inherited हैं?
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
यहाँ क्या महत्वपूर्ण है:

- यदि `/proc/self/uid_map` कंटेनर root को **high host UID range** से mapped दिखाता है, तो कई पुराने host-root writeups कम प्रासंगिक हो जाते हैं, क्योंकि कंटेनर का root अब host-root equivalent नहीं रहता।
- यदि `/sys/fs/cgroup` `cgroup2fs` है, तो पुराने **cgroup v1**-specific writeups, जैसे `release_agent` abuse, अब आपका पहला अनुमान नहीं होना चाहिए।
- यदि seccomp और AppArmor केवल implicitly inherited हैं, तो portability defenders की अपेक्षा से कमजोर हो सकती है। Kubernetes में `RuntimeDefault` को explicitly सेट करना, node defaults पर चुपचाप निर्भर रहने से अक्सर अधिक मजबूत होता है।
- यदि `supplementalGroupsPolicy` को `Strict` पर सेट किया गया है, तो pod को image के अंदर मौजूद `/etc/group` से अतिरिक्त group memberships को चुपचाप inherit करने से बचना चाहिए। इससे group-based volume और file access behavior अधिक predictable होता है।
- `pod-security.kubernetes.io/enforce=restricted` जैसे namespace labels को सीधे check करना उपयोगी है। `warn` और `audit` उपयोगी हैं, लेकिन वे किसी risky pod को create होने से नहीं रोकते।

## Runtime Baseline Triage

Runtime baseline वह quick pass है जो बताता है कि कोई container सामान्य isolated workload जैसा दिखता है या host-impacting control plane foothold जैसा। इसमें अगले पढ़े जाने वाले page को prioritize करने के लिए पर्याप्त facts collect होने चाहिए: runtime socket abuse, host mounts, namespaces, cgroups, capabilities या image-secret review।

Workload के अंदर से किए जाने वाले उपयोगी checks:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Interpretation:

- Missing or unlimited `memory.max` / `pids.max` एक clean escape के बिना भी कमजोर blast-radius controls की ओर संकेत करता है।
- `NoNewPrivs: 0`, broad capabilities और permissive seccomp वाला root shell, narrow non-root workload की तुलना में कहीं अधिक महत्वपूर्ण है।
- Runtime sockets और writable host mounts आमतौर पर kernel exploits से ऊपर होते हैं, क्योंकि वे पहले से ही management या filesystem control path उजागर करते हैं।
- Shared PID, network, IPC या cgroup namespaces अपने-आप में हमेशा full escapes नहीं होते, लेकिन वे अगला चरण ढूँढना आसान बना देते हैं।

## Resource-Exhaustion Examples

Resource controls आकर्षक नहीं होते, लेकिन वे container security का हिस्सा हैं क्योंकि वे compromise के blast radius को सीमित करते हैं। Memory, CPU या PID limits के बिना, एक साधारण shell host या आस-पास के workloads को degrade करने के लिए पर्याप्त हो सकता है।

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
ये उदाहरण उपयोगी हैं क्योंकि वे दिखाते हैं कि हर खतरनाक container परिणाम एक साफ़ "escape" नहीं होता। कमजोर cgroup limits फिर भी code execution को वास्तविक operational impact में बदल सकती हैं।

Kubernetes-backed environments में, DoS को केवल सैद्धांतिक मानने से पहले यह भी जांचें कि resource controls मौजूद भी हैं या नहीं:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Docker-केंद्रित environments के लिए, `docker-bench-security` अभी भी एक उपयोगी host-side audit baseline है, क्योंकि यह व्यापक रूप से मान्यता प्राप्त benchmark guidance के आधार पर सामान्य configuration issues की जाँच करता है:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
यह tool threat modeling का substitute नहीं है, लेकिन समय के साथ जमा होने वाले careless daemon, mount, network और runtime defaults को खोजने के लिए फिर भी उपयोगी है।

Kubernetes और runtime-heavy environments के लिए static checks को runtime visibility के साथ इस्तेमाल करें:

- `Tracee` container-aware runtime detection और quick forensics के लिए उपयोगी है, जब आपको यह पुष्टि करनी हो कि compromised workload ने वास्तव में किन चीज़ों को access किया।
- `Inspektor Gadget` तब उपयोगी है, जब assessment में kernel-level telemetry को pods, containers, DNS activity, file execution या network behavior से map करना हो।

## Checks

Assessment के दौरान quick first-pass commands के रूप में इनका उपयोग करें:
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

- Broad capabilities वाला और `Seccomp: 0` वाला root process तुरंत ध्यान देने योग्य है।
- ऐसा root process जिसमें **1:1 UID map** भी हो, वह properly isolated user namespace के अंदर मौजूद "root" से कहीं अधिक interesting है।
- `cgroup2fs` का आमतौर पर अर्थ है कि कई पुराने **cgroup v1** escape chains आपका सबसे अच्छा starting point नहीं हैं, जबकि `memory.max` या `pids.max` का न होना अभी भी weak blast-radius controls की ओर संकेत करता है।
- Suspicious mounts और runtime sockets अक्सर किसी kernel exploit की तुलना में impact तक पहुँचने का तेज़ रास्ता प्रदान करते हैं।
- Weak runtime posture और weak resource limits का संयोजन आमतौर पर किसी एक isolated mistake के बजाय generally permissive container environment का संकेत देता है।

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
