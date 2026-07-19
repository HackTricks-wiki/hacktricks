# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

एक अच्छा container assessment दो समानांतर प्रश्नों का उत्तर देना चाहिए। पहला, मौजूदा workload से attacker क्या कर सकता है? दूसरा, operator के किन विकल्पों के कारण यह संभव हुआ? Enumeration tools पहले प्रश्न में सहायता करते हैं, और hardening guidance दूसरे प्रश्न में। दोनों को एक ही पेज पर रखने से यह section केवल escape tricks के catalog के बजाय field reference के रूप में अधिक उपयोगी बनता है।

Modern environments के लिए एक व्यावहारिक अपडेट यह है कि कई पुराने container writeups चुपचाप **rootful runtime**, **no user namespace isolation**, और अक्सर **cgroup v1** मानकर चलते हैं। ये assumptions अब सुरक्षित नहीं हैं। पुराने escape primitives पर समय खर्च करने से पहले यह पुष्टि करें कि workload rootless या userns-remapped है या नहीं, host cgroup v2 का उपयोग कर रहा है या नहीं, और Kubernetes या runtime अब default seccomp और AppArmor profiles लागू कर रहा है या नहीं। ये विवरण अक्सर तय करते हैं कि कोई प्रसिद्ध breakout अभी भी लागू होता है या नहीं।

## Enumeration Tools

Container environment को जल्दी characterize करने के लिए कई tools अभी भी उपयोगी हैं:

- `linpeas` कई container indicators, mounted sockets, capability sets, dangerous filesystems और breakout hints की पहचान कर सकता है।
- `CDK` विशेष रूप से container environments पर केंद्रित है और इसमें enumeration के साथ कुछ automated escape checks भी शामिल हैं।
- `amicontained` lightweight है और container restrictions, capabilities, namespace exposure तथा संभावित breakout classes की पहचान के लिए उपयोगी है।
- `deepce` एक अन्य container-focused enumerator है, जिसमें breakout-oriented checks शामिल हैं।
- `grype` तब उपयोगी है जब assessment में केवल runtime escape analysis के बजाय image-package vulnerability review भी शामिल हो।
- `Tracee` तब उपयोगी है जब आपको केवल static posture के बजाय **runtime evidence** की आवश्यकता हो, विशेष रूप से suspicious process execution, file access और container-aware event collection के लिए।
- `Inspektor Gadget` Kubernetes और Linux-host investigations में उपयोगी है, जब आपको eBPF-backed visibility चाहिए जो pods, containers, namespaces और अन्य higher-level concepts से जुड़ी हो।

इन tools का मूल्य speed और coverage है, certainty नहीं। ये rough posture को जल्दी उजागर करने में सहायता करते हैं, लेकिन महत्वपूर्ण findings की वास्तविक runtime, namespace, capability और mount model के आधार पर manual interpretation अभी भी आवश्यक होती है।

## Hardening Priorities

सबसे महत्वपूर्ण hardening principles वैचारिक रूप से सरल हैं, भले ही उनका implementation platform के अनुसार अलग हो। Privileged containers से बचें। Mounted runtime sockets से बचें। Containers को writable host paths न दें, जब तक इसका कोई बहुत विशिष्ट कारण न हो। जहाँ संभव हो, user namespaces या rootless execution का उपयोग करें। सभी capabilities को drop करें और केवल वही वापस जोड़ें जिनकी workload को वास्तव में आवश्यकता है। Application compatibility problems को ठीक करने के लिए seccomp, AppArmor और SELinux को disable करने के बजाय enabled रखें। Resources को सीमित करें, ताकि compromised container host को आसानी से deny service न कर सके।

Image और build hygiene runtime posture जितने ही महत्वपूर्ण हैं। Minimal images का उपयोग करें, उन्हें बार-बार rebuild करें, scan करें, जहाँ व्यावहारिक हो वहाँ provenance आवश्यक करें, और secrets को layers से बाहर रखें। Non-root के रूप में चलने वाला container, जिसमें छोटी image और सीमित syscall तथा capability surface हो, उस बड़े convenience image की तुलना में defend करना बहुत आसान है जो host-equivalent root के रूप में चलती हो और जिसमें debugging tools पहले से installed हों।

Kubernetes के लिए current hardening baselines अभी भी कई operators की अपेक्षा से अधिक opinionated हैं। Built-in **Pod Security Standards**, `restricted` को "current best practice" profile मानते हैं: `allowPrivilegeEscalation` को `false` होना चाहिए, workloads को non-root के रूप में चलना चाहिए, seccomp को स्पष्ट रूप से `RuntimeDefault` या `Localhost` पर set किया जाना चाहिए, और capability sets को aggressively drop किया जाना चाहिए। Assessment के दौरान यह महत्वपूर्ण है, क्योंकि केवल `warn` या `audit` labels का उपयोग करने वाला cluster कागज़ पर hardened दिखाई दे सकता है, जबकि व्यवहार में risky pods को स्वीकार कर रहा हो।

## Modern Triage Questions

Escape-specific pages पर जाने से पहले इन quick questions के उत्तर दें:

1. क्या workload **rootful**, **rootless**, या **userns-remapped** है?
2. क्या node **cgroup v1** या **cgroup v2** का उपयोग कर रहा है?
3. क्या **seccomp** और **AppArmor/SELinux** स्पष्ट रूप से configured हैं, या उपलब्ध होने पर केवल inherited हैं?
4. Kubernetes में क्या namespace वास्तव में `baseline` या `restricted` को **enforcing** कर रहा है, या केवल warning/auditing कर रहा है?

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

- यदि `/proc/self/uid_map` में container root को **high host UID range** पर mapped दिखाया जाता है, तो पुराने host-root writeups कम प्रासंगिक हो जाते हैं, क्योंकि container में root अब host-root के बराबर नहीं रहता।
- यदि `/sys/fs/cgroup` `cgroup2fs` है, तो `release_agent` abuse जैसे पुराने **cgroup v1**-specific writeups अब आपकी पहली संभावना नहीं होने चाहिए।
- यदि seccomp और AppArmor केवल implicitly inherit किए गए हैं, तो portability defenders की अपेक्षा से कमजोर हो सकती है। Kubernetes में node defaults पर चुपचाप निर्भर रहने की तुलना में `RuntimeDefault` को explicitly सेट करना अक्सर अधिक मजबूत होता है।
- यदि `supplementalGroupsPolicy` को `Strict` पर सेट किया गया है, तो pod को image के अंदर `/etc/group` से अतिरिक्त group memberships को चुपचाप inherit करने से बचना चाहिए, जिससे group-based volume और file access behavior अधिक predictable हो जाता है।
- `pod-security.kubernetes.io/enforce=restricted` जैसे namespace labels को सीधे जाँचना उपयोगी है। `warn` और `audit` उपयोगी हैं, लेकिन वे किसी risky pod को create होने से नहीं रोकते।

## Runtime Baseline Triage

Runtime baseline वह quick pass है जो बताता है कि container एक सामान्य isolated workload जैसा दिखता है या host-impacting control plane foothold जैसा। इसमें अगले पढ़े जाने वाले page को prioritize करने के लिए पर्याप्त facts collect किए जाने चाहिए: runtime socket abuse, host mounts, namespaces, cgroups, capabilities या image-secret review।

Workload के अंदर से उपयोगी checks:
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
व्याख्या:

- साफ़ escape के बिना भी अनुपस्थित या unlimited `memory.max` / `pids.max` कमजोर blast-radius controls की ओर संकेत करते हैं।
- `NoNewPrivs: 0`, broad capabilities और permissive seccomp वाला root shell, narrow non-root workload की तुलना में कहीं अधिक दिलचस्प होता है।
- Runtime sockets और writable host mounts आमतौर पर kernel exploits से अधिक महत्वपूर्ण होते हैं, क्योंकि वे पहले से ही management या filesystem control path उजागर करते हैं।
- Shared PID, network, IPC या cgroup namespaces अपने-आप में हमेशा full escapes नहीं होते, लेकिन वे अगला step ढूँढना आसान बना देते हैं।

## Resource-Exhaustion Examples

Resource controls आकर्षक नहीं होते, लेकिन वे container security का हिस्सा हैं क्योंकि वे compromise के blast radius को सीमित करते हैं। Memory, CPU या PID limits के बिना, एक simple shell host या neighboring workloads को degrade करने के लिए पर्याप्त हो सकता है।

Host पर प्रभाव डालने वाले tests के उदाहरण:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
ये examples उपयोगी हैं क्योंकि वे दिखाते हैं कि हर खतरनाक container outcome एक साफ़ "escape" नहीं होता। कमजोर cgroup limits अब भी code execution को वास्तविक operational impact में बदल सकते हैं।

Kubernetes-backed environments में, DoS को केवल सैद्धांतिक मानने से पहले यह भी जाँचें कि resource controls मौजूद हैं या नहीं:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Docker-केंद्रित environments के लिए, `docker-bench-security` host-side audit baseline के रूप में उपयोगी बना हुआ है, क्योंकि यह व्यापक रूप से मान्यता प्राप्त benchmark guidance के अनुसार सामान्य configuration issues की जाँच करता है:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
यह tool threat modeling का substitute नहीं है, लेकिन समय के साथ जमा होने वाले careless daemon, mount, network और runtime defaults को खोजने के लिए फिर भी उपयोगी है।

Kubernetes और runtime-heavy environments के लिए, static checks को runtime visibility के साथ मिलाकर उपयोग करें:

- `Tracee` container-aware runtime detection और quick forensics के लिए उपयोगी है, जब आपको यह confirm करना हो कि compromised workload ने वास्तव में किन चीज़ों को access किया।
- `Inspektor Gadget` तब उपयोगी है जब assessment में kernel-level telemetry को pods, containers, DNS activity, file execution या network behavior से map करना हो।

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
यहाँ क्या महत्वपूर्ण है:

- व्यापक capabilities वाली root process और `Seccomp: 0` को तुरंत ध्यान देने योग्य माना जाना चाहिए।
- **1:1 UID map** वाली root process, उचित रूप से isolated user namespace के अंदर मौजूद "root" से कहीं अधिक महत्वपूर्ण होती है।
- `cgroup2fs` का आमतौर पर अर्थ है कि कई पुराने **cgroup v1** escape chains आपके लिए सबसे अच्छा शुरुआती बिंदु नहीं हैं, जबकि `memory.max` या `pids.max` का न होना अभी भी कमजोर blast-radius controls की ओर संकेत करता है।
- संदिग्ध mounts और runtime sockets अक्सर किसी kernel exploit की तुलना में impact तक पहुँचने का तेज़ रास्ता प्रदान करते हैं।
- कमजोर runtime posture और कमजोर resource limits का संयोजन आमतौर पर किसी एक isolated mistake के बजाय सामान्य रूप से permissive container environment का संकेत देता है।

## संदर्भ

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
