# आकलन और सुदृढ़ीकरण

{{#include ../../../banners/hacktricks-training.md}}

## Overview

एक अच्छे container assessment को दो समानांतर सवालों के जवाब देने चाहिए। पहला, मौजूदा workload से attacker क्या कर सकता है? दूसरा, operator के किन विकल्पों के कारण यह संभव हुआ? Enumeration tools पहले सवाल में मदद करते हैं, और hardening guidance दूसरे में। दोनों को एक ही पेज पर रखने से यह section escape tricks की सूची भर न रहकर field reference के रूप में अधिक उपयोगी बनता है।

आधुनिक environments के लिए एक व्यावहारिक अपडेट यह है कि container के बारे में कई पुराने लेख चुपचाप **rootful runtime**, **बिना user namespace isolation**, और अक्सर **cgroup v1** मानकर चलते हैं। अब इन मान्यताओं पर भरोसा करना सुरक्षित नहीं है। पुराने escape primitives पर समय लगाने से पहले पुष्टि करें कि workload rootless है या userns-remapped, host cgroup v2 इस्तेमाल कर रहा है या नहीं, और Kubernetes या runtime अब default seccomp और AppArmor profiles लागू कर रहा है या नहीं। अक्सर यही विवरण तय करते हैं कि कोई चर्चित breakout अब भी लागू होता है या नहीं।

## Enumeration Tools

Container environment को जल्दी समझने के लिए कई tools अब भी उपयोगी हैं:

- `linpeas` कई container indicators, mounted sockets, capability sets, खतरनाक filesystems और breakout से जुड़े संकेतों की पहचान कर सकता है।
- `CDK` खास तौर पर container environments पर केंद्रित है और इसमें enumeration के साथ कुछ automated escape checks भी शामिल हैं।
- `amicontained` हल्का है और container restrictions, capabilities, namespace exposure और breakout की संभावित श्रेणियों की पहचान के लिए उपयोगी है।
- `deepce` container-केंद्रित एक और enumerator है, जिसमें breakout पर केंद्रित checks शामिल हैं।
- `grype` तब उपयोगी है जब assessment में केवल runtime escape analysis के बजाय image-package vulnerabilities की समीक्षा भी शामिल हो।
- `Tracee` तब उपयोगी है जब आपको केवल static posture के बजाय **runtime evidence** चाहिए, खासकर संदिग्ध process execution, file access और container-aware event collection के लिए।
- `Inspektor Gadget` Kubernetes और Linux-host investigations में तब उपयोगी है जब आपको pods, containers, namespaces और अन्य उच्च-स्तरीय concepts से जुड़ी eBPF-आधारित visibility चाहिए।

इन tools का लाभ उनकी गति और coverage है, निश्चितता नहीं। ये मोटे तौर पर posture को जल्दी समझने में मदद करते हैं, लेकिन महत्वपूर्ण findings की वास्तविक runtime, namespace, capability और mount model के संदर्भ में अब भी manual interpretation ज़रूरी है।

## Hardening Priorities

Hardening के सबसे महत्वपूर्ण सिद्धांत अवधारणा में सरल हैं, भले ही platform के अनुसार उनका implementation अलग-अलग हो। Privileged containers से बचें। Mounted runtime sockets से बचें। किसी खास कारण के बिना containers को writable host paths न दें। जहां संभव हो, user namespaces या rootless execution इस्तेमाल करें। सभी capabilities हटाएं और केवल वही वापस जोड़ें जिनकी workload को वास्तव में ज़रूरत है। Application compatibility की समस्याएं ठीक करने के लिए seccomp, AppArmor और SELinux को बंद करने के बजाय चालू रखें। Resources सीमित करें, ताकि compromised container आसानी से host की service बाधित न कर सके।

Image और build hygiene उतने ही महत्वपूर्ण हैं जितना runtime posture। Minimal images इस्तेमाल करें, उन्हें नियमित रूप से rebuild और scan करें, जहां व्यावहारिक हो provenance अनिवार्य करें, और secrets को layers से बाहर रखें। Non-root के रूप में चलने वाला, छोटी image और सीमित syscall तथा capability surface वाला container, debugging tools पहले से मौजूद किसी बड़े convenience image के host-equivalent root के रूप में चलने की तुलना में बचाव करना बहुत आसान है।

Kubernetes के लिए मौजूदा hardening baselines कई operators की अब भी मानी हुई अपेक्षाओं से अधिक सख्त हैं। Built-in **Pod Security Standards** `restricted` को "वर्तमान सर्वोत्तम अभ्यास" profile मानते हैं: `allowPrivilegeEscalation` का मान `false` होना चाहिए, workloads non-root के रूप में चलने चाहिए, seccomp को स्पष्ट रूप से `RuntimeDefault` या `Localhost` पर सेट किया जाना चाहिए, और capability sets को आक्रामक रूप से हटाया जाना चाहिए। Assessment के दौरान यह इसलिए महत्वपूर्ण है क्योंकि केवल `warn` या `audit` labels इस्तेमाल करने वाला cluster कागज़ पर hardened दिख सकता है, जबकि व्यवहार में अब भी risky pods को अनुमति दे रहा हो।<sup>[[1]](#references)</sup>

जब किसी Pod में mounted service-account token हो, तो उसकी permissions का आकलन **हर target namespace के लिए अलग-अलग** करें। किसी एक namespace में Pods सूचीबद्ध करने वाला rule दूसरे namespace में अनुमति साबित नहीं करता; किसी दूसरे Pod में mounted token के अधिकार अलग हो सकते हैं। समीक्षा की जा रही वास्तविक identity के साथ `kubectl auth can-i list pods -n <target-namespace>` और `kubectl auth can-i list secrets -n <target-namespace>` इस्तेमाल करें। Secret-list check की अनुमति मिलना एक गंभीर संकेत है, क्योंकि list response में Secret contents शामिल हो सकते हैं, लेकिन इससे यह साबित नहीं होता कि कोई privileged token मौजूद है। Host तक पहुंचने के लिए इसके अतिरिक्त एक उपयोगी workload-creation right, प्रस्तावित `hostPath` mount की admission, और ऐसा node/pod security context भी ज़रूरी है जो इच्छित file operation की अनुमति दे। Kubernetes की [authorization checks](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) और [RBAC privilege-escalation guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) देखें।

## Modern Triage Questions

Escape-विशिष्ट पेजों को देखने से पहले इन त्वरित सवालों के जवाब दें:

1. क्या workload **rootful**, **rootless**, या **userns-remapped** है?
2. क्या node **cgroup v1** या **cgroup v2** इस्तेमाल कर रहा है?
3. क्या **seccomp** और **AppArmor/SELinux** स्पष्ट रूप से configure किए गए हैं, या उपलब्ध होने पर केवल inherit किए गए हैं?
4. Kubernetes में, क्या namespace वास्तव में `baseline` या `restricted` **enforce** कर रहा है, या केवल warning/auditing कर रहा है?

उपयोगी checks:

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

- अगर `/proc/self/uid_map` में container root को **host UID की उच्च रेंज** से mapped दिखाया गया है, तो host-root से जुड़े कई पुराने writeup कम प्रासंगिक हो जाते हैं, क्योंकि container का root अब host-root के बराबर नहीं है।
- अगर `/sys/fs/cgroup` `cgroup2fs` है, तो `release_agent` abuse जैसे **cgroup v1**-विशिष्ट पुराने writeup अब आपकी पहली आशंका नहीं होने चाहिए।
- अगर seccomp और AppArmor केवल implicit रूप से inherit किए गए हैं, तो portability defenders की अपेक्षा से कमज़ोर हो सकती है। Kubernetes में, node defaults पर चुपचाप निर्भर रहने के बजाय स्पष्ट रूप से `RuntimeDefault` सेट करना अक्सर अधिक मज़बूत होता है।
- अगर `supplementalGroupsPolicy` को `Strict` पर सेट किया गया है, तो pod को image के अंदर `/etc/group` से अतिरिक्त group memberships चुपचाप inherit करने से बचना चाहिए। इससे group-आधारित volume और file access का व्यवहार अधिक अनुमानित होता है।
- `pod-security.kubernetes.io/enforce=restricted` जैसे namespace labels को सीधे जाँचना उपयोगी है। `warn` और `audit` काम के हैं, लेकिन वे किसी जोखिमपूर्ण pod को बनने से नहीं रोकते।

## Runtime Baseline की शुरुआती जाँच

Runtime baseline एक त्वरित जाँच है, जो बताती है कि container एक सामान्य isolated workload जैसा दिखता है या host को प्रभावित करने वाले control plane foothold जैसा। इसमें अगले पेज को प्राथमिकता देने के लिए पर्याप्त तथ्य जुटाने चाहिए: runtime socket abuse, host mounts, namespaces, cgroups, capabilities या image-secret की समीक्षा।

Workload के अंदर से उपयोगी जाँचें:

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

- `memory.max` / `pids.max` का अनुपस्थित या असीमित होना कमज़ोर blast-radius controls की ओर संकेत करता है, भले ही कोई स्पष्ट escape न हो।
- `NoNewPrivs: 0`, व्यापक capabilities और permissive seccomp वाला root shell, सीमित non-root workload से कहीं अधिक दिलचस्प है।
- Runtime sockets और writable host mounts को आम तौर पर kernel exploits से ऊपर प्राथमिकता दी जाती है, क्योंकि वे पहले से ही management या filesystem control path उजागर करते हैं।
- Shared PID, network, IPC या cgroup namespaces अपने आप में हमेशा full escapes नहीं होते, लेकिन वे अगला कदम ढूँढ़ना आसान बना देते हैं।

## Resource-Exhaustion के उदाहरण

Resource controls भले ही आकर्षक न हों, लेकिन वे container security का हिस्सा हैं, क्योंकि वे compromise के blast radius को सीमित करते हैं। Memory, CPU या PID limits के बिना, एक साधारण shell भी host या पड़ोसी workloads को प्रभावित करने के लिए पर्याप्त हो सकता है।

Host को प्रभावित करने वाले परीक्षणों के उदाहरण:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

ये उदाहरण उपयोगी हैं, क्योंकि इनसे पता चलता है कि हर खतरनाक container परिणाम साफ़-सुथरा "escape" नहीं होता। कमज़ोर cgroup limits फिर भी code execution को वास्तविक परिचालन प्रभाव में बदल सकती हैं।

Kubernetes-backed environments में, DoS को केवल सैद्धांतिक मानने से पहले यह भी जाँचें कि resource controls मौजूद हैं या नहीं:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Hardening Tooling

Docker-केंद्रित environments के लिए, `docker-bench-security` host-side audit baseline के रूप में उपयोगी बना हुआ है, क्योंकि यह आम configuration समस्याओं को व्यापक रूप से मान्यता प्राप्त benchmark guidance के आधार पर जाँचता है। Runtime advisories की अलग से समीक्षा करनी चाहिए, क्योंकि configuration benchmark यह पता नहीं लगा सकता कि installed runtime हाल ही में disclosed vulnerability से प्रभावित है या नहीं। <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

यह tool threat modeling का विकल्प नहीं है, लेकिन समय के साथ जमा होने वाले लापरवाह daemon, mount, network और runtime defaults को खोजने के लिए फिर भी उपयोगी है।

Kubernetes और runtime-प्रधान परिवेशों के लिए, static checks के साथ runtime visibility का उपयोग करें:

- `Tracee` container-aware runtime detection और quick forensics के लिए उपयोगी है, जब आपको यह पुष्टि करनी हो कि compromised workload ने वास्तव में किन चीज़ों को छुआ।
- `Inspektor Gadget` तब उपयोगी है, जब assessment में kernel-level telemetry को pods, containers, DNS activity, file execution या network behavior से जोड़ना हो।

## जाँच

Assessment के दौरान शुरुआती जाँच के लिए इन commands का उपयोग करें:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

यहाँ क्या दिलचस्प है:

- व्यापक capabilities वाला और `Seccomp: 0` वाला root process तुरंत ध्यान देने योग्य है।
- **1:1 UID map** वाला root process, ठीक से isolated user namespace के अंदर मौजूद "root" से कहीं ज़्यादा दिलचस्प है।
- `cgroup2fs` का आमतौर पर मतलब है कि कई पुराने **cgroup v1** escape chains शुरुआत करने के लिए सबसे अच्छा विकल्प नहीं हैं, जबकि `memory.max` या `pids.max` का न होना अब भी कमज़ोर blast-radius controls की ओर इशारा करता है।
- संदिग्ध mounts और runtime sockets अक्सर किसी भी kernel exploit से तेज़ी से असर डालने का रास्ता देते हैं।
- कमज़ोर runtime posture और कमज़ोर resource limits का मेल आमतौर पर किसी एक अलग-थलग गलती के बजाय एक सामान्य रूप से permissive container environment का संकेत देता है।

## References

- [1] [Kubernetes Pod सुरक्षा मानक](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker सुरक्षा सलाह: runc, BuildKit और Moby में कई कमजोरियाँ](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
