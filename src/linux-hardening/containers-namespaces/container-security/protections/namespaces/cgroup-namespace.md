# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

cgroup namespace, cgroups को replace नहीं करता और स्वयं resource limits enforce नहीं करता। इसके बजाय, यह बदलता है कि **cgroup hierarchy process को कैसे दिखाई देती है**। दूसरे शब्दों में, यह दिखाई देने वाली cgroup path information को virtualize करता है, ताकि workload को पूरी host hierarchy के बजाय container-scoped view दिखाई दे।

यह मुख्य रूप से visibility और information-reduction feature है। यह environment को self-contained दिखाने में मदद करता है और host के cgroup layout के बारे में कम information reveal करता है। यह मामूली लग सकता है, लेकिन फिर भी महत्वपूर्ण है, क्योंकि host structure की अनावश्यक visibility reconnaissance में सहायता कर सकती है और environment-dependent exploit chains को सरल बना सकती है।

## संचालन

Private cgroup namespace के बिना, कोई process host-relative cgroup paths देख सकता है, जो machine की आवश्यकता से अधिक hierarchy expose करते हैं। Private cgroup namespace के साथ, `/proc/self/cgroup` और संबंधित observations container के अपने view तक अधिक localized हो जाते हैं। यह विशेष रूप से modern runtime stacks में उपयोगी है, जो workload को अधिक clean और host को कम reveal करने वाला environment दिखाना चाहते हैं।

Virtualization `/proc/<pid>/mountinfo` को भी प्रभावित करती है, केवल `/proc/<pid>/cgroup` को नहीं। जब आप किसी दूसरे process को अलग cgroup-namespace perspective से read करते हैं, तो आपके namespace root के बाहर के paths में शुरुआत में `../` components दिखाई देते हैं। यह एक उपयोगी clue है कि आप अपने delegated subtree के ऊपर देख रहे हैं। Labs और post-exploitation के लिए एक महत्वपूर्ण nuance यह है कि freshly created cgroup namespace को अक्सर **उस namespace के अंदर से cgroupfs remount** की आवश्यकता होती है, इससे पहले कि `mountinfo` नए root को सही ढंग से reflect करे। अन्यथा आपको अभी भी `/..` जैसा mount root दिखाई दे सकता है, जिसका अर्थ है कि inherited mount अभी भी ancestor-rooted view expose कर रहा है, भले ही namespace स्वयं पहले ही बदल चुका हो।

## Lab

आप cgroup namespace को इस प्रकार inspect कर सकते हैं:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
यदि आप चाहते हैं कि `mountinfo` नए cgroup-namespace root को अधिक स्पष्ट रूप से दिखाए, तो नए namespace के अंदर से cgroup filesystem को remount करें और फिर से तुलना करें:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
और runtime behavior की तुलना करें:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
यह बदलाव मुख्यतः इस बात से संबंधित है कि process क्या देख सकता है, न कि इस बात से कि cgroup enforcement मौजूद है या नहीं।

## Security Impact

cgroup namespace को **visibility-hardening layer** के रूप में समझना सबसे उचित है। अपने आप में यह breakout को नहीं रोकेगा, यदि container में writable cgroup mounts, broad capabilities, या कोई खतरनाक cgroup v1 environment मौजूद हो। हालांकि, यदि host cgroup namespace shared है, तो process यह अधिक जान सकता है कि system किस तरह organized है और अन्य observations के साथ host-relative cgroup paths को मिलाना उसके लिए आसान हो सकता है।

**cgroup v2** पर namespace कुछ अधिक महत्वपूर्ण हो जाता है, क्योंकि delegation rules अधिक सख्त होते हैं। यदि hierarchy को `nsdelegate` के साथ mount किया गया है, तो kernel cgroup namespaces को delegation boundaries की तरह treat करता है: ancestor control files delegatee की पहुंच से बाहर रहने चाहिए, और namespace root पर writes delegation-safe files तक सीमित होती हैं, जैसे `cgroup.procs`, `cgroup.threads`, और `cgroup.subtree_control`। फिर भी, इससे namespace अपने आप कोई escape primitive नहीं बन जाता, लेकिन यह बदल देता है कि compromised workload क्या inspect कर सकता है और वह सुरक्षित रूप से sub-cgroups कहां create कर सकता है।

इसलिए, हालांकि यह namespace आमतौर पर container breakout writeups का मुख्य विषय नहीं होता, फिर भी यह host information leakage को minimize करने और cgroup delegation को constrain करने के व्यापक लक्ष्य में योगदान देता है।

## Abuse

इसका तत्काल abuse value मुख्यतः reconnaissance है। यदि host cgroup namespace shared है, तो दिखाई देने वाले paths की तुलना करें और host से संबंधित hierarchy details खोजें:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
यदि writable cgroup paths भी exposed हों, तो उस visibility को dangerous legacy interfaces की search के साथ combine करें:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace स्वयं शायद ही कभी तुरंत escape प्रदान करता है, लेकिन cgroup-based abuse primitives का परीक्षण करने से पहले यह अक्सर environment को map करना आसान बना देता है।

एक त्वरित runtime reality check attack path को प्राथमिकता देने में भी मदद करता है। Docker `--cgroupns=host|private` expose करता है, जबकि Podman `host`, `private`, `container:<id>`, और `ns:<path>` support करता है। विशेष रूप से Podman पर, default आमतौर पर **`host` on cgroup v1** और **`private` on cgroup v2** होता है, इसलिए केवल cgroup version की पहचान करने से ही आपको पता चल जाता है कि पूरी OCI config inspect करने से पहले कौन-सा namespace posture अधिक संभावित है।

### Modern v2 Recon: क्या यह Delegated Subtree है?

Modern hosts पर अक्सर दिलचस्प सवाल `release_agent` नहीं, बल्कि यह होता है कि क्या current process पर्याप्त visibility या write access वाले delegated **cgroup v2** subtree के अंदर है, ताकि nested groups बनाए जा सकें:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
उपयोगी व्याख्या:

- `cgroup2fs` का अर्थ है कि आप unified v2 hierarchy में हैं, इसलिए classic v1-only `release_agent` chains को अपना पहला अनुमान नहीं मानना चाहिए।
- `cgroup.controllers` दिखाता है कि parent से कौन-से controllers उपलब्ध हैं और इसलिए current subtree children तक संभावित रूप से किन controllers को आगे बढ़ा सकता है।
- `cgroup.subtree_control` दिखाता है कि descendants के लिए वास्तव में कौन-से controllers enabled हैं।
- `cgroup.events` `populated=0/1` को expose करता है, जो यह देखने के लिए उपयोगी है कि कोई subtree empty हुआ है या नहीं, लेकिन यह v1 `release_agent` जैसा host-code-execution primitive **नहीं** है।

यदि आपके पास किसी अन्य process namespace का सीधे निरीक्षण करने के लिए पर्याप्त privilege पहले से है, तो इनसे views की तुलना करें:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### पूर्ण उदाहरण: Shared cgroup Namespace + Writable cgroup v1

अकेला cgroup namespace आमतौर पर escape के लिए पर्याप्त नहीं होता। Practical escalation तब होती है जब host-revealing cgroup paths को writable cgroup v1 interfaces के साथ जोड़ा जाता है:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
यदि वे files reachable और writable हैं, तो [cgroups.md](../cgroups.md) में दिए गए पूरे `release_agent` exploitation flow में तुरंत pivot करें। इसका impact container के अंदर से host code execution है।

Writable cgroup interfaces के बिना, impact आमतौर पर reconnaissance तक सीमित रहता है।

## Checks

इन commands का उद्देश्य यह देखना है कि process के पास private cgroup namespace view है या वह host hierarchy के बारे में वास्तव में आवश्यक जानकारी से अधिक जान रहा है।
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
यहाँ क्या महत्वपूर्ण है:

- यदि namespace identifier उस host process से मेल खाता है जिसकी आपको परवाह है, तो cgroup namespace साझा किया गया हो सकता है।
- `/proc/self/cgroup` में host को उजागर करने वाले paths या `mountinfo` में ancestor-rooted entries उपयोगी reconnaissance हैं, भले ही वे सीधे exploitable न हों।
- यदि `cgroup2fs` उपयोग में है, तो पुराने v1 primitives के अभी भी मौजूद होने की धारणा बनाने के बजाय delegation, visible controllers और writable subtrees पर ध्यान दें।
- यदि cgroup mounts भी writable हैं, तो visibility का प्रश्न और अधिक महत्वपूर्ण हो जाता है।

cgroup namespace को primary escape-prevention mechanism के बजाय visibility-hardening layer के रूप में माना जाना चाहिए। अनावश्यक रूप से host cgroup structure को उजागर करने से attacker के लिए reconnaissance value बढ़ जाती है।

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
