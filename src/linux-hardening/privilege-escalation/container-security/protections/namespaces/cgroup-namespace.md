# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

cgroup namespace cgroups को replace नहीं करता और यह खुद resource limits enforce नहीं करता। इसके बजाय, यह process के लिए **cgroup hierarchy कैसी दिखाई देती है** इसे बदलता है। दूसरे शब्दों में, यह visible cgroup path information को virtualize करता है ताकि workload को full host hierarchy की बजाय container-scoped view दिखे।

यह मुख्य रूप से visibility और information-reduction feature है। यह environment को self-contained जैसा दिखाने में मदद करता है और host के cgroup layout के बारे में कम जानकारी उजागर करता है। यह साधारण लग सकता है, लेकिन फिर भी महत्वपूर्ण है क्योंकि host structure की unnecessary visibility reconnaissance में मदद कर सकती है और environment-dependent exploit chains को आसान बना सकती है।

## Operation

Private cgroup namespace के बिना, process host-relative cgroup paths देख सकता है जो machine की hierarchy का ज़रूरत से ज़्यादा हिस्सा expose करते हैं। Private cgroup namespace के साथ, `/proc/self/cgroup` और related observations container के अपने view तक ज़्यादा localized हो जाते हैं। यह modern runtime stacks में खास तौर पर उपयोगी है जो चाहते हैं कि workload को एक cleaner, कम host-revealing environment दिखे।

यह virtualization सिर्फ `/proc/<pid>/mountinfo` पर भी असर डालती है, न कि केवल `/proc/<pid>/cgroup` पर। जब आप किसी दूसरे process को अलग cgroup-namespace perspective से पढ़ते हैं, तो आपके namespace root के बाहर के paths leading `../` components के साथ दिखाए जाते हैं, जो यह एक उपयोगी संकेत है कि आप अपनी delegated subtree से ऊपर देख रहे हैं। labs और post-exploitation के लिए एक useful nuance यह है कि freshly created cgroup namespace को अक्सर `mountinfo` के नए root को साफ़ तरीके से reflect करने से पहले उस namespace के अंदर से एक **cgroupfs remount** की ज़रूरत होती है। वरना आप अभी भी `/..` जैसा mount root देख सकते हैं, जिसका मतलब है कि inherited mount अभी भी ancestor-rooted view expose कर रहा है, भले ही namespace खुद already बदल चुका हो।

## Lab

आप एक cgroup namespace को इसके साथ inspect कर सकते हैं:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
यदि आप चाहते हैं कि `mountinfo` नया cgroup-namespace root और अधिक स्पष्ट रूप से दिखाए, तो नए namespace के अंदर से cgroup filesystem को remount करें और फिर से compare करें:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
और इसके साथ runtime behavior की तुलना करें:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
परिवर्तन ज़्यादातर इस बारे में है कि process क्या देख सकता है, न कि इस बारे में कि cgroup enforcement मौजूद है या नहीं।

## Security Impact

cgroup namespace को सबसे अच्छी तरह एक **visibility-hardening layer** के रूप में समझा जा सकता है। अपने आप में यह breakout को नहीं रोकेगा अगर container के पास writable cgroup mounts, broad capabilities, या एक dangerous cgroup v1 environment है। हालांकि, अगर host cgroup namespace shared है, तो process को system की organization के बारे में ज़्यादा जानकारी मिलती है और उसे host-relative cgroup paths को अन्य observations के साथ align करना आसान लग सकता है।

**cgroup v2** पर, namespace थोड़ा ज़्यादा महत्वपूर्ण हो जाता है क्योंकि delegation rules ज्यादा strict होते हैं। अगर hierarchy `nsdelegate` के साथ mounted है, तो kernel cgroup namespaces को delegation boundaries की तरह treat करता है: ancestor control files को delegatee की reach के बाहर रहना चाहिए, और namespace root पर writes को सिर्फ delegation-safe files तक सीमित किया जाता है, जैसे `cgroup.procs`, `cgroup.threads`, और `cgroup.subtree_control`। फिर भी यह namespace को अपने आप में escape primitive नहीं बनाता, लेकिन यह बदलता है कि compromised workload क्या inspect कर सकता है और वह safely कहाँ sub-cgroups बना सकता है।

इसलिए जबकि यह namespace आम तौर पर container breakout writeups का star नहीं होता, यह फिर भी host information leakage को कम करने और cgroup delegation को constrain करने के बड़े लक्ष्य में योगदान देता है।

## Abuse

तुरंत abuse value ज़्यादातर reconnaissance है। अगर host cgroup namespace shared है, तो visible paths की तुलना करें और host-revealing hierarchy details देखें:
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
namespace स्वयं शायद ही कभी तुरंत escape देता है, लेकिन यह अक्सर cgroup-based abuse primitives का परीक्षण करने से पहले environment को map करना आसान बना देता है।

एक quick runtime reality check भी attack path को prioritize करने में मदद करता है। Docker `--cgroupns=host|private` expose करता है, जबकि Podman `host`, `private`, `container:<id>`, और `ns:<path>` support करता है। खास तौर पर Podman पर, default आमतौर पर **cgroup v1 पर `host`** और **cgroup v2 पर `private`** होता है, इसलिए सिर्फ cgroup version identify करने से ही आपको पहले से पता चल जाता है कि पूरा OCI config inspect करने से पहले कौन-सा namespace posture ज़्यादा likely है।

### Modern v2 Recon: Is This A Delegated Subtree?

Modern hosts पर interesting question अक्सर `release_agent` नहीं होता, बल्कि यह होता है कि क्या current process एक delegated **cgroup v2** subtree के अंदर है, जिसमें nested groups बनाने के लिए enough visibility या write access हो:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
उपयोगी व्याख्या:

- `cgroup2fs` का मतलब है कि आप unified v2 hierarchy में हैं, इसलिए classic v1-only `release_agent` chains को अपनी पहली guess नहीं मानना चाहिए।
- `cgroup.controllers` दिखाता है कि parent से कौन-से controllers उपलब्ध हैं और इसलिए current subtree संभावित रूप से children तक क्या fan out कर सकता है।
- `cgroup.subtree_control` दिखाता है कि descendants के लिए वास्तव में कौन-से controllers enabled हैं।
- `cgroup.events` `populated=0/1` expose करता है, जो यह देखने में उपयोगी है कि subtree खाली हुआ है या नहीं, लेकिन यह v1 `release_agent` की तरह host-code-execution primitive नहीं है।

अगर आपके पास किसी दूसरे process namespace को सीधे inspect करने के लिए पर्याप्त privilege है, तो views की तुलना करें:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Full Example: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace अकेला आमतौर पर escape के लिए पर्याप्त नहीं होता। व्यावहारिक escalation तब होती है जब host-revealing cgroup paths को writable cgroup v1 interfaces के साथ combine किया जाता है:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
यदि वे files reachable और writable हैं, तो तुरंत [cgroups.md](../cgroups.md) से पूरे `release_agent` exploitation flow में pivot करें। इसका impact container के अंदर से host code execution है।

writable cgroup interfaces के बिना, impact आमतौर पर reconnaissance तक सीमित होता है।

## Checks

इन commands का उद्देश्य यह देखना है कि process के पास private cgroup namespace view है या वह host hierarchy के बारे में उससे ज़्यादा सीख रहा है जितनी उसे वास्तव में ज़रूरत है।
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
What is interesting here:

- If the namespace identifier matches a host process you care about, the cgroup namespace may be shared.
- `/proc/self/cgroup` में host-revealing paths या `mountinfo` में ancestor-rooted entries उपयोगी reconnaissance हैं, भले ही वे सीधे exploitable न हों।
- यदि `cgroup2fs` use में है, तो पुराने v1 primitives अभी भी मौजूद हैं मानकर चलने के बजाय delegation, visible controllers, और writable subtrees पर focus करें।
- यदि cgroup mounts भी writable हैं, तो visibility question और भी अधिक important हो जाता है।

cgroup namespace को primary escape-prevention mechanism के बजाय visibility-hardening layer के रूप में treat किया जाना चाहिए। Host cgroup structure को unnecessarily expose करना attacker को reconnaissance value देता है।

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
