# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux एक **लेबल-आधारित अनिवार्य एक्सेस नियंत्रण (MAC)** सिस्टम है। व्यवहार में, इसका मतलब है कि भले ही DAC permissions, groups, या Linux capabilities किसी कार्रवाई के लिए पर्याप्त दिखें, kernel फिर भी इसे अस्वीकार कर सकता है क्योंकि **source context** को अनुरोधित class/permission के साथ **target context** तक पहुँचने की अनुमति नहीं है।

A context usually looks like:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
From a privesc perspective, the `type` (domain for processes, type for objects) is usually the most important field:

- एक process किसी **domain** में चलता है, जैसे `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- फ़ाइलें और सॉकेट का एक **type** होता है, जैसे `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy तय करती है कि एक domain दूसरे पर read/write/execute/transition कर सकता है या नहीं

## त्वरित खोज

यदि SELinux सक्षम है, तो इसे जल्द ही जाँचें क्योंकि यह बता सकता है कि सामान्य Linux privesc रास्ते क्यों विफल होते हैं या किसी "harmless" SELinux टूल के चारों ओर मौजूद privileged wrapper क्यों वास्तव में महत्वपूर्ण है:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
उपयोगी अनुवर्ती जाँचें:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
दिलचस्प निष्कर्ष:

- `Disabled` or `Permissive` मोड SELinux की सीमा के रूप में अधिकतर उपयोगिता हटा देता है।
- `unconfined_t` आमतौर पर बताता है कि SELinux मौजूद है लेकिन वह उस प्रक्रिया को सार्थक तरीके से प्रतिबंधित नहीं कर रहा है।
- `default_t`, `file_t`, या कस्टम पाथ्स पर स्पष्ट रूप से गलत लेबल अक्सर गलत लेबलिंग या अधूरी तैनाती को दर्शाते हैं।
- लोकल ओवरराइड्स `file_contexts.local` में नीतिगत डिफॉल्ट्स पर प्राथमिकता रखते हैं, इसलिए इन्हें ध्यान से समीक्षा करें।

## नीति विश्लेषण

जब आप दो प्रश्नों का उत्तर दे सकते हैं, तब SELinux पर attack या bypass करना बहुत आसान हो जाता है:

1. **मेरा वर्तमान डोमेन क्या एक्सेस कर सकता है?**
2. **मैं किन डोमेनों में transition कर सकता हूँ?**

इसके लिए सबसे उपयोगी टूल्स `sepolicy` और **SETools** (`seinfo`, `sesearch`, `sedta`):
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
यह विशेष रूप से तब उपयोगी है जब कोई होस्ट सभी को `unconfined_u` पर मैप करने के बजाय **सीमित उपयोगकर्ता** का उपयोग करता है। इस मामले में, खोजें:

- `semanage login -l` के माध्यम से उपयोगकर्ता मैपिंग्स
- `semanage user -l` के माध्यम से अनुमत भूमिकाएँ
- `sysadm_t`, `secadm_t`, `webadm_t` जैसे पहुँच योग्य प्रशासनिक डोमेन्स
- `ROLE=` या `TYPE=` का उपयोग करते हुए `sudoers` एंट्रीज़

यदि `sudo -l` में इस तरह की प्रविष्टियाँ मौजूद हैं, तो SELinux अधिकार सीमा का हिस्सा है:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
यह भी जांचें कि `newrole` उपलब्ध है:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` and `newrole` स्वतः रूप से exploitable नहीं हैं, लेकिन अगर कोई privileged wrapper या `sudoers` नियम आपको बेहतर role/type चुनने देता है, तो ये उच्च-मूल्य के escalation primitives बन जाते हैं।

## फाइलें, रिलेबलिंग, और उच्च-मूल्य गलत कॉन्फ़िगरेशन

सामान्य SELinux टूल्स के बीच सबसे महत्वपूर्ण ऑपरेशनल अंतर है:

- `chcon`: किसी विशिष्ट path पर अस्थायी लेबल परिवर्तन
- `semanage fcontext`: पथ-से-लेबल का स्थायी नियम
- `restorecon` / `setfiles`: नीति/डिफ़ॉल्ट लेबल को फिर से लागू करें

यह privesc के दौरान बहुत मायने रखता है क्योंकि **रिलेबलिंग सिर्फ़ सजावटी नहीं है**। यह एक फ़ाइल को "blocked by policy" से "readable/executable by a privileged confined service" में बदल सकता है।

स्थानीय रिलेबल नियमों और रिलेबल ड्रिफ्ट के लिए जाँच करें:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
उच्च-मूल्य कमांड जिन्हें `sudo -l`, root wrappers, automation scripts, या file capabilities में तलाशें:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
विशेष रूप से दिलचस्प:

- `semanage fcontext`: किसी path को स्थायी रूप से मिलने वाले label को बदलता है
- `restorecon` / `setfiles`: उन परिवर्तनों को बड़े पैमाने पर फिर से लागू करता है
- `semodule -i`: एक custom policy module लोड करता है
- `semanage permissive -a <domain_t>`: पूरा host बदलने बिना एक domain को permissive बनाता है
- `setsebool -P`: policy booleans को स्थायी रूप से बदलता है
- `load_policy`: active policy को reload करता है

ये अक्सर **helper primitives**, standalone root exploits नहीं होते। इनकी उपयोगिता यह है कि ये आपको:

- किसी target domain को permissive बनाना
- आपके domain और एक protected type के बीच access को बढ़ाना
- attacker-controlled files को relabel करना ताकि एक privileged service उन्हें पढ़ सके या execute कर सके
- किसी confined service को इतना कमजोर करना कि मौजूद local bug exploitable बन जाए

उदाहरण जाँच:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
यदि आप root के रूप में एक policy module लोड कर सकते हैं, तो आम तौर पर आप SELinux boundary को नियंत्रित करते हैं:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
इसी लिए `audit2allow`, `semodule`, और `semanage permissive` को post-exploitation के दौरान संवेदनशील admin surfaces के रूप में माना जाना चाहिए। ये बिना classic UNIX permissions बदले चुपचाप एक blocked chain को काम करने योग्य बना सकते हैं।

## ऑडिट संकेत

AVC denials अक्सर सिर्फ रक्षात्मक शोर नहीं होते, बल्कि आक्रामक संकेत होते हैं। वे आपको बताते हैं:

- आपने किस target object/type को लक्षित किया
- किस permission को अस्वीकार किया गया था
- आप वर्तमान में किस domain को नियंत्रित करते हैं
- क्या एक छोटा सा policy परिवर्तन chain को काम करने योग्य बना देगा
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
यदि कोई local exploit या persistence attempt लगातार `EACCES` या अजीब "permission denied" त्रुटियों के साथ विफल हो रहा है जबकि root-looking DAC permissions दिखाई दे रही हों, तो SELinux को vector छोड़ने से पहले जांचना अक्सर फायदे का होता है।

## SELinux उपयोगकर्ता

नियमित Linux उपयोगकर्ताओं के अलावा SELinux users भी होते हैं। नीति के हिस्से के रूप में प्रत्येक Linux user को एक SELinux user से मैप किया जाता है, जिससे सिस्टम विभिन्न खातों पर अलग-अलग allowed roles और domains लागू कर सकता है।

त्वरित जांच:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
कई मुख्यधारा वाले सिस्टमों पर उपयोगकर्ताओं को `unconfined_u` से मैप किया जाता है, जो उपयोगकर्ता सीमांकन के व्यावहारिक प्रभाव को कम कर देता है। हालाँकि, कठोर तैनाती पर, सीमित उपयोगकर्ता `sudo`, `su`, `newrole`, और `runcon` को बहुत अधिक दिलचस्प बना सकते हैं क्योंकि **उत्थान पथ बेहतर SELinux role/type में प्रवेश करने पर निर्भर कर सकता है, न कि केवल UID 0 बनने पर**।

## कंटेनरों में SELinux

Container runtimes सामान्यतः workloads को एक सीमित domain में लॉन्च करते हैं जैसे `container_t` और container सामग्री को `container_file_t` के रूप में लेबल करते हैं। यदि कोई container प्रक्रिया escape कर भी ले और फिर भी container लेबल के साथ चलती रहे, तो host पर लिखने के प्रयास अभी भी विफल हो सकते हैं क्योंकि लेबल की सीमा अक्षत बनी रहती है।

त्वरित उदाहरण:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
ध्यान देने योग्य आधुनिक container ऑपरेशन:

- `--security-opt label=disable` प्रभावी रूप से वर्कलोड को unconfined container-related type जैसे `spc_t` में स्थानांतरित कर सकता है
- bind mounts with `:z` / `:Z` host path के relabeling को ट्रिगर करते हैं ताकि वह shared/private container उपयोग के लिए relabel हो सके
- host कंटेंट का व्यापक relabeling अपने आप में एक सुरक्षा समस्या बन सकता है

This page keeps the container content short to avoid duplication. For the container-specific abuse cases and runtime examples, check:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## संदर्भ

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
