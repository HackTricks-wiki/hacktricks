# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux एक **लेबल-आधारित अनिवार्य एक्सेस कंट्रोल (MAC)** प्रणाली है। व्यवहार में, इसका मतलब यह है कि भले ही DAC permissions, groups, या Linux capabilities किसी क्रिया के लिए पर्याप्त दिखें, कर्नेल इसे फिर भी अस्वीकार कर सकता है क्योंकि **स्रोत संदर्भ** को अनुरोधित क्लास/अनुमति के साथ **लक्षित संदर्भ** तक पहुँचने की अनुमति नहीं है।

एक संदर्भ आमतौर पर इस तरह दिखता है:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
From a privesc perspective, the `type` (domain for processes, type for objects) is usually the most important field:

- एक process किसी **domain** में चलता है, जैसे कि `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- फ़ाइलें और sockets का एक **type** होता है, जैसे कि `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy तय करती है कि एक domain दूसरे को read/write/execute/transition कर सकता है या नहीं

## Fast Enumeration

If SELinux is enabled, enumerate it early because it can explain why common Linux privesc paths fail or why a privileged wrapper around a "harmless" SELinux tool is actually critical:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
उपयोगी अनुवर्ती जांचें:
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

- `Disabled` या `Permissive` मोड SELinux की एक सीमा के रूप में अधिकतर मूल्य को हटा देता है।
- `unconfined_t` आमतौर पर संकेत करता है कि SELinux मौजूद है लेकिन वह प्रक्रिया को प्रभावी ढंग से सीमित नहीं कर रहा है।
- `default_t`, `file_t`, या कस्टम पाथ्स पर स्पष्ट रूप से गलत लेबल अक्सर गलत लेबलिंग या अधूरी तैनाती को इंगित करते हैं।
- `file_contexts.local` में स्थानीय ओवरराइड्स नीति डिफॉल्ट्स पर प्राथमिकता रखते हैं, इसलिए उन्हें सावधानी से समीक्षा करें।

## नीति विश्लेषण

यदि आप दो प्रश्नों का उत्तर दे सकते हैं तो SELinux पर हमला करना या उसे बायपास करना काफी आसान हो जाता है:

1. **मेरे वर्तमान domain क्या एक्सेस कर सकता है?**
2. **मैं किन domains में transition कर सकता हूँ?**

इसके लिए सबसे उपयोगी टूल हैं `sepolicy` और **SETools** (`seinfo`, `sesearch`, `sedta`):
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
यह विशेष रूप से तब उपयोगी है जब कोई होस्ट सभी को `unconfined_u` पर मैप करने के बजाय **बंधित उपयोगकर्ताओं** का उपयोग करता है। ऐसे मामलों में, देखें:

- `semanage login -l` के माध्यम से उपयोगकर्ता मैपिंग
- `semanage user -l` के माध्यम से अनुमत भूमिकाएँ
- पहुँच योग्य प्रशासनिक डोमेन जैसे `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` प्रविष्टियाँ जिनमें `ROLE=` या `TYPE=` का उपयोग होता है

यदि `sudo -l` में इस तरह की प्रविष्टियाँ हों, तो SELinux विशेषाधिकार सीमा का हिस्सा है:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
यह भी जाँचें कि `newrole` उपलब्ध है या नहीं:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` और `newrole` स्वतः शोषणीय नहीं होते, लेकिन अगर कोई विशेषाधिकार प्राप्त wrapper या `sudoers` नियम आपको बेहतर role/type चुनने देता है, तो ये उच्च-मूल्य के escalation primitives बन जाते हैं।

## फाइलें, रीलैबलिंग, और उच्च-मूल्य गलत कॉन्फ़िगरेशन

सामान्य SELinux टूल्स के बीच सबसे महत्वपूर्ण ऑपरेशनल अंतर यह है:

- `chcon`: किसी विशिष्ट पथ पर अस्थायी लेबल परिवर्तन
- `semanage fcontext`: पथ-से-लेबल के लिए स्थायी नियम
- `restorecon` / `setfiles`: नीति/डिफ़ॉल्ट लेबल को फिर से लागू करना

यह privesc के दौरान बहुत मायने रखता है क्योंकि **रीलेबलिंग सिर्फ दिखावटी नहीं है**।

स्थानीय रीलेबल नियम और रीलेबल ड्रिफ्ट की जाँच करें:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
उच्च‑मूल्य वाले कमांड जिन्हें `sudo -l`, root wrappers, automation scripts, या file capabilities में खोजें:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
विशेष रूप से दिलचस्प:

- `semanage fcontext`: किसी पथ को कौन सा लेबल मिलना चाहिए, इसे स्थायी रूप से बदलता है
- `restorecon` / `setfiles`: उन परिवर्तनों को बड़े पैमाने पर पुन: लागू करता है
- `semodule -i`: कस्टम policy मॉड्यूल लोड करता है
- `semanage permissive -a <domain_t>`: एक domain को permissive बनाता है बिना पूरे होस्ट को प्रभावित किए
- `setsebool -P`: policy booleans को स्थायी रूप से बदलता है
- `load_policy`: सक्रिय policy को पुनः लोड करता है

ये अक्सर **helper primitives** होते हैं, standalone root exploits नहीं। इनका मूल्य यह है कि ये आपको सक्षम करते हैं:

- लक्षित domain को permissive बनाना
- आपके domain और किसी protected type के बीच पहुँच बढ़ाना
- attacker-controlled फाइलों के लेबल बदलना ताकि एक privileged service उन्हें पढ़ या execute कर सके
- किसी confined service को इतना कमजोर करना कि मौजूदा local bug exploitable बन जाए

उदाहरण जांच:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
यदि आप एक policy module को root के रूप में लोड कर सकते हैं, तो आप आमतौर पर SELinux सीमा को नियंत्रित करते हैं:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
इसीलिए `audit2allow`, `semodule`, और `semanage permissive` को post-exploitation के दौरान संवेदनशील admin सतहें माना जाना चाहिए। ये पारंपरिक UNIX permissions को बदले बिना चुपचाप एक रोकी गई श्रृंखला को काम करने वाली श्रृंखला में बदल सकती हैं।

## ऑडिट संकेत

AVC denials अक्सर सिर्फ रक्षात्मक शोर नहीं बल्कि आक्रामक संकेत होते हैं। वे आपको बताते हैं:

- आपने किस target object/type को टार्गेट किया
- कौन-सा permission अस्वीकार किया गया
- आप वर्तमान में किस domain को नियंत्रित करते हैं
- क्या एक छोटा policy परिवर्तन श्रृंखला को काम में ला देगा
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
यदि कोई local exploit या persistence प्रयास `EACCES` या अजीब "permission denied" त्रुटियों के साथ बार-बार विफल हो रहा है जबकि root-जैसी DAC अनुमतियाँ दिख रही हों, तो vector को त्यागने से पहले SELinux की जाँच करना आम तौर पर फायदेमंद होता है।

## SELinux उपयोगकर्ता

सामान्य Linux उपयोगकर्ताओं के अलावा SELinux उपयोगकर्ता भी होते हैं। नीति के हिस्से के रूप में प्रत्येक Linux उपयोगकर्ता को एक SELinux उपयोगकर्ता से मैप किया जाता है, जिससे सिस्टम विभिन्न खातों पर अलग-अलग अनुमत भूमिकाएँ और डोमेन लागू कर सकता है।

त्वरित जाँच:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
कई प्रमुख सिस्टमों पर उपयोगकर्ता `unconfined_u` से मैप होते हैं, जो user confinement के व्यावहारिक प्रभाव को कम कर देता है। हालांकि, hardened deployments में confined users `sudo`, `su`, `newrole`, और `runcon` को बहुत अधिक रोचक बना सकते हैं क्योंकि **the escalation path may depend on entering a better SELinux role/type, not only on becoming UID 0**।

## SELinux in Containers

Container runtimes आमतौर पर workloads को एक confined domain में लॉन्च करते हैं, जैसे कि `container_t`, और container content को `container_file_t` के रूप में label करते हैं। यदि कोई container process escapes कर भी जाता है लेकिन फिर भी container label के साथ चलता है, तो host पर writes अभी भी फेल हो सकते हैं क्योंकि label boundary अपरिवर्तित रहा। 

त्वरित उदाहरण:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
ध्यान देने योग्य आधुनिक container संचालन:

- `--security-opt label=disable` वास्तव में workload को unconfined container-related type जैसे `spc_t` में स्थानांतरित कर सकता है
- bind mounts with `:z` / `:Z` host path की relabeling को ट्रिगर करते हैं ताकि shared/private container उपयोग के लिए
- होस्ट कंटेंट का व्यापक relabeling स्वयं में एक सुरक्षा समस्या बन सकता है

यह पृष्ठ container सामग्री को दोहराव से बचने के लिए संक्षेप में रखता है। container-विशिष्ट दुरुपयोग मामलों और runtime उदाहरणों के लिए, देखें:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## संदर्भ

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
