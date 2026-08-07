# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux एक **label-based Mandatory Access Control (MAC)** system है। व्यवहार में, इसका अर्थ है कि भले ही DAC permissions, groups या Linux capabilities किसी action के लिए पर्याप्त दिखाई दें, kernel फिर भी उसे deny कर सकता है, क्योंकि **source context** को अनुरोधित class/permission के साथ **target context** तक access की अनुमति नहीं है।

एक context आमतौर पर इस प्रकार दिखाई देता है:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privesc के दृष्टिकोण से, `type` (processes के लिए domain, objects के लिए type) आमतौर पर सबसे महत्वपूर्ण field होता है:

- एक process `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` जैसे **domain** में चलता है
- Files और sockets का `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` जैसा **type** होता है
- Policy तय करती है कि एक domain दूसरे domain को read/write/execute/transition कर सकता है या नहीं

## Fast Enumeration

यदि SELinux enabled है, तो इसे जल्दी enumerate करें, क्योंकि इससे यह समझने में मदद मिल सकती है कि common Linux privesc paths क्यों fail हो रहे हैं या किसी "harmless" SELinux tool के आसपास मौजूद privileged wrapper वास्तव में critical क्यों है:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
उपयोगी follow-up checks:
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
Interesting findings:

- `Disabled` या `Permissive` mode boundary के रूप में SELinux की अधिकांश उपयोगिता समाप्त कर देता है।
- `unconfined_t` का आमतौर पर अर्थ है कि SELinux मौजूद है, लेकिन उस process को प्रभावी रूप से constrain नहीं कर रहा है।
- Custom paths पर `default_t`, `file_t` या स्पष्ट रूप से गलत labels अक्सर mislabeling या अधूरे deployment का संकेत देते हैं।
- `file_contexts.local` में मौजूद local overrides policy defaults पर precedence रखते हैं, इसलिए उनकी सावधानीपूर्वक समीक्षा करें।

## Policy Analysis

जब आप इन दो प्रश्नों के उत्तर दे सकते हैं, तो SELinux को attack या bypass करना काफी आसान हो जाता है:

1. **मेरी current domain किसे access कर सकती है?**
2. **मैं किन domains में transition कर सकता हूं?**

इसके लिए सबसे उपयोगी tools `sepolicy` और **SETools** (`seinfo`, `sesearch`, `sedta`) हैं:<sup>[[2]](#references)</sup>
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
यह विशेष रूप से तब उपयोगी होता है जब कोई host सभी users को `unconfined_u` से map करने के बजाय **confined users** का उपयोग करता है। ऐसी स्थिति में देखें:<sup>[[3]](#references)</sup>

- `semanage login -l` के माध्यम से user mappings
- `semanage user -l` के माध्यम से allowed roles
- पहुंच योग्य admin domains, जैसे `sysadm_t`, `secadm_t`, `webadm_t`
- `ROLE=` या `TYPE=` का उपयोग करने वाली `sudoers` entries

यदि `sudo -l` में इस तरह की entries हैं, तो SELinux privilege boundary का हिस्सा है:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
यह भी जाँचें कि `newrole` उपलब्ध है:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` और `newrole` अपने-आप exploit करने योग्य नहीं होते, लेकिन यदि कोई privileged wrapper या `sudoers` rule आपको बेहतर role/type चुनने देता है, तो वे high-value escalation primitives बन जाते हैं।

## Files, Relabeling, और High-Value Misconfigurations

सामान्य SELinux tools के बीच सबसे महत्वपूर्ण operational difference यह है:<sup>[[1]](#references)</sup>

- `chcon`: किसी specific path पर temporary label change
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: policy/default label को फिर से apply करना

यह privesc के दौरान बहुत महत्वपूर्ण है क्योंकि **relabeling केवल cosmetic नहीं है**। यह किसी file को "policy द्वारा blocked" से बदलकर "privileged confined service द्वारा readable/executable" बना सकता है।

Local relabel rules और relabel drift की जाँच करें:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
एक सूक्ष्म लेकिन उपयोगी विवरण: plain `restorecon` हमेशा किसी संदिग्ध label को पूरी तरह revert **नहीं** करता। यदि target type `customizable_types` में है, तो पूर्ण reset को force करने के लिए आपको `-F` की आवश्यकता हो सकती है। Offensive दृष्टिकोण से, यह बताता है कि असामान्य `chcon` कभी-कभी "हमने पहले ही restorecon चला दिया है" जैसी सतही cleanup के बाद भी क्यों बना रह सकता है।
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrappers, automation scripts, या file capabilities में तलाशने के लिए उच्च-मूल्य वाले commands:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
यदि कोई भी MAC capability दिखाई दे, तो [Linux capabilities page](linux-capabilities.md) को भी cross-check करें; `cap_mac_admin` और `cap_mac_override` असामान्य हैं, लेकिन जब SELinux boundary का हिस्सा हो, तो सीधे relevant होते हैं।

विशेष रूप से interesting:

- `semanage fcontext`: किसी path को मिलने वाला label persistently बदलता है
- `restorecon` / `setfiles`: उन changes को बड़े scale पर reapplies करता है
- `semodule -i`: एक custom policy module load करता है
- `semanage permissive -a <domain_t>`: पूरे host को flip किए बिना एक domain को permissive बनाता है
- `setsebool -P`: policy booleans को permanently बदलता है
- `load_policy`: active policy को reload करता है

ये अक्सर **helper primitives** होते हैं, standalone root exploits नहीं। इनकी value यह है कि ये आपको:

- किसी target domain को permissive बनाने देते हैं
- आपके domain और protected type के बीच access broaden करने देते हैं
- attacker-controlled files को relabel करने देते हैं, ताकि कोई privileged service उन्हें read या execute कर सके
- किसी confined service को इतना weaken करने देते हैं कि कोई existing local bug exploitable बन जाए

उदाहरण checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
यदि आप root के रूप में policy module लोड कर सकते हैं, तो आमतौर पर आप SELinux boundary को नियंत्रित करते हैं:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
इसी कारण `audit2allow`, `semodule`, और `semanage permissive` को post-exploitation के दौरान संवेदनशील admin surfaces माना जाना चाहिए। ये classic UNIX permissions में बदलाव किए बिना, किसी blocked chain को चुपचाप working chain में बदल सकते हैं।

## Hidden Denials और Module Extraction

एक बहुत सामान्य offensive frustration ऐसी chain है जो साधारण `EACCES` के साथ fail हो जाती है, जबकि अपेक्षित AVC denial कभी दिखाई नहीं देता। `dontaudit` rules उस exact permission को छिपा सकते हैं जिसकी आपको आवश्यकता है। यदि आप `sudo` या किसी अन्य privileged wrapper के माध्यम से `semodule` चला सकते हैं, तो `dontaudit` को अस्थायी रूप से disable करने से silent failure एक precise policy clue में बदल सकता है:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
यह समीक्षा करने के लिए भी उपयोगी है कि local admins ने पहले से क्या बदला है। एक छोटा custom module या one-domain permissive rule अक्सर वह कारण होता है जिसकी वजह से कोई target service base policy के संकेत से कहीं अधिक ढीले तरीके से व्यवहार करती है।

## Audit Clues

AVC denials अक्सर केवल defensive noise नहीं, बल्कि offensive signal होते हैं। वे आपको बताते हैं:

- आपने किस target object/type को hit किया
- कौन-सी permission denied हुई
- वर्तमान में आप किस domain को control करते हैं
- क्या policy में छोटा-सा बदलाव chain को काम करने योग्य बना देगा
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
यदि कोई local exploit या persistence attempt `EACCES` या अजीब "permission denied" errors के साथ बार-बार विफल हो रहा हो, जबकि root जैसी दिखने वाली DAC permissions मौजूद हों, तो vector को खारिज करने से पहले SELinux की जाँच करना आमतौर पर उचित होता है।

## SELinux Users

सामान्य Linux users के अलावा SELinux users भी होते हैं। Policy के एक भाग के रूप में प्रत्येक Linux user को एक SELinux user से map किया जाता है, जिससे system अलग-अलग accounts पर अलग-अलग allowed roles और domains लागू कर सकता है।<sup>[[3]](#references)</sup>

त्वरित जाँचें:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
कई मुख्यधारा systems पर users को `unconfined_u` से map किया जाता है, जिससे user confinement का व्यावहारिक प्रभाव कम हो जाता है। हालांकि, hardened deployments में confined users `sudo`, `su`, `newrole`, और `runcon` को कहीं अधिक महत्वपूर्ण बना सकते हैं, क्योंकि **escalation path केवल UID 0 बनने पर ही नहीं, बल्कि बेहतर SELinux role/type में प्रवेश करने पर भी निर्भर हो सकता है**। यह भी याद रखें कि कुछ confined users `sudo`/`su` को बिल्कुल invoke नहीं कर सकते, जब तक policy underlying setuid transition की स्पष्ट अनुमति न दे। इसलिए `staff_u` + `sysadm_r` का उपयोग करने वाला host, दिखने में मामूली `sudo ROLE=` / `TYPE=` rule को वास्तविक privilege boundary में बदल सकता है।<sup>[[3]](#references)</sup>

## Containers में SELinux

Container runtimes आमतौर पर workloads को `container_t` जैसे confined domain में launch करते हैं और container content को `container_file_t` के रूप में label करते हैं। यदि कोई container process escape कर जाए, लेकिन फिर भी container label के साथ चलता रहे, तो host पर writes फिर भी fail हो सकती हैं, क्योंकि label boundary intact रहती है।

त्वरित उदाहरण:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` भाग सजावटी नहीं है। कई container deployments में runtimes MCS categories को dynamically assign करते हैं, ताकि `container_t` के रूप में चलने वाली दो processes भी एक-दूसरे से अलग रहें। यदि कोई escape आपको host namespace में पहुंचा देता है, लेकिन original category set को बनाए रखता है, तो category mismatches अब भी यह समझा सकते हैं कि कुछ host paths पढ़ने या लिखने योग्य क्यों नहीं रहते।

ध्यान देने योग्य आधुनिक container operations:

- `--security-opt label=disable` workload को प्रभावी रूप से `spc_t` जैसे unconfined container-related type में ले जा सकता है
- `:z` / `:Z` वाले bind mounts shared/private container use के लिए host path का relabeling trigger करते हैं
- host content का व्यापक relabeling अपने आप में security issue बन सकता है

यह page duplication से बचने के लिए container content को संक्षिप्त रखता है। Container-specific abuse cases और runtime examples के लिए देखें:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## संदर्भ

- [1] [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [3] [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
