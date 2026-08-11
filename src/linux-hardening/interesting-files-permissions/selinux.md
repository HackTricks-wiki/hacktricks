# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux एक **label-based Mandatory Access Control (MAC)** system है। व्यवहार में, इसका अर्थ है कि भले ही DAC permissions, groups या Linux capabilities किसी action के लिए पर्याप्त दिखाई दें, फिर भी kernel उसे अस्वीकार कर सकता है क्योंकि **source context**, अनुरोधित class/permission के साथ **target context** को access करने के लिए allowed नहीं है।<sup>[[1]](#references)</sup>

एक context आमतौर पर इस प्रकार दिखाई देता है:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privesc के दृष्टिकोण से, `type` (processes के लिए domain, objects के लिए type) आमतौर पर सबसे महत्वपूर्ण field होता है:<sup>[[1]](#references)</sup>

- कोई process `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` जैसे **domain** में चलता है
- Files और sockets में `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` जैसे **type** होते हैं
- Policy यह तय करती है कि कोई domain दूसरे domain में read/write/execute/transition कर सकता है या नहीं

## त्वरित Enumeration

यदि SELinux enabled है, तो इसे जल्दी enumerate करें, क्योंकि यह बता सकता है कि सामान्य Linux privesc paths क्यों fail होते हैं या किसी "हानिरहित" SELinux tool के चारों ओर मौजूद privileged wrapper वास्तव में critical क्यों है:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
उपयोगी follow-up checks:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
रोचक निष्कर्ष:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled` या `Permissive` mode, boundary के रूप में SELinux के अधिकांश मूल्य को समाप्त कर देता है।
- `unconfined_t` का आमतौर पर अर्थ है कि SELinux मौजूद है, लेकिन उस process पर प्रभावी रूप से कोई constraint लागू नहीं कर रहा है।
- Custom paths पर `default_t`, `file_t` या स्पष्ट रूप से गलत labels अक्सर mislabeling या अधूरे deployment का संकेत देते हैं।
- `file_contexts.local` में मौजूद local overrides, policy defaults पर प्राथमिकता रखते हैं, इसलिए उनकी सावधानीपूर्वक समीक्षा करें।

## Policy Analysis

SELinux पर attack या bypass करना तब बहुत आसान हो जाता है, जब आप इन दो प्रश्नों के उत्तर दे सकें:

1. **मेरा current domain किसे access कर सकता है?**
2. **मैं किन domains में transition कर सकता हूं?**

इसके लिए सबसे उपयोगी tools `sepolicy` और **SETools** (`seinfo`, `sesearch`, `sedta`) हैं:<sup>[[2]](#references)[[9]](#references)</sup>
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
यह विशेष रूप से तब उपयोगी है जब कोई host सभी users को `unconfined_u` पर map करने के बजाय **confined users** का उपयोग करता है। उस स्थिति में, निम्न देखें:<sup>[[3]](#references)</sup>

- `semanage login -l` के माध्यम से user mappings
- `semanage user -l` के माध्यम से allowed roles
- पहुंच योग्य admin domains जैसे `sysadm_t`, `secadm_t`, `webadm_t`
- `ROLE=` या `TYPE=` का उपयोग करने वाली `sudoers` entries

यदि `sudo -l` में इस तरह की entries हैं, तो SELinux privilege boundary का हिस्सा है:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
यह भी जाँचें कि `newrole` उपलब्ध है:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` और `newrole` अपने-आप exploit नहीं किए जा सकते, लेकिन यदि कोई privileged wrapper या `sudoers` rule आपको बेहतर role/type चुनने देता है, तो वे high-value escalation primitives बन जाते हैं।<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Files, Relabeling, और High-Value Misconfigurations

सामान्य SELinux tools के बीच सबसे महत्वपूर्ण operational अंतर यह है:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: किसी specific path पर temporary label change
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: policy/default label को दोबारा लागू करना

privesc के दौरान यह बहुत महत्वपूर्ण है, क्योंकि **relabeling केवल cosmetic नहीं है**। यह किसी file को "policy द्वारा blocked" से "किसी privileged confined service द्वारा readable/executable" में बदल सकता है।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

local relabel rules और relabel drift की जाँच करें:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
एक सूक्ष्म लेकिन उपयोगी विवरण: साधारण `restorecon` **हमेशा किसी संदिग्ध label को पूरी तरह वापस पहले जैसा नहीं करता**। यदि target type `customizable_types` में है, तो पूर्ण reset को force करने के लिए आपको `-F` की आवश्यकता हो सकती है। Offensive दृष्टिकोण से, इससे स्पष्ट होता है कि कोई असामान्य `chcon` कभी-कभी केवल "हमने पहले ही restorecon चला दिया है" वाली सतही cleanup के बाद भी बना रह सकता है।<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrappers, automation scripts या file capabilities में तलाशने योग्य महत्वपूर्ण commands:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
यदि इनमें से कोई भी MAC capability दिखाई दे, तो [Linux capabilities page](linux-capabilities.md) को भी cross-check करें; Linux capabilities documentation `cap_mac_admin` और `cap_mac_override` को Smack-specific बताता है, इसलिए केवल उनके नाम देखकर यह न मानें कि वे SELinux को bypass कर देते हैं।<sup>[[5]](#references)</sup>

विशेष रूप से interesting:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: किसी path को मिलने वाला label स्थायी रूप से बदलता है
- `restorecon` / `setfiles`: इन बदलावों को बड़े स्तर पर फिर से लागू करता है
- `semodule -i`: custom policy module लोड करता है
- `semanage permissive -a <domain_t>`: पूरे host को permissive किए बिना एक domain को permissive बनाता है
- `setsebool -P`: policy booleans को स्थायी रूप से बदलता है
- `load_policy`: active policy को फिर से लोड करता है

ये अक्सर **helper primitives** होते हैं, standalone root exploits नहीं। इनका महत्व यह है कि ये आपको सक्षम बनाते हैं:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- किसी target domain को permissive बनाना
- अपने domain और protected type के बीच access को broad करना
- attacker-controlled files को इस तरह relabel करना कि कोई privileged service उन्हें पढ़ या execute कर सके
- किसी confined service को इतना कमजोर करना कि कोई मौजूदा local bug exploitable बन जाए

Example checks:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
यदि आप root के रूप में policy module लोड कर सकते हैं, तो आमतौर पर आप SELinux boundary को नियंत्रित करते हैं:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
इसीलिए `audit2allow`, `semodule` और `semanage permissive` को post-exploitation के दौरान संवेदनशील admin surfaces माना जाना चाहिए। ये classic UNIX permissions को बदले बिना किसी blocked chain को चुपचाप working chain में बदल सकते हैं।<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Hidden Denials और Module Extraction

एक बहुत सामान्य offensive frustration ऐसी chain है जो साधारण `EACCES` के साथ fail हो जाती है, जबकि अपेक्षित AVC denial कभी दिखाई नहीं देता। `dontaudit` rules आपके लिए आवश्यक exact permission को छिपा सकते हैं। यदि आप `sudo` या किसी अन्य privileged wrapper के माध्यम से `semodule` चला सकते हैं, तो `dontaudit` को अस्थायी रूप से disable करने से silent failure एक precise policy clue में बदल सकता है:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
यह समीक्षा करने के लिए भी उपयोगी है कि local admins ने पहले से क्या बदला है। एक छोटा custom module या one-domain permissive rule अक्सर इसका कारण होता है कि कोई target service base policy के संकेत से कहीं अधिक ढीले तरीके से व्यवहार करती है।<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit संकेत

AVC denials अक्सर केवल defensive noise नहीं, बल्कि offensive signal होते हैं। वे आपको बताते हैं:<sup>[[1]](#references)[[15]](#references)</sup>

- आपने किस target object/type को hit किया
- किस permission को deny किया गया
- वर्तमान में आपके नियंत्रण में कौन-सा domain है
- क्या policy में छोटा-सा बदलाव chain को काम करने योग्य बना देगा
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
यदि कोई local exploit या persistence attempt, root-जैसी DAC permissions के बावजूद, `EACCES` या अजीब "permission denied" errors के साथ बार-बार विफल हो रहा है, तो vector को खारिज करने से पहले SELinux की जाँच करना आमतौर पर उचित होता है।<sup>[[1]](#references)</sup>

## SELinux Users

सामान्य Linux users के अतिरिक्त SELinux users भी होते हैं। Policy के भाग के रूप में प्रत्येक Linux user को एक SELinux user से map किया जाता है, जिससे system अलग-अलग accounts पर विभिन्न अनुमत roles और domains लागू कर सकता है।<sup>[[3]](#references)</sup>

त्वरित जाँचें:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
कई mainstream systems पर, users को `unconfined_u` से map किया जाता है, जिससे user confinement का practical impact कम हो जाता है। हालांकि, hardened deployments पर confined users `sudo`, `su`, `newrole`, और `runcon` को कहीं अधिक interesting बना सकते हैं, क्योंकि **escalation path केवल UID 0 बनने पर ही नहीं, बल्कि बेहतर SELinux role/type में प्रवेश करने पर भी निर्भर कर सकता है**। यह भी याद रखें कि कुछ confined users `sudo`/`su` को बिल्कुल invoke नहीं कर सकते, जब तक policy underlying setuid transition की अनुमति स्पष्ट रूप से न दे। इसलिए `staff_u` + `sysadm_r` का उपयोग करने वाला host, मामूली दिखने वाले `sudo ROLE=` / `TYPE=` rule को वास्तविक privilege boundary में बदल सकता है।<sup>[[3]](#references)</sup>

## Containers में SELinux

Container runtimes आमतौर पर workloads को `container_t` जैसे confined domain में launch करते हैं और container content को `container_file_t` के रूप में label करते हैं। यदि कोई container process escape कर जाता है, लेकिन फिर भी container label के साथ चलता है, तो host writes फिर भी fail हो सकते हैं क्योंकि label boundary intact रहती है।<sup>[[1]](#references)[[17]](#references)</sup>

त्वरित उदाहरण:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` भाग सजावटी नहीं है। कई container deployments में runtimes MCS categories को dynamically assign करते हैं, ताकि `container_t` के रूप में चलने वाली दो processes भी एक-दूसरे से अलग रहें। यदि कोई escape आपको host namespace में पहुंचा देता है, लेकिन original category set को बनाए रखता है, तो category mismatches अभी भी यह समझा सकते हैं कि host के कुछ paths unreadable या unwritable क्यों बने रहते हैं।<sup>[[17]](#references)</sup>

ध्यान देने योग्य आधुनिक container operations:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` container के लिए SELinux label separation को बंद कर देता है
- `:z` / `:Z` वाले bind mounts shared/private container use के लिए host path की relabeling trigger करते हैं
- host content की broad relabeling अपने आप में security issue बन सकती है

Duplication से बचने के लिए यह page container content को संक्षिप्त रखता है। Container-specific abuse cases और runtime examples के लिए देखें:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat docs: SELinux का उपयोग](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux के लिए policy analysis tools](https://github.com/SELinuxProject/setools)
- [3] [Confined और unconfined users का management - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux manual page](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux manual page](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux manual page](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux manual page](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [आपको अपने Linux containers के लिए Multi-Category Security का उपयोग क्यों करना चाहिए](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top documentation](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux manual page](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
