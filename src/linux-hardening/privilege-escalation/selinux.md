# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux एक **label-based Mandatory Access Control (MAC)** सिस्टम है। व्यवहार में, इसका मतलब है कि भले ही DAC permissions, groups, या Linux capabilities किसी action के लिए पर्याप्त लगें, kernel फिर भी उसे deny कर सकता है क्योंकि **source context** को requested class/permission के साथ **target context** access करने की अनुमति नहीं है।

एक context आमतौर पर इस तरह दिखता है:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Privesc के दृष्टिकोण से, `type` (processes के लिए domain, objects के लिए type) आमतौर पर सबसे महत्वपूर्ण field होती है:

- एक process किसी **domain** में चलता है, जैसे `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Files और sockets के पास एक **type** होता है, जैसे `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy तय करती है कि एक domain दूसरे को read/write/execute/transition कर सकता है या नहीं

## Fast Enumeration

अगर SELinux enabled है, तो इसे जल्दी enumerate करें क्योंकि यह समझा सकता है कि common Linux privesc paths क्यों fail होते हैं या क्यों किसी "harmless" SELinux tool के ऊपर एक privileged wrapper actually critical है:
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
दिलचस्प निष्कर्ष:

- `Disabled` या `Permissive` mode, SELinux के boundary के रूप में अधिकांश value को हटा देता है।
- `unconfined_t` आमतौर पर इसका मतलब है कि SELinux मौजूद है, लेकिन उस process पर meaningful constraints नहीं लगा रहा।
- `default_t`, `file_t`, या custom paths पर obviously wrong labels अक्सर mislabeling या incomplete deployment का संकेत देते हैं।
- `file_contexts.local` में local overrides, policy defaults पर precedence लेते हैं, इसलिए उन्हें carefully review करें।

## Policy Analysis

SELinux को attack या bypass करना काफी आसान होता है जब आप दो सवालों के जवाब दे सकते हैं:

1. **मेरा current domain क्या access कर सकता है?**
2. **मैं किन domains में transition कर सकता हूँ?**

इसके लिए सबसे useful tools हैं `sepolicy` और **SETools** (`seinfo`, `sesearch`, `sedta`):
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
यह खास तौर पर तब उपयोगी है जब कोई host सभी को `unconfined_u` पर map करने के बजाय **confined users** का उपयोग करता है। उस स्थिति में, देखें:

- `semanage login -l` के जरिए user mappings
- `semanage user -l` के जरिए allowed roles
- `sysadm_t`, `secadm_t`, `webadm_t` जैसे reachable admin domains
- `ROLE=` या `TYPE=` का उपयोग करने वाली `sudoers` entries

अगर `sudo -l` में इस तरह की entries हों, तो SELinux privilege boundary का हिस्सा है:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
इसके अलावा, `newrole` उपलब्ध है या नहीं, यह भी जांचें:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` और `newrole` अपने-आप exploitable नहीं हैं, लेकिन अगर कोई privileged wrapper या कोई `sudoers` rule आपको बेहतर role/type चुनने देता है, तो वे high-value escalation primitives बन जाते हैं।

## Files, Relabeling, and High-Value Misconfigurations

Common SELinux tools के बीच सबसे महत्वपूर्ण operational difference यह है:

- `chcon`: किसी specific path पर temporary label change
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: policy/default label को फिर से apply करना

privesc के दौरान यह बहुत महत्वपूर्ण है क्योंकि **relabeling सिर्फ cosmetic नहीं है**। यह किसी file को "blocked by policy" से "privileged confined service द्वारा readable/executable" में बदल सकता है।

Local relabel rules और relabel drift की जांच करें:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
एक सूक्ष्म लेकिन उपयोगी बात: साधारण `restorecon` **हमेशा किसी संदिग्ध label को पूरी तरह वापस नहीं बदलता**। अगर target type `customizable_types` में है, तो पूरा reset force करने के लिए आपको `-F` की जरूरत पड़ सकती है। offensive perspective से, यह समझाता है कि एक असामान्य `chcon` कभी-कभी साधारण "हम already `restorecon` चला चुके हैं" cleanup के बाद भी बना रह सकता है।
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrappers, automation scripts, या file capabilities में hunt करने के लिए high-value commands:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
यदि कोई भी MAC capability दिखती है, तो [Linux capabilities page](linux-capabilities.md) को भी cross-check करें; `cap_mac_admin` और `cap_mac_override` असामान्य हैं लेकिन सीधे relevant हैं जब SELinux boundary का हिस्सा हो।

खास तौर पर interesting:

- `semanage fcontext`: किसी path को कौन सा label मिलना चाहिए, इसे persistently बदलता है
- `restorecon` / `setfiles`: उन बदलावों को scale पर दोबारा लागू करता है
- `semodule -i`: एक custom policy module लोड करता है
- `semanage permissive -a <domain_t>`: पूरे host को बदले बिना एक domain को permissive बनाता है
- `setsebool -P`: policy booleans को permanently बदलता है
- `load_policy`: active policy को reload करता है

ये अक्सर **helper primitives** होते हैं, standalone root exploits नहीं। इनकी value यह है कि ये आपको यह करने देते हैं:

- target domain को permissive बनाना
- आपके domain और protected type के बीच access broaden करना
- attacker-controlled files को relabel करना ताकि कोई privileged service उन्हें read या execute कर सके
- किसी confined service को इतना weaken करना कि existing local bug exploitable बन जाए

Example checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
यदि आप root के रूप में policy module load कर सकते हैं, तो आमतौर पर आप SELinux boundary को नियंत्रित करते हैं:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
यही कारण है कि `audit2allow`, `semodule`, और `semanage permissive` को post-exploitation के दौरान संवेदनशील admin surfaces के रूप में माना जाना चाहिए। ये classic UNIX permissions बदले बिना एक blocked chain को चुपचाप working one में बदल सकते हैं।

## Hidden Denials and Module Extraction

एक बहुत सामान्य offensive frustration यह है कि एक chain `EACCES` के bland error के साथ fail हो जाती है, जबकि expected AVC denial कभी दिखाई ही नहीं देता। `dontaudit` rules शायद वही exact permission छिपा रहे हों जिसकी आपको ज़रूरत है। अगर आप `sudo` या किसी और privileged wrapper के जरिए `semodule` चला सकते हैं, तो अस्थायी रूप से `dontaudit` को disable करना एक silent failure को precise policy clue में बदल सकता है:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
यह स्थानीय admins ने पहले से क्या बदला है, इसे review करने के लिए भी useful है। एक छोटा custom module या one-domain permissive rule अक्सर वह reason होता है जिसकी वजह से target service base policy की तुलना में कहीं अधिक loosely behave करती है।

## Audit Clues

AVC denials अक्सर offensive signal होते हैं, सिर्फ defensive noise नहीं। वे आपको बताते हैं:

- आपने किस target object/type को hit किया
- कौन-सी permission deny हुई
- आप अभी किस domain को control कर रहे हैं
- क्या एक छोटा policy change chain को काम करने लायक बना देगा
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
यदि कोई local exploit या persistence प्रयास बार-बार `EACCES` या अजीब "permission denied" errors के साथ fail हो रहा है, जबकि root-looking DAC permissions सही लग रही हैं, तो vector को discard करने से पहले SELinux को check करना आमतौर पर worth होता है।

## SELinux Users

Regular Linux users के अलावा SELinux users भी होते हैं। policy के हिस्से के रूप में हर Linux user को एक SELinux user से map किया जाता है, जिससे system अलग-अलग accounts पर अलग allowed roles और domains लागू कर सकता है।

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
कई मुख्यधारा systems पर, users को `unconfined_u` पर map किया जाता है, जिससे user confinement का practical impact कम हो जाता है। हालांकि hardened deployments पर, confined users `sudo`, `su`, `newrole`, और `runcon` को much more interesting बना सकते हैं क्योंकि **escalation path सिर्फ UID 0 बनने पर नहीं, बल्कि बेहतर SELinux role/type में enter करने पर भी depend कर सकता है**। यह भी याद रखें कि कुछ confined users `sudo`/`su` को बिल्कुल invoke नहीं कर सकते जब तक policy underlying setuid transition को explicitly allow न करे, इसलिए `staff_u` + `sysadm_r` वाला host एक seemingly minor `sudo ROLE=` / `TYPE=` rule को real privilege boundary में बदल सकता है।

## Containers में SELinux

Container runtimes आमतौर पर workloads को `container_t` जैसे confined domain में launch करते हैं और container content को `container_file_t` के रूप में label करते हैं। अगर कोई container process escape कर जाता है लेकिन फिर भी container label के साथ run करता है, तो host writes फिर भी fail हो सकती हैं क्योंकि label boundary intact रही।

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` हिस्सा सजावट नहीं है। कई container deployments में, runtimes dynamically MCS categories assign करते हैं ताकि `container_t` के रूप में चल रही दो प्रक्रियाएँ फिर भी एक-दूसरे से अलग रहें। अगर कोई escape आपको host namespace में पहुँचा दे लेकिन original category set बना रहे, तो category mismatches यह भी समझा सकते हैं कि कुछ host paths अभी भी unreadable या unwritable क्यों रहते हैं।

Modern container operations जिन पर ध्यान देना चाहिए:

- `--security-opt label=disable` workload को effectively एक unconfined container-related type जैसे `spc_t` में ले जा सकता है
- `:z` / `:Z` वाले bind mounts shared/private container use के लिए host path का relabeling trigger करते हैं
- host content का broad relabeling अपने आप में भी एक security issue बन सकता है

इस page में container content छोटा रखा गया है ताकि duplication से बचा जा सके। container-specific abuse cases और runtime examples के लिए, देखें:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
