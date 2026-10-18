# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux एक **लेबल-आधारित Mandatory Access Control (MAC)** प्रणाली है। व्यवहार में, इसका अर्थ है कि भले ही किसी कार्रवाई के लिए DAC permissions, groups या Linux capabilities पर्याप्त लगें, kernel फिर भी उसे अस्वीकार कर सकता है, क्योंकि **source context** को अनुरोधित class/permission के साथ **target context** तक पहुँचने की अनुमति नहीं है।<sup>[[1]](#references)</sup>

एक context आमतौर पर ऐसा दिखता है:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

privesc के दृष्टिकोण से, `type` (processes के लिए domain, objects के लिए type) आमतौर पर सबसे महत्वपूर्ण field होता है:<sup>[[1]](#references)</sup>

- एक process `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` जैसे **domain** में चलता है
- Files और sockets का `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` जैसा **type** होता है
- Policy तय करती है कि एक domain दूसरे domain में read/write/execute कर सकता है या transition कर सकता है या नहीं

## तेज़ Enumeration

यदि SELinux enabled है, तो इसे शुरुआत में ही enumerate करें, क्योंकि इससे पता चल सकता है कि Linux privesc के आम रास्ते क्यों विफल होते हैं, या किसी "हानिरहित" SELinux tool के चारों ओर privileged wrapper वास्तव में क्यों महत्वपूर्ण है:<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

उपयोगी अनुवर्ती जाँचें:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

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

दिलचस्प निष्कर्ष:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled` या `Permissive` mode, boundary के रूप में SELinux की अधिकांश उपयोगिता खत्म कर देता है।
- `unconfined_t` का आमतौर पर मतलब है कि SELinux मौजूद है, लेकिन वह उस process को प्रभावी रूप से सीमित नहीं कर रहा है।
- custom paths पर `default_t`, `file_t` या स्पष्ट रूप से गलत labels अक्सर mislabeling या अधूरे deployment का संकेत देते हैं।
- `file_contexts.local` में local overrides को policy defaults पर प्राथमिकता मिलती है, इसलिए उनकी सावधानीपूर्वक समीक्षा करें।

## Policy Analysis

SELinux पर हमला करना या उसे bypass करना बहुत आसान हो जाता है, जब आप इन दो सवालों के जवाब दे सकें:

1. **मेरा current domain किन चीज़ों को access कर सकता है?**
2. **मैं किन domains में transition कर सकता हूँ?**

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

यह विशेष रूप से तब उपयोगी होता है जब कोई host सभी users को `unconfined_u` पर map करने के बजाय **confined users** का उपयोग करता है। ऐसे में, यह देखें:<sup>[[3]](#references)</sup>

- `semanage login -l` के ज़रिए user mappings
- `semanage user -l` के ज़रिए अनुमत roles
- पहुँच योग्य admin domains, जैसे `sysadm_t`, `secadm_t`, `webadm_t`
- `ROLE=` या `TYPE=` का उपयोग करने वाली `sudoers` entries

यदि `sudo -l` में इस तरह की entries हों, तो SELinux privilege boundary का हिस्सा है:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

यह भी जाँचें कि `newrole` उपलब्ध है:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` और `newrole` अपने-आप exploit नहीं किए जा सकते, लेकिन यदि कोई privileged wrapper या `sudoers` rule आपको बेहतर role/type चुनने देता है, तो वे escalation के उच्च-मूल्य वाले primitives बन जाते हैं।<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Writable transition entrypoints का ऑडिट करें

Transition graph केवल policy की दिशा बताता है। इसे attack path में बदलने के लिए, उस executable type की पहचान करें जो अधिक उपयोगी domain में प्रवेश कराता है, फिर जाँचें कि क्या आप उस label वाले executable को संशोधित कर सकते हैं या उसकी parent directory के ज़रिए उसे बदल सकते हैं।<sup>[[9]](#references)[[20]](#references)</sup> Automatic `execve` transition के लिए लागू `type_transition` rule, source-domain में execute access, target-domain में `entrypoint` access, और domains के बीच transition की अनुमति आवश्यक है।<sup>[[20]](#references)</sup> Target domain को SELinux access मिल सकता है, लेकिन execution से Linux UID अपने-आप नहीं बदलता; [SUID/SGID and ACLs](suid-sgid-and-acl-triage.md) को अलग से जाँचें।<sup>[[20]](#references)[[21]](#references)</sup>

रिपोर्ट किए गए entrypoint type का उपयोग करके संबंधित rules जाँचें, फिर write access के लिए path और उसकी parent directory की जाँच करें।<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Entrypoint type को वास्तविक executable path से correlate करें। किसी policy edge को reachable मानने से पहले DAC, ACLs, फ़ाइल या parent directory पर SELinux write permission, फ़ाइल label और किसी conditional boolean की जाँच करें।<sup>[[20]](#references)[[22]](#references)</sup> अगर किसी path को उसी जगह edit करने के बजाय replace किया जाता है, तो नए inode का context verify करें: filesystem labels extended attributes के रूप में store होते हैं, और replacement में entrypoint type बना रहे, यह ज़रूरी नहीं है।<sup>[[21]](#references)</sup> SELinux-aware programs `setexeccon` के साथ transition का अनुरोध कर सकते हैं, इसलिए automatic `type_transition` rule का न होना हर तरह के transition की संभावना को खारिज नहीं करता।<sup>[[20]](#references)</sup>

## Files, Relabeling, और High-Value Misconfigurations

आमतौर पर इस्तेमाल होने वाले SELinux tools के बीच सबसे महत्वपूर्ण operational अंतर है:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: किसी विशेष path पर temporary label change
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: policy/default label को फिर से लागू करना

privesc के दौरान यह बहुत मायने रखता है, क्योंकि **relabeling सिर्फ़ दिखावटी बदलाव नहीं है**। इससे कोई फ़ाइल "policy द्वारा blocked" से "privileged confined service द्वारा readable/executable" बन सकती है।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Local relabel rules और relabel drift की जाँच करें:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

एक सूक्ष्म लेकिन उपयोगी बात: सामान्य `restorecon` किसी संदिग्ध label को **हमेशा पूरी तरह वापस नहीं बदलता**। यदि target type `customizable_types` में है, तो पूरा reset करने के लिए आपको `-F` की ज़रूरत पड़ सकती है। Offensive दृष्टिकोण से, इससे समझ आता है कि कोई असामान्य `chcon` कभी-कभी "हमने पहले ही restorecon चला दिया है" जैसी सतही cleanup के बाद भी क्यों बना रह सकता है।<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

`sudo -l`, root wrappers, automation scripts या file capabilities में तलाशने के लिए उच्च-मूल्य वाले commands:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

यदि इनमें से कोई MAC capability दिखाई दे, तो [Linux capabilities page](linux-capabilities.md) भी जाँचें; Linux capabilities documentation में `cap_mac_admin` और `cap_mac_override` को Smack-specific बताया गया है, इसलिए केवल उनके नाम देखकर यह न मानें कि वे SELinux को bypass करते हैं।<sup>[[5]](#references)</sup>

खास तौर पर दिलचस्प:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: किसी path को कौन-सा label मिलना चाहिए, इसे स्थायी रूप से बदलता है
- `restorecon` / `setfiles`: इन बदलावों को बड़े पैमाने पर फिर से लागू करता है
- `semodule -i`: एक custom policy module लोड करता है
- `semanage permissive -a <domain_t>`: पूरे host को permissive किए बिना एक domain को permissive बनाता है
- `setsebool -P`: policy booleans को स्थायी रूप से बदलता है
- `load_policy`: सक्रिय policy को फिर से लोड करता है

अक्सर ये standalone root exploits नहीं, बल्कि **helper primitives** होते हैं। इनका महत्व यह है कि इनसे आप:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- किसी target domain को permissive बना सकते हैं
- अपने domain और किसी protected type के बीच access बढ़ा सकते हैं
- attacker-controlled files को relabel कर सकते हैं, ताकि कोई privileged service उन्हें पढ़ या execute कर सके
- किसी confined service की सुरक्षा इतनी कमज़ोर कर सकते हैं कि कोई मौजूदा local bug exploit किया जा सके

उदाहरण के लिए जाँचें:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

यदि आप root के रूप में policy module load कर सकते हैं, तो आमतौर पर SELinux boundary पर आपका नियंत्रण होता है:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

इसीलिए post-exploitation के दौरान `audit2allow`, `semodule`, और `semanage permissive` को संवेदनशील admin surfaces मानना चाहिए। ये classic UNIX permissions में बदलाव किए बिना, चुपचाप किसी blocked chain को काम करने वाली chain में बदल सकते हैं।<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## छिपे हुए Denials और Module Extraction

एक आम offensive परेशानी यह है कि कोई chain एक सपाट-से `EACCES` के साथ विफल हो जाती है, जबकि अपेक्षित AVC denial दिखाई नहीं देता। `dontaudit` rules शायद वही सटीक permission छिपा रहे हों जिसकी आपको ज़रूरत है। अगर आप `sudo` या किसी अन्य privileged wrapper के ज़रिए `semodule` चला सकते हैं, तो `dontaudit` को अस्थायी रूप से disable करने से एक खामोश विफलता, policy का सटीक सुराग बन सकती है:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

यह यह समीक्षा करने में भी उपयोगी है कि local admins ने पहले से क्या बदलाव किए हैं। एक छोटा custom module या one-domain permissive rule अक्सर इसकी वजह होता है कि target service, base policy के संकेत से कहीं अधिक ढीली तरह से काम करती है।<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit Clues

AVC denials अक्सर सिर्फ defensive noise नहीं, बल्कि offensive signal होते हैं। वे आपको बताते हैं:<sup>[[1]](#references)[[15]](#references)</sup>

- आपने किस target object/type को hit किया
- किस permission को deny किया गया
- आप वर्तमान में किस domain को control करते हैं
- क्या policy में एक छोटा बदलाव chain को काम करने योग्य बना देगा

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

यदि कोई local exploit या persistence प्रयास root जैसी DAC permissions के बावजूद बार-बार `EACCES` या अजीब "permission denied" errors के साथ विफल हो रहा है, तो इस vector को छोड़ने से पहले आमतौर पर SELinux की जाँच करना उचित है।<sup>[[1]](#references)</sup>

## SELinux उपयोगकर्ता

सामान्य Linux उपयोगकर्ताओं के अलावा SELinux उपयोगकर्ता भी होते हैं। Policy के हिस्से के रूप में प्रत्येक Linux उपयोगकर्ता को एक SELinux उपयोगकर्ता से map किया जाता है, जिससे system अलग-अलग accounts पर अलग-अलग अनुमत roles और domains लागू कर सकता है।<sup>[[3]](#references)</sup>

त्वरित जाँच:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

कई mainstream systems में, users को `unconfined_u` से map किया जाता है, जिससे user confinement का व्यावहारिक प्रभाव कम हो जाता है। हालांकि, hardened deployments में confined users के लिए `sudo`, `su`, `newrole`, और `runcon` कहीं अधिक दिलचस्प हो सकते हैं, क्योंकि **escalation path केवल UID 0 बनने पर ही नहीं, बल्कि बेहतर SELinux role/type में प्रवेश करने पर भी निर्भर हो सकता है**। यह भी याद रखें कि कुछ confined users `sudo`/`su` का उपयोग बिल्कुल नहीं कर सकते, जब तक policy अंतर्निहित setuid transition की स्पष्ट अनुमति न दे। इसलिए `staff_u` + `sysadm_r` का उपयोग करने वाला host, `sudo ROLE=` / `TYPE=` के एक मामूली दिखने वाले rule को ही वास्तविक privilege boundary बना सकता है।<sup>[[3]](#references)</sup>

## Containers में SELinux

Container runtimes आमतौर पर workloads को `container_t` जैसे confined domain में launch करते हैं और container content को `container_file_t` के रूप में label करते हैं। यदि कोई container process escape कर जाए, लेकिन फिर भी container label के साथ चले, तो host पर writes फिर भी विफल हो सकते हैं, क्योंकि label boundary बरकरार रहती है।<sup>[[1]](#references)[[17]](#references)</sup>

त्वरित उदाहरण:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

`c647,c780` वाला हिस्सा सजावट नहीं है। कई container deployments में, runtimes MCS categories को गतिशील रूप से असाइन करते हैं, ताकि `container_t` के रूप में चलने वाली दो processes भी एक-दूसरे से अलग रहें। अगर escape के बाद आप host namespace में पहुँचते हैं, लेकिन मूल category set बना रहता है, तो category mismatches यह समझा सकते हैं कि host के कुछ paths अब भी पढ़ने या लिखने के लिए उपलब्ध क्यों नहीं हैं।<sup>[[17]](#references)</sup>

ध्यान देने योग्य आधुनिक container operations:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` container के लिए SELinux label separation बंद करता है
- `:z` / `:Z` वाले bind mounts, shared/private container use के लिए host path को relabel करते हैं
- host content को बड़े पैमाने पर relabel करना अपने आप में सुरक्षा समस्या बन सकता है

दोहराव से बचने के लिए इस पेज में container की जानकारी संक्षिप्त रखी गई है। container-विशिष्ट abuse cases और runtime examples के लिए देखें:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Red Hat docs: SELinux का उपयोग](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux के लिए Policy analysis tools](https://github.com/SELinuxProject/setools)
- [3] [Confined और unconfined users का प्रबंधन - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
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
- [20] [SELinux Notebook: Domain और Object Transitions](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: SELinux का उपयोग](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [SETools sesearch(1) manual](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
