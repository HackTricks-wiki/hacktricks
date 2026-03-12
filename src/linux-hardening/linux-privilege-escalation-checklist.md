# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Linux local privilege escalation vectors खोजने के लिए सबसे अच्छा टूल:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] प्राप्त करें **OS जानकारी**
- [ ] Check the [**PATH**](privilege-escalation/index.html#path), कोई **writable folder**?
- [ ] Check [**env variables**](privilege-escalation/index.html#env-info), कोई संवेदनशील विवरण?
- [ ] Search for [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **using scripts** (DirtyCow?)
- [ ] **जाँच करें** क्या [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] अधिक system enum ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **List mounted** drives
- [ ] **कोई unmounted drive?**
- [ ] **fstab में कोई creds?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **जाँच करें** क्या [ **useful software**](privilege-escalation/index.html#useful-software) इंस्टॉल है
- [ ] **जाँच करें** क्या [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) इंस्टॉल है

### [Processes](privilege-escalation/index.html#processes)

- [ ] क्या कोई **unknown software चल रही है**?
- [ ] क्या कोई software ऐसे **privileges के साथ चल रही है जो उसे नहीं मिलने चाहिए**?
- [ ] चल रहे processes के लिए **exploits खोजें** (खासकर चल रही version के लिए).
- [ ] क्या आप किसी चलती process का **binary modify** कर सकते हैं?
- [ ] **प्रक्रियाओं की निगरानी करें** और देखें क्या कोई रोचक process बार-बार चल रही है.
- [ ] क्या आप किसी रोचक **process memory** को **read** कर सकते हैं (जहाँ passwords saved हो सकते हैं)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] क्या [**PATH** ](privilege-escalation/index.html#cron-path) किसी cron द्वारा modify हो रहा है और आप उसमें **write** कर सकते हैं?
- [ ] किसी cron job में कोई [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] कोई [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) execute हो रहा है या कोई **modifiable folder** के अंदर है?
- [ ] क्या आपने detect किया है कि कोई **script** बहुत **बार-बार execute** हो रहा है? (हर 1, 2 या 5 मिनट)

### [Services](privilege-escalation/index.html#services)

- [ ] कोई **writable .service** file?
- [ ] कोई **writable binary** जो किसी **service** द्वारा execute हो रहा हो?
- [ ] systemd PATH में कोई **writable folder**?
- [ ] `/etc/systemd/system/<unit>.d/*.conf` में कोई **writable systemd unit drop-in** जो `ExecStart`/`User` override कर सके?

### [Timers](privilege-escalation/index.html#timers)

- [ ] कोई **writable timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] कोई **writable .socket** file?
- [ ] क्या आप किसी socket के साथ **communicate** कर सकते हैं?
- [ ] रोचक जानकारी वाले **HTTP sockets**?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] क्या आप किसी D-Bus के साथ **communicate** कर सकते हैं?

### [Network](privilege-escalation/index.html#network)

- [ ] नेटवर्क enumerate करें ताकि आप जान सकें आप कहाँ हैं
- [ ] क्या shell मिलने के बाद वे **open ports जो पहले access नहीं किए जा सकते थे** अब open हैं?
- [ ] क्या आप `tcpdump` का उपयोग करके **traffic sniff** कर सकते हैं?

### [Users](privilege-escalation/index.html#users)

- [ ] Generic users/groups **enumeration**
- [ ] क्या आपकी UID बहुत बड़ी है? क्या **machine** **vulnerable** है?
- [ ] क्या आप किसी ऐसे [**group**](privilege-escalation/interesting-groups-linux-pe/index.html) के कारण **privileges escalate** कर सकते हैं जिसके आप सदस्य हैं?
- [ ] **Clipboard** डेटा?
- [ ] Password Policy?
- [ ] पहले से मिले हर **known password** को हर संभव **user** से login करने के लिए आज़माएँ। पासवर्ड के बिना भी login आज़माएँ।

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] यदि आपके पास PATH में किसी folder पर **write privileges** हैं तो आप privileges escalate कर सकते हैं

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] क्या आप **किसी भी command को sudo से execute** कर सकते हैं? क्या आप इसे root के रूप में किसी चीज़ को READ, WRITE या EXECUTE करने के लिए उपयोग कर सकते हैं? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] यदि `sudo -l` `sudoedit` की अनुमति देता है, तो **sudoedit argument injection** (CVE-2023-22809) के लिए `SUDO_EDITOR`/`VISUAL`/`EDITOR` की जाँच करें ताकि कमजोर versions (`sudo -V` < 1.9.12p2) पर arbitrary files edit किए जा सकें। उदाहरण: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] क्या कोई **exploitable SUID binary** है? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] क्या [**sudo** commands **path द्वारा सीमित** हैं? क्या आप प्रतिबंधों को **bypass** कर सकते हैं](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] क्या किसी writable folder से [**.so library की कमी वाला SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) है?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**क्या आप SUDO token बना सकते हैं**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] क्या आप [**sudoers files पढ़ या modify कर सकते हैं**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] क्या आप [**/etc/ld.so.conf.d/** modify कर सकते हैं](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] क्या किसी binary में कोई **अनपेक्षित capability** है?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] क्या किसी file में कोई **अनपेक्षित ACL** है?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - संवेदनशील डेटा पढ़ें? privesc के लिए लिखें?
- [ ] **passwd/shadow files** - संवेदनशील डेटा पढ़ें? privesc के लिए लिखें?
- [ ] संवेदनशील डेटा के लिए सामान्य रूप से रोचक फ़ोल्डरों की जाँच करें
- [ ] **अजीब Location/Owned files,** जिन तक आपकी पहुँच हो सकती है या आप executable files बदल सकते हैं
- [ ] हाल ही में **modified** (last mins)
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Known files that contains passwords**: उपयोग करें **Linpeas** और **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] क्या आप python library **modify** कर सकते हैं ताकि arbitrary commands execute हों?
- [ ] क्या आप **log files modify** कर सकते हैं? **Logtotten** exploit
- [ ] क्या आप **/etc/sysconfig/network-scripts/** modify कर सकते हैं? Centos/Redhat exploit
- [ ] क्या आप [**ini, int.d, systemd or rc.d files में लिख सकते हैं**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] क्या आप [**NFS को abuse करके privileges escalate** कर सकते हैं](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] क्या आपको किसी restrictive shell से [**escape**](privilege-escalation/index.html#escaping-from-restricted-shells) करने की जरूरत है?

## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
