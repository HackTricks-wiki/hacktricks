# Linux Privilege Escalation Checklist

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation



### **Linux local privilege escalation vectors खोजने के लिए Best tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS information** प्राप्त करें
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) जांचें, क्या कोई **writable folder** है?
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) जांचें, क्या कोई sensitive detail है?
- [ ] **scripts का उपयोग करके** [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) खोजें (DirtyCow?)
- [ ] जांचें कि [**sudo version** vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version) है या नहीं
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module और module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) की समीक्षा करें: `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement और `modules_disabled`।
- [ ] [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) जांचें, यदि helper path को modify या trigger किया जा सकता है।
- [ ] [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review) जांचें, जिसमें writable `.ko*` files और `modules.*` metadata शामिल हैं।
- [ ] अधिक system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [अधिक defenses enumerate करें](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mounted** drives की सूची बनाएं
- [ ] **कोई unmounted drive है?**
- [ ] **fstab में कोई creds हैं?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **installed** [**useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) की **जांच करें**
- [ ] **installed** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) की **जांच करें**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] क्या कोई **unknown software running** है?
- [ ] क्या कोई software **अपेक्षित से अधिक privileges के साथ running** है?
- [ ] **running processes के exploits** खोजें (विशेषकर running version के)।
- [ ] क्या आप किसी running process के **binary को modify** कर सकते हैं?
- [ ] **processes को monitor करें** और जांचें कि कोई interesting process बार-बार running तो नहीं है।
- [ ] क्या आप किसी interesting **process memory को read** कर सकते हैं (जहां passwords save हो सकते हैं)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] क्या किसी cron द्वारा [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)को modify किया जा रहा है और क्या आप उसमें **write** कर सकते हैं?
- [ ] किसी cron job में कोई [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)है?
- [ ] कोई [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**executed** हो रही है या **modifiable folder** के अंदर है?
- [ ] क्या आपने detect किया है कि कोई **script** [**बहुत **frequently** executed](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) हो सकती है या हो रही है? (हर 1, 2 या 5 मिनट में)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] कोई **writable .service** file है?
- [ ] किसी **service** द्वारा कोई **writable binary** executed हो रही है?
- [ ] क्या systemd PATH में कोई **writable folder** है?
- [ ] क्या `/etc/systemd/system/<unit>.d/*.conf` में कोई **writable systemd unit drop-in** है जो `ExecStart`/`User` को override कर सके?

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] कोई **writable timer** है?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] कोई **writable .socket** file है?
- [ ] क्या आप किसी **socket के साथ communicate** कर सकते हैं?
- [ ] Interesting info वाले **HTTP sockets**?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] क्या आप किसी **D-Bus के साथ communicate** कर सकते हैं?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] यह जानने के लिए network enumerate करें कि आप कहां हैं
- [ ] Machine के अंदर shell प्राप्त करने से पहले access न कर सकने वाले **open ports**?
- [ ] क्या आप `tcpdump` का उपयोग करके **traffic sniff** कर सकते हैं?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic users/groups की **enumeration**
- [ ] क्या आपके पास **बहुत बड़ा UID** है? क्या **machine** **vulnerable** है?
- [ ] क्या आप जिस group के member हैं, उसकी मदद से [**privileges escalate**](../user-information/interesting-groups-linux-pe/index.html) कर सकते हैं?
- [ ] **Clipboard** data?
- [ ] Password Policy?
- [ ] पहले discover किए गए हर **known password** को login करने के लिए हर संभावित **user** के साथ **use** करने का प्रयास करें। बिना password के भी login करने का प्रयास करें।

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] यदि आपके पास PATH में किसी folder पर **write privileges** हैं, तो आप privileges escalate कर सकते हैं

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] क्या आप **sudo के साथ कोई command execute** कर सकते हैं? क्या आप इसका उपयोग root के रूप में कुछ भी READ, WRITE या EXECUTE करने के लिए कर सकते हैं? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] यदि `sudo -l` `sudoedit` की अनुमति देता है, तो vulnerable versions (`sudo -V` < 1.9.12p2) पर arbitrary files edit करने के लिए `SUDO_EDITOR`/`VISUAL`/`EDITOR` के माध्यम से **sudoedit argument injection** (CVE-2023-22809) जांचें। Example: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] क्या कोई **exploitable SUID binary** है? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] क्या [**sudo** commands **path** द्वारा **limited** हैं? क्या आप [**restrictions bypass**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) कर सकते हैं?
- [ ] [**Sudo/SUID binary बिना path indicated**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] क्या किसी writable folder से [**SUID binary में .so library missing**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) है?
- [ ] [**SUID RPATH/RUNPATH या writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens available**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**क्या आप SUDO token create कर सकते हैं**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] क्या आप [**sudoers files read या modify**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) कर सकते हैं?
- [ ] क्या आप [**modify /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration) कर सकते हैं?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] क्या किसी binary में कोई **unexpected capability** है?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] क्या किसी file में कोई **unexpected ACL** है?

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Sensitive data read करें? Privesc के लिए write करें?
- [ ] **passwd/shadow files** - Sensitive data read करें? Privesc के लिए write करें?
- [ ] Sensitive data के लिए **commonly interesting folders check करें**
- [ ] **Weird Location/Owned files,** जिन तक आपकी access हो सकती है या जिन्हें आप executable files में alter कर सकते हैं
- [ ] पिछले कुछ मिनटों में **Modified**
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Known files that contains passwords**: **Linpeas** और **LaZagne** का उपयोग करें
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Arbitrary commands execute करने के लिए **python library modify** करें?
- [ ] क्या आप **log files modify** कर सकते हैं? **Logtotten** exploit
- [ ] क्या आप **modify /etc/sysconfig/network-scripts/** कर सकते हैं? Centos/Redhat exploit
- [ ] क्या आप [**ini, int.d, systemd या rc.d files में write**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) कर सकते हैं?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] क्या आप [**privileges escalate करने के लिए NFS abuse**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) कर सकते हैं?
- [ ] क्या आपको [**restrictive shell से escape**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) करना है?



## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
