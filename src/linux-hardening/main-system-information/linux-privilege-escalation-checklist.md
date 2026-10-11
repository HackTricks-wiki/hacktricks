# Linux Privilege Escalation चेकलिस्ट

{{#include ../../banners/hacktricks-training.md}}

# चेकलिस्ट - Linux Privilege Escalation



### **Linux local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS information** प्राप्त करें
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) जाँचें, क्या कोई **writable folder** है?
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) जाँचें, क्या कोई sensitive detail है?
- [ ] **scripts का उपयोग करके** [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) खोजें (DirtyCow?)
- [ ] Kernel PoC चलाने से पहले, केवल `uname -r` ही नहीं, बल्कि उसकी **वास्तविक prerequisites** भी verify करें: architecture, आवश्यक `CONFIG_*` options/modules, namespace creation और active mitigations। उदाहरण के लिए, `unshare -Urn true` से user/network namespace की उपलब्धता जाँचें; आधुनिक netfilter exploits के लिए `CONFIG_USER_NS`, unprivileged user namespaces और `CONFIG_NF_TABLES` आवश्यक हो सकते हैं।<sup>[[3]](#references)</sup>
- [ ] जाँचें कि [**sudo version** vulnerable है या नहीं](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification विफल](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module और module-loading की misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) की समीक्षा करें: `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement और `modules_disabled`।
- [ ] अगर helper path को modify या trigger किया जा सकता है, तो [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) जाँचें।
- [ ] [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review) जाँचें, जिनमें writable `.ko*` files और `modules.*` metadata शामिल हैं।
- [ ] और system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [और defenses enumerate करें](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mounted** drives की सूची देखें
- [ ] क्या कोई **unmounted drive** है?
- [ ] क्या fstab में कोई **creds** हैं?

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] जाँचें कि कोई [**useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **installed** है या नहीं
- [ ] जाँचें कि कोई [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **installed** है या नहीं
- [ ] Debian/Ubuntu पर जाँचें कि **needrestart interpreter scanning** installed/enabled है या नहीं: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`। Vulnerable builds में, जब APT या `unattended-upgrades` ने needrestart को root के रूप में invoke किया, तब attacker-controlled `PYTHONPATH`/`RUBYLIB` का फिर से उपयोग करके, `/proc/<pid>/exe` के साथ race करके, या attacker-controlled Perl paths को scan करके privilege boundary पार की जा सकती थी।<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] क्या कोई **unknown software चल रहा है**?
- [ ] क्या कोई software **उससे अधिक privileges के साथ चल रहा है जितना उसे चलना चाहिए**?
- [ ] **Running processes के exploits** खोजें (खासकर चल रहे version के लिए)।
- [ ] क्या आप किसी running process का **binary modify** कर सकते हैं?
- [ ] **Processes monitor** करें और जाँचें कि कोई interesting process बार-बार चल रहा है या नहीं।
- [ ] क्या आप किसी interesting **process memory को read** कर सकते हैं (जहाँ passwords save हो सकते हैं)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] क्या कोई cron [**PATH**](../linux-basics/linux-privilege-escalation/index.html#cron-path) को modify कर रहा है और क्या आप उसमें **write** कर सकते हैं?
- [ ] क्या किसी cron job में [**wildcard**](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) है?
- [ ] क्या कोई [**modifiable script**](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **execute** हो रही है या किसी **modifiable folder** के अंदर है?
- [ ] क्या आपने पता लगाया है कि कोई **script** [बहुत **frequently execute**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) हो सकती है या हो रही है? (हर 1, 2 या 5 मिनट में)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] क्या कोई **writable .service** file है?
- [ ] क्या किसी **service** द्वारा execute किया जाने वाला कोई **writable binary** है?
- [ ] क्या किसी root unit द्वारा referenced कोई writable **helper, config या environment file** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`) है? `systemctl cat <unit>` से merged unit inspect करें और [service/socket file abuse](../interesting-files-permissions/write-to-root.md) की समीक्षा करें।
- [ ] क्या कोई on-demand privileged workflow, lower-privilege writable directory के अंदर मौजूद helper चलाता है? Helper और उसके parent, दोनों को [user-modifiable paths का root execution](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries) के लिए जाँचें; short-lived helpers केवल workflow चलते समय दिखाई दे सकते हैं।
- [ ] क्या **systemd PATH** में कोई **writable folder** है?
- [ ] क्या `/etc/systemd/system/<unit>.d/*.conf` में कोई **writable systemd unit drop-in** है जो `ExecStart`/`User` को override कर सकता है?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] क्या कोई **writable timer** है?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] क्या कोई **writable .socket** file है?
- [ ] क्या आप किसी socket के साथ **communicate** कर सकते हैं?
- [ ] क्या किसी **HTTP socket** में interesting info है?
- [ ] क्या आप किसी [**container-runtime या node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) को access कर सकते हैं, जैसे `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` या kubelet endpoint? सामान्य CLI मौजूद न होने पर भी raw HTTP/gRPC API को test करें।

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] क्या आप किसी D-Bus के साथ **communicate** कर सकते हैं?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] यह जानने के लिए network enumerate करें कि आप कहाँ हैं
- [ ] क्या machine के अंदर shell मिलने के बाद ऐसे **open ports** दिखे जिन्हें आप पहले access नहीं कर सकते थे?
- [ ] क्या आप `tcpdump` का उपयोग करके **traffic sniff** कर सकते हैं?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] सामान्य users/groups की **enumeration**
- [ ] क्या आपका **UID बहुत बड़ा** है? क्या **machine vulnerable** है?
- [ ] क्या आप जिस group के सदस्य हैं, उसकी मदद से [**privileges escalate**](../user-information/interesting-groups-linux-pe/index.html) कर सकते हैं?
- [ ] **Clipboard** data?
- [ ] Password Policy?
- [ ] पहले खोजे गए हर **known password** को हर संभावित **user** के साथ login करने के लिए **use** करके देखें। बिना password के भी login करने की कोशिश करें।

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] अगर आपको PATH के किसी folder पर **write privileges** हैं, तो आप privileges escalate कर सकते हैं

### [SUDO और SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] क्या आप **sudo के साथ कोई command execute** कर सकते हैं? क्या आप इसका उपयोग root के रूप में कुछ READ, WRITE या EXECUTE करने के लिए कर सकते हैं? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] अगर `sudo -l` में `sudoedit` की अनुमति है, तो vulnerable versions (`sudo -V` < 1.9.12p2) पर arbitrary files edit करने के लिए `SUDO_EDITOR`/`VISUAL`/`EDITOR` के ज़रिए **sudoedit argument injection** (CVE-2023-22809) जाँचें। उदाहरण: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`।<sup>[[1]](#references)</sup>
- [ ] क्या कोई **exploitable SUID binary** है? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] क्या [**sudo** commands **path** से **limited** हैं? क्या आप restrictions को **bypass** कर सकते हैं](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary जिसमें path नहीं दिया गया है**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Path specify करने वाली SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] क्या किसी writable folder में SUID binary की [**.so library मौजूद नहीं है**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)?
- [ ] [**SUID RPATH/RUNPATH या writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] क्या [**SUDO tokens उपलब्ध**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) हैं? क्या आप [**SUDO token बना सकते हैं**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] क्या आप [**sudoers files read या modify**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) कर सकते हैं?
- [ ] क्या आप [**/etc/ld.so.conf.d/** को modify](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration) कर सकते हैं?
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
- [ ] [**SSH की interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - क्या sensitive data read कर सकते हैं? क्या privesc के लिए इनमें write कर सकते हैं?
- [ ] **passwd/shadow files** - क्या sensitive data read कर सकते हैं? क्या privesc के लिए इनमें write कर सकते हैं?
- [ ] Sensitive data के लिए आम तौर पर interesting folders **जाँचें**
- [ ] **अजीब स्थानों पर मौजूद/किसी के स्वामित्व वाली files**, जिन्हें आप access कर सकते हैं या जिनकी executable files बदल सकते हैं
- [ ] पिछले कुछ मिनटों में **Modified**
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH में Scripts/Binaries**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **वे ज्ञात files जिनमें passwords होते हैं**: **Linpeas** और **LaZagne** का उपयोग करें
- [ ] **सामान्य खोज**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] क्या arbitrary commands execute करने के लिए **python library modify** कर सकते हैं?
- [ ] क्या आप **log files modify** कर सकते हैं? **Logtotten** exploit
- [ ] क्या आप **/etc/sysconfig/network-scripts/** modify कर सकते हैं? Centos/Redhat exploit
- [ ] क्या आप [**ini, int.d, systemd या rc.d files में write**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) कर सकते हैं?

### [**अन्य तरकीबें**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] क्या आप [**privileges escalate करने के लिए NFS का abuse**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) कर सकते हैं?
- [ ] क्या आपको [**restrictive shell से escape**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) करना है?



## References

- [1] [Sudo advisory: sudoedit से arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit की आवश्यकताएँ और research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: needrestart में LPEs](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
