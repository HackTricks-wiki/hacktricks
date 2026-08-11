# Linux Privilege Escalation Checklist

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation



### **Linux local privilege escalation vectors खोजने का सबसे अच्छा tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS information** प्राप्त करें
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) check करें, क्या कोई **writable folder** है?
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) check करें, क्या कोई sensitive detail है?
- [ ] [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) को **scripts का उपयोग करके** search करें (DirtyCow?)
- [ ] Kernel PoC run करने से पहले केवल `uname -r` ही नहीं, बल्कि उसकी **actual prerequisites** verify करें: architecture, आवश्यक `CONFIG_*` options/modules, namespace creation और active mitigations। उदाहरण के लिए, `unshare -Urn true` से user/network namespace availability test करें; modern netfilter exploits के लिए `CONFIG_USER_NS`, unprivileged user namespaces और `CONFIG_NF_TABLES` आवश्यक हो सकते हैं।<sup>[[3]](#references)</sup>
- [ ] **Check** करें कि [**sudo version** vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version) है या नहीं
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module और module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) review करें: `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement और `modules_disabled`।
- [ ] [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) check करें, यदि helper path को modify या trigger किया जा सकता है।
- [ ] [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review) check करें, जिसमें writable `.ko*` files और `modules.*` metadata शामिल हैं।
- [ ] अधिक system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [अधिक defenses enumerate करें](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mounted** drives की list बनाएं
- [ ] क्या कोई **unmounted drive** है?
- [ ] क्या fstab में कोई **creds** हैं?

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] Check करें कि [**useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **installed** है या नहीं
- [ ] Check करें कि [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **installed** है या नहीं
- [ ] Debian/Ubuntu पर check करें कि **needrestart interpreter scanning** installed/enabled है या नहीं: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`। Vulnerable builds ने attacker-controlled `PYTHONPATH`/`RUBYLIB` का reuse करके, `/proc/<pid>/exe` के साथ race करके, या APT अथवा `unattended-upgrades` द्वारा needrestart को root के रूप में invoke किए जाने पर attacker-controlled Perl paths scan करके privilege boundary पार की।<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] क्या कोई **unknown software running** है?
- [ ] क्या कोई software अपनी अपेक्षित privileges से **अधिक privileges के साथ running** है?
- [ ] **Running processes के exploits** search करें (विशेष रूप से running version)।
- [ ] क्या आप किसी running process की **binary modify** कर सकते हैं?
- [ ] **Processes monitor** करें और check करें कि कोई interesting process frequently running है या नहीं।
- [ ] क्या आप किसी interesting **process memory को read** कर सकते हैं (जहां passwords saved हो सकते हैं)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] क्या कोई cron [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)modify कर रहा है और आप उसमें **write** कर सकते हैं?
- [ ] क्या किसी cron job में [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)है?
- [ ] क्या कोई [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**executed** हो रही है या **modifiable folder** के अंदर है?
- [ ] क्या आपने detect किया है कि कोई **script** [**बहुत frequently executed**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) हो सकती है या हो रही है? (हर 1, 2 या 5 मिनट)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] क्या कोई **writable .service** file है?
- [ ] क्या किसी **service** द्वारा कोई **writable binary** executed की जा रही है?
- [ ] क्या किसी root unit द्वारा referenced कोई writable **helper, config या environment file** है (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? `systemctl cat <unit>` से merged unit inspect करें और [service/socket file abuse](../interesting-files-permissions/write-to-root.md) review करें।
- [ ] क्या systemd PATH में कोई **writable folder** है?
- [ ] क्या `/etc/systemd/system/<unit>.d/*.conf` में कोई **writable systemd unit drop-in** है जो `ExecStart`/`User` को override कर सकता है?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] क्या कोई **writable timer** है?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] क्या कोई **writable .socket** file है?
- [ ] क्या आप किसी socket के साथ **communicate** कर सकते हैं?
- [ ] क्या कोई interesting info वाले **HTTP sockets** हैं?
- [ ] क्या आप किसी [**container-runtime या node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), जैसे `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` या kubelet endpoint को access कर सकते हैं? जब इसका usual CLI मौजूद न हो, तब भी raw HTTP/gRPC API test करें।

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] क्या आप किसी **D-Bus** के साथ **communicate** कर सकते हैं?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] यह जानने के लिए network enumerate करें कि आप कहां हैं
- [ ] Machine के अंदर shell मिलने के बाद क्या ऐसे **open ports** हैं जिन्हें आप पहले access नहीं कर सकते थे?
- [ ] क्या आप `tcpdump` का उपयोग करके traffic **sniff** कर सकते हैं?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic users/groups **enumeration**
- [ ] क्या आपके पास **बहुत बड़ा UID** है? क्या **machine** **vulnerable** है?
- [ ] क्या आप जिस [**group से संबंधित हैं, उसके कारण privileges escalate**](../user-information/interesting-groups-linux-pe/index.html) कर सकते हैं?
- [ ] **Clipboard** data?
- [ ] Password Policy?
- [ ] पहले discover किए गए प्रत्येक **known password** को हर संभव **user** के साथ login करने के लिए **use** करने का प्रयास करें। बिना password के भी login करने का प्रयास करें।

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] यदि आपके पास PATH में किसी folder पर **write privileges** हैं, तो आप privileges escalate करने में सक्षम हो सकते हैं

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] क्या आप **sudo के साथ कोई command execute** कर सकते हैं? क्या आप इसका उपयोग root के रूप में कुछ READ, WRITE या EXECUTE करने के लिए कर सकते हैं? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] यदि `sudo -l` `sudoedit` की अनुमति देता है, तो vulnerable versions (`sudo -V` < 1.9.12p2) पर arbitrary files edit करने के लिए `SUDO_EDITOR`/`VISUAL`/`EDITOR` के माध्यम से **sudoedit argument injection** (CVE-2023-22809) check करें। उदाहरण: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`।<sup>[[1]](#references)</sup>
- [ ] क्या कोई **exploitable SUID binary** है? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] क्या [**sudo** commands को **path** द्वारा **limited** किया गया है? क्या आप [restrictions bypass कर सकते हैं](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary बिना path indicated**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary path specify कर रही है**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] क्या writable folder से [**SUID binary में .so library missing**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) है?
- [ ] [**SUID RPATH/RUNPATH या writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] क्या [**SUDO tokens available**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) हैं? क्या [**आप SUDO token create कर सकते हैं**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] क्या आप [**sudoers files read या modify**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) कर सकते हैं?
- [ ] क्या आप [**/etc/ld.so.conf.d/ modify**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration) कर सकते हैं?
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
- [ ] Sensitive data के लिए **commonly interesting folders check** करें
- [ ] **Weird Location/Owned files,** जिन तक आप access या executable files alter कर सकते हैं
- [ ] पिछली कुछ mins में **Modified**
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Known files that contains passwords**: **Linpeas** और **LaZagne** use करें
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Arbitrary commands execute करने के लिए **python library modify** कर सकते हैं?
- [ ] क्या आप **log files modify** कर सकते हैं? **Logtotten** exploit
- [ ] क्या आप **/etc/sysconfig/network-scripts/ modify** कर सकते हैं? Centos/Redhat exploit
- [ ] क्या आप [**ini, int.d, systemd या rc.d files में write**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) कर सकते हैं?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] क्या आप [**privileges escalate करने के लिए NFS abuse**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) कर सकते हैं?
- [ ] क्या आपको [**restrictive shell से escape**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) करना है?



## References

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit requirements and research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
