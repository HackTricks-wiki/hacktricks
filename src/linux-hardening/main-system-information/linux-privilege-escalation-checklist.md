# Linux Privilege Escalation Checklist

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation



### **Beste tool om na Linux local privilege escalation vectors te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Kry **OS information**
- [ ] Kontroleer die [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), enige **writable folder**?
- [ ] Kontroleer [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), enige sensitiewe detail?
- [ ] Soek na [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **using scripts** (DirtyCow?)
- [ ] **Kontroleer** of die [**sudo version** kwesbaar is](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Hersien [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement en `modules_disabled`.
- [ ] Kontroleer [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) indien die helper path gewysig of ge-trigger kan word.
- [ ] Kontroleer [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), insluitend writable `.ko*`-lêers en `modules.*` metadata.
- [ ] Meer system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Lys gemounte** drives
- [ ] **Enige ongemounte drive?**
- [ ] **Enige creds in fstab?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kontroleer vir**[ **useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **wat geïnstalleer is**
- [ ] **Kontroleer vir** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **wat geïnstalleer is**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Loop enige **unknown software**?
- [ ] Loop enige software met **meer privileges as wat dit behoort te hê**?
- [ ] Soek na **exploits van lopende prosesse** (veral die weergawe wat loop).
- [ ] Kan jy die **binary van enige lopende proses wysig**?
- [ ] **Monitor prosesse** en kontroleer of enige interessante proses gereeld loop.
- [ ] Kan jy sekere interessante **process memory lees** (waar passwords gestoor kan wees)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Word die [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)deur ’n cron gewysig en kan jy daarin **write**?
- [ ] Enige [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in ’n cron job?
- [ ] Word ’n [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **executed**, of is dit binne ’n **modifiable folder**?
- [ ] Het jy bespeur dat ’n **script** [**executed**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) kan word of word dit baie **frequently** **executed**? (elke 1, 2 of 5 minute)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Enige **writable .service**-lêer?
- [ ] Enige **writable binary** wat deur ’n **service** executed word?
- [ ] Enige **writable folder in systemd PATH**?
- [ ] Enige **writable systemd unit drop-in** in `/etc/systemd/system/<unit>.d/*.conf` wat `ExecStart`/`User` kan override?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Enige **writable timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Enige **writable .socket**-lêer?
- [ ] Kan jy met enige **socket communicate**?
- [ ] **HTTP sockets** met interessante inligting?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Kan jy met enige **D-Bus communicate**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerate die network om te weet waar jy is
- [ ] **Open ports waartoe jy nie voorheen toegang gehad het nie** nadat jy ’n shell binne die machine gekry het?
- [ ] Kan jy traffic met `tcpdump` **sniff**?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic users/groups **enumeration**
- [ ] Het jy ’n **baie groot UID**? Is die **machine** **vulnerable**?
- [ ] Kan jy [**escalate privileges thanks to a group**](../user-information/interesting-groups-linux-pe/index.html) waaraan jy behoort?
- [ ] **Clipboard** data?
- [ ] Password Policy?
- [ ] Probeer om elke **known password** wat jy voorheen ontdek het, te **use** om met **elke** moontlike **user** in te log. Probeer ook sonder ’n password in te log.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Indien jy **write privileges oor ’n folder in PATH** het, kan jy moontlik privileges escalate

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Kan jy **enige command with sudo execute**? Kan jy dit gebruik om enigiets as root te READ, WRITE of EXECUTE? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Indien `sudo -l` `sudoedit` toelaat, kontroleer vir **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` om arbitrêre lêers te edit op vulnerable versions (`sudo -V` < 1.9.12p2). Voorbeeld: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Is enige **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Word [**sudo** commands **limited** deur **path**? Kan jy [**bypass the restrictions**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Lack of .so library in SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) vanuit ’n writable folder?
- [ ] [**SUID RPATH/RUNPATH or writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens available**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kan jy [**read or modify sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kan jy [**modify /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Het enige binary enige **unexpected capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Het enige file enige **unexpected ACL**?

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Lees sensitiewe data? Skryf na privesc?
- [ ] **passwd/shadow files** - Lees sensitiewe data? Skryf om privesc te verkry?
- [ ] **Kontroleer algemeen interessante folders** vir sensitiewe data
- [ ] **Weird Location/Owned files,** jy het moontlik toegang tot executable files of kan dit alter
- [ ] **Modified** in die laaste minute
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Known files that contains passwords**: Gebruik **Linpeas** en **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modify python library** om arbitrêre commands te execute?
- [ ] Kan jy **log files modify**? **Logtotten** exploit
- [ ] Kan jy **modify /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Kan jy [**write in ini, int.d, systemd or rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Kan jy [**abuse NFS to escalate privileges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Moet jy [**escape from a restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?

## References

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
