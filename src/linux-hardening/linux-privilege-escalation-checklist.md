# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Get **OS information**
- [ ] Check the [**PATH**](privilege-escalation/index.html#path), any **writable folder**?
- [ ] Check [**env variables**](privilege-escalation/index.html#env-info), any sensitive detail?
- [ ] Search for [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **using scripts** (DirtyCow?)
- [ ] **Check** if the [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] More system enum ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **List mounted** drives
- [ ] **Any unmounted drive?**
- [ ] **Any creds in fstab?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Check for**[ **useful software**](privilege-escalation/index.html#useful-software) **installed**
- [ ] **Check for** [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) **installed**

### [Processes](privilege-escalation/index.html#processes)

- [ ] Is any **unknown software running**?
- [ ] Is any software running with **more privileges than it should have**?
- [ ] Search for **exploits of running processes** (especially the version running).
- [ ] Can you **modify the binary** of any running process?
- [ ] **Monitor processes** and check if any interesting process is running frequently.
- [ ] Can you **read** some interesting **process memory** (where passwords could be saved)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Is the [**PATH** ](privilege-escalation/index.html#cron-path)being modified by some cron and you can **write** in it?
- [ ] Any [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in a cron job?
- [ ] Some [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink)is being **executed** or is inside **modifiable folder**?
- [ ] Have you detected that some **script** could be or are being [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs)? (every 1, 2 or 5 minutes)

### [Services](privilege-escalation/index.html#services)

- [ ] Any **writable .service** file?
- [ ] Any **writable binary** executed by a **service**?
- [ ] Any **writable folder in systemd PATH**?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Any **writable timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Any **writable .socket** file?
- [ ] Can you **communicate with any socket**?
- [ ] **HTTP sockets** with interesting info?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Can you **communicate with any D-Bus**?

### [Network](privilege-escalation/index.html#network)

- [ ] Enumerate the network to know where you are
- [ ] **Open ports you couldn't access before** getting a shell inside the machine?
- [ ] Can you **sniff traffic** using `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Generic users/groups **enumeration**
- [ ] Do you have a **very big UID**? Is the **machine** **vulnerable**?
- [ ] Can you [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html) you belong to?
- [ ] **Clipboard** data?
- [ ] Password Policy?
- [ ] Try to **use** every **known password** that you have discovered previously to login **with each** possible **user**. Try to login also without a password.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] If you have **write privileges over some folder in PATH** you may be able to escalate privileges

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Can you execute **any command with sudo**? Can you use it to READ, WRITE or EXECUTE anything as root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Is any **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) from a writable folder?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Can you [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Can you [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Has any binary any **unexpected capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Has any file any **unexpected ACL**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Read sensitive data? Write to privesc?
- [ ] **passwd/shadow files** - Read sensitive data? Write to privesc?
- [ ] **Check commonly interesting folders** for sensitive data
- [ ] **Weird Location/Owned files,** you may have access to or alter executable files
- [ ] **Modified** in last mins
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Known files that contains passwords**: Use **Linpeas** and **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Modify python library** to execute arbitrary commands?
- [ ] Can you **modify log files**? **Logtotten** exploit
- [ ] Can you **modify /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Can you [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Can you [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Do you need to [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}



