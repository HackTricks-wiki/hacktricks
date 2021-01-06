---
description: Checklist for privilege escalation in Linux
---

# Checklist - Linux Privilege Escalation

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)\*\*\*\*

### [System Information](privilege-escalation/#system-information)

* [ ] Get **OS information**
* [ ] Check the [**PATH**](privilege-escalation/#path), any **writable folder**?
* [ ] Check [**env variables**](privilege-escalation/#env-info), any sensitive detail?
* [ ] Search for [**kernel exploits**](privilege-escalation/#kernel-exploits) **using scripts** \(DirtyCow?\)
* [ ] **Check** if the [**sudo version** is vulnerable](privilege-escalation/#sudo-version)
* [ ] \*\*\*\*[**Dmesg** signature verification failed](privilege-escalation/#dmesg-signature-verification-failed) error?
* [ ] More system enum \([date, system stats, cpu info, printers](privilege-escalation/#more-system-enumeration)\)
* [ ] [Enumerate more defenses](privilege-escalation/#enumerate-possible-defenses)

### [Drives](privilege-escalation/#drives)

* [ ] **List mounted** drives
* [ ] **Any unmounted drive?**
* [ ] **Any creds in fstab?**

### \*\*\*\*[**Installed Software**](privilege-escalation/#installed-software)\*\*\*\*

1. [ ] **Check for**[ **useful software**](privilege-escalation/#useful-software) **installed**
2. [ ] **Check for** [**vulnerable software**](privilege-escalation/#vulnerable-software-installed) **installed**

### \*\*\*\*[Processes](privilege-escalation/#processes)

* [ ] Is  any **unknown software running**?
* [ ] Is any software with **more privileges that it should have running**?
* [ ] Search for **exploits for running processes** \(specially if running of versions\)
* [ ] Can you **modify the binary** of any running process?
* [ ] **Monitor processes** and check if any interesting process is running frequently
* [ ] Can you **read** some interesting **process memory** \(where passwords could be saved\)?

### [Scheduled/Cron jobs?](privilege-escalation/#scheduled-jobs)

* [ ] Is the [**PATH** ](privilege-escalation/#cron-path)being modified by some cron and you can **write** in it?
* [ ] Any [**wildcard** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)in a cron job?
* [ ] Some [**modifiable script** ](privilege-escalation/#cron-script-overwriting-and-symlink)is being **executed** or is inside **modifiable folder**?
* [ ] Have you detected that some **script** could be being [**executed** very **frequently**](privilege-escalation/#frequent-cron-jobs)? \(every 1, 2 or 5 minutes\)

### [Services](privilege-escalation/#services)

* [ ] Any **writable .service** file?
* [ ] Any **writable binary** executed by a **service**?
* [ ] Any **writable folder in systemd PATH**?

### [Timers](privilege-escalation/#timers)

* [ ] Any **writable timer**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Any **writable .socket** file?
* [ ] Can you **communicate with any socket**?
* [ ] **HTTP sockets** with interesting info?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Can you **communicate with any D-Bus**?

### [Network](privilege-escalation/#network)

* [ ] Enumerate the network to know where you are
* [ ] **Open ports you couldn't access before** getting a shell inside the machine?
* [ ] Can you **sniff traffic** using `tcpdump`?

### [Users](privilege-escalation/#users)

* [ ] Generic users/groups **enumeration**
* [ ] Do you have a **very big UID**? Is the **machine** **vulnerable**?
* [ ] Can you [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/) you belong to?
* [ ] **Clipboard** data?
* [ ] Password Policy?
* [ ] Try to **use** every **known password** that you have discovered previously to login **with each** possible **user**. Try to login also without password.

### [Writable PATH](privilege-escalation/#writable-path-abuses)

* [ ] If you have **write privileges over some folder in PATH** you may be able to escalate privileges

### [SUDO and SUID commands](privilege-escalation/#sudo-and-suid)

* [ ] Can you execute **any comand with sudo**? Can you use it to READ, WRITE or EXECUTE anything as root? \([**GTFOBins**](https://gtfobins.github.io/)\)
* [ ] Is any **exploitable suid binary**? \([**GTFOBins**](https://gtfobins.github.io/)\)
* [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] \*\*\*\*[**Sudo/SUID binary without path indicated**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] \*\*\*\*[**SUID binary specifying path**](privilege-escalation/#suid-binary-with-command-path)? Bypass
* [ ] \*\*\*\*[**LD\_PRELOAD vuln**](privilege-escalation/#ld_preload)\*\*\*\*
* [ ] \*\*\*\*[**Lack of .so library in SUID binary**](privilege-escalation/#suid-binary-so-injection) ****from a writable folder?
* [ ] \*\*\*\*[**SUDO tokens available**](privilege-escalation/#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Can you [**read or modify sudoers files**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Can you [**modify /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) ****command

### [Capabilities](privilege-escalation/#capabilities)

* [ ] Has any binary any **unexpected capability**?

### [ACLs](privilege-escalation/#acls)

* [ ] Has any file any **unexpected ACL**?

### [Open Shell sessions](privilege-escalation/#open-shell-sessions)

* [ ] **screen**?
* [ ] **tmux**?

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)\*\*\*\*
* [ ] \*\*\*\*[**SSH Interesting configuration values**](privilege-escalation/#ssh-interesting-configuration-values)\*\*\*\*

### [Interesting Files](privilege-escalation/#interesting-files)

* [ ] **Profile files** - Read sensitive data? Write to privesc?
* [ ] **passwd/shadow files** - Read sensitive data? Write to privesc?
* [ ] **Check commonly interesting folders** for sensitive data
* [ ] **Weird Localtion/Owned files,** you may have access or alter executable files
* [ ] **Modified** in last mins
* [ ] **Sqlite DB files**
* [ ] **Hidden files**
* [ ] **Script/Binaries in PATH**
* [ ] **Web files** \(passwords?\)
* [ ] **Backups**?
* [ ] **Known files that contains passwords**: Use **Linpeas** and **LaZagne**
* [ ] **Generic search**

### \*\*\*\*[**Writable Files**](privilege-escalation/#writable-files)\*\*\*\*

* [ ] **Modify python library** to execute arbitrary commands?
* [ ] Can you **modify log files**? **Logtotten** exploit
* [ ] Can you **modify /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
* [ ] Can you [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### \*\*\*\*[**Other tricks**](privilege-escalation/#other-tricks)\*\*\*\*

* [ ] Can you [**abuse NFS to escalate privileges**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Do you need to [**escape from a restrictive shell**](privilege-escalation/#escaping-from-restricted-shells)?

If you want to **know** about my **latest modifications**/**additions** or you have **any suggestion for HackTricks or PEASS**, ****join the [💬](https://emojipedia.org/speech-balloon/) ****[**PEASS & HackTricks telegram group here**](https://t.me/peass), or **follow me on Twitter** [🐦](https://emojipedia.org/bird/)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**  
If you want to **share some tricks with the community** you can also submit **pull requests** to ****[**https://github.com/carlospolop/hacktricks**](https://github.com/carlospolop/hacktricks) ****that will be reflected in this book.  
Don't forget to **give ⭐ on the github** to motivate me to continue developing this book.

![](../.gitbook/assets/68747470733a2f2f7777772e6275796d6561636f666665652e636f6d2f6173736574732f696d672f637573746f6d5f696d616765732f6f72616e67655f696d672e706e67%20%286%29%20%284%29%20%285%29.png)

​[**Buy me a coffee here**](https://www.buymeacoffee.com/carlospolop)\*\*\*\*

