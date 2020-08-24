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

### [Any sudo command?](privilege-escalation/#commands-with-sudo-and-suid-commands)

* [ ] Can you execute **any comand with sudo**? Can you use it to READ, WRITE or EXECUTE anything as root?
* [ ] Is some **wildcard used**?
* [ ] Is the binary specified **without path**?
* [ ] Is _**env\_keep+=LD\_PRELOAD**_?

### [Any weird suid command?](privilege-escalation/#commands-with-sudo-and-suid-commands)

* [ ] **SUID** any **interesting command**? Can you use it to READ, WRITE or EXECUTE anything as root?
* [ ] Is some **wildcard used**?
* [ ] Is the SUID binary **executing some other binary without specifying the path**? or specifying it?
* [ ] Is it trying to **load .so from writable folders**?

### [Weird capabilities?](privilege-escalation/#capabilities)

* [ ] Has any binary any **uncommon capability**?

### [Open Shell sessions?](privilege-escalation/#open-shell-sessions)

* [ ] screen?
* [ ] tmux?

### [Can you read some sensitive data?](privilege-escalation/#read-sensitive-data)

* [ ] Can you **read** some **interesting files**? \(files with passwords, \*\_history, backups...\)

### [Can you write important files?](privilege-escalation/#writable-files)

* [ ] Are you able to **write files that could grant you more privileges**? \(service conf files, shadow,a script that is executed by other users, libraries...\)

### [Internal open ports?](privilege-escalation/#internal-open-ports)

* [ ] You should check if any undiscovered service is running in some port/interface. Maybe it is running with more privileges that it should or it is vulnerable to some kind of privilege escalation vulnerability.

### [Can you sniff some passwords in the network?](privilege-escalation/#sniffing)

* [ ] Can you **sniff** and get **passwords** from the **network**?

### [Any service missconfigurated? NFS? belongs to docker or lxd?](privilege-escalation/#privesc-exploiting-service-misconfigurations)

1. [ ] Any well known missconfiguration? \([**NFS no\_root\_squash**](privilege-escalation/nfs-no_root_squash-misconfiguration-pe.md)\)

### [Any weird executable in path?](privilege-escalation/#check-for-weird-executables)



If you want to **know** about my **latest modifications**/**additions or you have any suggestion for HackTricks or PEASS**, **join the** [**PEASS & HackTricks telegram group here**](https://t.me/peass)**.**  
If you want to **share some tricks with the community** you can also submit **pull requests** to ****[**https://github.com/carlospolop/hacktricks**](https://github.com/carlospolop/hacktricks) ****that will be reflected in this book.  
Don't forget to **give ⭐ on the github** to motivate me to continue developing this book.

![](../.gitbook/assets/68747470733a2f2f7777772e6275796d6561636f666665652e636f6d2f6173736574732f696d672f637573746f6d5f696d616765732f6f72616e67655f696d672e706e67%20%284%29.png)

​[**Buy me a coffee here**](https://www.buymeacoffee.com/carlospolop)\*\*\*\*

