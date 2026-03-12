# Kontrolna lista - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za traženje Linux local privilege escalation vektora:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Nabavite **OS informacije**
- [ ] Proverite [**PATH**](privilege-escalation/index.html#path), postoji li neki **direktorijum u koji se može pisati**?
- [ ] Proverite [**env variables**](privilege-escalation/index.html#env-info), ima li osetljivih detalja?
- [ ] Pretražite za [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **koristeći skripte** (DirtyCow?)
- [ ] **Proverite** da li je [**sudo version is vulnerable**](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Dodatna sistemska enumeracija ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Navedite montirane** diskove
- [ ] Postoji li **nemontirani disk**?
- [ ] **Ima li kredencijala u fstab?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Proverite** da li je instaliran [**useful software**](privilege-escalation/index.html#useful-software)
- [ ] **Proverite** da li je instaliran [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed)

### [Processes](privilege-escalation/index.html#processes)

- [ ] Da li se pokreće neki **nepoznat softver**?
- [ ] Da li neki softver radi sa **većim privilegijama nego što bi trebalo**?
- [ ] Pretražite **exploits of running processes** (posebno verziju koja se pokreće).
- [ ] Možete li **izmeniti binarni fajl** bilo kog pokrenutog procesa?
- [ ] **Pratite procese** i proverite da li se neki interesantan proces često pokreće.
- [ ] Možete li **pročitati** neku interesantnu **memoriju procesa** (gde bi lozinke mogle biti sačuvane)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li [**PATH**](privilege-escalation/index.html#cron-path) menja neki cron i možete li u njega **pisati**?
- [ ] Ima li [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) u cron zadatku?
- [ ] Da li se neki [**modifiable script**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) izvršava ili se nalazi u **direktorijumu koji se može menjati**?
- [ ] Da li ste primetili da se neki **script** može ili se [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs)? (svakih 1, 2 ili 5 minuta)

### [Services](privilege-escalation/index.html#services)

- [ ] Postoji li neki **writable .service** fajl?
- [ ] Postoji li neki **writable binary** koji izvršava **service**?
- [ ] Postoji li **writable folder u systemd PATH**?
- [ ] Postoji li **writable systemd unit drop-in** u `/etc/systemd/system/<unit>.d/*.conf` koji može prebrisati `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Postoji li neki **writable timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Postoji li neki **writable .socket** fajl?
- [ ] Možete li **komunicirati sa bilo kojim socketom**?
- [ ] Postoje li **HTTP sockets** sa interesantnim informacijama?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Možete li **komunicirati sa bilo kojim D-Busom**?

### [Network](privilege-escalation/index.html#network)

- [ ] Izvršite enumeraciju mreže da biste znali gde se nalazite
- [ ] Ima li **otvorenih portova kojima ranije niste mogli pristupiti** otkako imate shell na mašini?
- [ ] Možete li **presretati saobraćaj** koristeći `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Generička enumeracija korisnika/grupa
- [ ] Imate li **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Možete li [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html) kojem pripadate?
- [ ] **Clipboard** podaci?
- [ ] Politika lozinki?
- [ ] Pokušajte **koristiti** svaku **poznatu lozinku** koju ste prethodno otkrili da biste se prijavili **sa svakim** mogućim **korisnikom**. Pokušajte se prijaviti i bez lozinke.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imate **privilegije upisa nad nekim folderom u PATH** možda možete eskalirati privilegije

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Možete li izvršiti **bilo koju komandu sa sudo**? Možete li ga iskoristiti da čitate, pišete ili izvršavate bilo šta kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ako `sudo -l` dozvoljava `sudoedit`, proverite za **sudoedit argument injection** (CVE-2023-22809) preko `SUDO_EDITOR`/`VISUAL`/`EDITOR` da biste menjali proizvoljne fajlove na ranjivim verzijama (`sudo -V` < 1.9.12p2). Primer: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Postoji li neki **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) from a writable folder?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Možete li [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Možete li [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Ima li neki binarni fajl neku **neočekivanu capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Ima li neki fajl neku **neočekivanu ACL**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Pročitati osetljive podatke? Upisati za privesc?
- [ ] **passwd/shadow files** - Pročitati osetljive podatke? Upisati za privesc?
- [ ] **Check commonly interesting folders** for sensitive data
- [ ] **Weird Location/Owned files,** možda imate pristup ili možete izmeniti izvršne fajlove
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
- [ ] Možete li **izmeniti log fajlove**? **Logtotten** exploit
- [ ] Možete li **izmeniti /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Možete li [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Možete li [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Treba li vam da [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
