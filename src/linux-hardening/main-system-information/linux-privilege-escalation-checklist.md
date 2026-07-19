# Orodha ya ukaguzi - Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Tool bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pata **taarifa za OS**
- [ ] Kagua [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), kuna **folder inayoweza kuandikwa**?
- [ ] Kagua [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), kuna taarifa nyeti?
- [ ] Tafuta [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **kwa kutumia scripts** (DirtyCow?)
- [ ] **Kagua** kama [**sudo version** ina vulnerability](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Kagua [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement na `modules_disabled`.
- [ ] Kagua [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) iwapo helper path inaweza kubadilishwa au ku-triggeriwa.
- [ ] Kagua [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), ikijumuisha files za `.ko*` zinazoweza kuandikwa na metadata za `modules.*`.
- [ ] Fanya system enum zaidi ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate defenses zaidi](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizomountiwa
- [ ] **Kuna drive yoyote ambayo haijamountiwa?**
- [ ] **Kuna creds zozote kwenye fstab?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kagua kama** [ **useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **imewekwa**
- [ ] **Kagua kama** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **imewekwa**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Kuna **unknown software inay运行**?
- [ ] Kuna software inay运行 ikiwa na **privileges zaidi kuliko inavyopaswa**?
- [ ] Tafuta **exploits za processes zinazo运行** (hasa version inay运行).
- [ ] Unaweza **kubadilisha binary** ya process yoyote inayo运行?
- [ ] **Monitor processes** na uangalie kama process yoyote ya kuvutia ina运行 mara kwa mara.
- [ ] Unaweza **kusoma** **process memory** ya kuvutia (ambapo passwords zinaweza kuwa zimehifadhiwa)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
- [ ] Kuna [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)kwenye cron job?
- [ ] Kuna [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)inayo **executiwa** au iliyopo ndani ya **modifiable folder**?
- [ ] Umegundua kuwa **script** fulani inaweza au ina [**executiwa** mara **kwa mara**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Kuna file ya **.service inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** na ambayo **service** ina-execute?
- [ ] Kuna **folder inayoweza kuandikwa kwenye systemd PATH**?
- [ ] Kuna **systemd unit drop-in inayoweza kuandikwa** ndani ya `/etc/systemd/system/<unit>.d/*.conf` inayoweza ku-override `ExecStart`/`User`?

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Kuna file ya **.socket inayoweza kuandikwa**?
- [ ] Unaweza **kuwasiliana na socket** yoyote?
- [ ] Kuna **HTTP sockets** zenye taarifa za kuvutia?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Unaweza **kuwasiliana na D-Bus** yoyote?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Fanya network enumeration ili kujua ulipo
- [ ] Kuna **ports zilizofunguliwa ambazo hukuweza kuzifikia kabla** ya kupata shell ndani ya machine?
- [ ] Unaweza **kusniff traffic** kwa kutumia `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Fanya **enumeration** ya users/groups kwa ujumla
- [ ] Una **UID kubwa sana**? Je, **machine** ina **vulnerability**?
- [ ] Unaweza [**kuescalate privileges kwa sababu ya group**](../user-information/interesting-groups-linux-pe/index.html) ambalo wewe ni mwanachama wake?
- [ ] Kuna data ya **Clipboard**?
- [ ] Password Policy?
- [ ] Jaribu **kutumia** kila **password inayojulikana** ambayo uligundua awali ku-login **kwa kila** **user** anayewezekana. Jaribu pia ku-login bila password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **write privileges kwenye folder fulani iliyo ndani ya PATH**, unaweza kuweza kuescalate privileges

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Unaweza ku-execute **command yoyote kwa sudo**? Unaweza kuitumia READ, WRITE au EXECUTE chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ikiwa `sudo -l` inaruhusu `sudoedit`, kagua **sudoedit argument injection** (CVE-2023-22809) kupitia `SUDO_EDITOR`/`VISUAL`/`EDITOR` ili ku-edit files kiholela kwenye versions zilizo na vulnerability (`sudo -V` < 1.9.12p2). Mfano: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Kuna **SUID binary inayoweza ku-exploitika**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, commands za [**sudo** zinawekewa **mipaka** na **path**? unaweza **kuzipita restrictions**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bila path iliyoonyeshwa**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary inayobainisha path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Pita restriction
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ukosefu wa .so library kwenye SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) kutoka kwenye folder inayoweza kuandikwa?
- [ ] [**SUID RPATH/RUNPATH au library path inayoweza kuandikwa**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens zinapatikana**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Unaweza kuunda SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Unaweza [**kusoma au kubadilisha sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Unaweza [**kubadilisha /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Command ya [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Je, binary yoyote ina **capability isiyotarajiwa**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Je, file yoyote ina **ACL isiyotarajiwa**?

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Soma data nyeti? Andika ili kufanya privesc?
- [ ] **passwd/shadow files** - Soma data nyeti? Andika ili kufanya privesc?
- [ ] **Kagua folders zinazovutia kwa kawaida** kwa data nyeti
- [ ] **Files zenye location/umiliki usio wa kawaida,** huenda ukaweza kufikia au kubadilisha executable files
- [ ] **Zilizobadilishwa** ndani ya dakika za mwisho
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries kwenye PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Files zinazojulikana kuwa na passwords**: Tumia **Linpeas** na **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Badilisha python library** ili ku-execute commands kiholela?
- [ ] Unaweza **kubadilisha log files**? **Logtotten** exploit
- [ ] Unaweza **kubadilisha /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Unaweza [**kuandika kwenye ini, int.d, systemd au rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Unaweza [**kutumia vibaya NFS ili kuescalate privileges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Je, unahitaji [**kutoka kwenye restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Marejeo

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
