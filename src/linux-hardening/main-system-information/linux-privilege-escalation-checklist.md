# Orodha ya Ukaguzi wa Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Orodha ya Ukaguzi - Linux Privilege Escalation



### **Tool bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Taarifa za Mfumo](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pata **taarifa za OS**
- [ ] Kagua [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), kuna **folda inayoweza kuandikwa**?
- [ ] Kagua [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), kuna maelezo nyeti?
- [ ] Tafuta [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **kwa kutumia scripts** (DirtyCow?)
- [ ] **Kagua** ikiwa [**sudo version** ina vulnerability](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Uthibitishaji wa signature wa Dmesg** umeshindikana](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Kagua [**kernel module na module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement na `modules_disabled`.
- [ ] Kagua [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ikiwa helper path inaweza kurekebishwa au ku-trigger.
- [ ] Kagua [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), pamoja na files za `.ko*` zinazoweza kuandikwa na metadata ya `modules.*`.
- [ ] System enum zaidi ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate defenses zaidi](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizomountiwa
- [ ] **Kuna drive yoyote ambayo haijamountiwa?**
- [ ] **Kuna creds zozote katika fstab?**

### [**Software Iliyosakinishwa**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kagua kama kuna**[ **software muhimu**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **iliyosakinishwa**
- [ ] **Kagua kama kuna** [**software yenye vulnerability**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **iliyosakinishwa**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Kuna **software isiyojulikana inayo-run**?
- [ ] Kuna software yoyote inayo-run ikiwa na **privileges zaidi kuliko inavyopaswa kuwa nazo**?
- [ ] Tafuta **exploits za processes zinazo-run** (hasa version inayotumika).
- [ ] Unaweza **kurekebisha binary** ya process yoyote inayo-run?
- [ ] **Monitor processes** na kagua ikiwa process yoyote ya kuvutia ina-run mara kwa mara.
- [ ] Unaweza **kusoma** baadhi ya **process memory** inayovutia (ambapo passwords zinaweza kuwa zimehifadhiwa)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
- [ ] Kuna [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)katika cron job?
- [ ] Kuna [**script inayoweza kurekebishwa** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)inayokuwa **executed** au iko ndani ya **folda inayoweza kurekebishwa**?
- [ ] Umegundua kuwa **script** fulani inaweza au inaendelea kuwa [**executed** mara **nyingi**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Kuna file yoyote ya **.service inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** inayotekelezwa na **service**?
- [ ] Kuna **folda inayoweza kuandikwa katika systemd PATH**?
- [ ] Kuna **systemd unit drop-in inayoweza kuandikwa** katika `/etc/systemd/system/<unit>.d/*.conf` ambayo inaweza ku-override `ExecStart`/`User`?

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Kuna file yoyote ya **.socket inayoweza kuandikwa**?
- [ ] Unaweza **kuwasiliana na socket yoyote**?
- [ ] Kuna **HTTP sockets** zenye taarifa za kuvutia?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Unaweza **kuwasiliana na D-Bus yoyote**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerate network ili kujua ulipo
- [ ] **Ports zilizofunguliwa ambazo hukuweza kuzifikia** kabla ya kupata shell ndani ya machine?
- [ ] Unaweza **kusniff traffic** kwa kutumia `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeration** ya jumla ya users/groups
- [ ] Una **UID kubwa sana**? Je, **machine** ina **vulnerability**?
- [ ] Unaweza [**ku-escalate privileges kwa sababu ya group**](../user-information/interesting-groups-linux-pe/index.html) ambalo wewe ni mwanachama wake?
- [ ] Data ya **Clipboard**?
- [ ] Password Policy?
- [ ] Jaribu **kutumia** kila **password inayojulikana** ambayo uligundua awali ku-login **kwa kila** **user** anayewezekana. Jaribu pia ku-login bila password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **write privileges kwenye folda fulani iliyo ndani ya PATH**, unaweza kuweza ku-escalate privileges

### [SUDO na SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Unaweza ku-execute **command yoyote kwa sudo**? Unaweza kuitumia READ, WRITE au EXECUTE kitu chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ikiwa `sudo -l` inaruhusu `sudoedit`, kagua **sudoedit argument injection** (CVE-2023-22809) kupitia `SUDO_EDITOR`/`VISUAL`/`EDITOR` ili ku-edit files kiholela kwenye versions zilizo na vulnerability (`sudo -V` < 1.9.12p2). Mfano: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Kuna **SUID binary inayoweza ku-exploitwa**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, commands za [**sudo** zimewekewa kikomo](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) kwa **path**? unaweza **kupita** restrictions hizo?
- [ ] [**Sudo/SUID binary bila path iliyoonyeshwa**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary inayobainisha path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ukosefu wa .so library katika SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) kutoka kwenye folda inayoweza kuandikwa?
- [ ] [**SUID RPATH/RUNPATH au library path inayoweza kuandikwa**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens zinapatikana**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Unaweza kuunda SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Unaweza [**kusoma au kurekebisha sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Unaweza [**kurekebisha /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Command ya [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Kuna binary yoyote yenye **capability isiyotarajiwa**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Kuna file yoyote yenye **ACL isiyotarajiwa**?

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Soma data nyeti? Andika ili ku-privesc?
- [ ] **passwd/shadow files** - Soma data nyeti? Andika ili ku-privesc?
- [ ] **Kagua folda zinazovutia kwa kawaida** kwa data nyeti
- [ ] **Files zilizo katika location/owned isiyo ya kawaida,** huenda ukaweza kufikia au kurekebisha executable files
- [ ] **Zilizorekebishwa** katika dakika za hivi karibuni
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries katika PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Files zinazojulikana kuwa na passwords**: Tumia **Linpeas** na **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Rekebisha python library** ili ku-execute commands kiholela?
- [ ] Unaweza **kurekebisha log files**? **Logtotten** exploit
- [ ] Unaweza **kurekebisha /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Unaweza [**kuandika katika ini, int.d, systemd au rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Unaweza [**kutumia vibaya NFS ku-escalate privileges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Je, unahitaji [**kutoka kwenye restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Marejeo

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
