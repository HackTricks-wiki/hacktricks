# Orodha ya Ukaguzi wa Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Orodha ya Ukaguzi - Linux Privilege Escalation



### **Tool bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pata **taarifa za OS**
- [ ] Kagua [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), kuna **folda inayoweza kuandikwa**?
- [ ] Kagua [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), kuna maelezo nyeti?
- [ ] Tafuta [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **kwa kutumia scripts** (DirtyCow?)
- [ ] **Kagua** ikiwa [**sudo version** inaweza kudhurika](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Uthibitishaji wa saini wa Dmesg** umeshindwa](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Kagua [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement na `modules_disabled`.
- [ ] Kagua [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ikiwa helper path inaweza kurekebishwa au ku-triggeriwa.
- [ ] Kagua [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), ikijumuisha faili za `.ko*` zinazoweza kuandikwa na metadata ya `modules.*`.
- [ ] System enum zaidi ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate defenses zaidi](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizomountiwa
- [ ] **Kuna drive ambayo haijamountiwa?**
- [ ] **Kuna creds katika fstab?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kagua kama kuna**[ **useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **iliyosakinishwa**
- [ ] **Kagua kama kuna** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **iliyosakinishwa**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Kuna **unknown software inayoendesha**?
- [ ] Kuna software yoyote inayoendesha ikiwa na **privileges zaidi kuliko inavyopaswa kuwa**?
- [ ] Tafuta **exploits za processes zinazoendesha** (hasa version inayoendesha).
- [ ] Je, unaweza **kurekebisha binary** ya process yoyote inayoendesha?
- [ ] **Monitor processes** na ukague ikiwa process yoyote ya kuvutia inaendeshwa mara kwa mara.
- [ ] Je, unaweza **kusoma** baadhi ya **process memory** ya kuvutia (ambapo passwords zinaweza kuwa zimehifadhiwa)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)inarekebishwa na cron fulani na unaweza **kuandika** ndani yake?
- [ ] Kuna [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)katika cron job?
- [ ] Kuna [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)inayokuwa **executed** au iko ndani ya **modifiable folder**?
- [ ] Umegundua kwamba **script** fulani inaweza au inaendelea kuwa [**executed** mara **kwa mara**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Kuna faili ya **.service inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** inayotekelezwa na **service**?
- [ ] Kuna **folda inayoweza kuandikwa katika systemd PATH**?
- [ ] Kuna **systemd unit drop-in inayoweza kuandikwa** katika `/etc/systemd/system/<unit>.d/*.conf` ambayo inaweza ku-override `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Kuna faili ya **.socket inayoweza kuandikwa**?
- [ ] Je, unaweza **kuwasiliana na socket yoyote**?
- [ ] **HTTP sockets** zenye taarifa za kuvutia?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Je, unaweza **kuwasiliana na D-Bus yoyote**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Fanya network enumeration ili kujua ulipo
- [ ] **Open ports ambazo hukuweza kufikia hapo awali** baada ya kupata shell ndani ya machine?
- [ ] Je, unaweza **kusniff traffic** ukitumia `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeration** ya jumla ya users/groups
- [ ] Una **UID kubwa sana**? Je, **machine** iko **vulnerable**?
- [ ] Je, unaweza [**ku-escalate privileges kupitia group**](../user-information/interesting-groups-linux-pe/index.html) ambalo wewe ni mwanachama wake?
- [ ] Data ya **Clipboard**?
- [ ] Password Policy?
- [ ] Jaribu **kutumia** kila **password inayojulikana** ambayo umeigundua awali ili ku-login **kwa kila** **user** anayewezekana. Jaribu pia ku-login bila password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **write privileges kwenye folda fulani iliyo katika PATH**, unaweza kuweza ku-escalate privileges

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Je, unaweza ku-execute **command yoyote kwa sudo**? Unaweza kuitumia kusoma, kuandika au ku-execute chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ikiwa `sudo -l` inaruhusu `sudoedit`, kagua **sudoedit argument injection** (CVE-2023-22809) kupitia `SUDO_EDITOR`/`VISUAL`/`EDITOR` ili ku-edit faili arbitrary kwenye versions vulnerable (`sudo -V` < 1.9.12p2). Mfano: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Kuna **SUID binary inayoweza ku-exploitwa**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, [**sudo** commands **zimewekewa mipaka** na **path**? unaweza **kuzibypass restrictions**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bila path iliyoonyeshwa**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary inayobainisha path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ukosefu wa .so library katika SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) kutoka kwenye folda inayoweza kuandikwa?
- [ ] [**SUID RPATH/RUNPATH au library path inayoweza kuandikwa**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens zinapatikana**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Unaweza kuunda SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Je, unaweza [**kusoma au kurekebisha sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Je, unaweza [**kurekebisha /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Command ya [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Je, binary yoyote ina **capability isiyotarajiwa**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Je, faili yoyote ina **ACL isiyotarajiwa**?

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Soma data nyeti? Andika ili ku-privesc?
- [ ] **passwd/shadow files** - Soma data nyeti? Andika ili ku-privesc?
- [ ] **Kagua folda zinazojulikana kuwa za kuvutia** kwa data nyeti
- [ ] **Faili zilizo katika Location/Owned isiyo ya kawaida,** unaweza kuwa na access au kubadilisha executable files
- [ ] **Zilizorekebishwa** ndani ya dakika za mwisho
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries katika PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Faili zinazojulikana kuwa na passwords**: Tumia **Linpeas** na **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Rekebisha python library** ili ku-execute arbitrary commands?
- [ ] Je, unaweza **kurekebisha log files**? **Logtotten** exploit
- [ ] Je, unaweza **kurekebisha /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Je, unaweza [**kuandika katika ini, int.d, systemd au rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Je, unaweza [**kutumia vibaya NFS ili ku-escalate privileges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Je, unahitaji [**ku-escape kutoka restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?

## Marejeo

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
