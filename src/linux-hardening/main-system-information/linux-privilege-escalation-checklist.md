# Orodha ya Ukaguzi wa Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Orodha ya Ukaguzi - Linux Privilege Escalation



### **Tool bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pata **taarifa za OS**
- [ ] Kagua [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), kuna **folda inayoweza kuandikwa**?
- [ ] Kagua [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), kuna maelezo nyeti?
- [ ] Tafuta [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **kwa kutumia scripts** (DirtyCow?)
- [ ] Kabla ya kuendesha kernel PoC, thibitisha **masharti yake halisi**, si `uname -r` pekee: architecture, `CONFIG_*` options/modules zinazohitajika, uundaji wa namespace na mitigations zilizo active. Kwa mfano, jaribu upatikanaji wa user/network namespace kwa `unshare -Urn true`; netfilter exploits za kisasa zinaweza kuhitaji `CONFIG_USER_NS`, unprivileged user namespaces na `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Kagua** ikiwa [**sudo version** ina vulnerability](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification ilishindwa](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Kagua [**kernel module na module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement na `modules_disabled`.
- [ ] Kagua [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ikiwa helper path inaweza kurekebishwa au ku-triggeriwa.
- [ ] Kagua [**paths za /lib/modules zinazoweza kuandikwa**](kernel-modules-and-modprobe.md#writable-libmodules-review), zikiwemo files za `.ko*` zinazoweza kuandikwa na metadata ya `modules.*`.
- [ ] System enum zaidi ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate defenses zaidi](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizomountiwa
- [ ] **Kuna drive yoyote ambayo haijamountiwa?**
- [ ] **Kuna creds kwenye fstab?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kagua kama**[ **useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **imewekwa**
- [ ] **Kagua kama** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **imewekwa**
- [ ] Kwenye Debian/Ubuntu, kagua ikiwa **needrestart interpreter scanning** imewekwa/enabled: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Builds zenye vulnerability zilivuka privilege boundary kwa kutumia tena `PYTHONPATH`/`RUBYLIB` inayodhibitiwa na attacker, kushindana kwenye `/proc/<pid>/exe`, au kuscan Perl paths zinazodhibitiwa na attacker wakati APT au `unattended-upgrades` iliita needrestart kama root.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Kuna **unknown software inayoendesha**?
- [ ] Kuna software yoyote inayoendesha ikiwa na **privileges zaidi kuliko inavyopaswa kuwa**?
- [ ] Tafuta **exploits za processes zinazoendesha** (hasa version inayoendesha).
- [ ] Unaweza **kurekebisha binary** ya process yoyote inayoendesha?
- [ ] **Monitor processes** na kagua ikiwa process yoyote ya kuvutia inaendesha mara kwa mara.
- [ ] Unaweza **kusoma** baadhi ya **process memory** ya kuvutia (ambapo passwords zinaweza kuwa zimehifadhiwa)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
- [ ] Kuna [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)kwenye cron job?
- [ ] Kuna [**script inayoweza kurekebishwa** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)inayokuwa **executed** au iko ndani ya **folda inayoweza kurekebishwa**?
- [ ] Umegundua kuwa **script** fulani inaweza kuwa au inaendelea [**ku-execute** mara **kwa mara sana**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Kuna **.service file inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** inayotekelezwa na **service**?
- [ ] Kuna **helper, config au environment file inayoweza kuandikwa inayorejelewa na root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Kagua merged unit kwa `systemctl cat <unit>` na pitia [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Kuna **folder inayoweza kuandikwa kwenye systemd PATH**?
- [ ] Kuna **systemd unit drop-in inayoweza kuandikwa** kwenye `/etc/systemd/system/<unit>.d/*.conf` inayoweza ku-override `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Kuna **.socket file inayoweza kuandikwa**?
- [ ] Unaweza **kuwasiliana na socket yoyote**?
- [ ] Kuna **HTTP sockets** zenye taarifa za kuvutia?
- [ ] Unaweza kufikia [**container-runtime au node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) kama `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` au kubelet endpoint? Test raw HTTP/gRPC API hata kama CLI yake ya kawaida haipo.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Unaweza **kuwasiliana na D-Bus yoyote**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Fanya network enumeration ili kujua ulipo
- [ ] Kuna **ports zilizo wazi ambazo hukuweza kuzifikia kabla** ya kupata shell ndani ya mashine?
- [ ] Unaweza **kusniff traffic** kwa kutumia `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeration** ya generic users/groups
- [ ] Una **UID kubwa sana**? Je, **machine** ina **vulnerability**?
- [ ] Unaweza [**ku-escalate privileges kwa sababu ya group**](../user-information/interesting-groups-linux-pe/index.html) ambayo wewe ni mwanachama wake?
- [ ] Data ya **Clipboard**?
- [ ] Password Policy?
- [ ] Jaribu **kutumia** kila **password inayojulikana** ambayo umeigundua awali ku-login **kwa kila** **user** anayewezekana. Pia jaribu ku-login bila password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **write privileges kwenye folder fulani iliyo ndani ya PATH**, unaweza kuweza ku-escalate privileges

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Unaweza ku-execute **command yoyote kwa sudo**? Unaweza kuitumia kusoma, kuandika au ku-execute chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ikiwa `sudo -l` inaruhusu `sudoedit`, kagua **sudoedit argument injection** (CVE-2023-22809) kupitia `SUDO_EDITOR`/`VISUAL`/`EDITOR` ili ku-edit files arbitrary kwenye versions zenye vulnerability (`sudo -V` < 1.9.12p2). Mfano: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Kuna **SUID binary inayoweza ku-exploitwa**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, commands za [**sudo** zinawekewa **mipaka** na **path**? Unaweza **kuzipita restrictions**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bila path iliyoonyeshwa**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary inayobainisha path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ukosefu wa .so library kwenye SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) kutoka kwenye folder inayoweza kuandikwa?
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

- [ ] **Profile files** - Soma data nyeti? Andika ili kufanya privesc?
- [ ] **passwd/shadow files** - Soma data nyeti? Andika ili kufanya privesc?
- [ ] **Kagua folda zinazovutia kwa kawaida** kwa data nyeti
- [ ] **Files zilizo kwenye Location/Owned isiyo ya kawaida,** ambazo unaweza kuzifikia au kurekebisha executable files
- [ ] **Zilizorekebishwa** ndani ya dakika za mwisho
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Scripts/Binaries kwenye PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Files zinazojulikana zilizo na passwords**: Tumia **Linpeas** na **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Rekebisha python library** ili ku-execute commands arbitrary?
- [ ] Unaweza **kurekebisha log files**? **Logtotten** exploit
- [ ] Unaweza **kurekebisha /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Unaweza [**kuandika kwenye ini, int.d, systemd au rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Unaweza [**kutumia NFS vibaya ili ku-escalate privileges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Unahitaji [**kutoka kwenye restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Ushauri wa Sudo: sudoedit ku-edit file yoyote](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Nyaraka za Oracle Linux: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: Mahitaji na utafiti wa CVE-2024-1086 exploit](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Ushauri wa Usalama wa Qualys: LPEs kwenye needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
