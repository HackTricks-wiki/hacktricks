# Orodha ya ukaguzi ya Linux Privilege Escalation

# Orodha ya ukaguzi - Linux Privilege Escalation



### **Tool bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Maelezo ya Mfumo](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pata **maelezo ya OS**
- [ ] Kagua [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), kuna **folder inayoweza kuandikwa**?
- [ ] Kagua [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), kuna taarifa nyeti?
- [ ] Tafuta [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **kwa kutumia scripts** (DirtyCow?)
- [ ] Kabla ya kuendesha kernel PoC, hakikisha **prerequisites zake halisi**, si `uname -r` pekee: architecture, options/modules za lazima za `CONFIG_*`, uundaji wa namespace na mitigations zinazotumika. Kwa mfano, jaribu upatikanaji wa user/network namespace kwa `unshare -Urn true`; netfilter exploits za kisasa zinaweza kuhitaji `CONFIG_USER_NS`, unprivileged user namespaces na `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Kagua** kama [**sudo version** ina vulnerability](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [Uthibitishaji wa signature wa **Dmesg** umeshindikana](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Kagua [**kernel module na module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement na `modules_disabled`.
- [ ] Kagua [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ikiwa helper path inaweza kubadilishwa au ku-triggeriwa.
- [ ] Kagua [**paths za /lib/modules zinazoweza kuandikwa**](kernel-modules-and-modprobe.md#writable-libmodules-review), zikiwemo files za `.ko*` zinazoweza kuandikwa na metadata ya `modules.*`.
- [ ] System enum zaidi ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate defenses zaidi](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizomountiwa
- [ ] **Kuna drive ambayo haijamountiwa?**
- [ ] **Kuna creds kwenye fstab?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kagua kama** [ **useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **imewekwa**
- [ ] **Kagua kama** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **imewekwa**
- [ ] Kwenye Debian/Ubuntu, kagua ikiwa **needrestart interpreter scanning** imewekwa/imewezeshwa: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Builds zilizo na vulnerability zilivuka privilege boundary kwa kutumia tena `PYTHONPATH`/`RUBYLIB` zinazodhibitiwa na attacker, kufanya race ya `/proc/<pid>/exe`, au kuscan Perl paths zinazodhibitiwa na attacker wakati APT au `unattended-upgrades` iliita needrestart kama root.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Kuna **unknown software inayotumika**?
- [ ] Kuna software inayotumika ikiwa na **privileges zaidi kuliko inavyopaswa kuwa**?
- [ ] Tafuta **exploits za processes zinazoendelea** (hasa version inayotumika).
- [ ] Unaweza **kubadilisha binary** ya process yoyote inayoendelea?
- [ ] **Monitor processes** na kagua kama process yoyote ya kuvutia inatumika mara kwa mara.
- [ ] Unaweza **kusoma** baadhi ya **process memory** yenye kuvutia (ambapo passwords zinaweza kuwa zimehifadhiwa)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
- [ ] Kuna [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)kwenye cron job?
- [ ] Kuna [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)inayokuwa **executed** au iliyo ndani ya **folder inayoweza kubadilishwa**?
- [ ] Umegundua kuwa **script** fulani inaweza kuwa au inaendelea [**executed** mara **kwa mara sana**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Kuna file yoyote ya **.service inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** ambayo inaendeshwa na **service**?
- [ ] Kuna **helper, config au environment file inayoweza kuandikwa** inayorejelewa na root unit (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Kagua merged unit kwa `systemctl cat <unit>` na pitia [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Kuna **folder inayoweza kuandikwa kwenye systemd PATH**?
- [ ] Kuna **systemd unit drop-in inayoweza kuandikwa** ndani ya `/etc/systemd/system/<unit>.d/*.conf` inayoweza kubadilisha `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Kuna file yoyote ya **.socket inayoweza kuandikwa**?
- [ ] Unaweza **kuwasiliana na socket yoyote**?
- [ ] Kuna **HTTP sockets** zenye taarifa ya kuvutia?
- [ ] Unaweza kufikia [**container-runtime au node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) kama `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` au kubelet endpoint? Test raw HTTP/gRPC API hata kama CLI yake ya kawaida haipo.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Unaweza **kuwasiliana na D-Bus yoyote**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerate network ili kujua ulipo
- [ ] **Ports zilizofunguliwa ambazo hukuweza kufikia hapo awali** baada ya kupata shell ndani ya machine?
- [ ] Unaweza **kunusa traffic** kwa kutumia `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeration** ya users/groups kwa ujumla
- [ ] Una **UID kubwa sana**? Je, **machine** iko **vulnerable**?
- [ ] Unaweza [**ku-escalate privileges kupitia group**](../user-information/interesting-groups-linux-pe/index.html) ambayo wewe ni mwanachama wake?
- [ ] Data ya **Clipboard**?
- [ ] Password Policy?
- [ ] Jaribu **kutumia** kila **password inayojulikana** ambayo uligundua awali ku-login **kwa kila** **user** anayewezekana. Jaribu pia ku-login bila password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **write privileges kwenye folder fulani iliyo kwenye PATH**, huenda ukaweza ku-escalate privileges

### [SUDO na SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Unaweza ku-execute **command yoyote kwa sudo**? Unaweza kuitumia KUSOMA, KUANDIKA au KU-EXECUTE kitu chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ikiwa `sudo -l` inaruhusu `sudoedit`, kagua **sudoedit argument injection** (CVE-2023-22809) kupitia `SUDO_EDITOR`/`VISUAL`/`EDITOR` ili ku-edit files kiholela kwenye versions zilizo vulnerable (`sudo -V` < 1.9.12p2). Mfano: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Kuna **SUID binary inayoweza ku-exploitiwa**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, commands za [**sudo** zinawekewa mipaka](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) kwa **path**? unaweza **kupita** restrictions?
- [ ] [**Sudo/SUID binary bila path iliyoonyeshwa**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary inayotaja path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
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

- [ ] **Profile files** - Soma data nyeti? Andika kwa privesc?
- [ ] **passwd/shadow files** - Soma data nyeti? Andika kwa privesc?
- [ ] **Kagua folders zinazovutia kwa kawaida** kwa data nyeti
- [ ] **Files zenye location/ownership isiyo ya kawaida,** huenda ukawa na access ya ku-fikia au kubadilisha executable files
- [ ] **Zilizobadilishwa** ndani ya dakika za mwisho
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries kwenye PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Files zinazojulikana kuwa na passwords**: Tumia **Linpeas** na **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Badilisha python library** ili ku-execute arbitrary commands?
- [ ] Unaweza **kubadilisha log files**? **Logtotten** exploit
- [ ] Unaweza **kubadilisha /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Unaweza [**kuandika kwenye ini, int.d, systemd au rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Unaweza [**kutumia vibaya NFS ili ku-escalate privileges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Je, unahitaji [**kutoka kwenye restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Ushauri wa Sudo: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Nyaraka za Oracle Linux: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: Mahitaji ya CVE-2024-1086 exploit na utafiti](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Ushauri wa Usalama wa Qualys: LPEs kwenye needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
