# Orodha Hakiki ya Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Orodha Hakiki - Linux Privilege Escalation



### **Zana bora ya kutafuta Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Taarifa za Mfumo](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pata **taarifa za OS**
- [ ] Kagua [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), kuna **folder inayoweza kuandikwa**?
- [ ] Kagua [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), kuna taarifa nyeti?
- [ ] Tafuta [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **kwa kutumia scripts** (DirtyCow?)
- [ ] Kabla ya kuendesha kernel PoC, thibitisha **prerequisites zake halisi**, si `uname -r` pekee: architecture, options/modules za `CONFIG_*` zinazohitajika, uundaji wa namespace na mitigations zilizo active. Kwa mfano, jaribu upatikanaji wa user/network namespace kwa `unshare -Urn true`; netfilter exploits za kisasa zinaweza kuhitaji `CONFIG_USER_NS`, unprivileged user namespaces na `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Kagua** kama [**sudo version** ina vulnerability](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification ilishindwa](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Kagua [**kernel module na module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement na `modules_disabled`.
- [ ] Kagua [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ikiwa helper path inaweza kurekebishwa au ku-triggeriwa.
- [ ] Kagua [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), pamoja na files za `.ko*` zinazoweza kuandikwa na metadata ya `modules.*`.
- [ ] System enum zaidi ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate defenses zaidi](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizomountiwa
- [ ] **Kuna drive ambayo haijamountiwa?**
- [ ] **Kuna creds kwenye fstab?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kagua kama**[ **useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **imewekwa**
- [ ] **Kagua kama** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **imewekwa**
- [ ] Kwenye Debian/Ubuntu, kagua kama **needrestart interpreter scanning** imewekwa/enabled: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Builds zenye vulnerability zilivuka privilege boundary kwa kutumia tena `PYTHONPATH`/`RUBYLIB` iliyodhibitiwa na attacker, kufanya race kwenye `/proc/<pid>/exe`, au kuscan Perl paths zinazodhibitiwa na attacker wakati APT au `unattended-upgrades` iliita needrestart kama root.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Kuna **unknown software inayo-run**?
- [ ] Kuna software inayo-run ikiwa na **privileges zaidi kuliko inavyopaswa kuwa nazo**?
- [ ] Tafuta **exploits za processes zinazo-run** (hasa version inayotumika).
- [ ] Unaweza **kurekebisha binary** ya process yoyote inayo-run?
- [ ] **Monitor processes** na kagua kama process yoyote ya kuvutia ina-run mara kwa mara.
- [ ] Unaweza **kusoma** baadhi ya **process memory** ya kuvutia (ambapo passwords zinaweza kuwa zimehifadhiwa)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
- [ ] Kuna [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)kwenye cron job?
- [ ] Kuna [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)inayo-**executiwa** au iko ndani ya **modifiable folder**?
- [ ] Umegundua kuwa **script** fulani inaweza au inaendelea [**ku-executiwa** mara **kwa mara**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Kuna **.service file inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** ambayo **service** ina-execute?
- [ ] Kuna **helper, config au environment file inayoweza kuandikwa inayoreferenciwa na root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Kagua merged unit kwa `systemctl cat <unit>` na pitia [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Kuna **folder inayoweza kuandikwa kwenye systemd PATH**?
- [ ] Kuna **systemd unit drop-in inayoweza kuandikwa** ndani ya `/etc/systemd/system/<unit>.d/*.conf` ambayo inaweza ku-override `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Kuna **.socket file inayoweza kuandikwa**?
- [ ] Unaweza **kuwasiliana na socket yoyote**?
- [ ] Kuna **HTTP sockets** zenye taarifa za kuvutia?
- [ ] Unaweza kufikia [**container-runtime or node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) kama `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` au kubelet endpoint? Test raw HTTP/gRPC API hata kama CLI yake ya kawaida haipo.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Unaweza **kuwasiliana na D-Bus yoyote**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerate network ili kujua ulipo
- [ ] Kuna **ports zilizofunguka ambazo hukuweza kuzifikia kabla** ya kupata shell ndani ya machine?
- [ ] Unaweza **kusniff traffic** kwa kutumia `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeration** ya kawaida ya users/groups
- [ ] Una **UID kubwa sana**? Je, **machine** iko **vulnerable**?
- [ ] Unaweza [**ku-escalate privileges kwa sababu ya group**](../user-information/interesting-groups-linux-pe/index.html) ambayo wewe ni mwanachama wake?
- [ ] Data ya **Clipboard**?
- [ ] Password Policy?
- [ ] Jaribu **kutumia** kila **password inayojulikana** ambayo umegundua awali ku-login **kwa kila** **user** anayekubalika. Jaribu pia ku-login bila password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **write privileges kwenye folder fulani iliyo ndani ya PATH**, unaweza kuweza ku-escalate privileges

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Unaweza ku-execute **command yoyote kwa sudo**? Unaweza kuitumia READ, WRITE au EXECUTE chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ikiwa `sudo -l` inaruhusu `sudoedit`, kagua **sudoedit argument injection** (CVE-2023-22809) kupitia `SUDO_EDITOR`/`VISUAL`/`EDITOR` ili ku-edit files kiholela kwenye versions zenye vulnerability (`sudo -V` < 1.9.12p2). Mfano: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Kuna **SUID binary inayoweza ku-exploitiwa**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, commands za [**sudo** **zimewekewa mipaka** na **path**? unaweza **kuzipita restrictions**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bila path iliyoonyeshwa**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary inayobainisha path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Lack of .so library in SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) kutoka kwenye folder inayoweza kuandikwa?
- [ ] [**SUID RPATH/RUNPATH au writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens zinapatikana**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Unaweza kuunda SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Unaweza [**kusoma au kurekebisha sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Unaweza [**kurekebisha /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
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
- [ ] **Files zenye location/ownership isiyo ya kawaida,** unaweza kuzifikia au kurekebisha executable files
- [ ] **Zilizorekebishwa** ndani ya dakika za mwisho
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries ndani ya PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Known files zenye passwords**: Tumia **Linpeas** na **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Rekebisha python library** ili ku-execute commands kiholela?
- [ ] Unaweza **kurekebisha log files**? **Logtotten** exploit
- [ ] Unaweza **kurekebisha /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Unaweza [**kuandika kwenye ini, int.d, systemd au rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Unaweza [**kutumia vibaya NFS ili ku-escalate privileges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Unahitaji [**kutoka kwenye restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit requirements and research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
