# Kontrolelys vir Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Kontrolelys - Linux Privilege Escalation



### **Beste tool om Linux local privilege escalation vectors te vind:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Kry **OS-inligting**
- [ ] Kontroleer die [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), enige **writable folder**?
- [ ] Kontroleer [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), enige sensitiewe detail?
- [ ] Soek vir [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **using scripts** (DirtyCow?)
- [ ] **Kontroleer** of die [**sudo version** kwesbaar is](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Hersien [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement en `modules_disabled`.
- [ ] Kontroleer [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) indien die helper path gewysig of ge-trigger kan word.
- [ ] Kontroleer [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), insluitend writable `.ko*`-lêers en `modules.*` metadata.
- [ ] Meer system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumereer meer defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Lys gemounte** drives
- [ ] **Enige ongemounte drive?**
- [ ] **Enige creds in fstab?**

### [**Geïnstalleerde Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kontroleer vir**[ **nuttige software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **wat geïnstalleer is**
- [ ] **Kontroleer vir** [**kwesbare software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **wat geïnstalleer is**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Loop enige **onbekende software**?
- [ ] Loop enige software met **meer privileges as wat dit behoort te hê**?
- [ ] Soek vir **exploits van lopende prosesse** (veral die weergawe wat loop).
- [ ] Kan jy die **binary** van enige lopende proses **wysig**?
- [ ] **Monitor prosesse** en kontroleer of enige interessante proses gereeld loop.
- [ ] Kan jy **lees** uit enige interessante **process memory** (waar wagwoorde gestoor kon wees)?

### [Geskeduleerde/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Word die [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)deur enige cron gewysig en kan jy daarin **skryf**?
- [ ] Enige [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in ’n cron job?
- [ ] Word ’n [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **uitgevoer** of is dit binne ’n **modifiable folder**?
- [ ] Het jy bespeur dat enige **script** [**baie gereeld**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) **uitgevoer** kan word of word? (elke 1, 2 of 5 minute)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Enige **writable .service**-lêer?
- [ ] Enige **writable binary** wat deur ’n **service** uitgevoer word?
- [ ] Enige **writable folder in systemd PATH**?
- [ ] Enige **writable systemd unit drop-in** in `/etc/systemd/system/<unit>.d/*.conf` wat `ExecStart`/`User` kan override?

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Enige **writable timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Enige **writable .socket**-lêer?
- [ ] Kan jy met enige **socket kommunikeer**?
- [ ] **HTTP sockets** met interessante inligting?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Kan jy met enige **D-Bus kommunikeer**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumereer die network om te weet waar jy is
- [ ] **Open poorte waartoe jy voorheen nie toegang gehad het nie** nadat jy ’n shell binne die masjien gekry het?
- [ ] Kan jy traffic **sniff** deur `tcpdump` te gebruik?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic users/groups **enumeration**
- [ ] Het jy ’n **baie groot UID**? Is die **masjien** **kwesbaar**?
- [ ] Kan jy [**privileges eskaleer danksy ’n groep**](../user-information/interesting-groups-linux-pe/index.html) waarvan jy lid is?
- [ ] **Clipboard**-data?
- [ ] Password Policy?
- [ ] Probeer om elke **bekende wagwoord** wat jy voorheen ontdek het te **gebruik** om met **elke** moontlike **user** aan te meld. Probeer ook om sonder ’n wagwoord aan te meld.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] As jy **write privileges oor enige folder in PATH** het, kan jy moontlik privileges eskaleer

### [SUDO- en SUID-opdragte](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Kan jy **enige opdrag met sudo uitvoer**? Kan jy dit gebruik om enigiets as root te READ, WRITE of EXECUTE? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Indien `sudo -l` `sudoedit` toelaat, kontroleer vir **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` om arbitrêre lêers op kwesbare weergawes te wysig (`sudo -V` < 1.9.12p2). Voorbeeld: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Is enige **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Word [**sudo**-opdragte **beperk** deur **path**? kan jy die [**beperkings omseil**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary sonder path aangedui**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary wat path spesifiseer**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Omseil
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Gebrek aan .so library in SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) vanuit ’n writable folder?
- [ ] [**SUID RPATH/RUNPATH of writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens beskikbaar**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Kan jy ’n SUDO token skep**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kan jy [**sudoers-lêers lees of wysig**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kan jy [**/etc/ld.so.conf.d/ wysig**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)-opdrag

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Het enige binary enige **onverwagte capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Het enige lêer enige **onverwagte ACL**?

### [Oop Shell-sessies](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interessante SSH-konfigurasiewaardes**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interessante Lêers](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Lees sensitiewe data? Skryf na privesc?
- [ ] **passwd/shadow files** - Lees sensitiewe data? Skryf om privesc?
- [ ] **Kontroleer algemeen interessante folders** vir sensitiewe data
- [ ] **Weird Location/Owned files,** waartoe jy moontlik toegang het of uitvoerbare lêers kan wysig
- [ ] **Gewysig** in die laaste minute
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Scripts/Binaries in PATH**
- [ ] **Web files** (wagwoorde?)
- [ ] **Backups**?
- [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Wysig python library** om arbitrêre opdragte uit te voer?
- [ ] Kan jy **log files wysig**? **Logtotten** exploit
- [ ] Kan jy **/etc/sysconfig/network-scripts/ wysig**? Centos/Redhat exploit
- [ ] Kan jy [**in ini, int.d, systemd of rc.d files skryf**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Kan jy [**NFS misbruik om privileges te eskaleer**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Moet jy [**uit ’n restrictive shell ontsnap**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Verwysings

- [Sudo advisory: sudoedit arbitrêre lêerwysiging](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux-dokumentasie: systemd drop-in-konfigurasie](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
