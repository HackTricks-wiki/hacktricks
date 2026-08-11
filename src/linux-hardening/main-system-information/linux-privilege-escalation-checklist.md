# Linux Privilege Escalation-kontrolelys

# Kontrolelys - Linux Privilege Escalation



### **Beste tool om Linux local privilege escalation vectors te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Kry **OS-inligting**
- [ ] Kontroleer die [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), enige **skryfbare vouer**?
- [ ] Kontroleer [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), enige sensitiewe detail?
- [ ] Soek vir [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **deur scripts te gebruik** (DirtyCow?)
- [ ] Voordat jy ’n kernel PoC uitvoer, verifieer die **werklike prerequisites**, nie net `uname -r` nie: argitektuur, vereiste `CONFIG_*`-opsies/modules, namespace-skepping en aktiewe mitigations. Toets byvoorbeeld user/network namespace-beskikbaarheid met `unshare -Urn true`; moderne netfilter exploits mag `CONFIG_USER_NS`, unprivileged user namespaces en `CONFIG_NF_TABLES` vereis.<sup>[[3]](#references)</sup>
- [ ] **Kontroleer** of die [**sudo version** kwesbaar is](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Hersien [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement en `modules_disabled`.
- [ ] Kontroleer [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) indien die helper path gewysig of geaktiveer kan word.
- [ ] Kontroleer [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), insluitend skryfbare `.ko*`-lêers en `modules.*`-metadata.
- [ ] Meer system enum ([datum, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumereer meer defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Lys gemounte** drives
- [ ] **Enige ongemounte drive?**
- [ ] **Enige creds in fstab?**

### [**Geïnstalleerde Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kontroleer vir**[ **nuttige software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **wat geïnstalleer is**
- [ ] **Kontroleer vir** [**kwesbare software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **wat geïnstalleer is**
- [ ] Op Debian/Ubuntu, kontroleer of **needrestart interpreter scanning** geïnstalleer/geaktiveer is: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Kwesbare builds het die privilege boundary oorgesteek deur aanvaller-beheerde `PYTHONPATH`/`RUBYLIB` te hergebruik, `/proc/<pid>/exe` te race, of aanvaller-beheerde Perl paths te skandeer wanneer APT of `unattended-upgrades` needrestart as root opgeroep het.<sup>[[4]](#references)</sup>

### [Prosesse](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Is enige **onbekende software aan die loop**?
- [ ] Loop enige software met **meer privileges as wat dit behoort te hê**?
- [ ] Soek vir **exploits van lopende prosesse** (veral die weergawe wat loop).
- [ ] Kan jy die **binary van enige lopende proses wysig**?
- [ ] **Monitor prosesse** en kontroleer of enige interessante proses gereeld loop.
- [ ] Kan jy sommige interessante **process memory lees** (waar wagwoorde gestoor kon wees)?

### [Geskeduleerde/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Word die [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)deur ’n cron gewysig en kan jy daarin **skryf**?
- [ ] Enige [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in ’n cron job?
- [ ] Word ’n [**wysigbare script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**uitgevoer**, of is dit binne ’n **wysigbare vouer**?
- [ ] Het jy bespeur dat ’n **script** [**baie gereeld**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) **uitgevoer** kan word of word? (elke 1, 2 of 5 minute)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Enige **skryfbare .service**-lêer?
- [ ] Enige **skryfbare binary** wat deur ’n **service** uitgevoer word?
- [ ] Enige skryfbare **helper-, config- of environment-lêer waarna ’n root unit verwys** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Inspekteer die saamgevoegde unit met `systemctl cat <unit>` en hersien [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Enige **skryfbare vouer in systemd PATH**?
- [ ] Enige **skryfbare systemd unit drop-in** in `/etc/systemd/system/<unit>.d/*.conf` wat `ExecStart`/`User` kan oorskryf?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Enige **skryfbare timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Enige **skryfbare .socket**-lêer?
- [ ] Kan jy met enige **socket kommunikeer**?
- [ ] **HTTP-sockets** met interessante inligting?
- [ ] Kan jy toegang tot ’n [**container-runtime or node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) verkry, soos `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` of ’n kubelet endpoint? Toets die rou HTTP/gRPC API selfs wanneer die gewone CLI daarvan ontbreek.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Kan jy met enige **D-Bus kommunikeer**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumereer die network om te weet waar jy is
- [ ] **Oop poorte waartoe jy voorheen nie toegang gehad het nie** nadat jy ’n shell binne die masjien verkry het?
- [ ] Kan jy traffic **sniff** met `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Algemene users/groups **enumeration**
- [ ] Het jy ’n **baie groot UID**? Is die **masjien** **kwesbaar**?
- [ ] Kan jy [**privileges eskaleer danksy ’n group**](../user-information/interesting-groups-linux-pe/index.html) waarvan jy lid is?
- [ ] **Clipboard**-data?
- [ ] Password Policy?
- [ ] Probeer om elke **bekende wagwoord** wat jy voorheen ontdek het te **gebruik** om met **elke** moontlike **user** aan te meld. Probeer ook sonder ’n wagwoord aanmeld.

### [Skryfbare PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] As jy **skryftoestemmings oor ’n vouer in PATH** het, kan jy moontlik privileges eskaleer

### [SUDO- en SUID-opdragte](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Kan jy **enige opdrag met sudo uitvoer**? Kan jy dit gebruik om enigiets as root te READ, WRITE of EXECUTE? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Indien `sudo -l` `sudoedit` toelaat, kontroleer vir **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` om arbitrêre lêers op kwesbare weergawes te wysig (`sudo -V` < 1.9.12p2). Voorbeeld: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Is enige **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Word [**sudo**-opdragte **beperk** deur **path**? Kan jy die beperkings **omseil**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary sonder aangeduide path**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary wat ’n path spesifiseer**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Omseil
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ontbrekende .so-library in SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) vanuit ’n skryfbare vouer?
- [ ] [**SUID RPATH/RUNPATH of skryfbare library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
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

- [ ] **Profile-lêers** - Lees sensitiewe data? Skryf om privesc te doen?
- [ ] **passwd/shadow-lêers** - Lees sensitiewe data? Skryf om privesc te doen?
- [ ] **Kontroleer algemeen interessante vouers** vir sensitiewe data
- [ ] **Vreemde ligging/lêers waarvan jy die eienaar is,** waartoe jy toegang het of wat jy kan uitvoerbare lêers kan wysig
- [ ] **Gewysig** in die laaste minute
- [ ] **Sqlite DB-lêers**
- [ ] **Versteekte lêers**
- [ ] **Scripts/Binaries in PATH**
- [ ] **Web-lêers** (wagwoorde?)
- [ ] **Backups**?
- [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
- [ ] **Algemene search**

### [**Skryfbare Lêers**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Wysig python-library** om arbitrêre opdragte uit te voer?
- [ ] Kan jy **log-lêers wysig**? **Logtotten** exploit
- [ ] Kan jy **/etc/sysconfig/network-scripts/** wysig? Centos/Redhat exploit
- [ ] Kan jy [**in ini-, int.d-, systemd- of rc.d-lêers skryf**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Kan jy [**NFS misbruik om privileges te eskaleer**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Moet jy [**uit ’n restrictive shell ontsnap**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo-advies: sudoedit arbitrêre lêerwysiging](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux-dokumentasie: systemd drop-in-konfigurasie](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit-vereistes en navorsing](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
