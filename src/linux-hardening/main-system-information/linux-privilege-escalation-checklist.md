# Linux Privilege Escalation-kontrolelys

{{#include ../../banners/hacktricks-training.md}}

# Kontrolelys - Linux Privilege Escalation



### **Beste tool om Linux local privilege escalation vectors te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Kry **OS-inligting**
- [ ] Kontroleer die [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), enige **skryfbare vouer**?
- [ ] Kontroleer [**env-veranderlikes**](../linux-basics/linux-privilege-escalation/index.html#env-info), enige sensitiewe detail?
- [ ] Soek vir [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **met scripts** (DirtyCow?)
- [ ] Voordat jy ’n kernel PoC uitvoer, verifieer die **werklike prerequisites** daarvan, nie slegs `uname -r` nie: argitektuur, vereiste `CONFIG_*`-opsies/modules, namespace-skepping en aktiewe mitigations. Toets byvoorbeeld user/network namespace-beskikbaarheid met `unshare -Urn true`; moderne netfilter exploits kan `CONFIG_USER_NS`, unprivileged user namespaces en `CONFIG_NF_TABLES` vereis.<sup>[[3]](#references)</sup>
- [ ] **Kontroleer** of die [**sudo-weergawe** kwesbaar is](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg**-handtekeningverifikasie het misluk](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Hersien [**kernel module- en module-laaikonfigurasies**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement en `modules_disabled`.
- [ ] Kontroleer [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) indien die helper path gewysig of ge-trigger kan word.
- [ ] Kontroleer [**skryfbare /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), insluitend skryfbare `.ko*`-lêers en `modules.*`-metadata.
- [ ] Meer system enum ([datum, stelselstatistieke, CPU-inligting, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumereer meer defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Lys gemounte** drives
- [ ] **Enige ongemounte drive?**
- [ ] **Enige creds in fstab?**

### [**Geïnstalleerde sagteware**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kontroleer vir**[ **nuttige sagteware**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **wat geïnstalleer is**
- [ ] **Kontroleer vir** [**kwesbare sagteware**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **wat geïnstalleer is**
- [ ] Kontroleer op Debian/Ubuntu of **needrestart interpreter scanning** geïnstalleer/geaktiveer is: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Kwesbare builds het die privilege boundary oorgesteek deur aanvaller-beheerde `PYTHONPATH`/`RUBYLIB` te hergebruik, `/proc/<pid>/exe` te race, of aanvaller-beheerde Perl paths te scan wanneer APT of `unattended-upgrades` needrestart as root aangeroep het.<sup>[[4]](#references)</sup>

### [Prosesse](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Loop enige **onbekende sagteware**?
- [ ] Loop enige sagteware met **meer privileges as wat dit behoort te hê**?
- [ ] Soek vir **exploits van lopende prosesse** (veral die weergawe wat loop).
- [ ] Kan jy die **binary** van enige lopende proses **wysig**?
- [ ] **Monitor prosesse** en kontroleer of enige interessante proses gereeld loop.
- [ ] Kan jy **lees** uit enige interessante **prosesgeheue** (waar wagwoorde gestoor kon wees)?

### [Geskeduleerde/Cron-take?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Word die [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)deur enige cron gewysig en kan jy daarin **skryf**?
- [ ] Enige [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in ’n cron-job?
- [ ] Word ’n [**wysigbare script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **uitgevoer**, of is dit binne ’n **wysigbare vouer**?
- [ ] Het jy ontdek dat enige **script** [**baie gereeld uitgevoer**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) kon word of word? (elke 1, 2 of 5 minute)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Enige **skryfbare .service**-lêer?
- [ ] Enige **skryfbare binary** wat deur ’n **service** uitgevoer word?
- [ ] Enige skryfbare **helper-, config- of environment-lêer waarna ’n root unit verwys** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Inspekteer die saamgevoegde unit met `systemctl cat <unit>` en hersien [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Enige **skryfbare vouer in systemd PATH**?
- [ ] Enige **skryfbare systemd unit drop-in** in `/etc/systemd/system/<unit>.d/*.conf` wat `ExecStart`/`User` kan override?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Enige **skryfbare timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Enige **skryfbare .socket**-lêer?
- [ ] Kan jy met enige **socket kommunikeer**?
- [ ] **HTTP-sockets** met interessante inligting?
- [ ] Kan jy toegang verkry tot ’n [**container-runtime- of node-agent-API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) soos `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` of ’n kubelet-endpoint? Toets die rou HTTP/gRPC API selfs wanneer die gewone CLI daarvan afwesig is.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Kan jy met enige **D-Bus kommunikeer**?

### [Netwerk](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumereer die netwerk om te weet waar jy is
- [ ] **Oop poorte waartoe jy voorheen nie toegang gehad het nie** nadat jy ’n shell binne die masjien gekry het?
- [ ] Kan jy verkeer **sniff** met `tcpdump`?

### [Gebruikers](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generiese gebruikers/groepe se **enumeration**
- [ ] Het jy ’n **baie groot UID**? Is die **masjien** **kwesbaar**?
- [ ] Kan jy [**privileges eskaleer danksy ’n groep**](../user-information/interesting-groups-linux-pe/index.html) waarvan jy lid is?
- [ ] **Clipboard**-data?
- [ ] Wagwoordbeleid?
- [ ] Probeer om elke **bekende wagwoord** wat jy voorheen ontdek het, te **gebruik** om met **elke** moontlike **gebruiker** aan te meld. Probeer ook sonder ’n wagwoord aanmeld.

### [Skryfbare PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Indien jy **skryfreghte oor enige vouer in PATH** het, kan jy moontlik privileges eskaleer

### [SUDO- en SUID-opdragte](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Kan jy **enige opdrag met sudo uitvoer**? Kan jy dit gebruik om enigiets as root te READ, WRITE of EXECUTE? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Indien `sudo -l` `sudoedit` toelaat, kontroleer vir **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` om arbitrêre lêers op kwesbare weergawes te wysig (`sudo -V` < 1.9.12p2). Voorbeeld: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Is enige **exploitable SUID-binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Word [**sudo**-opdragte deur **path** **beperk**? Kan jy die [**beperkings omseil**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID-binary sonder aangeduide path**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-binary wat ’n path spesifiseer**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Omseil dit
- [ ] [**LD_PRELOAD-vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ontbrekende .so-library in SUID-binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) vanuit ’n skryfbare vouer?
- [ ] [**SUID RPATH/RUNPATH of skryfbare library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO-tokens beskikbaar**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Kan jy ’n SUDO-token skep**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kan jy [**sudoers-lêers lees of wysig**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kan jy [**/etc/ld.so.conf.d/** wysig](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)-opdrag

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Het enige binary enige **onverwagte capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Het enige lêer enige **onverwagte ACL**?

### [Oop shell-sessies](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interessante SSH-konfigurasiewaardes**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interessante lêers](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile-lêers** - Lees sensitiewe data? Skryf na privesc?
- [ ] **passwd/shadow-lêers** - Lees sensitiewe data? Skryf vir privesc?
- [ ] **Kontroleer algemeen interessante vouers** vir sensitiewe data
- [ ] **Vreemde ligging/lêers in besit van iemand,** waartoe jy toegang kan hê of uitvoerbare lêers kan wysig
- [ ] **Gewysig** in die afgelope minute
- [ ] **Sqlite DB-lêers**
- [ ] **Versteekte lêers**
- [ ] **Scripts/Binaries in PATH**
- [ ] **Weblêers** (wagwoorde?)
- [ ] **Backups**?
- [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
- [ ] **Generiese search**

### [**Skryfbare lêers**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Wysig Python-library** om arbitrêre opdragte uit te voer?
- [ ] Kan jy **loglêers wysig**? **Logtotten** exploit
- [ ] Kan jy **/etc/sysconfig/network-scripts/** wysig? Centos/Redhat exploit
- [ ] Kan jy [**in ini, int.d, systemd of rc.d-lêers skryf**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Kan jy [**NFS misbruik om privileges te eskaleer**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Moet jy [**uit ’n restrictive shell ontsnap**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Verwysings

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit requirements and research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
