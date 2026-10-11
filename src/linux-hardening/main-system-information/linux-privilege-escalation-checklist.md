# Linux Privilege Escalation-kontrolelys

{{#include ../../banners/hacktricks-training.md}}

# Kontrolelys - Linux Privilege Escalation



### **Beste hulpmiddel om plaaslike Linux-voorregte-escalering-vektore te vind:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Kry **OS-inligting**
- [ ] Gaan die [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) na: is daar enige **skryfbare vouer**?
- [ ] Gaan [**omgewingsveranderlikes**](../linux-basics/linux-privilege-escalation/index.html#env-info) na: is daar enige sensitiewe besonderhede?
- [ ] Soek met **scripts** vir [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) (DirtyCow?)
- [ ] Verifieer die **werklike voorvereistes** voordat jy ’n kernel PoC uitvoer, nie net `uname -r` nie: argitektuur, vereiste `CONFIG_*`-opsies/-modules, skepping van namespaces en aktiewe versagtingsmaatreëls. Toets byvoorbeeld of user/network namespaces beskikbaar is met `unshare -Urn true`; moderne netfilter-exploits vereis moontlik `CONFIG_USER_NS`, onbevoorregte user namespaces en `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Kyk** of die [**sudo-weergawe kwesbaar** is](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg**-handtekeningverifikasie het misluk](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Gaan [**kernel module- en module-laaikonfigurasieprobleme**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) na: `insmod`, `modinfo`, `lsmod`, `dmesg`, handtekeningafdwinging en `modules_disabled`.
- [ ] Gaan [**misbruikpaaie vir kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) na indien die helper-pad gewysig of geaktiveer kan word.
- [ ] Gaan [**skryfbare /lib/modules-paaie**](kernel-modules-and-modprobe.md#writable-libmodules-review) na, insluitend skryfbare `.ko*`-lêers en `modules.*`-metadata.
- [ ] Meer stelsel-enum ([datum, stelselstatistieke, CPU-inligting, drukkers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumereer meer verdedigingsmaatreëls](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Skywe](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Lys gekoppelde** skywe
- [ ] Is daar **ongekoppelde skywe**?
- [ ] Is daar enige geloofsbriewe in fstab?

### [**Geïnstalleerde sagteware**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kyk of** [**nuttige sagteware**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **geïnstalleer is**
- [ ] **Kyk of** [**kwesbare sagteware**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **geïnstalleer is**
- [ ] Gaan op Debian/Ubuntu na of **needrestart interpreter scanning** geïnstalleer/geaktiveer is: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Kwesbare bouwe het die voorreggrens oorgesteek deur aanvallerbeheerde `PYTHONPATH`/`RUBYLIB` te hergebruik, ’n wedloop met `/proc/<pid>/exe` te veroorsaak, of aanvallerbeheerde Perl-paaie te skandeer wanneer APT of `unattended-upgrades` needrestart as root uitgevoer het.<sup>[[4]](#references)</sup>

### [Prosesse](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Loop daar enige **onbekende sagteware**?
- [ ] Loop enige sagteware met **meer voorregte as wat dit behoort te hê**?
- [ ] Soek vir **exploits vir prosesse wat loop** (veral die weergawe wat loop).
- [ ] Kan jy die **binêre lêer** van enige proses wat loop **wysig**?
- [ ] **Monitor prosesse** en kyk of enige interessante proses gereeld loop.
- [ ] Kan jy enige interessante **prosesgeheue lees** (waar wagwoorde dalk gestoor is)?

### [Geskeduleerde/Cron-take?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Word die [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)deur ’n cron-taak gewysig en kan jy daarin **skryf**?
- [ ] Is daar ’n [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in ’n cron-taak?
- [ ] Word ’n [**wysigbare script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**uitgevoer**, of is dit in ’n **wysigbare vouer**?
- [ ] Het jy ontdek dat ’n **script** dalk [**baie gereeld**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) **uitgevoer word**? (elke 1, 2 of 5 minute)

### [Dienste](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Is daar enige **skryfbare .service**-lêer?
- [ ] Is daar enige **skryfbare binêre lêer** wat deur ’n **diens** uitgevoer word?
- [ ] Is daar enige skryfbare **helper-, konfigurasie- of omgewingslêer waarna ’n root-unit verwys** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Ondersoek die saamgevoegde unit met `systemctl cat <unit>` en hersien [misbruik van diens-/socket-lêers](../interesting-files-permissions/write-to-root.md).
- [ ] Voer ’n bevoorregte werkvloei op aanvraag ’n helper uit onder ’n skryfbare vouer met laer voorregte? Gaan die helper én sy ouervouer na vir [root-uitvoering van gebruikerwysigbare paaie](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); kortstondige helpers verskyn moontlik net terwyl die werkvloei loop.
- [ ] Is daar enige **skryfbare vouer in die systemd PATH**?
- [ ] Is daar enige **skryfbare systemd-unit-invoeglêer** in `/etc/systemd/system/<unit>.d/*.conf` wat `ExecStart`/`User` kan oorskryf?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Is daar enige **skryfbare timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Is daar enige **skryfbare .socket**-lêer?
- [ ] Kan jy met enige socket **kommunikeer**?
- [ ] **HTTP-sockets** met interessante inligting?
- [ ] Kan jy toegang kry tot ’n [**container-runtime- of node-agent-API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) soos `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` of ’n kubelet-eindpunt? Toets die rou HTTP/gRPC-API selfs wanneer die gewone CLI ontbreek.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Kan jy met enige D-Bus **kommunikeer**?

### [Netwerk](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumereer die netwerk om te weet waar jy is
- [ ] Is daar **oop poorte waartoe jy nie toegang gehad het voordat** jy ’n shell op die masjien gekry het nie?
- [ ] Kan jy verkeer met `tcpdump` **snuif**?

### [Gebruikers](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Algemene **enumerasie** van gebruikers/groepe
- [ ] Het jy ’n **baie groot UID**? Is die **masjien** **kwesbaar**?
- [ ] Kan jy [**voorregte eskaleer danksy ’n groep**](../user-information/interesting-groups-linux-pe/index.html) waaraan jy behoort?
- [ ] **Knipbord**-data?
- [ ] Wagwoordbeleid?
- [ ] Probeer om elke **bekende wagwoord** wat jy voorheen ontdek het te **gebruik** om met elke moontlike **gebruiker** aan te meld. Probeer ook sonder ’n wagwoord aanmeld.

### [Skryfbare PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] As jy **skryfregte op ’n vouer in PATH** het, kan jy moontlik voorregte eskaleer

### [SUDO- en SUID-opdragte](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Kan jy **enige opdrag met sudo** uitvoer? Kan jy dit gebruik om enigiets as root te LEES, SKRYF of UIT TE VOER? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] As `sudo -l` `sudoedit` toelaat, kyk vir **sudoedit-argument-inspuiting** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` om arbitrêre lêers op kwesbare weergawes te wysig (`sudo -V` < 1.9.12p2). Voorbeeld: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Is daar enige **uitbuitbare SUID-binêre lêer**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Word [**sudo**-opdragte deur **paaie** **beperk**? Kan jy die beperkings **omseil**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID-binêre lêer sonder aangeduide pad**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-binêre lêer met aangeduide pad**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Omseil dit
- [ ] [**LD_PRELOAD-kwesbaarheid**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ontbrekende .so-biblioteek in ’n SUID-binêre lêer**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) vanaf ’n skryfbare vouer?
- [ ] [**SUID RPATH/RUNPATH of skryfbare biblioteekpad**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] Is [**SUDO-tokens beskikbaar**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Kan jy ’n SUDO-token skep**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kan jy [**sudoers-lêers lees of wysig**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kan jy [**/etc/ld.so.conf.d/** wysig](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)-opdrag

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Het enige binêre lêer ’n **onverwagte capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Het enige lêer ’n **onverwagte ACL**?

### [Oop shell-sessies](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Voorspelbare PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interessante SSH-konfigurasiewaardes**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interessante lêers](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile-lêers** - Lees sensitiewe data? Skryf om voorregte te eskaleer?
- [ ] **passwd/shadow-lêers** - Lees sensitiewe data? Skryf om voorregte te eskaleer?
- [ ] **Gaan algemene interessante vouers na** vir sensitiewe data
- [ ] **Vreemd geleë/lêers met vreemde eienaarskap,** waartoe jy toegang kan hê, of waardeur jy uitvoerbare lêers kan wysig
- [ ] **Gewysig** in die afgelope minute
- [ ] **Sqlite DB-lêers**
- [ ] **Versteekte lêers**
- [ ] **Scripts/binêre lêers in PATH**
- [ ] **Weblêers** (wagwoorde?)
- [ ] **Rugsteune**?
- [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
- [ ] **Algemene soektog**

### [**Skryfbare lêers**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Wysig Python-biblioteek** om arbitrêre opdragte uit te voer?
- [ ] Kan jy **loglêers wysig**? **Logtotten**-exploit
- [ ] Kan jy **/etc/sysconfig/network-scripts/** wysig? Centos/Redhat-exploit
- [ ] Kan jy [**in ini-, int.d-, systemd- of rc.d-lêers skryf**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Kan jy [**NFS misbruik om voorregte te eskaleer**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Moet jy [**uit ’n beperkende shell ontsnap**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo-advies: sudoedit wysig arbitrêre lêers](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux-dokumentasie: systemd-invoegkonfigurasie](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086-vereistes vir exploits en navorsing](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys-sekuriteitsadvies: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
