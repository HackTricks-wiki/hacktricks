# Kontrolelys - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Beste tool om vir Linux local privilege escalation vectors te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Kry **OS inligting**
- [ ] Kontroleer die [**PATH**](privilege-escalation/index.html#path), enige **skryfbare gids**?
- [ ] Kontroleer [**env variables**](privilege-escalation/index.html#env-info), enige sensitiewe besonderhede?
- [ ] Soek na [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **met behulp van skripte** (DirtyCow?)
- [ ] **Kontroleer** if the [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Meer stelsel-enumerasie ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Lys aangekoppelde aandrywers**
- [ ] **Enige nie-aangekoppelde aandrywer?**
- [ ] **Enige creds in fstab?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Kontroleer vir** [**useful software**](privilege-escalation/index.html#useful-software) wat geïnstalleer is
- [ ] **Kontroleer vir** [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) wat geïnstalleer is

### [Processes](privilege-escalation/index.html#processes)

- [ ] Is daar enige **onbekende software wat loop**?
- [ ] Draai enige sagteware met **meer bevoegdhede as wat dit behoort te hê**?
- [ ] Soek na **exploits van lopende prosesse** (veral die weergawe wat loop).
- [ ] Kan jy die **binaire** van enige lopende proses **wysig**?
- [ ] **Moniteer prosesse** en kontroleer of enige interessante proses gereeld loop.
- [ ] Kan jy sekere interessante **prosesgeheue** lees (waar wagwoorde gestoor kan wees)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Word die [**PATH**](privilege-escalation/index.html#cron-path) deur 'n cron gewysig en kan jy daarin **skryf**?
- [ ] Enige [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) in 'n cron job?
- [ ] Is enige [**modifiable script**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) wat **uitgevoer** word of binne 'n **wysigbare gids**?
- [ ] Het jy opgemerk dat sommige **skripte** moontlik of werklik [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs) word? (elke 1, 2 of 5 minute)

### [Services](privilege-escalation/index.html#services)

- [ ] Enige **skryfbare .service** lêer?
- [ ] Enige **skryfbare binêre** wat deur 'n **service** uitgevoer word?
- [ ] Enige **skryfbare gids in systemd PATH**?
- [ ] Enige **skryfbare systemd unit drop-in** in `/etc/systemd/system/<unit>.d/*.conf` wat `ExecStart`/`User` kan oorskryf?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Enige **skryfbare timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Enige **skryfbare .socket** lêer?
- [ ] Kan jy met enige socket **kommunikeer**?
- [ ] **HTTP sockets** met interessante inligting?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Kan jy met enige D-Bus **kommunikeer**?

### [Network](privilege-escalation/index.html#network)

- [ ] Enumereer die netwerk om te weet waar jy is
- [ ] **Oop poorte wat jy nie voorheen kon bereik nie** nadat jy 'n shell op die masjien gekry het?
- [ ] Kan jy verkeer afluister met `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Generiese gebruikers/groepe **enumerasie**
- [ ] Het jy 'n **baie groot UID**? Is die **masjien** **kwesbaar**?
- [ ] Kan jy [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html) waartoe jy behoort?
- [ ] **Kleefbord** data?
- [ ] Wagwoordbeleid?
- [ ] Probeer om elke **bekende wagwoord** wat jy voorheen ontdek het te **gebruik** om in te teken **met elke** moontlike **gebruiker**. Probeer ook sonder wagwoord in te teken.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] As jy **skryfbevoegdhede oor 'n gids in PATH** het, kan jy dalk escalate privileges

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Kan jy enige opdrag met **sudo** uitvoer? Kan jy dit gebruik om IETS as root TE LEES, TE SKRYF of TE UITVOER? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Indien `sudo -l` `sudoedit` toelaat, kontroleer vir **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` om arbitrêre lêers te wysig op kwetsbare weergawes (`sudo -V` < 1.9.12p2). Example: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Is daar enige **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Is [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) from a writable folder?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kan jy [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kan jy [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Het enige binêre 'n **onverwagte capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Het enige lêer 'n **onverwagte ACL**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profiellêers** - Lees sensitiewe data? Skryf vir privesc?
- [ ] **passwd/shadow-lêers** - Lees sensitiewe data? Skryf vir privesc?
- [ ] **Kontroleer algemeen interessante gidse** vir sensitiewe data
- [ ] **Vreemde ligging/besit-lêers,** jy mag toegang hê tot of uitvoerbare lêers kan wysig
- [ ] **Gewysig** in die laaste minute
- [ ] **Sqlite DB-lêers**
- [ ] **Verborge lêers**
- [ ] **Skrippe/Binêre in PATH**
- [ ] **Web-lêers** (wagwoorde?)
- [ ] **Rugsteun**?
- [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
- [ ] **Algemene soektog**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Wysig python-biblioteek** om arbitrêre opdragte uit te voer?
- [ ] Kan jy **loglêers wysig**? **Logtotten** exploit
- [ ] Kan jy **/etc/sysconfig/network-scripts/** wysig? Centos/Redhat exploit
- [ ] Kan jy [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Kan jy [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Moet jy [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Verwysings

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
