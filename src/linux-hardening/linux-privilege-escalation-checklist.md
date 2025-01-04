# Kontrolelys - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Linux plaaslike privilege escalatie vektore te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](privilege-escalation/index.html#system-information)

- [ ] Kry **OS-inligting**
- [ ] Kontroleer die [**PATH**](privilege-escalation/index.html#path), enige **skryfbare gids**?
- [ ] Kontroleer [**omgewing veranderlikes**](privilege-escalation/index.html#env-info), enige sensitiewe besonderhede?
- [ ] Soek na [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **met behulp van skripte** (DirtyCow?)
- [ ] **Kontroleer** of die [**sudo weergawe** kwesbaar is](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** handtekeningverifikasie het misluk](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Meer stelselinventaris ([datum, stelselsyfers, cpu-inligting, drukkers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Inventariseer meer verdediging](privilege-escalation/index.html#enumerate-possible-defenses)

### [Skyfies](privilege-escalation/index.html#drives)

- [ ] **Lys gemonteerde** skywe
- [ ] **Enige ongemonteerde skyf?**
- [ ] **Enige krediete in fstab?**

### [**Gemonteerde Sagteware**](privilege-escalation/index.html#installed-software)

- [ ] **Kontroleer vir** [**nuttige sagteware**](privilege-escalation/index.html#useful-software) **geïnstalleer**
- [ ] **Kontroleer vir** [**kwesbare sagteware**](privilege-escalation/index.html#vulnerable-software-installed) **geïnstalleer**

### [Prosesse](privilege-escalation/index.html#processes)

- [ ] Is enige **onbekende sagteware aan die gang**?
- [ ] Is enige sagteware aan die gang met **meer bevoegdhede as wat dit behoort te hê**?
- [ ] Soek na **exploits van lopende prosesse** (veral die weergawe wat aan die gang is).
- [ ] Kan jy die **binaire** van enige lopende proses **wysig**?
- [ ] **Monitor prosesse** en kyk of enige interessante proses gereeld aan die gang is.
- [ ] Kan jy **lees** van sommige interessante **prosesgeheue** (waar wagwoorde gestoor kan word)?

### [Geplande/Cron werke?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Word die [**PATH**](privilege-escalation/index.html#cron-path) deur 'n cron gewysig en kan jy daarin **skryf**?
- [ ] Enige [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) in 'n cron werk?
- [ ] Sommige [**wysigbare skrip**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) word **uitgevoer** of is binne **wysigbare gids**?
- [ ] Het jy opgemerk dat sommige **skrip** of [**uitgevoer** word **baie** **gereeld**](privilege-escalation/index.html#frequent-cron-jobs)? (elke 1, 2 of 5 minute)

### [Dienste](privilege-escalation/index.html#services)

- [ ] Enige **skryfbare .service** lêer?
- [ ] Enige **skryfbare binaire** wat deur 'n **diens** uitgevoer word?
- [ ] Enige **skryfbare gids in systemd PATH**?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Enige **skryfbare timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Enige **skryfbare .socket** lêer?
- [ ] Kan jy **kommunikeer met enige socket**?
- [ ] **HTTP sockets** met interessante inligting?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Kan jy **kommunikeer met enige D-Bus**?

### [Netwerk](privilege-escalation/index.html#network)

- [ ] Inventariseer die netwerk om te weet waar jy is
- [ ] **Oop poorte wat jy voorheen nie kon toegang nie** om 'n shell binne die masjien te kry?
- [ ] Kan jy **verkeer afluister** met `tcpdump`?

### [Gebruikers](privilege-escalation/index.html#users)

- [ ] Generiese gebruikers/groepe **inventarisering**
- [ ] Het jy 'n **baie groot UID**? Is die **masjien** **kwesbaar**?
- [ ] Kan jy [**privileges verhoog danksy 'n groep**](privilege-escalation/interesting-groups-linux-pe/index.html) waartoe jy behoort?
- [ ] **Klipbord** data?
- [ ] Wagwoordbeleid?
- [ ] Probeer om **elke** **bekende wagwoord** wat jy voorheen ontdek het te gebruik om in te log **met elke** moontlike **gebruiker**. Probeer ook om sonder 'n wagwoord in te log.

### [Skryfbare PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] As jy **skryfregte oor 'n gids in PATH** het, kan jy dalk privileges verhoog

### [SUDO en SUID opdragte](privilege-escalation/index.html#sudo-and-suid)

- [ ] Kan jy **enige opdrag met sudo** uitvoer? Kan jy dit gebruik om IES, SKRYF of UITVOER enigiets as root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Is enige **exploitable SUID binaire**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Is [**sudo** opdragte **beperk** deur **pad**? kan jy die beperkings **omseil**](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binaire sonder pad aangedui**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binaire wat pad spesifiseer**](privilege-escalation/index.html#suid-binary-with-command-path)? Omseil
- [ ] [**LD_PRELOAD kwesbaarheid**](privilege-escalation/index.html#ld_preload)
- [ ] [**Gebrek aan .so biblioteek in SUID binaire**](privilege-escalation/index.html#suid-binary-so-injection) van 'n skryfbare gids?
- [ ] [**SUDO tokens beskikbaar**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Kan jy 'n SUDO token skep**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kan jy [**lees of wysig sudoers lêers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kan jy [**wysig /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) opdrag

### [Vermoeëns](privilege-escalation/index.html#capabilities)

- [ ] Het enige binaire enige **onverwagte vermoë**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Het enige lêer enige **onverwagte ACL**?

### [Oop Shell sessies](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Voorspelbare PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interessante konfigurasiewaardes**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interessante Lêers](privilege-escalation/index.html#interesting-files)

- [ ] **Profiel lêers** - Lees sensitiewe data? Skryf na privesk?
- [ ] **passwd/shadow lêers** - Lees sensitiewe data? Skryf na privesk?
- [ ] **Kontroleer algemeen interessante gidsen** vir sensitiewe data
- [ ] **Vreemde Ligging/Eienaars lêers,** jy mag toegang hê tot of uitvoerbare lêers verander
- [ ] **Gewysig** in laaste minute
- [ ] **Sqlite DB lêers**
- [ ] **Versteekte lêers**
- [ ] **Skrip/Binaries in PATH**
- [ ] **Web lêers** (wagwoorde?)
- [ ] **Backups**?
- [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
- [ ] **Generiese soektog**

### [**Skryfbare Lêers**](privilege-escalation/index.html#writable-files)

- [ ] **Wysig python biblioteek** om arbitrêre opdragte uit te voer?
- [ ] Kan jy **log lêers wysig**? **Logtotten** kwesbaarheid
- [ ] Kan jy **wysig /etc/sysconfig/network-scripts/**? Centos/Redhat kwesbaarheid
- [ ] Kan jy [**skryf in ini, int.d, systemd of rc.d lêers**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](privilege-escalation/index.html#other-tricks)

- [ ] Kan jy [**NFS misbruik om privileges te verhoog**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Moet jy [**ontsnap uit 'n beperkende shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
