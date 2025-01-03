# Kontrolelys - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Linux plaaslike privilege escalatie vektore te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](privilege-escalation/#system-information)

- [ ] Kry **OS-inligting**
- [ ] Kontroleer die [**PATH**](privilege-escalation/#path), enige **skryfbare gids**?
- [ ] Kontroleer [**omgewing veranderlikes**](privilege-escalation/#env-info), enige sensitiewe besonderhede?
- [ ] Soek na [**kernel exploits**](privilege-escalation/#kernel-exploits) **met behulp van skripte** (DirtyCow?)
- [ ] **Kontroleer** of die [**sudo weergawe** kwesbaar is](privilege-escalation/#sudo-version)
- [ ] [**Dmesg** handtekeningverifikasie het misluk](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Meer stelselinventaris ([datum, stelselsyfers, cpu-inligting, drukkers](privilege-escalation/#more-system-enumeration))
- [ ] [**Inventariseer meer verdediging**](privilege-escalation/#enumerate-possible-defenses)

### [Skyfies](privilege-escalation/#drives)

- [ ] **Lys gemonteerde** skywe
- [ ] **Enige ongemonteerde skyf?**
- [ ] **Enige krediete in fstab?**

### [**Gemonteerde Sagteware**](privilege-escalation/#installed-software)

- [ ] **Kontroleer vir** [**nuttige sagteware**](privilege-escalation/#useful-software) **geïnstalleer**
- [ ] **Kontroleer vir** [**kwesbare sagteware**](privilege-escalation/#vulnerable-software-installed) **geïnstalleer**

### [Prosesse](privilege-escalation/#processes)

- [ ] Is enige **onbekende sagteware aan die gang**?
- [ ] Is enige sagteware aan die gang met **meer bevoegdhede as wat dit behoort te hê**?
- [ ] Soek na **exploits van lopende prosesse** (veral die weergawe wat aan die gang is).
- [ ] Kan jy die **binaire** van enige lopende proses **wysig**?
- [ ] **Monitor prosesse** en kyk of enige interessante proses gereeld aan die gang is.
- [ ] Kan jy **lees** van sommige interessante **prosesgeheue** (waar wagwoorde gestoor kan word)?

### [Geskeduleerde/Cron werke?](privilege-escalation/#scheduled-jobs)

- [ ] Word die [**PATH**](privilege-escalation/#cron-path) deur 'n cron gewysig en kan jy daarin **skryf**?
- [ ] Enige [**wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) in 'n cron werk?
- [ ] Sommige [**wysigbare skrip**](privilege-escalation/#cron-script-overwriting-and-symlink) word **uitgevoer** of is binne **wysigbare gids**?
- [ ] Het jy opgemerk dat sommige **skrip** [**baie gereeld**](privilege-escalation/#frequent-cron-jobs) **uitgevoer** kan word of word? (elke 1, 2 of 5 minute)

### [Dienste](privilege-escalation/#services)

- [ ] Enige **skryfbare .service** lêer?
- [ ] Enige **skryfbare binaire** wat deur 'n **diens** uitgevoer word?
- [ ] Enige **skryfbare gids in systemd PATH**?

### [Timers](privilege-escalation/#timers)

- [ ] Enige **skryfbare timer**?

### [Sockets](privilege-escalation/#sockets)

- [ ] Enige **skryfbare .socket** lêer?
- [ ] Kan jy **kommunikeer met enige socket**?
- [ ] **HTTP sockets** met interessante inligting?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Kan jy **kommunikeer met enige D-Bus**?

### [Netwerk](privilege-escalation/#network)

- [ ] Inventariseer die netwerk om te weet waar jy is
- [ ] **Oop poorte wat jy voorheen nie kon toegang nie** om 'n shell binne die masjien te kry?
- [ ] Kan jy **verkeer snuffel** met `tcpdump`?

### [Gebruikers](privilege-escalation/#users)

- [ ] Generiese gebruikers/groepe **inventarisering**
- [ ] Het jy 'n **baie groot UID**? Is die **masjien** **kwesbaar**?
- [ ] Kan jy [**privileges verhoog danksy 'n groep**](privilege-escalation/interesting-groups-linux-pe/) waartoe jy behoort?
- [ ] **Klipbord** data?
- [ ] Wagwoordbeleid?
- [ ] Probeer om **elke bekende wagwoord** wat jy voorheen ontdek het te gebruik om in te log met **elke** moontlike **gebruiker**. Probeer ook om sonder 'n wagwoord in te log.

### [Skryfbare PATH](privilege-escalation/#writable-path-abuses)

- [ ] As jy **skryfregte oor 'n gids in PATH** het, kan jy dalk privileges verhoog

### [SUDO en SUID opdragte](privilege-escalation/#sudo-and-suid)

- [ ] Kan jy **enige opdrag met sudo** uitvoer? Kan jy dit gebruik om IES, SKRYF of UITVOER enigiets as root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Is enige **kwesbare SUID binaire**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Word [**sudo** opdragte **beperk** deur **pad**? kan jy die **beperkings omseil**](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binaire sonder pad aangedui**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binaire wat pad spesifiseer**](privilege-escalation/#suid-binary-with-command-path)? Omseil
- [ ] [**LD_PRELOAD kwesbaarheid**](privilege-escalation/#ld_preload)
- [ ] [**Gebrek aan .so biblioteek in SUID binaire**](privilege-escalation/#suid-binary-so-injection) van 'n skryfbare gids?
- [ ] [**SUDO tokens beskikbaar**](privilege-escalation/#reusing-sudo-tokens)? [**Kan jy 'n SUDO token skep**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kan jy [**sudoers lêers lees of wysig**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] Kan jy [**/etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) wysig?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) opdrag

### [Vermoeë](privilege-escalation/#capabilities)

- [ ] Het enige binaire enige **onverwagte vermoë**?

### [ACLs](privilege-escalation/#acls)

- [ ] Het enige lêer enige **onverwagte ACL**?

### [Oop Shell sessies](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL Voorspelbare PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interessante konfigurasiewaardes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interessante Lêers](privilege-escalation/#interesting-files)

- [ ] **Profiel lêers** - Lees sensitiewe data? Skryf na privesk?
- [ ] **passwd/shadow lêers** - Lees sensitiewe data? Skryf na privesk?
- [ ] **Kontroleer algemeen interessante gids** vir sensitiewe data
- [ ] **Vreemde Ligging/Eienaars lêers,** jy mag toegang hê tot of uitvoerbare lêers verander
- [ ] **Gewysig** in laaste minute
- [ ] **Sqlite DB lêers**
- [ ] **Versteekte lêers**
- [ ] **Skrip/Binaries in PATH**
- [ ] **Web lêers** (wagwoorde?)
- [ ] **Backups**?
- [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
- [ ] **Generiese soektog**

### [**Skryfbare Lêers**](privilege-escalation/#writable-files)

- [ ] **Wysig python biblioteek** om arbitrêre opdragte uit te voer?
- [ ] Kan jy **log lêers wysig**? **Logtotten** kwesbaarheid
- [ ] Kan jy **/etc/sysconfig/network-scripts/** wysig? Centos/Redhat kwesbaarheid
- [ ] Kan jy [**skryf in ini, int.d, systemd of rc.d lêers**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](privilege-escalation/#other-tricks)

- [ ] Kan jy [**NFS misbruik om privileges te verhoog**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] Moet jy [**ontsnap uit 'n beperkende shell**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
