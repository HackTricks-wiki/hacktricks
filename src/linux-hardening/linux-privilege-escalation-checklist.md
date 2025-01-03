# Lista - Eskalacija privilegija na Linuxu

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za traženje lokalnih vektora eskalacije privilegija na Linuxu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](privilege-escalation/#system-information)

- [ ] Dobiti **informacije o OS-u**
- [ ] Proveriti [**PATH**](privilege-escalation/#path), da li postoji **pisiva fascikla**?
- [ ] Proveriti [**env varijable**](privilege-escalation/#env-info), da li ima osetljivih podataka?
- [ ] Tražiti [**kernel exploit-e**](privilege-escalation/#kernel-exploits) **koristeći skripte** (DirtyCow?)
- [ ] **Proveriti** da li je [**sudo verzija** ranjiva](privilege-escalation/#sudo-version)
- [ ] [**Dmesg** verifikacija potpisa nije uspela](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Više sistemskih enumeracija ([datum, sistemske statistike, cpu informacije, štampači](privilege-escalation/#more-system-enumeration))
- [ ] [**Enumerisati više odbrana**](privilege-escalation/#enumerate-possible-defenses)

### [Diskovi](privilege-escalation/#drives)

- [ ] **Lista montiranih** diskova
- [ ] **Da li postoji nemontirani disk?**
- [ ] **Da li ima kredencijala u fstab?**

### [**Instalirani softver**](privilege-escalation/#installed-software)

- [ ] **Proveriti** [**koristan softver**](privilege-escalation/#useful-software) **koji je instaliran**
- [ ] **Proveriti** [**ranjiv softver**](privilege-escalation/#vulnerable-software-installed) **koji je instaliran**

### [Procesi](privilege-escalation/#processes)

- [ ] Da li se pokreće **nepoznati softver**?
- [ ] Da li se neki softver pokreće sa **više privilegija nego što bi trebao**?
- [ ] Tražiti **exploite pokrenutih procesa** (posebno verziju koja se pokreće).
- [ ] Možete li **modifikovati binarni** fajl nekog pokrenutog procesa?
- [ ] **Pratiti procese** i proveriti da li se neki zanimljiv proces često pokreće.
- [ ] Možete li **pročitati** neku zanimljivu **memoriju procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](privilege-escalation/#scheduled-jobs)

- [ ] Da li se [**PATH**](privilege-escalation/#cron-path) menja od strane nekog crona i možete li **pisati** u njega?
- [ ] Da li postoji [**wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) u cron poslu?
- [ ] Da li se neki [**modifikovani skript**](privilege-escalation/#cron-script-overwriting-and-symlink) **izvršava** ili se nalazi u **modifikovanoj fascikli**?
- [ ] Da li ste otkrili da se neki **skript** može ili se **izvršava** vrlo **često**](privilege-escalation/#frequent-cron-jobs)? (svakih 1, 2 ili 5 minuta)

### [Servisi](privilege-escalation/#services)

- [ ] Da li postoji **pisivi .service** fajl?
- [ ] Da li postoji **pisivi binarni** fajl koji izvršava **servis**?
- [ ] Da li postoji **pisiva fascikla u systemd PATH**?

### [Tajmeri](privilege-escalation/#timers)

- [ ] Da li postoji **pisivi tajmer**?

### [Soketi](privilege-escalation/#sockets)

- [ ] Da li postoji **pisivi .socket** fajl?
- [ ] Možete li **komunicirati sa nekim soketom**?
- [ ] **HTTP soketi** sa zanimljivim informacijama?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Možete li **komunicirati sa nekim D-Bus**?

### [Mreža](privilege-escalation/#network)

- [ ] Enumerisati mrežu da biste znali gde se nalazite
- [ ] **Otvoreni portovi koje niste mogli da pristupite pre** nego što ste dobili shell unutar mašine?
- [ ] Možete li **sniff-ovati saobraćaj** koristeći `tcpdump`?

### [Korisnici](privilege-escalation/#users)

- [ ] Generička enumeracija korisnika/grupa
- [ ] Da li imate **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Možete li [**eskalirati privilegije zahvaljujući grupi**](privilege-escalation/interesting-groups-linux-pe/) kojoj pripadate?
- [ ] **Podaci iz clipboard-a**?
- [ ] Politika lozinki?
- [ ] Pokušajte da **koristite** svaku **poznatu lozinku** koju ste prethodno otkrili da se prijavite **sa svakim** mogućim **korisnikom**. Pokušajte da se prijavite i bez lozinke.

### [Pisivi PATH](privilege-escalation/#writable-path-abuses)

- [ ] Ako imate **privilegije pisanja nad nekom fasciklom u PATH-u** možda ćete moći da eskalirate privilegije

### [SUDO i SUID komande](privilege-escalation/#sudo-and-suid)

- [ ] Možete li izvršiti **bilo koju komandu sa sudo**? Možete li ga koristiti da ČITATE, PIŠETE ili IZVRŠAVATE bilo šta kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li postoji **iskoristiv SUID binarni**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** po **putanji**? Možete li **obići** ograničenja](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binarni bez naznačene putanje**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binarni koji naznačava putanju**](privilege-escalation/#suid-binary-with-command-path)? Obilaženje
- [ ] [**LD_PRELOAD ranjivost**](privilege-escalation/#ld_preload)
- [ ] [**Nedostatak .so biblioteke u SUID binarnom**](privilege-escalation/#suid-binary-so-injection) iz pisive fascikle?
- [ ] [**SUDO tokeni dostupni**](privilege-escalation/#reusing-sudo-tokens)? [**Možete li kreirati SUDO token**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Možete li [**čitati ili modifikovati sudoers fajlove**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] Možete li [**modifikovati /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) komanda

### [Kapaciteti](privilege-escalation/#capabilities)

- [ ] Da li neki binarni fajl ima **neočekivani kapacitet**?

### [ACL-ovi](privilege-escalation/#acls)

- [ ] Da li neki fajl ima **neočekivani ACL**?

### [Otvorene Shell sesije](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL Predvidljiv PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Zanimljive konfiguracione vrednosti**](privilege-escalation/#ssh-interesting-configuration-values)

### [Zanimljivi fajlovi](privilege-escalation/#interesting-files)

- [ ] **Profilni fajlovi** - Pročitati osetljive podatke? Pisati za privesc?
- [ ] **passwd/shadow fajlovi** - Pročitati osetljive podatke? Pisati za privesc?
- [ ] **Proveriti uobičajene zanimljive fascikle** za osetljive podatke
- [ ] **Čudne lokacije/Owned fajlovi,** možda imate pristup ili možete izmeniti izvršne fajlove
- [ ] **Izmenjeni** u poslednjih minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Skripte/Binarni u PATH-u**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Backup-i**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: Koristite **Linpeas** i **LaZagne**
- [ ] **Generička pretraga**

### [**Pisivi fajlovi**](privilege-escalation/#writable-files)

- [ ] **Modifikovati python biblioteku** da izvršava proizvoljne komande?
- [ ] Možete li **modifikovati log fajlove**? **Logtotten** exploit
- [ ] Možete li **modifikovati /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Možete li [**pisati u ini, int.d, systemd ili rc.d fajlove**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Ostali trikovi**](privilege-escalation/#other-tricks)

- [ ] Možete li [**iskoristiti NFS za eskalaciju privilegija**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] Da li treba da [**pobegnete iz restriktivnog shell-a**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
