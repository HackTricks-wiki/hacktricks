# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija na Linuxu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](privilege-escalation/index.html#system-information)

- [ ] Dobiti **informacije o OS-u**
- [ ] Proveriti [**PATH**](privilege-escalation/index.html#path), da li postoji **pisiva fascikla**?
- [ ] Proveriti [**env promenljive**](privilege-escalation/index.html#env-info), da li postoji neka osetljiva informacija?
- [ ] Tražiti [**kernel exploit-e**](privilege-escalation/index.html#kernel-exploits) **koristeći skripte** (DirtyCow?)
- [ ] **Proveriti** da li je [**sudo verzija** ranjiva](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** verifikacija potpisa nije uspela](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Više sistemskih enumeracija ([datum, sistemske statistike, cpu informacije, štampači](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerisati više odbrana](privilege-escalation/index.html#enumerate-possible-defenses)

### [Diskovi](privilege-escalation/index.html#drives)

- [ ] **Lista montiranih** diskova
- [ ] **Da li postoji neki nemontirani disk?**
- [ ] **Da li postoje kredencijali u fstab?**

### [**Instalirani softver**](privilege-escalation/index.html#installed-software)

- [ ] **Proveriti** [**koristan softver**](privilege-escalation/index.html#useful-software) **koji je instaliran**
- [ ] **Proveriti** [**ranjiv softver**](privilege-escalation/index.html#vulnerable-software-installed) **koji je instaliran**

### [Procesi](privilege-escalation/index.html#processes)

- [ ] Da li se pokreće neki **nepoznati softver**?
- [ ] Da li se neki softver pokreće sa **više privilegija nego što bi trebao**?
- [ ] Tražiti **exploite pokrenutih procesa** (posebno verziju koja se pokreće).
- [ ] Možete li **modifikovati binarni** fajl nekog pokrenutog procesa?
- [ ] **Pratiti procese** i proveriti da li se neki zanimljiv proces često pokreće.
- [ ] Možete li **pročitati** neku zanimljivu **memoriju procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li se [**PATH**](privilege-escalation/index.html#cron-path) menja od strane nekog crona i možete li u njega **pisati**?
- [ ] Da li postoji neki [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) u cron poslu?
- [ ] Da li se neki [**modifikovani skript**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) **izvršava** ili se nalazi u **modifikovanoj fascikli**?
- [ ] Da li ste otkrili da se neki **skript** može ili se **izvršava vrlo često**](privilege-escalation/index.html#frequent-cron-jobs)? (svakih 1, 2 ili 5 minuta)

### [Servisi](privilege-escalation/index.html#services)

- [ ] Da li postoji neki **pisivi .service** fajl?
- [ ] Da li postoji neki **pisivi binarni** fajl koji izvršava **servis**?
- [ ] Da li postoji neka **pisiva fascikla u systemd PATH**?

### [Tajmeri](privilege-escalation/index.html#timers)

- [ ] Da li postoji neki **pisivi tajmer**?

### [Soketi](privilege-escalation/index.html#sockets)

- [ ] Da li postoji neki **pisivi .socket** fajl?
- [ ] Možete li **komunicirati sa nekim soketom**?
- [ ] **HTTP soketi** sa zanimljivim informacijama?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Možete li **komunicirati sa nekim D-Bus**?

### [Mreža](privilege-escalation/index.html#network)

- [ ] Enumerisati mrežu da biste znali gde se nalazite
- [ ] **Otvoreni portovi koje niste mogli da pristupite pre** nego što ste dobili shell unutar mašine?
- [ ] Možete li **sniff-ovati saobraćaj** koristeći `tcpdump`?

### [Korisnici](privilege-escalation/index.html#users)

- [ ] Generička enumeracija korisnika/grupa
- [ ] Da li imate **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Možete li [**escalirati privilegije zahvaljujući grupi**](privilege-escalation/interesting-groups-linux-pe/) kojoj pripadate?
- [ ] **Clipboard** podaci?
- [ ] Politika lozinki?
- [ ] Pokušajte da **koristite** svaku **poznatu lozinku** koju ste prethodno otkrili da se prijavite **sa svakim** mogućim **korisnikom**. Pokušajte da se prijavite i bez lozinke.

### [Pisivi PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imate **privilegije pisanja nad nekom fasciklom u PATH** možda ćete moći da eskalirate privilegije

### [SUDO i SUID komande](privilege-escalation/index.html#sudo-and-suid)

- [ ] Možete li izvršiti **bilo koju komandu sa sudo**? Možete li ga koristiti da ČITATE, PIŠETE ili IZVRŠAVATE bilo šta kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li postoji neki **exploitable SUID binarni**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** po **putanji**? Možete li **obići** ograničenja](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binarni bez naznačene putanje**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binarni koji naznačava putanju**](privilege-escalation/index.html#suid-binary-with-command-path)? Obilaženje
- [ ] [**LD_PRELOAD ranjivost**](privilege-escalation/index.html#ld_preload)
- [ ] [**Nedostatak .so biblioteke u SUID binarnom**](privilege-escalation/index.html#suid-binary-so-injection) iz pisive fascikle?
- [ ] [**SUDO tokeni dostupni**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Možete li kreirati SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Možete li [**čitati ili modifikovati sudoers fajlove**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Možete li [**modifikovati /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) komanda

### [Kapaciteti](privilege-escalation/index.html#capabilities)

- [ ] Da li neki binarni ima neku **neočekivanu sposobnost**?

### [ACL-ovi](privilege-escalation/index.html#acls)

- [ ] Da li neki fajl ima neki **neočekivani ACL**?

### [Otvorene Shell sesije](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predvidljiv PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Zanimljive konfiguracione vrednosti**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Zanimljivi fajlovi](privilege-escalation/index.html#interesting-files)

- [ ] **Profilni fajlovi** - Pročitati osetljive podatke? Pisati za privesc?
- [ ] **passwd/shadow fajlovi** - Pročitati osetljive podatke? Pisati za privesc?
- [ ] **Proveriti uobičajene zanimljive fascikle** za osetljive podatke
- [ ] **Čudne lokacije/Owned fajlovi,** možda imate pristup ili možete izmeniti izvršne fajlove
- [ ] **Izmenjeni** u poslednjih minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Skripte/Binarni u PATH**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Backup-i**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: Koristite **Linpeas** i **LaZagne**
- [ ] **Generička pretraga**

### [**Pisivi fajlovi**](privilege-escalation/index.html#writable-files)

- [ ] **Modifikovati python biblioteku** da izvršava proizvoljne komande?
- [ ] Možete li **modifikovati log fajlove**? **Logtotten** exploit
- [ ] Možete li **modifikovati /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Možete li [**pisati u ini, int.d, systemd ili rc.d fajlove**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ostali trikovi**](privilege-escalation/index.html#other-tricks)

- [ ] Možete li [**iskoristiti NFS za eskalaciju privilegija**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Da li treba da [**pobegnete iz restriktivnog shell-a**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
