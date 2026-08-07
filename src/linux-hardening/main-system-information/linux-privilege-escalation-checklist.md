# Lista za proveru eskalacije privilegija na Linuxu

{{#include ../../banners/hacktricks-training.md}}

# Lista za proveru - eskalacija privilegija na Linuxu



### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija na Linuxu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pribavite **informacije o OS-u**
- [ ] Proverite [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), da li postoji **folder sa dozvolom za pisanje**?
- [ ] Proverite [**env promenljive**](../linux-basics/linux-privilege-escalation/index.html#env-info), da li sadrže osetljive detalje?
- [ ] Pretražite [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **pomoću skripti** (DirtyCow?)
- [ ] **Proverite** da li je [**sudo verzija** ranjiva](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** verifikacija potpisa nije uspela](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Pregledajte [**pogrešne konfiguracije kernel modula i učitavanja modula**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, nametanje potpisa i `modules_disabled`.
- [ ] Proverite [**putanje za zloupotrebu kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ako se putanja pomoćnog programa može izmeniti ili pokrenuti.
- [ ] Proverite [**putanje sa dozvolom za pisanje u /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), uključujući `.ko*` fajlove i `modules.*` metapodatke sa dozvolom za pisanje.
- [ ] Dodatna enumeracija sistema ([datum, statistika sistema, informacije o CPU-u, štampači](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerišite dodatne odbrane](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Diskovi](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] Izlistajte **montirane** diskove
- [ ] **Da li postoji nemontiran disk?**
- [ ] **Da li u fstab-u postoje kredencijali?**

### [**Instalirani softver**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Proverite da li je instaliran** [**koristan softver**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Proverite da li je instaliran** [**ranjiv softver**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)

### [Procesi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Da li je pokrenut neki **nepoznat softver**?
- [ ] Da li neki softver radi sa **većim privilegijama nego što bi trebalo**?
- [ ] Pretražite **exploite pokrenutih procesa** (naročito verziju koja je pokrenuta).
- [ ] Možete li **izmeniti binarni fajl** nekog pokrenutog procesa?
- [ ] **Nadgledajte procese** i proverite da li se neki zanimljiv proces često pokreće.
- [ ] Možete li **čitati** memoriju nekog zanimljivog **procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li neki cron menja [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)i da li imate mogućnost **pisanja** u njega?
- [ ] Da li se u cron poslu koristi neki [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Da li se neka [**skripta koja se može izmeniti** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**izvršava** ili se nalazi unutar **foldera koji se može izmeniti**?
- [ ] Da li ste otkrili da bi neka **skripta** mogla biti ili da se već [**izvršava** veoma **često**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (svakih 1, 2 ili 5 minuta)

### [Servisi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Da li postoji **.service** fajl sa dozvolom za pisanje?
- [ ] Da li postoji **binarni fajl sa dozvolom za pisanje** koji izvršava neki **servis**?
- [ ] Da li postoji **folder sa dozvolom za pisanje u systemd PATH-u**?
- [ ] Da li postoji **systemd unit drop-in sa dozvolom za pisanje** u `/etc/systemd/system/<unit>.d/*.conf` koji može da nadjača `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timeri](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Da li postoji **timer sa dozvolom za pisanje**?

### [Socketi](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Da li postoji **.socket** fajl sa dozvolom za pisanje?
- [ ] Možete li **komunicirati sa nekim socketom**?
- [ ] **HTTP socketi** sa zanimljivim informacijama?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Možete li **komunicirati sa nekim D-Bus-om**?

### [Mreža](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerišite mrežu da biste utvrdili gde se nalazite
- [ ] **Otvoreni portovi kojima ranije niste mogli da pristupite** nakon dobijanja shell-a unutar mašine?
- [ ] Možete li **prisluškivati saobraćaj** pomoću `tcpdump`?

### [Korisnici](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generička **enumeracija korisnika/grupa**
- [ ] Da li imate **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Možete li [**eskalirati privilegije zahvaljujući grupi**](../user-information/interesting-groups-linux-pe/index.html) kojoj pripadate?
- [ ] Podaci iz **clipboard-a**?
- [ ] Politika lozinki?
- [ ] Pokušajte da **upotrebite** svaku **poznatu lozinku** koju ste ranije otkrili za prijavljivanje **sa svakim** mogućim **korisnikom**. Pokušajte da se prijavite i bez lozinke.

### [PATH sa dozvolom za pisanje](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imate **dozvole za pisanje nad nekim folderom u PATH-u**, možda ćete moći da eskalirate privilegije

### [SUDO i SUID komande](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Možete li izvršiti **bilo koju komandu sa sudo**? Možete li je upotrebiti za ČITANJE, PISANJE ili IZVRŠAVANJE bilo čega kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ako `sudo -l` dozvoljava `sudoedit`, proverite **sudoedit argument injection** (CVE-2023-22809) preko `SUDO_EDITOR`/`VISUAL`/`EDITOR` za izmenu proizvoljnih fajlova na ranjivim verzijama (`sudo -V` < 1.9.12p2). Primer: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Da li postoji **SUID binarni fajl koji se može iskoristiti**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** putanjom? Možete li **zaobići ograničenja**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binarni fajl bez navedene putanje**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binarni fajl sa navedenom putanjom**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Zaobilaženje
- [ ] [**LD_PRELOAD ranjivost**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Nedostatak .so biblioteke u SUID binarnom fajlu**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) iz foldera sa dozvolom za pisanje?
- [ ] [**SUID RPATH/RUNPATH ili putanja biblioteke sa dozvolom za pisanje**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokeni dostupni**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Možete li kreirati SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Možete li [**čitati ili izmeniti sudoers fajlove**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Možete li [**izmeniti /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Komanda [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Da li neki binarni fajl ima neku **neočekivanu capability**?

### [ACL-ovi](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Da li neki fajl ima neki **neočekivani ACL**?

### [Otvorene shell sesije](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Zanimljive vrednosti SSH konfiguracije**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Zanimljivi fajlovi](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile fajlovi** - Pročitati osetljive podatke? Pisati radi privesc-a?
- [ ] **passwd/shadow fajlovi** - Pročitati osetljive podatke? Pisati radi privesc-a?
- [ ] **Proverite uobičajeno zanimljive foldere** za osetljive podatke
- [ ] **Neobična lokacija/fajlovi u vlasništvu,** možda imate pristup izvršnim fajlovima ili možete da ih izmenite
- [ ] **Izmenjeni** u poslednjih nekoliko minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Skripte/binarni fajlovi u PATH-u**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Backup-i**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: Koristite **Linpeas** i **LaZagne**
- [ ] **Generička pretraga**

### [**Fajlovi sa dozvolom za pisanje**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Izmeniti Python biblioteku** radi izvršavanja proizvoljnih komandi?
- [ ] Možete li **izmeniti log fajlove**? **Logtotten** exploit
- [ ] Možete li **izmeniti /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Možete li [**pisati u ini, int.d, systemd ili rc.d fajlove**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ostale tehnike**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Možete li [**zloupotrebiti NFS za eskalaciju privilegija**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Da li morate da [**izađete iz restriktivnog shell-a**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?

## Reference

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
