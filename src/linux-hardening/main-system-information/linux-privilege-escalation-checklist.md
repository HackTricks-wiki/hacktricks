# Kontrolna lista za Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Kontrolna lista - Linux Privilege Escalation



### **Najbolji alat za pronalaženje vektora za lokalni Linux privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pribaviti **informacije o OS-u**
- [ ] Proveriti [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), da li postoji **folder sa dozvolom za pisanje**?
- [ ] Proveriti [**env promenljive**](../linux-basics/linux-privilege-escalation/index.html#env-info), da li sadrže osetljive detalje?
- [ ] Pretražiti [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **pomoću skripti** (DirtyCow?)
- [ ] **Proveriti** da li je [**sudo verzija** ranjiva](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** verifikacija potpisa nije uspela](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Pregledati [**pogrešne konfiguracije kernel modula i učitavanja modula**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, sprovođenje potpisa i `modules_disabled`.
- [ ] Proveriti [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ako se putanja pomoćnog programa može izmeniti ili pokrenuti.
- [ ] Proveriti [**putanje sa dozvolom za pisanje u /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), uključujući `.ko*` fajlove i `modules.*` metapodatke sa dozvolom za pisanje.
- [ ] Dodatni system enum ([datum, statistika sistema, informacije o CPU-u, štampači](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerisati dodatne odbrane](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Diskovi](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Izlistati montirane** diskove
- [ ] **Da li postoji nemontiran disk?**
- [ ] **Da li postoje kredencijali u fstab-u?**

### [**Instalirani software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Proveriti da li je**[ **koristan software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **instaliran**
- [ ] **Proveriti da li je** [**ranjiv software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **instaliran**

### [Procesi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Da li je pokrenut neki **nepoznat software**?
- [ ] Da li neki software radi sa **većim privilegijama nego što bi trebalo**?
- [ ] Pretražiti **exploits pokrenutih procesa** (naročito verzije koja se izvršava).
- [ ] Da li možete **izmeniti binary** nekog pokrenutog procesa?
- [ ] **Nadgledati procese** i proveriti da li se neki zanimljiv proces često pokreće.
- [ ] Da li možete **čitati** memoriju nekog zanimljivog **procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li neki cron menja [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)i da li možete da **pišete** u njega?
- [ ] Da li postoji [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)u cron poslu?
- [ ] Da li se neki [**izmenjivi script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **izvršava** ili se nalazi unutar **izmenjivog foldera**?
- [ ] Da li ste otkrili da se neki **script** može ili se već [**izvršava** veoma **često**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (svakog 1, 2 ili 5 minuta)

### [Servisi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Da li postoji **.service fajl sa dozvolom za pisanje**?
- [ ] Da li postoji **binary sa dozvolom za pisanje** koji izvršava neki **servis**?
- [ ] Da li postoji **folder sa dozvolom za pisanje u systemd PATH-u**?
- [ ] Da li postoji **systemd unit drop-in sa dozvolom za pisanje** u `/etc/systemd/system/<unit>.d/*.conf` koji može da premosti `ExecStart`/`User`?

### [Timeri](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Da li postoji **timer sa dozvolom za pisanje**?

### [Socketi](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Da li postoji **.socket fajl sa dozvolom za pisanje**?
- [ ] Da li možete **komunicirati sa nekim socketom**?
- [ ] **HTTP socketi** sa zanimljivim informacijama?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Da li možete **komunicirati sa nekim D-Bus-om**?

### [Mreža](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerisati mrežu da biste znali gde se nalazite
- [ ] **Otvoreni portovi kojima ranije niste mogli da pristupite** nakon dobijanja shell-a unutar mašine?
- [ ] Da li možete da **snimate saobraćaj** pomoću `tcpdump`?

### [Korisnici](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Opšta **enumeracija korisnika/grupa**
- [ ] Da li imate **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Da li možete da [**eskalirate privilegije zahvaljujući grupi**](../user-information/interesting-groups-linux-pe/index.html) kojoj pripadate?
- [ ] Podaci iz **Clipboard-a**?
- [ ] Politika lozinki?
- [ ] Pokušajte da **upotrebite** svaku **poznatu lozinku** koju ste prethodno otkrili za prijavljivanje **sa svakim** mogućim **korisnikom**. Pokušajte da se prijavite i bez lozinke.

### [PATH sa dozvolom za pisanje](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imate **dozvole za pisanje nad nekim folderom u PATH-u**, možda ćete moći da eskalirate privilegije

### [SUDO i SUID komande](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Da li možete izvršiti **bilo koju komandu sa sudo**? Da li možete da je upotrebite za ČITANJE, PISANJE ili IZVRŠAVANJE bilo čega kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ako `sudo -l` dozvoljava `sudoedit`, proveriti **sudoedit argument injection** (CVE-2023-22809) preko `SUDO_EDITOR`/`VISUAL`/`EDITOR` za izmenu proizvoljnih fajlova na ranjivim verzijama (`sudo -V` < 1.9.12p2). Primer: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Da li postoji **exploatabilan SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** putanjom? Možete li da **zaobiđete ograničenja**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bez navedene putanje**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary sa navedenom putanjom**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Zaobići
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Nedostajući .so library u SUID binary-ju**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) iz foldera sa dozvolom za pisanje?
- [ ] [**SUID RPATH/RUNPATH ili putanja library-ja sa dozvolom za pisanje**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokeni dostupni**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Možete li kreirati SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Da li možete [**čitati ili izmeniti sudoers fajlove**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Da li možete [**izmeniti /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Komanda [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Da li neki binary ima neku **neočekivanu capability**?

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
- [ ] **Proveriti uobičajeno zanimljive foldere** za osetljive podatke
- [ ] **Neobične lokacije/fajlovi u vlasništvu korisnika,** kojima možda možete pristupiti ili izmeniti executable fajlove
- [ ] **Izmenjeni** u poslednjih nekoliko minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Script/Binaries u PATH-u**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Backup-i**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: Koristiti **Linpeas** i **LaZagne**
- [ ] **Opšta pretraga**

### [**Fajlovi sa dozvolom za pisanje**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Izmeniti python library** radi izvršavanja proizvoljnih komandi?
- [ ] Da li možete **izmeniti log fajlove**? **Logtotten** exploit
- [ ] Da li možete **izmeniti /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Da li možete [**pisati u ini, int.d, systemd ili rc.d fajlove**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ostali trikovi**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Da li možete [**zloupotrebiti NFS za eskalaciju privilegija**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Da li je potrebno da [**izađete iz restriktivnog shell-a**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Reference

- [Sudo savet: sudoedit izmena proizvoljnog fajla](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux dokumentacija: systemd drop-in konfiguracija](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
