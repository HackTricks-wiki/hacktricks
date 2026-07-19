# Checklist - Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora lokalne Linux eskalacije privilegija:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pribavi **informacije o OS-u**
- [ ] Proveri [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), da li postoji **folder sa dozvolom upisa**?
- [ ] Proveri [**env promenljive**](../linux-basics/linux-privilege-escalation/index.html#env-info), da li sadrže osetljive detalje?
- [ ] Pretraži [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **pomoću skripti** (DirtyCow?)
- [ ] **Proveri** da li je [**sudo verzija** ranjiva](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** verifikacija potpisa nije uspela](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Pregledaj [**pogrešne konfiguracije kernel modula i učitavanja modula**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, sprovođenje potpisa i `modules_disabled`.
- [ ] Proveri [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ako putanja pomoćnog programa može da se menja ili aktivira.
- [ ] Proveri [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), uključujući `.ko*` fajlove sa dozvolom upisa i `modules.*` metapodatke.
- [ ] Dodatna enumeracija sistema ([datum, statistika sistema, informacije o CPU-u, štampači](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumeriši dodatne odbrane](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Diskovi](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Izlistaj montirane** diskove
- [ ] **Da li postoji nemontirani disk?**
- [ ] **Da li u fstab-u postoje kredencijali?**

### [**Instalirani softver**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Proveri da li je instaliran**[ **koristan softver**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Proveri da li je instaliran** [**ranjiv softver**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)

### [Procesi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Da li je pokrenut neki **nepoznat softver**?
- [ ] Da li neki softver radi sa **većim privilegijama nego što bi trebalo**?
- [ ] Pretraži **exploit-e pokrenutih procesa** (posebno pokrenutu verziju).
- [ ] Možeš li **izmeniti binarni fajl** nekog pokrenutog procesa?
- [ ] **Nadgledaj procese** i proveri da li se neki zanimljiv proces često pokreće.
- [ ] Možeš li **čitati** memoriju nekog zanimljivog **procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li neki cron menja [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)i da li možeš da vršiš **upis** u njega?
- [ ] Da li se u cron poslu koristi neki [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Da li se neki [**script sa dozvolom izmene** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**izvršava** ili se nalazi unutar **foldera sa dozvolom izmene**?
- [ ] Da li si otkrio da bi neka **skripta** mogla biti ili se trenutno [**izvršava** veoma **često**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (svakih 1, 2 ili 5 minuta)

### [Servisi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Da li postoji **.service fajl sa dozvolom upisa**?
- [ ] Da li neki **binarni fajl sa dozvolom upisa** izvršava **servis**?
- [ ] Da li postoji **folder sa dozvolom upisa u systemd PATH-u**?
- [ ] Da li postoji **systemd unit drop-in sa dozvolom upisa** u `/etc/systemd/system/<unit>.d/*.conf` koji može da nadjača `ExecStart`/`User`?

### [Timer-i](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Da li postoji **timer sa dozvolom upisa**?

### [Socket-i](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Da li postoji **.socket fajl sa dozvolom upisa**?
- [ ] Možeš li da **komuniciraš sa nekim socket-om**?
- [ ] **HTTP socket-i** sa zanimljivim informacijama?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Možeš li da **komuniciraš sa nekim D-Bus-om**?

### [Mreža](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumeriši mrežu da bi saznao gde se nalaziš
- [ ] **Otvoreni portovi kojima ranije nisi mogao da pristupiš** nakon dobijanja shell-a unutar mašine?
- [ ] Možeš li da **snimaš saobraćaj** pomoću `tcpdump`-a?

### [Korisnici](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Opšta **enumeracija korisnika/grupa**
- [ ] Da li imaš **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Možeš li da [**eskaliraš privilegije zahvaljujući grupi**](../user-information/interesting-groups-linux-pe/index.html) kojoj pripadaš?
- [ ] Podaci iz **clipboard-a**?
- [ ] Politika lozinki?
- [ ] Pokušaj da **upotrebiš** svaku **poznatu lozinku** koju si prethodno otkrio za prijavljivanje **sa svakim** mogućim **korisnikom**. Pokušaj prijavljivanje i bez lozinke.

### [PATH sa dozvolom upisa](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imaš **dozvole upisa nad nekim folderom u PATH-u**, možda možeš da eskaliraš privilegije

### [SUDO i SUID komande](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Možeš li da izvršiš **bilo koju komandu pomoću sudo**? Možeš li da je upotrebiš za ČITANJE, UPIS ili IZVRŠAVANJE bilo čega kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ako `sudo -l` dozvoljava `sudoedit`, proveri **sudoedit argument injection** (CVE-2023-22809) preko `SUDO_EDITOR`/`VISUAL`/`EDITOR` za izmenu proizvoljnih fajlova na ranjivim verzijama (`sudo -V` < 1.9.12p2). Primer: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Da li postoji **SUID binarni fajl koji može da se exploituje**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** putanjom? Možeš li da **zaobiđeš** ograničenja](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binarni fajl bez navedene putanje**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binarni fajl sa navedenom putanjom**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Zaobilaženje
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Nedostajuća .so biblioteka u SUID binarnom fajlu**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) iz foldera sa dozvolom upisa?
- [ ] [**SUID RPATH/RUNPATH ili putanja biblioteke sa dozvolom upisa**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokeni dostupni**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Možeš li da kreiraš SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Možeš li da [**čitaš ili menjaš sudoers fajlove**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Možeš li da [**menjaš /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) komanda

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

- [ ] **Profile fajlovi** - Čitanje osetljivih podataka? Upis za privesc?
- [ ] **passwd/shadow fajlovi** - Čitanje osetljivih podataka? Upis za privesc?
- [ ] **Proveri često zanimljive foldere** za osetljive podatke
- [ ] **Fajlovi na neobičnim lokacijama/u vlasništvu,** kojima možda možeš pristupiti ili izmeniti izvršne fajlove
- [ ] **Izmenjeni** u poslednjih nekoliko minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Skripte/Binarni fajlovi u PATH-u**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Backup-i**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: Koristi **Linpeas** i **LaZagne**
- [ ] **Opšta pretraga**

### [**Fajlovi sa dozvolom upisa**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Izmeni python biblioteku** da bi izvršila proizvoljne komande?
- [ ] Možeš li da **menjaš log fajlove**? **Logtotten** exploit
- [ ] Možeš li da **menjaš /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Možeš li da [**pišeš u ini, int.d, systemd ili rc.d fajlove**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ostale tehnike**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Možeš li da [**iskoristiš NFS za eskalaciju privilegija**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Da li treba da [**izađeš iz restriktivnog shell-a**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Reference

- [Sudo savet: sudoedit izmena proizvoljnog fajla](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux dokumentacija: systemd drop-in konfiguracija](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
