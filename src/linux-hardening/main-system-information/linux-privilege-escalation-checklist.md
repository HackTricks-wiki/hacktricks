# Kontrolna lista za Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Kontrolna lista - Linux Privilege Escalation



### **Najbolji alat za pronalaženje vektora za lokalni Linux privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pribaviti **informacije o OS-u**
- [ ] Proveriti [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), da li postoji **folder sa dozvolom za upis**?
- [ ] Proveriti [**env varijable**](../linux-basics/linux-privilege-escalation/index.html#env-info), da li sadrže osetljive podatke?
- [ ] Pretražiti [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **pomoću skripti** (DirtyCow?)
- [ ] Pre pokretanja kernel PoC-a proveriti njegove **stvarne preduslove**, a ne samo `uname -r`: arhitekturu, potrebne `CONFIG_*` opcije/module, kreiranje namespace-ova i aktivne mitigacije. Na primer, proveriti dostupnost user/network namespace-ova pomoću `unshare -Urn true`; moderni netfilter exploits mogu zahtevati `CONFIG_USER_NS`, unprivileged user namespace-ove i `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Proveriti** da li je [**sudo verzija** ranjiva](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** provera potpisa nije uspela](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Pregledati [**pogrešne konfiguracije kernel modula i učitavanja modula**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, enforcement potpisa i `modules_disabled`.
- [ ] Proveriti [**putanje za zloupotrebu kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ako se putanja pomoćnog programa može izmeniti ili aktivirati.
- [ ] Proveriti [**putanje sa dozvolom za upis u /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), uključujući `.ko*` fajlove i `modules.*` metapodatke sa dozvolom za upis.
- [ ] Dodatna system enum provera ([datum, statistika sistema, informacije o CPU-u, štampači](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerisati dodatne odbrane](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Diskovi](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Izlistati montirane** diskove
- [ ] **Da li postoji nemontiran disk?**
- [ ] **Da li postoje kredencijali u fstab-u?**

### [**Instalirani softver**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Proveriti da li je instaliran** [**koristan softver**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Proveriti da li je instaliran** [**ranjiv softver**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] Na Debian/Ubuntu sistemima proveriti da li je **needrestart interpreter scanning** instaliran/omogućen: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Ranjive verzije su prelazile granicu privilegija ponovnim korišćenjem napadačevih `PYTHONPATH`/`RUBYLIB` vrednosti, utrkivanjem sa `/proc/<pid>/exe` ili skeniranjem Perl putanja pod kontrolom napadača kada su APT ili `unattended-upgrades` pokretali needrestart kao root.<sup>[[4]](#references)</sup>

### [Procesi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Da li je pokrenut neki **nepoznat softver**?
- [ ] Da li neki softver radi sa **većim privilegijama nego što bi trebalo**?
- [ ] Pretražiti **exploits za pokrenute procese** (posebno za pokrenutu verziju).
- [ ] Da li možete **izmeniti binarni fajl** nekog pokrenutog procesa?
- [ ] **Nadgledati procese** i proveriti da li se neki zanimljiv proces često pokreće.
- [ ] Da li možete **čitati** memoriju nekog zanimljivog **procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li neki cron menja [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)i da li imate **dozvolu za upis** u njega?
- [ ] Da li se u cron poslu koristi [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Da li se neki [**skript sa dozvolom za izmenu** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **izvršava** ili se nalazi unutar **foldera sa dozvolom za izmenu**?
- [ ] Da li ste otkrili da bi neki **skript** mogao biti ili jeste [**izvršavan** veoma **često**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (svakog 1, 2 ili 5. minuta)

### [Servisi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Da li postoji **.service fajl sa dozvolom za upis**?
- [ ] Da li neki **binarni fajl sa dozvolom za upis** izvršava neki **servis**?
- [ ] Da li postoji pomoćni program, konfiguracioni ili environment fajl sa dozvolom za upis, na koji se root unit poziva (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Pregledati spojeni unit pomoću `systemctl cat <unit>` i pregledati [zloupotrebu service/socket fajlova](../interesting-files-permissions/write-to-root.md).
- [ ] Da li postoji **folder sa dozvolom za upis u systemd PATH-u**?
- [ ] Da li postoji **systemd unit drop-in sa dozvolom za upis** u `/etc/systemd/system/<unit>.d/*.conf`, koji može da nadjača `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timeri](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Da li postoji **timer sa dozvolom za upis**?

### [Socket-i](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Da li postoji **.socket fajl sa dozvolom za upis**?
- [ ] Da li možete **komunicirati sa nekim socket-om**?
- [ ] **HTTP socket-i** sa zanimljivim informacijama?
- [ ] Da li možete pristupiti [**container-runtime ili node-agent API-ju**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), kao što su `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ili kubelet endpoint? Testirati sirovi HTTP/gRPC API čak i kada njegov uobičajeni CLI nije dostupan.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Da li možete **komunicirati sa nekim D-Bus-om**?

### [Mreža](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerisati mrežu da biste saznali gde se nalazite
- [ ] **Otvoreni portovi kojima ranije niste mogli da pristupite** nakon dobijanja shell-a unutar mašine?
- [ ] Da li možete **sniff-ovati saobraćaj** pomoću `tcpdump`?

### [Korisnici](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generička **enumeracija korisnika/grupa**
- [ ] Da li imate **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Da li možete [**eskalirati privilegije zahvaljujući grupi**](../user-information/interesting-groups-linux-pe/index.html) čiji ste član?
- [ ] Podaci iz **clipboard-a**?
- [ ] Politika lozinki?
- [ ] Pokušati da **iskoristite** svaku **poznatu lozinku** koju ste ranije otkrili za prijavljivanje **sa svakim** mogućim **korisnikom**. Pokušati prijavljivanje i bez lozinke.

### [PATH sa dozvolom za upis](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imate **dozvole za upis u neki folder unutar PATH-a**, možda ćete moći da eskalirate privilegije

### [SUDO i SUID komande](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Da li možete izvršiti **bilo koju komandu pomoću sudo**? Da li možete da je iskoristite za ČITANJE, UPIS ili IZVRŠAVANJE bilo čega kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ako `sudo -l` dozvoljava `sudoedit`, proveriti **sudoedit argument injection** (CVE-2023-22809) preko `SUDO_EDITOR`/`VISUAL`/`EDITOR` za izmenu proizvoljnih fajlova na ranjivim verzijama (`sudo -V` < 1.9.12p2). Primer: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Da li postoji **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** putanjom? Možete li **zaobići ograničenja**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bez navedene putanje**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary sa navedenom putanjom**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Zaobilaženje
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Nedostajući .so library u SUID binary-ju**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) iz foldera sa dozvolom za upis?
- [ ] [**SUID RPATH/RUNPATH ili library path sa dozvolom za upis**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Dostupni SUDO tokeni**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Da li možete kreirati SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Da li možete [**čitati ili izmeniti sudoers fajlove**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Da li možete [**izmeniti /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) komanda

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Da li neki binary ima neku **neočekivanu capability**?

### [ACL-ovi](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Da li neki fajl ima neki **neočekivani ACL**?

### [Otvorene shell sesije](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Zanimljive SSH konfiguracione vrednosti**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Zanimljivi fajlovi](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile fajlovi** - Pročitati osetljive podatke? Izmeniti za privesc?
- [ ] **passwd/shadow fajlovi** - Pročitati osetljive podatke? Izmeniti za privesc?
- [ ] **Proveriti često zanimljive foldere** za osetljive podatke
- [ ] **Neobična lokacija/fajlovi u vlasništvu,** možda imate pristup izvršnim fajlovima ili možete da ih izmenite
- [ ] **Izmenjeno** u poslednjih nekoliko minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Skripte/Binary fajlovi u PATH-u**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Backup-i**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: Koristiti **Linpeas** i **LaZagne**
- [ ] **Generička pretraga**

### [**Fajlovi sa dozvolom za upis**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Izmeniti Python library** radi izvršavanja proizvoljnih komandi?
- [ ] Da li možete **izmeniti log fajlove**? **Logtotten** exploit
- [ ] Da li možete **izmeniti /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Da li možete [**pisati u ini, int.d, systemd ili rc.d fajlove**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ostale tehnike**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Da li možete [**zloupotrebiti NFS za eskalaciju privilegija**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Da li je potrebno da [**izađete iz restriktivnog shell-a**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo savet: sudoedit izmena proizvoljnog fajla](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux dokumentacija: systemd drop-in konfiguracija](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: zahtevi i istraživanje za CVE-2024-1086 exploit](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPE-ovi u needrestart-u](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
