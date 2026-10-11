# Kontrolna lista za eskalaciju privilegija u Linuxu

{{#include ../../banners/hacktricks-training.md}}

# Kontrolna lista - eskalacija privilegija u Linuxu



### **Najbolji alat za traženje vektora lokalne eskalacije privilegija u Linuxu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Prikupite **informacije o OS-u**
- [ ] Proverite [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), postoji li **folder sa dozvolom za pisanje**?
- [ ] Proverite [**env promenljive**](../linux-basics/linux-privilege-escalation/index.html#env-info), ima li osetljivih podataka?
- [ ] Pomoću [**skripti**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) potražite **kernel exploit-e** (DirtyCow?)
- [ ] Pre pokretanja kernel PoC-a proverite njegove **stvarne preduslove**, a ne samo `uname -r`: arhitekturu, potrebne opcije/module `CONFIG_*`, kreiranje namespace-ova i aktivne mere ublažavanja. Na primer, proverite da li su dostupni user/network namespace-ovi pomoću `unshare -Urn true`; savremenim netfilter exploit-ima mogu biti potrebni `CONFIG_USER_NS`, neprivilegovani user namespace-ovi i `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Proverite** da li je [**sudo verzija** ranjiva](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** provera potpisa nije uspela](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Pregledajte [**pogrešne konfiguracije kernel modula i učitavanja modula**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, sprovođenje provere potpisa i `modules_disabled`.
- [ ] Proverite [**puteve za zloupotrebu kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ako se putanja pomoćnog programa može izmeniti ili aktivirati.
- [ ] Proverite [**putanje /lib/modules sa dozvolom za pisanje**](kernel-modules-and-modprobe.md#writable-libmodules-review), uključujući `.ko*` fajlove i metapodatke `modules.*` sa dozvolom za pisanje.
- [ ] Prikupite još informacija o sistemu ([datum, statistika sistema, informacije o CPU-u, štampači](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Nabrojte dodatne mere zaštite](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Diskovi](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Nabrojte montirane** diskove
- [ ] Ima li **nemontiranih diskova**?
- [ ] Ima li **kredencijala u fstab-u**?

### [**Instalirani softver**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Proverite da li je instaliran** [**koristan softver**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Proverite da li je instaliran** [**ranjiv softver**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] Na Debian/Ubuntu sistemima proverite da li je instalirano/omogućeno **needrestart skeniranje interpretera**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Ranjive verzije prelazile su granicu privilegija ponovnim korišćenjem napadačevih `PYTHONPATH`/`RUBYLIB` promenljivih, utrkivanjem sa `/proc/<pid>/exe` ili skeniranjem Perl putanja pod kontrolom napadača, kada bi APT ili `unattended-upgrades` pozvali needrestart kao root.<sup>[[4]](#references)</sup>

### [Procesi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Da li je pokrenut neki **nepoznat softver**?
- [ ] Da li neki softver radi sa **većim privilegijama nego što bi trebalo**?
- [ ] Potražite **exploit-e za pokrenute procese** (posebno za verziju koja je pokrenuta).
- [ ] Možete li **izmeniti binarni fajl** nekog pokrenutog procesa?
- [ ] **Nadgledajte procese** i proverite da li se neki zanimljiv proces često pokreće.
- [ ] Možete li **čitati** memoriju nekog zanimljivog **procesa** (u kojoj bi mogle biti sačuvane lozinke)?

### [Zakazani/Cron poslovi?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li se [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)menja putem nekog cron posla i možete li da **pišete** u njega?
- [ ] Ima li [**džoker znakova** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)u cron poslu?
- [ ] Da li se **izvršava** neka [**skripta koju je moguće izmeniti** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)ili se ona nalazi u **folderu koji je moguće izmeniti**?
- [ ] Da li ste otkrili da bi neka **skripta** mogla da se [**izvršava** veoma **često**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) ili se već tako izvršava? (svakih 1, 2 ili 5 minuta)

### [Servisi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Ima li **.service fajlova sa dozvolom za pisanje**?
- [ ] Ima li **binarnih fajlova sa dozvolom za pisanje** koje **servis** izvršava?
- [ ] Ima li neki **pomoćni, konfiguracioni ili environment fajl sa dozvolom za pisanje na koji upućuje root jedinica** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Pregledajte spojenu jedinicu pomoću `systemctl cat <unit>` i proverite [zloupotrebu service/socket fajlova](../interesting-files-permissions/write-to-root.md).
- [ ] Pokreće li se pomoćni program u privilegovanom toku rada na zahtev iz direktorijuma nižih privilegija u koji može da se piše? Proverite i pomoćni program i njegov nadređeni direktorijum u potrazi za [root izvršavanjem putanja koje korisnik može da menja](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); kratkotrajni pomoćni programi mogu biti vidljivi samo dok je tok rada aktivan.
- [ ] Ima li **foldera sa dozvolom za pisanje u systemd PATH-u**?
- [ ] Ima li **systemd drop-in fajlova sa dozvolom za pisanje** u `/etc/systemd/system/<unit>.d/*.conf` koji mogu da zamene `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Tajmeri](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Ima li **tajmera sa dozvolom za pisanje**?

### [Socket-i](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Ima li **.socket fajlova sa dozvolom za pisanje**?
- [ ] Možete li **komunicirati sa nekim socket-om**?
- [ ] Ima li **HTTP socket-a** sa zanimljivim informacijama?
- [ ] Možete li pristupiti [**API-ju container-runtime-a ili node-agent-a**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), kao što su `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ili kubelet endpoint? Testirajte sirovi HTTP/gRPC API čak i ako uobičajeni CLI nije dostupan.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Možete li **komunicirati sa nekim D-Bus-om**?

### [Mreža](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Istražite mrežu da biste utvrdili gde se nalazite
- [ ] Da li postoje **otvoreni portovi kojima ranije niste mogli da pristupite**, pre nego što ste dobili shell na mašini?
- [ ] Možete li **hvatati mrežni saobraćaj** pomoću `tcpdump`?

### [Korisnici](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Opšte **nabrajanje korisnika/grupa**
- [ ] Imate li **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Možete li [**eskalirati privilegije zahvaljujući grupi**](../user-information/interesting-groups-linux-pe/index.html) kojoj pripadate?
- [ ] Podaci iz **clipboard-a**?
- [ ] Politika lozinki?
- [ ] Pokušajte da se prijavite kao svaki mogući **korisnik** koristeći svaku **poznatu lozinku** koju ste prethodno otkrili. Pokušajte da se prijavite i bez lozinke.

### [PATH sa dozvolom za pisanje](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imate **dozvole za pisanje u neki folder u PATH-u**, možda ćete moći da eskalirate privilegije

### [SUDO i SUID komande](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Možete li izvršiti **neku komandu pomoću sudo**? Možete li ga upotrebiti da čitate, pišete ili izvršavate bilo šta kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ako `sudo -l` dozvoljava `sudoedit`, proverite **sudoedit ubacivanje argumenata** (CVE-2023-22809) preko `SUDO_EDITOR`/`VISUAL`/`EDITOR` da biste menjali proizvoljne fajlove na ranjivim verzijama (`sudo -V` < 1.9.12p2). Primer: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Postoji li **iskoristiv SUID binarni fajl**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** putanjom](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)? Možete li **zaobići** ograničenja?
- [ ] [**Sudo/SUID binarni fajl bez navedene putanje**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binarni fajl sa navedenom putanjom**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Zaobiđite ograničenje
- [ ] [**LD_PRELOAD ranjivost**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Nedostaje li [**.so biblioteka u SUID binarnom fajlu**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) iz foldera sa dozvolom za pisanje?
- [ ] [**SUID RPATH/RUNPATH ili putanja biblioteke sa dozvolom za pisanje**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] Jesu li [**SUDO tokeni dostupni**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Možete li kreirati SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Možete li [**čitati ili menjati sudoers fajlove**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Možete li [**izmeniti /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Komanda [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Ima li neki binarni fajl **neočekivanu capability**?

### [ACL-ovi](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Ima li neki fajl **neočekivan ACL**?

### [Otvorene shell sesije](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Predvidiv OpenSSL PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Zanimljive vrednosti SSH konfiguracije**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Zanimljivi fajlovi](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile fajlovi** - Mogu li se pročitati osetljivi podaci? Može li se pisati radi eskalacije privilegija?
- [ ] **passwd/shadow fajlovi** - Mogu li se pročitati osetljivi podaci? Može li se pisati radi eskalacije privilegija?
- [ ] **Proverite uobičajeno zanimljive foldere** u potrazi za osetljivim podacima
- [ ] **Neobične lokacije/fajlovi u vlasništvu korisnika** kojima možda možete pristupiti ili izmeniti izvršne fajlove
- [ ] Fajlovi **izmenjeni** u poslednjih nekoliko minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Skripte/binarni fajlovi u PATH-u**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Rezervne kopije**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: koristite **Linpeas** i **LaZagne**
- [ ] **Opšta pretraga**

### [**Fajlovi sa dozvolom za pisanje**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Možete li **izmeniti Python biblioteku** da biste izvršili proizvoljne komande?
- [ ] Možete li **izmeniti log fajlove**? **Logtotten** exploit
- [ ] Možete li **izmeniti /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Možete li [**pisati u ini, int.d, systemd ili rc.d fajlove**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ostali trikovi**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Možete li [**zloupotrebiti NFS za eskalaciju privilegija**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Treba li da [**izađete iz restriktivnog shell-a**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo bezbednosno obaveštenje: sudoedit omogućava proizvoljno uređivanje fajlova](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux dokumentacija: systemd drop-in konfiguracija](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: zahtevi za CVE-2024-1086 exploit i istraživanje](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys bezbednosno obaveštenje: LPE-ovi u needrestart-u](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
