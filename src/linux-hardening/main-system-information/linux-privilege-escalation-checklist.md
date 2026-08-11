# Kontrolna lista za eskalaciju privilegija na Linuxu

# Kontrolna lista - eskalacija privilegija na Linuxu



### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija na Linuxu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pribaviti **informacije o OS-u**
- [ ] Proveriti [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), da li postoji **folder sa pravom upisa**?
- [ ] Proveriti [**env promenljive**](../linux-basics/linux-privilege-escalation/index.html#env-info), da li sadrže osetljive detalje?
- [ ] Pretražiti [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **pomoću skripti** (DirtyCow?)
- [ ] Pre pokretanja kernel PoC-a proveriti njegove **stvarne preduslove**, a ne samo `uname -r`: arhitekturu, potrebne `CONFIG_*` opcije/module, kreiranje namespace-a i aktivne mitigacije. Na primer, proveriti dostupnost user/network namespace-a pomoću `unshare -Urn true`; moderni netfilter exploit-i mogu zahtevati `CONFIG_USER_NS`, unprivileged user namespace-e i `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Proveriti** da li je [**sudo verzija** ranjiva](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** verifikacija potpisa nije uspela](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Pregledati [**kernel module i module-loading pogrešne konfiguracije**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, sprovođenje potpisa i `modules_disabled`.
- [ ] Proveriti [**putanje za zloupotrebu kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ako se putanja helper-a može izmeniti ili pokrenuti.
- [ ] Proveriti [**writable /lib/modules putanje**](kernel-modules-and-modprobe.md#writable-libmodules-review), uključujući writable `.ko*` fajlove i `modules.*` metadata fajlove.
- [ ] Dodatna enumeracija sistema ([datum, statistika sistema, informacije o CPU-u, štampači](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerisati dodatne odbrane](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Diskovi](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] Izlistati **montirane** diskove
- [ ] **Da li postoji nemontirani disk?**
- [ ] **Da li postoje credentials u fstab-u?**

### [**Instalirani software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Proveriti da li je instaliran** [**koristan software**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Proveriti da li je instaliran** [**ranjiv software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] Na Debian/Ubuntu sistemima proveriti da li je **needrestart interpreter scanning** instaliran/omogućen: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Ranjive verzije su prelazile granicu privilegija ponovnim korišćenjem vrednosti `PYTHONPATH`/`RUBYLIB` pod kontrolom napadača, race uslovom nad `/proc/<pid>/exe` ili skeniranjem Perl putanja pod kontrolom napadača kada su APT ili `unattended-upgrades` pokretali needrestart kao root.<sup>[[4]](#references)</sup>

### [Procesi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Da li je pokrenut neki **nepoznat software**?
- [ ] Da li neki software radi sa **većim privilegijama nego što bi trebalo**?
- [ ] Pretražiti **exploite pokrenutih procesa** (posebno verziju koja radi).
- [ ] Da li možete **izmeniti binary** nekog pokrenutog procesa?
- [ ] **Nadgledati procese** i proveriti da li se neki zanimljiv proces često pokreće.
- [ ] Da li možete **čitati** memoriju nekog zanimljivog **procesa** (gde mogu biti sačuvane lozinke)?

### [Zakazani/Cron poslovi?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li neki cron menja [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)i da li imate pravo **upisa** u njega?
- [ ] Da li se u cron poslu nalazi [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Da li se neka [**izmenjiva skripta** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**izvršava** ili se nalazi unutar **izmenjivog foldera**?
- [ ] Da li ste otkrili da bi se neka **skripta** mogla ili da se već [**izvršava** veoma **često**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (svakog 1, 2 ili 5 minuta)

### [Servisi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Da li postoji **writable .service** fajl?
- [ ] Da li neki **writable binary** izvršava **servis**?
- [ ] Da li postoji writable **helper, config ili environment fajl na koji se root unit poziva** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Pregledati objedinjeni unit pomoću `systemctl cat <unit>` i proveriti [zloupotrebu service/socket fajlova](../interesting-files-permissions/write-to-root.md).
- [ ] Da li postoji **writable folder u systemd PATH-u**?
- [ ] Da li postoji **writable systemd unit drop-in** u `/etc/systemd/system/<unit>.d/*.conf` koji može da prepiše `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timer-i](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Da li postoji **writable timer**?

### [Socket-i](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Da li postoji **writable .socket** fajl?
- [ ] Da li možete **komunicirati sa nekim socket-om**?
- [ ] **HTTP socket-i** sa zanimljivim informacijama?
- [ ] Da li možete pristupiti [**container-runtime ili node-agent API-ju**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), kao što su `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ili kubelet endpoint? Testirati sirovi HTTP/gRPC API čak i kada njegov uobičajeni CLI nije prisutan.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Da li možete **komunicirati sa nekim D-Bus-om**?

### [Mreža](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerisati mrežu da biste utvrdili gde se nalazite
- [ ] **Otvoreni portovi kojima ranije niste mogli pristupiti** nakon dobijanja shell-a unutar mašine?
- [ ] Da li možete **sniff-ovati saobraćaj** pomoću `tcpdump`-a?

### [Korisnici](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Opšta **enumeracija korisnika/grupa**
- [ ] Da li imate **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Da li možete [**eskalirati privilegije zahvaljujući grupi**](../user-information/interesting-groups-linux-pe/index.html) čiji ste član?
- [ ] Podaci iz **clipboard-a**?
- [ ] Politika lozinki?
- [ ] Pokušati da **iskoristite** svaku **poznatu lozinku** koju ste ranije otkrili za prijavljivanje **svakim** mogućim **korisnikom**. Pokušati prijavljivanje i bez lozinke.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imate **prava upisa u neki folder unutar PATH-a**, možda možete eskalirati privilegije

### [SUDO i SUID komande](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Da li možete izvršiti **neku komandu pomoću sudo**? Možete li je koristiti za ČITANJE, UPIS ili IZVRŠAVANJE bilo čega kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ako `sudo -l` dozvoljava `sudoedit`, proveriti **sudoedit argument injection** (CVE-2023-22809) pomoću `SUDO_EDITOR`/`VISUAL`/`EDITOR` za izmenu proizvoljnih fajlova na ranjivim verzijama (`sudo -V` < 1.9.12p2). Primer: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Da li postoji **iskoristiv SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** putanjom? Možete li **zaobići ograničenja**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bez navedene putanje**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary sa navedenom putanjom**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Zaobići
- [ ] [**LD_PRELOAD ranjivost**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Nedostajući .so library u SUID binary-ju**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) iz writable foldera?
- [ ] [**SUID RPATH/RUNPATH ili writable library putanja**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokeni dostupni**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Možete li kreirati SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
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
- [ ] [**Zanimljive SSH vrednosti konfiguracije**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Zanimljivi fajlovi](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile fajlovi** - Pročitati osetljive podatke? Pisati za privesc?
- [ ] **passwd/shadow fajlovi** - Pročitati osetljive podatke? Pisati za privesc?
- [ ] **Proveriti uobičajeno zanimljive foldere** za osetljive podatke
- [ ] **Neobične lokacije/fajlovi u vlasništvu,** kojima možete pristupiti ili izmeniti executable fajlove
- [ ] **Izmenjeno** u poslednjih nekoliko minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Skripte/Binaries u PATH-u**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Backup-i**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: Koristiti **Linpeas** i **LaZagne**
- [ ] **Opšta pretraga**

### [**Writable fajlovi**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Izmeniti Python library** za izvršavanje proizvoljnih komandi?
- [ ] Da li možete **izmeniti log fajlove**? **Logtotten** exploit
- [ ] Da li možete **izmeniti /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Da li možete [**pisati u ini, int.d, systemd ili rc.d fajlove**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Druge tehnike**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Da li možete [**zloupotrebiti NFS za eskalaciju privilegija**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Da li je potrebno da [**izađete iz restrictive shell-a**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo savet: sudoedit izmena proizvoljnog fajla](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux dokumentacija: systemd drop-in konfiguracija](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 zahtevi exploit-a i istraživanje](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys bezbednosni savet: LPE-ovi u needrestart-u](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
