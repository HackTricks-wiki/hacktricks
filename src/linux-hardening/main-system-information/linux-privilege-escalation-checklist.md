# Kontrolna lista za Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Kontrolna lista - Linux Privilege Escalation



### **Najbolji alat za pronalaženje Linux local privilege escalation vektora:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pribavi **informacije o OS-u**
- [ ] Proveri [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), da li postoji **folder sa pravom upisa**?
- [ ] Proveri [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), da li sadrže osetljive podatke?
- [ ] Pretraži [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **pomoću skripti** (DirtyCow?)
- [ ] Pre pokretanja kernel PoC-a proveri njegove **stvarne prerequisites**, a ne samo `uname -r`: arhitekturu, potrebne `CONFIG_*` opcije/module, kreiranje namespace-a i aktivne mitigacije. Na primer, testiraj dostupnost user/network namespace-a pomoću `unshare -Urn true`; moderni netfilter exploits mogu zahtevati `CONFIG_USER_NS`, unprivileged user namespaces i `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Proveri** da li je [**sudo version** ranjiva](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** verifikacija potpisa nije uspela](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Pregledaj [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, sprovođenje verifikacije potpisa i `modules_disabled`.
- [ ] Proveri [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ako se putanja helper-a može izmeniti ili aktivirati.
- [ ] Proveri [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), uključujući `.ko*` fajlove i `modules.*` metadata fajlove sa pravom upisa.
- [ ] Dodatna enumeracija sistema ([datum, statistika sistema, informacije o CPU-u, štampači](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumeriši dodatne odbrane](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Diskovi](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Izlistaj montirane** diskove
- [ ] **Da li postoji nemontiran disk?**
- [ ] **Da li postoje credsi u fstab-u?**

### [**Instalirani software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Proveri da li je instaliran** [**koristan software**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Proveri da li je instaliran** [**ranjiv software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] Na Debian/Ubuntu sistemima proveri da li je instalirano/omogućeno **needrestart interpreter scanning**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Ranjive verzije su prelazile granicu privilegija ponovnim korišćenjem vrednosti `PYTHONPATH`/`RUBYLIB` pod kontrolom napadača, utrkivanjem sa `/proc/<pid>/exe` ili skeniranjem Perl putanja pod kontrolom napadača kada su APT ili `unattended-upgrades` pozivali needrestart kao root.<sup>[[4]](#references)</sup>

### [Procesi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Da li se izvršava neki **nepoznat software**?
- [ ] Da li se neki software izvršava sa **većim privilegijama nego što bi trebalo**?
- [ ] Pretraži **exploits za pokrenute procese** (posebno za pokrenutu verziju).
- [ ] Da li možeš da **izmeniš binary** nekog pokrenutog procesa?
- [ ] **Nadgledaj procese** i proveri da li se neki zanimljiv proces često izvršava.
- [ ] Da li možeš da **čitaš** memoriju nekog zanimljivog **procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Da li neki cron menja [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)i možeš li da **upisuješ** u njega?
- [ ] Da li se u cron poslu koristi [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Da li se neki [**script sa pravom izmene** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **izvršava** ili se nalazi unutar **foldera sa pravom izmene**?
- [ ] Da li si otkrio da bi neka **skripta** mogla biti ili da se već [**izvršava** veoma **često**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (svakog 1, 2 ili 5 minuta)

### [Servisi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Da li postoji neki **.service fajl sa pravom upisa**?
- [ ] Da li postoji neki **binary sa pravom upisa** koji izvršava **servis**?
- [ ] Da li postoji neki helper, config ili environment fajl sa pravom upisa na koji se poziva root unit (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Pregledaj spojeni unit pomoću `systemctl cat <unit>` i proveri [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Da li postoji neki **folder sa pravom upisa u systemd PATH-u**?
- [ ] Da li postoji neki **systemd unit drop-in sa pravom upisa** u `/etc/systemd/system/<unit>.d/*.conf` koji može da premosti `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timeri](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Da li postoji neki **timer sa pravom upisa**?

### [Socketi](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Da li postoji neki **.socket fajl sa pravom upisa**?
- [ ] Da li možeš da **komuniciraš sa nekim socketom**?
- [ ] Da li postoje **HTTP socketi** sa zanimljivim informacijama?
- [ ] Da li možeš da pristupiš [**container-runtime ili node-agent API-ju**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), kao što su `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ili kubelet endpoint? Testiraj raw HTTP/gRPC API čak i kada njegov uobičajeni CLI nije prisutan.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Da li možeš da **komuniciraš sa nekim D-Bus-om**?

### [Mreža](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumeriši mrežu da bi utvrdio gde se nalaziš
- [ ] Da li postoje **otvoreni portovi kojima ranije nisi mogao da pristupiš** nakon dobijanja shell-a unutar mašine?
- [ ] Da li možeš da **snimaš saobraćaj** pomoću `tcpdump`?

### [Korisnici](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generička **enumeracija korisnika/grupa**
- [ ] Da li imaš **veoma veliki UID**? Da li je **mašina** **ranjiva**?
- [ ] Da li možeš da [**eskaliraš privilegije zahvaljujući grupi**](../user-information/interesting-groups-linux-pe/index.html) kojoj pripadaš?
- [ ] Podaci iz **clipboard-a**?
- [ ] Policy lozinki?
- [ ] Pokušaj da **upotrebiš** svaku **poznatu lozinku** koju si prethodno otkrio za login **sa svakim** mogućim **korisnikom**. Pokušaj login i bez lozinke.

### [PATH sa pravom upisa](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ako imaš **pravo upisa u neki folder u PATH-u**, možda ćeš moći da eskaliraš privilegije

### [SUDO i SUID komande](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Da li možeš da izvršiš **bilo koju komandu pomoću sudo**? Možeš li da je upotrebiš za READ, WRITE ili EXECUTE bilo čega kao root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ako `sudo -l` dozvoljava `sudoedit`, proveri **sudoedit argument injection** (CVE-2023-22809) pomoću `SUDO_EDITOR`/`VISUAL`/`EDITOR` za izmenu proizvoljnih fajlova na ranjivim verzijama (`sudo -V` < 1.9.12p2). Primer: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Da li postoji neki **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Da li su [**sudo** komande **ograničene** putanjom? Možeš li da **zaobiđeš ograničenja**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bez navedene putanje**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary sa navedenom putanjom**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Zaobilaženje
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Nedostatak .so biblioteke u SUID binary-ju**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) iz foldera sa pravom upisa?
- [ ] [**SUID RPATH/RUNPATH ili putanja biblioteke sa pravom upisa**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokeni dostupni**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Možeš li da kreiraš SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Možeš li da [**čitaš ili izmeniš sudoers fajlove**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Možeš li da [**izmeniš /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
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

- [ ] **Profile fajlovi** - Pročitati osetljive podatke? Upis za privesc?
- [ ] **passwd/shadow fajlovi** - Pročitati osetljive podatke? Upis za privesc?
- [ ] **Proveri uobičajeno zanimljive foldere** za osetljive podatke
- [ ] **Fajlovi na neobičnoj lokaciji/u vlasništvu,** kojima možda možeš pristupiti ili izmeniti executable fajlove
- [ ] **Izmenjeni** u poslednjih nekoliko minuta
- [ ] **Sqlite DB fajlovi**
- [ ] **Skriveni fajlovi**
- [ ] **Skripte/Binaries u PATH-u**
- [ ] **Web fajlovi** (lozinke?)
- [ ] **Backup-i**?
- [ ] **Poznati fajlovi koji sadrže lozinke**: Upotrebi **Linpeas** i **LaZagne**
- [ ] **Generička pretraga**

### [**Fajlovi sa pravom upisa**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Izmeni python biblioteku** da bi izvršila proizvoljne komande?
- [ ] Možeš li da **izmeniš log fajlove**? **Logtotten** exploit
- [ ] Možeš li da **izmeniš /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Možeš li da [**upisuješ u ini, int.d, systemd ili rc.d fajlove**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Ostali trikovi**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Možeš li da [**zloupotrebiš NFS za eskalaciju privilegija**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Da li treba da [**izađeš iz restrictive shell-a**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Reference

- [1] [Sudo advisory: sudoedit izmena proizvoljnog fajla](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in konfiguracija](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit zahtevi i istraživanje](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPE-ovi u needrestart-u](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
