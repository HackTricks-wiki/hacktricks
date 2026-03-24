# Checkliste - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool, um Linux local privilege escalation Vektoren zu finden:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Ermittle **OS-Informationen**
- [ ] Überprüfe den [**PATH**](privilege-escalation/index.html#path), gibt es einen **beschreibbaren Ordner**?
- [ ] Überprüfe [**env variables**](privilege-escalation/index.html#env-info), gibt es sensible Details?
- [ ] Suche nach [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **mittels Skripten** (DirtyCow?)
- [ ] Prüfe, ob die [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Weitere System-Enumeration ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Gemountete Laufwerke auflisten**
- [ ] **Gibt es nicht gemountete Laufwerke?**
- [ ] **Gibt es Zugangsdaten in fstab?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Prüfe, ob**[ **useful software**](privilege-escalation/index.html#useful-software) **installiert** ist
- [ ] **Prüfe, ob** [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) **installiert** ist

### [Processes](privilege-escalation/index.html#processes)

- [ ] Läuft irgendwelche **unbekannte Software**?
- [ ] Läuft Software mit **mehr Rechten als sie haben sollte**?
- [ ] Suche nach **Exploits für laufende Prozesse** (insbesondere für die aktuell verwendete Version).
- [ ] Kannst du das **Binary** eines laufenden Prozesses ändern?
- [ ] **Prozesse überwachen** und prüfen, ob ein interessanter Prozess häufig läuft.
- [ ] Kannst du interessanten **Prozessspeicher** **lesen** (wo Passwörter gespeichert sein könnten)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Wird der [**PATH** ](privilege-escalation/index.html#cron-path) von einem cron geändert und kannst du darin **schreiben**?
- [ ] Irgendein [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) in einem Cron-Job?
- [ ] Wird ein [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) **ausgeführt** oder befindet es sich in einem **änderbaren Ordner**?
- [ ] Hast du erkannt, dass ein **Script** [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs)? (alle 1, 2 oder 5 Minuten)

### [Services](privilege-escalation/index.html#services)

- [ ] Gibt es eine **beschreibbare .service**-Datei?
- [ ] Gibt es ein **beschreibbares Binary**, das von einem **Service** ausgeführt wird?
- [ ] Gibt es einen **beschreibbaren Ordner im systemd PATH**?
- [ ] Gibt es eine **beschreibbare systemd unit drop-in** in `/etc/systemd/system/<unit>.d/*.conf`, die `ExecStart`/`User` überschreiben kann?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Gibt es einen **beschreibbaren Timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Gibt es eine **beschreibbare .socket**-Datei?
- [ ] Kannst du mit einem Socket **kommunizieren**?
- [ ] **HTTP sockets** mit interessanten Informationen?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Kannst du mit einem D-Bus **kommunizieren**?

### [Network](privilege-escalation/index.html#network)

- [ ] Netzwerke untersuchen, um zu wissen, wo du dich befindest
- [ ] **Offene Ports, auf die du vor dem Shell-Zugang keinen Zugriff hattest**?
- [ ] Kannst du den Traffic mit `tcpdump` sniffen?

### [Users](privilege-escalation/index.html#users)

- [ ] Generelle Benutzer-/Gruppen-Enumeration
- [ ] Hast du eine **sehr große UID**? Ist die **Maschine** **vulnerable**?
- [ ] Kannst du [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html), der du angehörst?
- [ ] **Clipboard** data?
- [ ] Password Policy?
- [ ] Versuche, jedes **bekannte Passwort**, das du zuvor gefunden hast, zu verwenden, um dich **mit jedem** möglichen **User** anzumelden. Versuche auch ohne Passwort anzumelden.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] If you have **write privileges over some folder in PATH** you may be able to escalate privileges

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Kannst du **beliebige Befehle mit sudo ausführen**? Kannst du es nutzen, um als root irgendetwas zu LESEN, SCHREIBEN oder AUSZUFÜHREN? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Wenn `sudo -l` `sudoedit` erlaubt, prüfe auf **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` um beliebige Dateien auf verwundbaren Versionen (`sudo -V` < 1.9.12p2) zu bearbeiten. Beispiel: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Gibt es ein **ausnutzbares SUID-Binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) von einem beschreibbaren Ordner?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kannst du [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kannst du [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) Befehl

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Hat irgendein Binary eine **unerwartete capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Hat irgendeine Datei eine **unerwartete ACL**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Sensible Daten lesen? Zum privesc schreiben?
- [ ] **passwd/shadow files** - Sensible Daten lesen? Zum privesc schreiben?
- [ ] **Check commonly interesting folders** for sensitive data
- [ ] **Weird Location/Owned files,** du könntest Zugriff auf sie haben oder ausführbare Dateien verändern
- [ ] **Modified** in last mins
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Known files that contains passwords**: Use **Linpeas** and **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Modify python library** to execute arbitrary commands?
- [ ] Kannst du **Logdateien verändern**? **Logtotten** exploit
- [ ] Kannst du **/etc/sysconfig/network-scripts/** verändern? Centos/Redhat exploit
- [ ] Kannst du [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Kannst du [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Musst du [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referenzen

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
