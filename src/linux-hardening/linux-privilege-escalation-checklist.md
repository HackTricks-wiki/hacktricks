# Checkliste - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Linux lokalen Privilege Escalation Vektoren zu suchen:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Ermittle **OS information**
- [ ] Prüfe den [**PATH**](privilege-escalation/index.html#path), irgendein **schreibbares Ordner**?
- [ ] Überprüfe [**env variables**](privilege-escalation/index.html#env-info), irgendwelche sensiblen Details?
- [ ] Suche nach [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **mit Skripten** (DirtyCow?)
- [ ] **Prüfe** ob die [**sudo version is vulnerable**](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Weitere System-Enumeration ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] Eingehängte Laufwerke auflisten
- [ ] Gibt es nicht eingehängte Laufwerke?
- [ ] Gibt es Credentials in fstab?

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Prüfe**, ob [ **useful software**](privilege-escalation/index.html#useful-software) **installiert** ist
- [ ] **Prüfe**, ob [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) **installiert** ist

### [Processes](privilege-escalation/index.html#processes)

- [ ] Läuft irgendwelche **unbekannte Software**?
- [ ] Läuft Software mit **mehr Privilegien als vorgesehen**?
- [ ] Suche nach **Exploits für laufende Prozesse** (besonders die laufende Version).
- [ ] Kannst du die **Binärdatei** eines laufenden Prozesses ändern?
- [ ] **Prozesse überwachen** und prüfen, ob ein interessanter Prozess häufig ausgeführt wird.
- [ ] Kannst du etwas interessanten **Prozessspeicher** **lesen** (wo Passwörter gespeichert sein könnten)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Wird der [**PATH** ](privilege-escalation/index.html#cron-path) von einem cron verändert und kannst du dort **schreiben**?
- [ ] Gibt es irgendein [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) in einem cron-Job?
- [ ] Wird ein [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) **ausgeführt** oder befindet es sich in einem **schreibbaren Ordner**?
- [ ] Hast du festgestellt, dass ein **Script** [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs)? (jede 1, 2 oder 5 Minuten)

### [Services](privilege-escalation/index.html#services)

- [ ] Gibt es eine **schreibbare .service**-Datei?
- [ ] Gibt es eine **schreibbare Binärdatei**, die von einem **Service** ausgeführt wird?
- [ ] Gibt es einen **schreibbaren Ordner im systemd PATH**?
- [ ] Gibt es einen **schreibbaren systemd unit drop-in** in `/etc/systemd/system/<unit>.d/*.conf`, der `ExecStart`/`User` überschreiben kann?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Gibt es einen **schreibbaren Timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Gibt es eine **schreibbare .socket**-Datei?
- [ ] Kannst du mit irgendeinem Socket **kommunizieren**?
- [ ] **HTTP sockets** mit interessanten Informationen?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Kannst du mit irgendeinem D-Bus **kommunizieren**?

### [Network](privilege-escalation/index.html#network)

- [ ] Netzwerk untersuchen, um herauszufinden, wo du dich befindest
- [ ] **Offene Ports, auf die du vor dem Shell-Zugang keinen Zugriff hattest?**
- [ ] Kannst du mit `tcpdump` **Traffic sniffen**?

### [Users](privilege-escalation/index.html#users)

- [ ] Generische Benutzer-/Gruppen-Auflistung
- [ ] Hast du eine **sehr große UID**? Ist die **machine** **vulnerable**?
- [ ] Kannst du durch eine Gruppe, der du angehörst, [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html)?
- [ ] **Clipboard** data?
- [ ] Passwort-Richtlinie?
- [ ] Versuche, jedes zuvor gefundene **bekannte Passwort** zu verwenden, um dich mit jedem möglichen **Benutzer** einzuloggen. Versuche dich auch ohne Passwort anzumelden.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Wenn du **Schreibrechte auf einen Ordner im PATH** hast, kannst du möglicherweise Privilegien eskalieren

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Kannst du **any command with sudo** ausführen? Kannst du es nutzen, um als root etwas zu lesen, zu schreiben oder auszuführen? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Wenn `sudo -l` `sudoedit` erlaubt, überprüfe auf **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR`, um beliebige Dateien auf verwundbaren Versionen (`sudo -V` < 1.9.12p2) zu editieren. Beispiel: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Gibt es ein **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Umgehen
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) aus einem schreibbaren Ordner?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kannst du [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kannst du [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Hat irgendeine Binärdatei eine **unerwartete capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Hat eine Datei eine **unerwartete ACL**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profil-Dateien** - Sensible Daten lesen? Zum privesc schreiben?
- [ ] **passwd/shadow files** - Sensible Daten lesen? Zum privesc schreiben?
- [ ] **Prüfe häufig interessante Ordner** nach sensiblen Daten
- [ ] **Ungewöhnliche Orte / Dateien im Besitz**, auf die du Zugriff hast oder die ausführbare Dateien enthalten, die du ändern kannst
- [ ] **In den letzten Minuten geändert**
- [ ] **Sqlite DB files**
- [ ] **Versteckte Dateien**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (Passwörter?)
- [ ] **Backups**?
- [ ] **Bekannte Dateien, die Passwörter enthalten**: Verwende **Linpeas** und **LaZagne**
- [ ] **Generische Suche**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Python-Bibliothek modifizieren**, um beliebige Befehle auszuführen?
- [ ] Kannst du **Logdateien ändern**? **Logtotten** Exploit
- [ ] Kannst du **/etc/sysconfig/network-scripts/** ändern? Centos/Redhat Exploit
- [ ] Kannst du [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Kannst du [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Musst du [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referenzen

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
