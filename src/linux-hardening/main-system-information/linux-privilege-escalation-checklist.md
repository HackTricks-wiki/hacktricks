# Checkliste - Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach lokalen Linux-Privilege-Escalation-Vektoren:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Systeminformationen](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS-Informationen** ermitteln
- [ ] Den [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) überprüfen; gibt es einen **beschreibbaren Ordner**?
- [ ] [**Umgebungsvariablen**](../linux-basics/linux-privilege-escalation/index.html#env-info) überprüfen; enthalten sie sensible Details?
- [ ] Nach [**Kernel-Exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **mithilfe von Skripten** suchen (DirtyCow?)
- [ ] **Überprüfen**, ob die [**sudo-Version** verwundbar](../linux-basics/linux-privilege-escalation/index.html#sudo-version) ist
- [ ] [**Dmesg**-Signaturüberprüfung fehlgeschlagen](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**Fehlkonfigurationen von Kernel-Modulen und dem Laden von Modulen**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) überprüfen: `insmod`, `modinfo`, `lsmod`, `dmesg`, Signaturerzwingung und `modules_disabled`.
- [ ] [**Missbrauchspfade von kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) überprüfen, wenn der Pfad des Helpers geändert oder ausgelöst werden kann.
- [ ] [**Beschreibbare /lib/modules-Pfade**](kernel-modules-and-modprobe.md#writable-libmodules-review) überprüfen, einschließlich beschreibbarer `.ko*`-Dateien und `modules.*`-Metadaten.
- [ ] Weitere System-Enum ([Datum, Systemstatistiken, CPU-Informationen, Drucker](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Weitere Schutzmaßnahmen enumerieren](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Laufwerke](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Eingehängte** Laufwerke auflisten
- [ ] Gibt es ein **nicht eingehängtes Laufwerk**?
- [ ] Gibt es **Credentials in der fstab**?

### [**Installierte Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] Nach **installierter**[ **nützlicher Software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **suchen**
- [ ] Nach **installierter** [**verwundbarer Software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **suchen**

### [Prozesse](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Läuft **unbekannte Software**?
- [ ] Läuft Software mit **mehr Privilegien, als sie haben sollte**?
- [ ] Nach **Exploits für laufende Prozesse** suchen (insbesondere für die laufende Version).
- [ ] Kannst du die **Binärdatei** eines laufenden Prozesses **ändern**?
- [ ] **Prozesse überwachen** und überprüfen, ob ein interessanter Prozess regelmäßig ausgeführt wird.
- [ ] Kannst du den **Speicher** eines interessanten **Prozesses lesen** (wo Passwörter gespeichert sein könnten)?

### [Geplante/Cron-Jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Wird der [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)von einem Cron-Job geändert und kannst du **darin schreiben**?
- [ ] Gibt es einen [**Wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in einem Cron-Job?
- [ ] Wird ein [**änderbares Skript** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **ausgeführt** oder befindet es sich in einem **änderbaren Ordner**?
- [ ] Hast du festgestellt, dass ein **Skript** [**sehr **häufig** ausgeführt](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) werden könnte oder ausgeführt wird? (alle 1, 2 oder 5 Minuten)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Gibt es eine **beschreibbare .service**-Datei?
- [ ] Gibt es eine **beschreibbare Binärdatei**, die von einem **Service** ausgeführt wird?
- [ ] Gibt es einen **beschreibbaren Ordner im systemd-PATH**?
- [ ] Gibt es ein **beschreibbares systemd-Unit-Drop-in** in `/etc/systemd/system/<unit>.d/*.conf`, das `ExecStart`/`User` überschreiben kann?

### [Timer](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Gibt es einen **beschreibbaren Timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Gibt es eine **beschreibbare .socket**-Datei?
- [ ] Kannst du mit einem **Socket kommunizieren**?
- [ ] Gibt es **HTTP-Sockets** mit interessanten Informationen?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Kannst du mit einem **D-Bus** kommunizieren?

### [Netzwerk](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Das Netzwerk enumerieren, um herauszufinden, wo du dich befindest
- [ ] **Offene Ports, auf die du zuvor nicht zugreifen konntest**, nachdem du eine Shell innerhalb der Maschine erhalten hast?
- [ ] Kannst du den Datenverkehr mit `tcpdump` **sniffen**?

### [Benutzer](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generische **Benutzer-/Gruppen-Enumeration**
- [ ] Hast du eine **sehr große UID**? Ist die **Maschine** **verwundbar**?
- [ ] Kannst du dank einer Gruppe, der du angehörst, [**Privilegien eskalieren**](../user-information/interesting-groups-linux-pe/index.html)?
- [ ] **Clipboard**-Daten?
- [ ] Passwort-Richtlinie?
- [ ] Versuche, jedes **bekannte Passwort**, das du zuvor entdeckt hast, zu verwenden, um dich mit **jedem** möglichen **Benutzer** anzumelden. Versuche auch, dich ohne Passwort anzumelden.

### [Beschreibbarer PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Wenn du **Schreibrechte für einen Ordner im PATH** hast, kannst du möglicherweise Privilegien eskalieren

### [SUDO- und SUID-Befehle](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Kannst du **beliebige Befehle mit sudo ausführen**? Kannst du damit etwas als root LESEN, SCHREIBEN oder AUSFÜHREN? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Wenn `sudo -l` `sudoedit` erlaubt, überprüfe eine **sudoedit-Argument-Injection** (CVE-2023-22809) über `SUDO_EDITOR`/`VISUAL`/`EDITOR`, um beliebige Dateien auf verwundbaren Versionen zu bearbeiten (`sudo -V` < 1.9.12p2). Beispiel: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Gibt es eine **ausnutzbare SUID-Binärdatei**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Sind [**sudo**-Befehle durch den **Pfad** **eingeschränkt**? Kannst du die Einschränkungen **umgehen**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo-/SUID-Binärdatei ohne angegebenen Pfad**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-Binärdatei mit angegebenem Pfad**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Umgehen
- [ ] [**LD_PRELOAD-Schwachstelle**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Fehlt die [**.so-Bibliothek in einer SUID-Binärdatei**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) in einem beschreibbaren Ordner?
- [ ] [**SUID-RPATH/RUNPATH oder beschreibbarer Bibliothekspfad**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] Sind [**SUDO-Tokens verfügbar**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Kannst du ein SUDO-Token erstellen**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kannst du [**sudoers-Dateien lesen oder ändern**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kannst du [**/etc/ld.so.conf.d/** ändern](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)-Befehl

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Hat eine Binärdatei eine **unerwartete Capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Hat eine Datei eine **unerwartete ACL**?

### [Offene Shell-Sitzungen](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Vorhersagbarer OpenSSL-PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interessante SSH-Konfigurationswerte**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interessante Dateien](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profildateien** - Sensible Daten lesen? Für Privilege Escalation schreiben?
- [ ] **passwd-/shadow-Dateien** - Sensible Daten lesen? Für Privilege Escalation schreiben?
- [ ] **Üblicherweise interessante Ordner** auf sensible Daten überprüfen
- [ ] **Dateien an ungewöhnlichen Orten/im Besitz anderer**, auf die du möglicherweise zugreifen oder deren ausführbare Dateien du ändern kannst
- [ ] In den letzten Minuten **geändert**
- [ ] **Sqlite-DB-Dateien**
- [ ] **Versteckte Dateien**
- [ ] **Skripte/Binärdateien im PATH**
- [ ] **Webdateien** (Passwörter?)
- [ ] **Backups**?
- [ ] **Bekannte Dateien, die Passwörter enthalten**: **Linpeas** und **LaZagne** verwenden
- [ ] **Generische Suche**

### [**Beschreibbare Dateien**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Python-Bibliothek ändern**, um beliebige Befehle auszuführen?
- [ ] Kannst du **Logdateien ändern**? **Logtotten**-Exploit
- [ ] Kannst du **/etc/sysconfig/network-scripts/** ändern? Centos/Redhat-Exploit
- [ ] Kannst du [**in ini-, int.d-, systemd- oder rc.d-Dateien schreiben**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Andere Tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Kannst du [**NFS missbrauchen, um Privilegien zu eskalieren**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Musst du [**aus einer restriktiven Shell entkommen**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referenzen

- [Sudo-Hinweis: sudoedit-Bearbeitung beliebiger Dateien](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle-Linux-Dokumentation: systemd-Drop-in-Konfiguration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
