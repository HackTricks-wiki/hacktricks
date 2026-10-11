# Linux-Checkliste zur Rechteausweitung

{{#include ../../banners/hacktricks-training.md}}

# Checkliste – Linux-Rechteausweitung



### **Bestes Tool zum Suchen nach lokalen Linux-Vektoren zur Rechteausweitung:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Systeminformationen](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **Betriebssysteminformationen** abrufen
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) überprüfen: Gibt es einen **beschreibbaren Ordner**?
- [ ] [**Umgebungsvariablen**](../linux-basics/linux-privilege-escalation/index.html#env-info) überprüfen: Gibt es sensible Informationen?
- [ ] Mit **Skripten** nach [**Kernel-Exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) suchen (DirtyCow?)
- [ ] Vor dem Ausführen eines Kernel-PoC dessen **tatsächliche Voraussetzungen** überprüfen, nicht nur `uname -r`: Architektur, erforderliche `CONFIG_*`-Optionen/Module, Erstellung von Namespaces und aktive Mitigations. Zum Beispiel die Verfügbarkeit von User- und Netzwerk-Namespaces mit `unshare -Urn true` testen; moderne netfilter-Exploits benötigen möglicherweise `CONFIG_USER_NS`, unprivilegierte User-Namespaces und `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] Überprüfen, ob die [**sudo-Version** verwundbar ist](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg**-Signaturüberprüfung fehlgeschlagen](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**Fehlkonfigurationen von Kernel-Modulen und deren Laden**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) überprüfen: `insmod`, `modinfo`, `lsmod`, `dmesg`, Signaturerzwingung und `modules_disabled`.
- [ ] [**Missbrauchswege über kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) überprüfen, wenn der Hilfspfad geändert oder ausgelöst werden kann.
- [ ] [**Beschreibbare Pfade unter /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review) überprüfen, darunter beschreibbare `.ko*`-Dateien und `modules.*`-Metadaten.
- [ ] Weitere Systeminformationen erfassen ([Datum, Systemstatistiken, CPU-Informationen, Drucker](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Weitere Schutzmaßnahmen erfassen](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Laufwerke](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] Eingehängte Laufwerke **auflisten**
- [ ] Gibt es **nicht eingehängte Laufwerke**?
- [ ] Gibt es **Anmeldedaten in der fstab**?

### [**Installierte Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] Überprüfen, ob [**nützliche Software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **installiert ist**
- [ ] Überprüfen, ob [**verwundbare Software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **installiert ist**
- [ ] Unter Debian/Ubuntu überprüfen, ob **needrestart-Interpreter-Scanning** installiert/aktiviert ist: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Verwundbare Builds überschritten die Privilegiengrenze, indem sie vom Angreifer kontrollierte `PYTHONPATH`/`RUBYLIB` wiederverwendeten, mit `/proc/<pid>/exe` um die Wette liefen oder vom Angreifer kontrollierte Perl-Pfade scannten, wenn APT oder `unattended-upgrades` needrestart als root aufriefen.<sup>[[4]](#references)</sup>

### [Prozesse](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Läuft **unbekannte Software**?
- [ ] Läuft Software mit **mehr Privilegien als nötig**?
- [ ] Nach **Exploits für laufende Prozesse** suchen (insbesondere für die laufende Version).
- [ ] Kannst du die **Binärdatei** eines laufenden Prozesses **ändern**?
- [ ] **Prozesse überwachen** und prüfen, ob ein interessanter Prozess regelmäßig läuft.
- [ ] Kannst du den **Speicher** eines interessanten **Prozesses lesen** (dort könnten Passwörter gespeichert sein)?

### [Geplante Aufgaben/Cron-Jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Wird der [**PATH**](../linux-basics/linux-privilege-escalation/index.html#cron-path) durch einen Cron-Job geändert, und kannst du hineinschreiben?
- [ ] Gibt es einen [**Wildcard**](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) in einem Cron-Job?
- [ ] Wird ein [**änderbares Skript**](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **ausgeführt** oder liegt es in einem **änderbaren Ordner**?
- [ ] Hast du festgestellt, dass ein **Skript** möglicherweise [**sehr häufig ausgeführt wird**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) oder bereits so ausgeführt wird? (jede 1, 2 oder 5 Minuten)

### [Dienste](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Gibt es eine **beschreibbare .service-Datei**?
- [ ] Gibt es eine **beschreibbare Binärdatei**, die von einem **Dienst** ausgeführt wird?
- [ ] Gibt es eine beschreibbare **Hilfs-, Konfigurations- oder Umgebungsdatei, auf die eine root-Unit verweist** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Die zusammengeführte Unit mit `systemctl cat <unit>` untersuchen und [Missbrauch von Service-/Socket-Dateien](../interesting-files-permissions/write-to-root.md) überprüfen.
- [ ] Führt ein privilegierter Workflow bei Bedarf einen Hilfsprozess in einem von einem weniger privilegierten Benutzer beschreibbaren Verzeichnis aus? Sowohl den Hilfsprozess als auch dessen übergeordnetes Verzeichnis auf [root-Ausführung von benutzeränderbaren Pfaden](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries) überprüfen; kurzlebige Hilfsprozesse sind möglicherweise nur während der Ausführung des Workflows sichtbar.
- [ ] Gibt es einen **beschreibbaren Ordner im systemd-PATH**?
- [ ] Gibt es ein **beschreibbares systemd-Unit-Drop-in** in `/etc/systemd/system/<unit>.d/*.conf`, das `ExecStart`/`User` überschreiben kann?<sup>[[2]](#references)</sup>

### [Timer](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Gibt es einen **beschreibbaren Timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Gibt es eine **beschreibbare .socket-Datei**?
- [ ] Kannst du mit einem Socket **kommunizieren**?
- [ ] Gibt es **HTTP-Sockets** mit interessanten Informationen?
- [ ] Kannst du auf eine [**API einer Container-Runtime oder eines Node-Agents**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) wie `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` oder einen kubelet-Endpunkt zugreifen? Teste die rohe HTTP-/gRPC-API auch dann, wenn die übliche CLI nicht vorhanden ist.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Kannst du mit D-Bus **kommunizieren**?

### [Netzwerk](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Das Netzwerk erfassen, um herauszufinden, wo du dich befindest
- [ ] Gibt es **offene Ports, auf die du vor dem Zugriff auf eine Shell auf dem Rechner nicht zugreifen konntest**?
- [ ] Kannst du den Datenverkehr mit `tcpdump` **mitschneiden**?

### [Benutzer](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Allgemeine **Benutzer-/Gruppen-Enumeration**
- [ ] Hast du eine **sehr große UID**? Ist der **Rechner** **verwundbar**?
- [ ] Kannst du dank einer Gruppe, der du angehörst, [**deine Privilegien ausweiten**](../user-information/interesting-groups-linux-pe/index.html)?
- [ ] **Zwischenablage-Daten**?
- [ ] Passwortrichtlinie?
- [ ] Versuche, jedes zuvor entdeckte **bekannte Passwort** zu verwenden, um dich als **jeder möglichen Benutzer** anzumelden. Versuche auch, dich ohne Passwort anzumelden.

### [Beschreibbarer PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Wenn du **Schreibrechte für einen Ordner im PATH** hast, kannst du möglicherweise deine Privilegien ausweiten.

### [SUDO- und SUID-Befehle](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Kannst du **einen beliebigen Befehl mit sudo ausführen**? Kannst du damit etwas als root LESEN, SCHREIBEN oder AUSFÜHREN? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Wenn `sudo -l` `sudoedit` erlaubt, auf **sudoedit-Argument-Injection** (CVE-2023-22809) über `SUDO_EDITOR`/`VISUAL`/`EDITOR` prüfen, um bei verwundbaren Versionen beliebige Dateien zu bearbeiten (`sudo -V` < 1.9.12p2). Beispiel: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Gibt es eine **ausnutzbare SUID-Binärdatei**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Sind [**sudo**-Befehle durch einen **Pfad** eingeschränkt? Kannst du die Beschränkungen **umgehen**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID-Binärdatei ohne angegebenen Pfad**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-Binärdatei mit angegebenem Pfad**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Umgehen
- [ ] [**LD_PRELOAD-Verwundbarkeit**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Fehlt eine [**.so-Bibliothek in einer SUID-Binärdatei**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) in einem beschreibbaren Ordner?
- [ ] [**SUID-RPATH/RUNPATH oder beschreibbarer Bibliothekspfad**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] Sind [**SUDO-Tokens verfügbar**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Kannst du ein SUDO-Token erstellen**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kannst du [**sudoers-Dateien lesen oder ändern**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kannst du [**/etc/ld.so.conf.d/** ändern](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Befehl [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Hat eine Binärdatei eine **unerwartete Capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Hat eine Datei eine **unerwartete ACL**?

### [Offene Shell-Sitzungen](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Vorhersagbarer OpenSSL-PRNG – CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interessante SSH-Konfigurationswerte**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interessante Dateien](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profil-Dateien** – Sensible Daten lesen? Für privesc hineinschreiben?
- [ ] **passwd-/shadow-Dateien** – Sensible Daten lesen? Für privesc hineinschreiben?
- [ ] **Häufig interessante Ordner auf sensible Daten überprüfen**
- [ ] **Seltsame Speicherorte/besitzende Dateien**: Möglicherweise kannst du auf ausführbare Dateien zugreifen oder sie ändern
- [ ] In den letzten Minuten **geändert**
- [ ] **Sqlite-DB-Dateien**
- [ ] **Versteckte Dateien**
- [ ] **Skripte/Binärdateien im PATH**
- [ ] **Webdateien** (Passwörter?)
- [ ] **Backups**?
- [ ] **Bekannte Dateien mit Passwörtern**: **Linpeas** und **LaZagne** verwenden
- [ ] **Allgemeine Suche**

### [**Beschreibbare Dateien**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Python-Bibliothek ändern**, um beliebige Befehle auszuführen?
- [ ] Kannst du **Log-Dateien ändern**? **Logtotten**-Exploit
- [ ] Kannst du **/etc/sysconfig/network-scripts/** ändern? Centos/Redhat-Exploit
- [ ] Kannst du in [**ini-, int.d-, systemd- oder rc.d-Dateien schreiben**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Weitere Tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Kannst du [**NFS missbrauchen, um deine Privilegien auszuweiten**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Musst du [**aus einer eingeschränkten Shell ausbrechen**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo-Sicherheitshinweis: Bearbeitung beliebiger Dateien mit sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle-Linux-Dokumentation: systemd-Drop-in-Konfiguration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: Voraussetzungen und Forschung zum CVE-2024-1086-Exploit](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys-Sicherheitshinweis: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
