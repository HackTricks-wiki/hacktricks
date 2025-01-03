# Checkliste - Linux Privilegieneskalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach lokalen Privilegieneskalationsvektoren in Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Systeminformationen](privilege-escalation/#system-information)

- [ ] **OS-Informationen** abrufen
- [ ] Überprüfen Sie den [**PATH**](privilege-escalation/#path), gibt es einen **beschreibbaren Ordner**?
- [ ] Überprüfen Sie die [**Umgebungsvariablen**](privilege-escalation/#env-info), gibt es sensible Details?
- [ ] Suchen Sie nach [**Kernel-Exploits**](privilege-escalation/#kernel-exploits) **mit Skripten** (DirtyCow?)
- [ ] **Überprüfen** Sie, ob die [**sudo-Version** anfällig ist](privilege-escalation/#sudo-version)
- [ ] [**Dmesg**-Signaturüberprüfung fehlgeschlagen](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Weitere Systemenumeration ([Datum, Systemstatistiken, CPU-Informationen, Drucker](privilege-escalation/#more-system-enumeration))
- [ ] [**Weitere Abwehrmaßnahmen enumerieren**](privilege-escalation/#enumerate-possible-defenses)

### [Laufwerke](privilege-escalation/#drives)

- [ ] **Aufgelistete** Laufwerke
- [ ] **Gibt es ein nicht gemountetes Laufwerk?**
- [ ] **Gibt es Anmeldeinformationen in fstab?**

### [**Installierte Software**](privilege-escalation/#installed-software)

- [ ] **Überprüfen Sie auf** [**nützliche Software**](privilege-escalation/#useful-software) **installiert**
- [ ] **Überprüfen Sie auf** [**anfällige Software**](privilege-escalation/#vulnerable-software-installed) **installiert**

### [Prozesse](privilege-escalation/#processes)

- [ ] Läuft **irgendwelche unbekannte Software**?
- [ ] Läuft irgendeine Software mit **mehr Rechten als sie haben sollte**?
- [ ] Suchen Sie nach **Exploits von laufenden Prozessen** (insbesondere der laufenden Version).
- [ ] Können Sie die **Binärdatei** eines laufenden Prozesses **modifizieren**?
- [ ] **Überwachen Sie Prozesse** und überprüfen Sie, ob ein interessanter Prozess häufig läuft.
- [ ] Können Sie **Speicher** eines interessanten **Prozesses lesen** (wo Passwörter gespeichert sein könnten)?

### [Geplante/Cron-Jobs?](privilege-escalation/#scheduled-jobs)

- [ ] Wird der [**PATH**](privilege-escalation/#cron-path) von einem Cron geändert und können Sie darin **schreiben**?
- [ ] Gibt es ein [**Wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) in einem Cron-Job?
- [ ] Wird ein [**modifizierbares Skript**](privilege-escalation/#cron-script-overwriting-and-symlink) **ausgeführt** oder befindet es sich in einem **modifizierbaren Ordner**?
- [ ] Haben Sie festgestellt, dass ein **Skript** [**sehr häufig ausgeführt wird**](privilege-escalation/#frequent-cron-jobs)? (alle 1, 2 oder 5 Minuten)

### [Dienste](privilege-escalation/#services)

- [ ] Gibt es eine **beschreibbare .service**-Datei?
- [ ] Gibt es eine **beschreibbare Binärdatei**, die von einem **Dienst** ausgeführt wird?
- [ ] Gibt es einen **beschreibbaren Ordner im systemd PATH**?

### [Timer](privilege-escalation/#timers)

- [ ] Gibt es einen **beschreibbaren Timer**?

### [Sockets](privilege-escalation/#sockets)

- [ ] Gibt es eine **beschreibbare .socket**-Datei?
- [ ] Können Sie mit **irgendeinem Socket kommunizieren**?
- [ ] **HTTP-Sockets** mit interessanten Informationen?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Können Sie mit **irgendeinem D-Bus kommunizieren**?

### [Netzwerk](privilege-escalation/#network)

- [ ] Enumerieren Sie das Netzwerk, um zu wissen, wo Sie sind
- [ ] **Offene Ports, auf die Sie vorher nicht zugreifen konnten**, um eine Shell im Inneren der Maschine zu erhalten?
- [ ] Können Sie **Traffic mit `tcpdump` sniffen**?

### [Benutzer](privilege-escalation/#users)

- [ ] Generische Benutzer-/Gruppenumeration
- [ ] Haben Sie eine **sehr große UID**? Ist die **Maschine** **anfällig**?
- [ ] Können Sie [**Privilegien dank einer Gruppe**](privilege-escalation/interesting-groups-linux-pe/) erhöhen, zu der Sie gehören?
- [ ] **Zwischenablage**-Daten?
- [ ] Passwort-Richtlinie?
- [ ] Versuchen Sie, **jedes bekannte Passwort**, das Sie zuvor entdeckt haben, zu verwenden, um sich **mit jedem möglichen Benutzer** anzumelden. Versuchen Sie auch, sich ohne Passwort anzumelden.

### [Beschreibbarer PATH](privilege-escalation/#writable-path-abuses)

- [ ] Wenn Sie **Schreibrechte über einen Ordner im PATH** haben, könnten Sie in der Lage sein, Privilegien zu eskalieren

### [SUDO- und SUID-Befehle](privilege-escalation/#sudo-and-suid)

- [ ] Können Sie **irgendeinen Befehl mit sudo ausführen**? Können Sie es verwenden, um als root zu LESEN, ZU SCHREIBEN oder ETWAS AUSZUFÜHREN? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Gibt es eine **ausnutzbare SUID-Binärdatei**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Sind [**sudo**-Befehle **durch den** **Pfad** **eingeschränkt**? Können Sie die Einschränkungen **umgehen**](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID-Binärdatei ohne angegebenen Pfad**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-Binärdatei mit angegebenem Pfad**](privilege-escalation/#suid-binary-with-command-path)? Umgehen
- [ ] [**LD_PRELOAD-Schwachstelle**](privilege-escalation/#ld_preload)
- [ ] [**Fehlende .so-Bibliothek in SUID-Binärdatei**](privilege-escalation/#suid-binary-so-injection) aus einem beschreibbaren Ordner?
- [ ] [**SUDO-Token verfügbar**](privilege-escalation/#reusing-sudo-tokens)? [**Können Sie ein SUDO-Token erstellen**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Können Sie [**sudoers-Dateien lesen oder modifizieren**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] Können Sie [**/etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) **modifizieren**?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) Befehl

### [Fähigkeiten](privilege-escalation/#capabilities)

- [ ] Hat eine Binärdatei eine **unerwartete Fähigkeit**?

### [ACLs](privilege-escalation/#acls)

- [ ] Hat eine Datei eine **unerwartete ACL**?

### [Offene Shell-Sitzungen](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL Vorhersehbarer PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interessante Konfigurationswerte**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interessante Dateien](privilege-escalation/#interesting-files)

- [ ] **Profil-Dateien** - Sensible Daten lesen? In privesc schreiben?
- [ ] **passwd/shadow-Dateien** - Sensible Daten lesen? In privesc schreiben?
- [ ] **Überprüfen Sie häufig interessante Ordner** auf sensible Daten
- [ ] **Seltsame Standorte/Besitzdateien,** auf die Sie möglicherweise zugreifen oder ausführbare Dateien ändern können
- [ ] **In den letzten Minuten geändert**
- [ ] **Sqlite DB-Dateien**
- [ ] **Versteckte Dateien**
- [ ] **Skripte/Binärdateien im PATH**
- [ ] **Web-Dateien** (Passwörter?)
- [ ] **Backups**?
- [ ] **Bekannte Dateien, die Passwörter enthalten**: Verwenden Sie **Linpeas** und **LaZagne**
- [ ] **Generische Suche**

### [**Beschreibbare Dateien**](privilege-escalation/#writable-files)

- [ ] **Python-Bibliothek modifizieren**, um beliebige Befehle auszuführen?
- [ ] Können Sie **Protokolldateien modifizieren**? **Logtotten**-Exploits
- [ ] Können Sie **/etc/sysconfig/network-scripts/** **modifizieren**? Centos/Redhat-Exploits
- [ ] Können Sie [**in ini, int.d, systemd oder rc.d-Dateien schreiben**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Andere Tricks**](privilege-escalation/#other-tricks)

- [ ] Können Sie [**NFS ausnutzen, um Privilegien zu eskalieren**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] Müssen Sie [**aus einer restriktiven Shell entkommen**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
