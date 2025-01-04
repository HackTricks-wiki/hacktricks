# Checklist - Linux Privilegieneskalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach lokalen Privilegieneskalationsvektoren in Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Systeminformationen](privilege-escalation/index.html#system-information)

- [ ] **Betriebssysteminformationen** abrufen
- [ ] Überprüfen Sie den [**PATH**](privilege-escalation/index.html#path), gibt es einen **beschreibbaren Ordner**?
- [ ] Überprüfen Sie die [**Umgebungsvariablen**](privilege-escalation/index.html#env-info), gibt es sensible Details?
- [ ] Suchen Sie nach [**Kernel-Exploits**](privilege-escalation/index.html#kernel-exploits) **unter Verwendung von Skripten** (DirtyCow?)
- [ ] **Überprüfen** Sie, ob die [**sudo-Version** anfällig ist](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg**-Signaturüberprüfung fehlgeschlagen](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Weitere Systemenumeration ([Datum, Systemstatistiken, CPU-Informationen, Drucker](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Weitere Abwehrmaßnahmen enumerieren](privilege-escalation/index.html#enumerate-possible-defenses)

### [Laufwerke](privilege-escalation/index.html#drives)

- [ ] **Aufgelistete** Laufwerke
- [ ] **Gibt es ein nicht gemountetes Laufwerk?**
- [ ] **Gibt es Anmeldeinformationen in fstab?**

### [**Installierte Software**](privilege-escalation/index.html#installed-software)

- [ ] **Überprüfen Sie auf** [**nützliche Software**](privilege-escalation/index.html#useful-software) **installiert**
- [ ] **Überprüfen Sie auf** [**anfällige Software**](privilege-escalation/index.html#vulnerable-software-installed) **installiert**

### [Prozesse](privilege-escalation/index.html#processes)

- [ ] Läuft **irgendwelche unbekannte Software**?
- [ ] Läuft irgendeine Software mit **mehr Rechten als sie haben sollte**?
- [ ] Suchen Sie nach **Exploits von laufenden Prozessen** (insbesondere der laufenden Version).
- [ ] Können Sie die **Binärdatei** eines laufenden Prozesses **modifizieren**?
- [ ] **Überwachen Sie Prozesse** und überprüfen Sie, ob ein interessanter Prozess häufig läuft.
- [ ] Können Sie **Speicher** eines interessanten **Prozesses lesen** (wo Passwörter gespeichert sein könnten)?

### [Geplante/Cron-Jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Wird der [**PATH**](privilege-escalation/index.html#cron-path) von einem Cron geändert und können Sie darin **schreiben**?
- [ ] Gibt es ein [**Wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) in einem Cron-Job?
- [ ] Wird ein [**modifizierbares Skript**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) **ausgeführt** oder befindet es sich in einem **modifizierbaren Ordner**?
- [ ] Haben Sie festgestellt, dass ein **Skript** [**sehr häufig ausgeführt wird**](privilege-escalation/index.html#frequent-cron-jobs)? (alle 1, 2 oder 5 Minuten)

### [Dienste](privilege-escalation/index.html#services)

- [ ] Gibt es eine **beschreibbare .service**-Datei?
- [ ] Gibt es eine **beschreibbare Binärdatei**, die von einem **Dienst** ausgeführt wird?
- [ ] Gibt es einen **beschreibbaren Ordner im systemd PATH**?

### [Timer](privilege-escalation/index.html#timers)

- [ ] Gibt es einen **beschreibbaren Timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Gibt es eine **beschreibbare .socket**-Datei?
- [ ] Können Sie mit **irgendeinem Socket kommunizieren**?
- [ ] **HTTP-Sockets** mit interessanten Informationen?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Können Sie mit **irgendeinem D-Bus kommunizieren**?

### [Netzwerk](privilege-escalation/index.html#network)

- [ ] Enumerieren Sie das Netzwerk, um zu wissen, wo Sie sich befinden
- [ ] **Offene Ports, auf die Sie vorher keinen Zugriff hatten**, um eine Shell im Inneren der Maschine zu erhalten?
- [ ] Können Sie **Traffic mit `tcpdump` sniffen**?

### [Benutzer](privilege-escalation/index.html#users)

- [ ] Generische Benutzer-/Gruppenumeration
- [ ] Haben Sie eine **sehr große UID**? Ist die **Maschine** **anfällig**?
- [ ] Können Sie [**Privilegien dank einer Gruppe**](privilege-escalation/interesting-groups-linux-pe/index.html) erhöhen, zu der Sie gehören?
- [ ] **Zwischenablage**-Daten?
- [ ] Passwort-Richtlinie?
- [ ] Versuchen Sie, **jedes bekannte Passwort**, das Sie zuvor entdeckt haben, zu verwenden, um sich **mit jedem** möglichen **Benutzer** anzumelden. Versuchen Sie auch, sich ohne Passwort anzumelden.

### [Beschreibbarer PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Wenn Sie **Schreibrechte über einen Ordner im PATH** haben, könnten Sie in der Lage sein, Privilegien zu eskalieren

### [SUDO- und SUID-Befehle](privilege-escalation/index.html#sudo-and-suid)

- [ ] Können Sie **irgendeinen Befehl mit sudo ausführen**? Können Sie es verwenden, um als root zu LESEN, ZU SCHREIBEN oder AUSZUFÜHREN? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Gibt es eine **ausnutzbare SUID-Binärdatei**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Sind [**sudo**-Befehle **durch den** **Pfad** **eingeschränkt**? Können Sie die Einschränkungen **umgehen**](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID-Binärdatei ohne angegebenen Pfad**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-Binärdatei mit Pfadangabe**](privilege-escalation/index.html#suid-binary-with-command-path)? Umgehen
- [ ] [**LD_PRELOAD-Schwachstelle**](privilege-escalation/index.html#ld_preload)
- [ ] [**Fehlende .so-Bibliothek in SUID-Binärdatei**](privilege-escalation/index.html#suid-binary-so-injection) aus einem beschreibbaren Ordner?
- [ ] [**SUDO-Token verfügbar**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Können Sie ein SUDO-Token erstellen**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Können Sie [**sudoers-Dateien lesen oder modifizieren**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Können Sie [**/etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d) **modifizieren**?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) Befehl

### [Fähigkeiten](privilege-escalation/index.html#capabilities)

- [ ] Hat eine Binärdatei eine **unerwartete Fähigkeit**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Hat eine Datei eine **unerwartete ACL**?

### [Offene Shell-Sitzungen](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Vorhersehbarer PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interessante Konfigurationswerte**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interessante Dateien](privilege-escalation/index.html#interesting-files)

- [ ] **Profil-Dateien** - Sensible Daten lesen? In privesc schreiben?
- [ ] **passwd/shadow-Dateien** - Sensible Daten lesen? In privesc schreiben?
- [ ] **Überprüfen Sie häufig interessante Ordner** auf sensible Daten
- [ ] **Seltsame Standort/besitzende Dateien,** auf die Sie möglicherweise Zugriff haben oder ausführbare Dateien ändern können
- [ ] **In den letzten Minuten geändert**
- [ ] **Sqlite DB-Dateien**
- [ ] **Versteckte Dateien**
- [ ] **Skripte/Binärdateien im PATH**
- [ ] **Web-Dateien** (Passwörter?)
- [ ] **Backups**?
- [ ] **Bekannte Dateien, die Passwörter enthalten**: Verwenden Sie **Linpeas** und **LaZagne**
- [ ] **Generische Suche**

### [**Beschreibbare Dateien**](privilege-escalation/index.html#writable-files)

- [ ] **Python-Bibliothek modifizieren**, um beliebige Befehle auszuführen?
- [ ] Können Sie **Protokolldateien modifizieren**? **Logtotten**-Exploits
- [ ] Können Sie **/etc/sysconfig/network-scripts/** **modifizieren**? Centos/Redhat-Exploits
- [ ] Können Sie [**in ini, int.d, systemd oder rc.d-Dateien schreiben**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Andere Tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Können Sie [**NFS ausnutzen, um Privilegien zu eskalieren**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Müssen Sie [**aus einer restriktiven Shell entkommen**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
