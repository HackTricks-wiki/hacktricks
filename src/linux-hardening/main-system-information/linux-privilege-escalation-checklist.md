# Linux-Privilege-Eskalations-Checkliste

# Checkliste – Linux-Privilege-Eskalation



### **Bestes Tool zur Suche nach lokalen Linux-Privilege-Eskalationsvektoren:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Systeminformationen](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS-Informationen** abrufen
- [ ] Den [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) prüfen, gibt es einen **beschreibbaren Ordner**?
- [ ] [**Umgebungsvariablen**](../linux-basics/linux-privilege-escalation/index.html#env-info) prüfen, enthalten sie sensible Details?
- [ ] Nach [**Kernel-Exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **mithilfe von Scripts** suchen (DirtyCow?)
- [ ] Vor dem Ausführen eines Kernel-PoC dessen **tatsächliche Voraussetzungen** prüfen, nicht nur `uname -r`: Architektur, erforderliche `CONFIG_*`-Optionen/-Module, Erstellung von Namespaces und aktive Mitigations. Beispielsweise die Verfügbarkeit von User-/Network-Namespaces mit `unshare -Urn true` testen; moderne Netfilter-Exploits können `CONFIG_USER_NS`, unprivilegierte User-Namespaces und `CONFIG_NF_TABLES` erfordern.<sup>[[3]](#references)</sup>
- [ ] **Prüfen**, ob die [**sudo-Version** verwundbar ist](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg**-Signaturüberprüfung fehlgeschlagen](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**Fehlkonfigurationen von Kernel-Modulen und dem Laden von Modulen**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) überprüfen: `insmod`, `modinfo`, `lsmod`, `dmesg`, Signaturerzwingung und `modules_disabled`.
- [ ] [**Missbrauchspfade von kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) prüfen, falls der Pfad des Helpers geändert oder ausgelöst werden kann.
- [ ] [**Beschreibbare /lib/modules-Pfade**](kernel-modules-and-modprobe.md#writable-libmodules-review) prüfen, einschließlich beschreibbarer `.ko*`-Dateien und `modules.*`-Metadaten.
- [ ] Weitere System-Enumeration ([Datum, Systemstatistiken, CPU-Informationen, Drucker](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Weitere Abwehrmechanismen enumerieren](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Laufwerke](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Eingehängte** Laufwerke auflisten
- [ ] Gibt es ein **nicht eingehängtes Laufwerk**?
- [ ] Gibt es **Credentials in der fstab**?

### [**Installierte Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] Prüfen, ob [**nützliche Software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **installiert** ist
- [ ] Prüfen, ob [**verwundbare Software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **installiert** ist
- [ ] Unter Debian/Ubuntu prüfen, ob **needrestart interpreter scanning** installiert/aktiviert ist: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Verwundbare Builds überschritten die Privilege-Grenze, indem sie vom Angreifer kontrolliertes `PYTHONPATH`/`RUBYLIB` wiederverwendeten, eine Race Condition bei `/proc/<pid>/exe` ausnutzten oder vom Angreifer kontrollierte Perl-Pfade scannten, wenn APT oder `unattended-upgrades` needrestart als root aufriefen.<sup>[[4]](#references)</sup>

### [Prozesse](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Läuft **unbekannte Software**?
- [ ] Läuft Software mit **mehr Privilegien, als sie haben sollte**?
- [ ] Nach **Exploits für laufende Prozesse** suchen (insbesondere nach der ausgeführten Version).
- [ ] Kannst du die **Binärdatei** eines laufenden Prozesses **ändern**?
- [ ] **Prozesse überwachen** und prüfen, ob ein interessanter Prozess regelmäßig ausgeführt wird.
- [ ] Kannst du den **Speicher eines interessanten Prozesses** **lesen** (dort könnten Passwörter gespeichert sein)?

### [Geplante/Cron-Jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Wird der [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)von einem Cron geändert und kannst du **darin schreiben**?
- [ ] Gibt es einen [**Wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in einem Cron-Job?
- [ ] Wird ein [**änderbares Script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **ausgeführt** oder befindet es sich in einem **änderbaren Ordner**?
- [ ] Hast du festgestellt, dass ein **Script** [**sehr häufig** **ausgeführt wird oder werden könnte**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (alle 1, 2 oder 5 Minuten)

### [Dienste](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Gibt es eine **beschreibbare .service**-Datei?
- [ ] Gibt es eine **beschreibbare Binärdatei**, die von einem **Dienst** ausgeführt wird?
- [ ] Gibt es einen beschreibbaren **Helper, eine Konfigurations- oder Umgebungsdatei, auf die eine Root-Unit verweist** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Die zusammengeführte Unit mit `systemctl cat <unit>` untersuchen und den [Missbrauch von Service-/Socket-Dateien](../interesting-files-permissions/write-to-root.md) überprüfen.
- [ ] Gibt es einen **beschreibbaren Ordner im systemd-PATH**?
- [ ] Gibt es ein **beschreibbares systemd-Unit-Drop-in** in `/etc/systemd/system/<unit>.d/*.conf`, das `ExecStart`/`User` überschreiben kann?<sup>[[2]](#references)</sup>

### [Timer](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Gibt es einen **beschreibbaren Timer**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Gibt es eine **beschreibbare .socket**-Datei?
- [ ] Kannst du mit einem **Socket kommunizieren**?
- [ ] Gibt es **HTTP-Sockets** mit interessanten Informationen?
- [ ] Kannst du auf eine [**container-runtime- oder node-agent-API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) wie `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` oder einen Kubelet-Endpunkt zugreifen? Die rohe HTTP/gRPC-API testen, auch wenn die übliche CLI nicht vorhanden ist.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Kannst du mit einem **D-Bus** kommunizieren?

### [Netzwerk](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Das Netzwerk enumerieren, um festzustellen, wo du dich befindest
- [ ] Gibt es **offene Ports, auf die du vor dem Erhalt einer Shell innerhalb der Maschine nicht zugreifen konntest**?
- [ ] Kannst du Datenverkehr mit `tcpdump` **sniffen**?

### [Benutzer](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Allgemeine **Enumeration von Benutzern/Gruppen**
- [ ] Hast du eine **sehr große UID**? Ist die **Maschine** **verwundbar**?
- [ ] Kannst du dank einer Gruppe, der du angehörst, [**Privilegien eskalieren**](../user-information/interesting-groups-linux-pe/index.html)?
- [ ] **Clipboard**-Daten?
- [ ] Passwortrichtlinie?
- [ ] Versuchen, jedes zuvor entdeckte **bekannte Passwort** zu verwenden, um sich mit **jedem** möglichen **Benutzer** anzumelden. Auch versuchen, sich ohne Passwort anzumelden.

### [Beschreibbarer PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Wenn du **Schreibrechte für einen Ordner im PATH** hast, kannst du möglicherweise Privilegien eskalieren

### [SUDO- und SUID-Befehle](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Kannst du **einen beliebigen Befehl mit sudo ausführen**? Kannst du ihn verwenden, um etwas als root zu LESEN, zu SCHREIBEN oder AUSZUFÜHREN? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Wenn `sudo -l` `sudoedit` erlaubt, auf **sudoedit-Argument-Injection** (CVE-2023-22809) über `SUDO_EDITOR`/`VISUAL`/`EDITOR` prüfen, um bei verwundbaren Versionen beliebige Dateien zu bearbeiten (`sudo -V` < 1.9.12p2). Beispiel: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Gibt es eine **ausnutzbare SUID-Binärdatei**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Sind [**sudo**-Befehle durch den **Pfad** **beschränkt**? Kannst du die Einschränkungen **umgehen**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID-Binärdatei ohne angegebenen Pfad**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID-Binärdatei mit angegebenem Pfad**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Umgehen
- [ ] [**LD_PRELOAD-Schwachstelle**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Fehlt eine [**.so-Bibliothek in einer SUID-Binärdatei**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) in einem beschreibbaren Ordner?
- [ ] [**SUID-RPATH/RUNPATH oder beschreibbarer Bibliothekspfad**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] Sind [**SUDO-Tokens verfügbar**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Kannst du ein SUDO-Token erstellen**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Kannst du [**sudoers-Dateien lesen oder ändern**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Kannst du [**/etc/ld.so.conf.d/** ändern](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)-Befehl

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Verfügt eine Binärdatei über eine **unerwartete Capability**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Verfügt eine Datei über eine **unerwartete ACL**?

### [Offene Shell-Sitzungen](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Vorhersagbarer OpenSSL-PRNG – CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interessante SSH-Konfigurationswerte**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interessante Dateien](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profildateien** – Sensible Daten lesen? Für Privesc beschreibbar?
- [ ] **passwd-/shadow-Dateien** – Sensible Daten lesen? Für Privesc beschreibbar?
- [ ] **Üblicherweise interessante Ordner prüfen** auf sensible Daten
- [ ] **Seltsame Speicherorte/Dateien im Besitz**, auf die du möglicherweise zugreifen oder deren ausführbare Dateien du ändern kannst
- [ ] In den letzten Minuten **geändert**
- [ ] **Sqlite-DB-Dateien**
- [ ] **Versteckte Dateien**
- [ ] **Scripts/Binärdateien im PATH**
- [ ] **Webdateien** (Passwörter?)
- [ ] **Backups**?
- [ ] **Bekannte Dateien, die Passwörter enthalten**: **Linpeas** und **LaZagne** verwenden
- [ ] **Allgemeine Suche**

### [**Beschreibbare Dateien**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Python-Bibliothek ändern**, um beliebige Befehle auszuführen?
- [ ] Kannst du **Logdateien ändern**? **Logtotten**-Exploit
- [ ] Kannst du **/etc/sysconfig/network-scripts/** ändern? Centos/Redhat-Exploit
- [ ] Kannst du [**in ini-, int.d-, systemd- oder rc.d-Dateien schreiben**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Andere Tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Kannst du [**NFS missbrauchen, um Privilegien zu eskalieren**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Musst du [**aus einer restriktiven Shell ausbrechen**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo-Sicherheitshinweis: sudoedit-Bearbeitung beliebiger Dateien](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle-Linux-Dokumentation: systemd-Drop-in-Konfiguration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: Anforderungen und Forschung zum CVE-2024-1086-Exploit](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys-Sicherheitshinweis: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
