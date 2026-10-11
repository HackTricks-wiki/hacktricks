# Benutzer, Sitzungen und Zugangsdaten-Artefakte

{{#include ../../banners/hacktricks-training.md}}

Beginne mit der Identität, der die aktuelle Shell gehört, und ermittle anschließend weitere Benutzer, Gruppen, aktive Sitzungen und Zugangsdaten-Speicher. Die Seite zu [realer, effektiver und gespeicherter Benutzer-ID](euid-ruid-suid.md) erklärt, warum sich die effektiven Rechte eines Prozesses von seinem Anmeldekonto unterscheiden können.

## Identitäten und gruppenbasierten Zugriff ermitteln

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` umfasst auch kontengestützte Verzeichnisdienste, die bei einer einfachen Abfrage von `/etc/passwd` fehlen können. Prüfe Konten mit UID 0, Login-Shells, Home-Verzeichnisse, ergänzende Gruppen und Konten, deren Konfiguration unerwartet eine interaktive Anmeldung erlaubt. Die Seite [interesting groups](interesting-groups-linux-pe/README.md) behandelt delegierten Zugriff wie `sudo`, `docker`, `disk` und `shadow`. Prüfe tatsächliche Dateisystem-ACLs und lokale Richtlinien, bevor du einen Gruppennamen als Privileg einstufst.

Wenn [NSS `passwd`-, `group`- oder `shadow`-Abfragen](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) einer Datenbank zuordnet, prüfe den aktiven Anbieter und dessen Konfigurationspfad, bevor du datenbankgestützte Identitäten bewertest. Bei PostgreSQL-NSS-Installationen sind `/etc/nss-pgsql.conf` und `/etc/nss-pgsql-root.conf` lediglich Hinweise auf Pfade, da Verbindungseinstellungen Zugangsdaten enthalten können. Eine Datenbankrolle ist nur relevant, wenn sie Datensätze ändern kann, die der aktive NSS-Anbieter tatsächlich zurückgibt, und sich ein Konto damit authentifizieren kann. Eine primäre GID von 0 gewährt Mitgliedschaft in der Root-Gruppe, nicht UID 0; eine Zuordnung zur sudo-Gruppe erfordert eine wirksame [sudoers-Gruppenregel](https://man7.org/linux/man-pages/man5/sudoers.5.html) und gegebenenfalls die erforderliche Authentifizierung. Eine UID-0-Zuordnung bildet eine andere Identitätsgrenze. Gib bei einer passiven Aufzählung keine Verbindungszeichenfolgen aus und ändere keine Kontodatensätze.

Vergleiche außerdem numerische UIDs zwischen lokalen Kontennamen. Zwei Namen in [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) können dieselbe Unix-Dateiidentität bezeichnen, während sich ihre Login-Authentifizierungsdatensätze unterscheiden. Ein neu hinzugefügter Alias mit einer gemeinsam genutzten UID ungleich 0 kann daher nach erfolgreicher Authentifizierung Zugriff auf Dateien oder Prozesse eines anderen Benutzers ermöglichen; Root-Zugriff gewährt er nicht, es sei denn, diese UID oder ein separater Privilegienpfad tut dies. Gemeinsam genutzte UIDs können beabsichtigt sein. Prüfe die Kontoquelle (`/etc/passwd` oder NSS), den Erstellungsverlauf, Shell und Home-Verzeichnis, die tatsächliche Authentifizierungsrichtlinie sowie die Berechtigung der Konten, diese Identität gemeinsam zu nutzen. Eine Prüfung, die nur lokale Konten berücksichtigt, kann einen Alias aus einem Verzeichnisdienst nicht ausschließen.

## Aktive und kürzlich verwendete Sitzungen finden

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Ein `screen`- oder `tmux`-Socket kann eine vorhandene Shell zugänglich machen, wenn seine Berechtigungen dem aktuellen Benutzer das Anbinden erlauben. Prüfe Besitzer und Socket-Modus, bevor du den Zugriff versuchst; die Sitzung eines anderen Benutzers ist nicht automatisch zugänglich. Ein aktiver sudo-Zeitstempel oder ein SSH-Agent-Socket kann ebenfalls relevant sein, doch ihre Wiederverwendung hängt von Benutzeridentität, Berechtigungen und Richtlinien ab. Informationen zum Missbrauch von Agent Forwarding findest du unter [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Ein [OpenSSH-Multiplexing-Control-Socket](https://man.openbsd.org/ssh_config#ControlMaster) ist etwas anderes als `SSH_AUTH_SOCK`: `ControlMaster` und `ControlPath` ermöglichen es späteren SSH-Clients, eine bestehende authentifizierte Verbindung gemeinsam zu nutzen, während `ControlPersist` den Master verfügbar halten kann, nachdem die erste Sitzung beendet wurde. Untersuche die `.ssh/config` des aktuellen Benutzers und die Socket-Pfade in `.ssh` auf oberster Ebene, einschließlich Besitzer und Berechtigungen. Ein Socket-Dateiname allein beweist weder, dass der Master aktiv ist, noch, dass der aktuelle Benutzer eine Verbindung herstellen darf oder welches Remote-Konto er verwendet.

## Benutzerartefakte überprüfen

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell-Verlauf, Startdateien, SSH-Schlüssel, Anwendungskonfigurationen, GPG-Schlüsselbunde und Kerberos-Caches können Zugangsdaten oder beschreibbare Persistenzpunkte offenlegen. Eine beschreibbare `authorized_keys`-Datei oder Shell-Startdatei für ein Konto mit höheren Berechtigungen sollte überprüft werden. Die [Post-Exploitation-Seite](../post-exploitation/README.md) behandelt die Verlagerung des GPG-Homedir-Verzeichnisses und die Suche nach Zugangsdaten; [Linux Active Directory](linux-active-directory.md) behandelt die Wiederverwendung von Kerberos-Caches und Keytabs. Die [PAM-Seite](../software-information/pam-pluggable-authentication-modules.md) erläutert die Risiken von Authentifizierungsrichtlinien.
{{#include ../../banners/hacktricks-training.md}}
