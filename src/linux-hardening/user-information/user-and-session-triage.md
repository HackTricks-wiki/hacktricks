# Benutzer, Sitzungen und Anmeldedaten-Artefakte

{{#include ../../banners/hacktricks-training.md}}

Beginne mit der Identität, der die aktuelle Shell gehört, und ermittle dann weitere Benutzer, Gruppen, aktive Sitzungen und Anmeldedatenspeicher. Die Seite [real, effective, and saved user ID](euid-ruid-suid.md) erklärt, warum sich die effektiven Berechtigungen eines Prozesses von seinem Login-Konto unterscheiden können.

## Identitäten und gruppenbasierten Zugriff ermitteln

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` umfasst auch verzeichnisgestützte Konten, die beim einfachen Auslesen von `/etc/passwd` möglicherweise fehlen. Prüfen Sie Konten mit UID 0, Login-Shells, Home-Verzeichnisse, zusätzliche Gruppen und Konten, deren Konfiguration unerwartet interaktive Logins zulässt. Die Seite zu [interessanten Gruppen](interesting-groups-linux-pe/README.md) behandelt delegierte Zugriffe wie `sudo`, `docker`, `disk` und `shadow`. Prüfen Sie die tatsächlichen Dateisystem-ACLs und lokalen Richtlinien, bevor Sie aus einem Gruppennamen auf Berechtigungen schließen.

Wenn [NSS Abfragen von `passwd`, `group` oder `shadow` auf eine Datenbank abbildet](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html), prüfen Sie den aktiven Provider und dessen Konfigurationspfad, bevor Sie datenbankgestützte Identitäten bewerten. Bei PostgreSQL-NSS-Deployments sind `/etc/nss-pgsql.conf` und `/etc/nss-pgsql-root.conf` lediglich Hinweise auf Pfade, da die Verbindungseinstellungen Zugangsdaten enthalten können. Eine Datenbankrolle ist nur dann relevant, wenn sie Einträge ändern kann, die der aktive NSS-Provider tatsächlich zurückgibt, und sich ein Konto damit authentifizieren kann. Eine primäre GID von 0 bedeutet Mitgliedschaft in der Root-Gruppe, nicht UID 0; eine sudo-Gruppenzuordnung setzt eine wirksame [sudoers-Gruppenregel](https://man7.org/linux/man-pages/man5/sudoers.5.html) und gegebenenfalls eine erforderliche Authentifizierung voraus. Eine UID-0-Zuordnung stellt eine andere Identitätsgrenze dar. Geben Sie bei passiver Aufzählung keine Verbindungszeichenfolgen aus und ändern Sie keine Kontoeinträge.

Vergleichen Sie außerdem numerische UIDs über lokale Kontennamen hinweg. Zwei Namen in [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) können dieselbe Unix-Dateiidentität bezeichnen, während ihre Login-Authentifizierungseinträge unterschiedlich sein können. Ein neu hinzugefügter Alias mit gemeinsamer, von null verschiedener UID kann nach erfolgreicher Authentifizierung daher Zugriff auf die Dateien oder Prozesse eines anderen Benutzers ermöglichen; Root-Rechte verleiht er nur, wenn diese UID oder ein separater Berechtigungspfad dies ermöglicht. Gemeinsame UIDs können beabsichtigt sein. Überprüfen Sie die Kontoquelle (`/etc/passwd` oder NSS), den Erstellungsverlauf, Shell und Home-Verzeichnis, die tatsächlichen Authentifizierungsrichtlinien sowie die Berechtigung der Konten, diese Identität gemeinsam zu verwenden. Eine Prüfung, die nur lokale Konten berücksichtigt, kann einen verzeichnisgestützten Alias nicht ausschließen.

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

Ein `screen`- oder `tmux`-Socket kann eine bestehende Shell offenlegen, wenn seine Berechtigungen dem aktuellen Benutzer das Anhängen erlauben. Prüfe vor dem Zugriffsversuch den Eigentümer und den Socket-Modus; an die Sitzung eines anderen Benutzers kann nicht automatisch angehängt werden. Ein aktiver sudo-Zeitstempel oder ein SSH-Agent-Socket kann ebenfalls relevant sein, doch ihre Wiederverwendung hängt von Benutzeridentität, Berechtigungen und Richtlinien ab. Informationen zum Missbrauch von Agent Forwarding findest du unter [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Ein [OpenSSH-Multiplexing-Control-Socket](https://man.openbsd.org/ssh_config#ControlMaster) ist von `SSH_AUTH_SOCK` getrennt: `ControlMaster` und `ControlPath` ermöglichen späteren SSH-Clients, eine bestehende authentifizierte Verbindung gemeinsam zu nutzen, während `ControlPersist` den Master nach Ende der ersten Sitzung verfügbar halten kann. Untersuche die `.ssh/config` des aktuellen Benutzers und die direkt oder flach verschachtelten Socket-Pfade unter `.ssh`, einschließlich Eigentümer und Berechtigungen. Ein Socket-Dateiname allein beweist weder, dass der Master aktiv ist, noch, dass der aktuelle Benutzer eine Verbindung herstellen darf oder welches Remote-Konto er verwendet.

## Benutzerartefakte überprüfen

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell-Historie, Startdateien, SSH-Schlüssel, Anwendungskonfigurationen, GPG-Schlüsselringe und Kerberos-Caches können Zugangsdaten oder beschreibbare Persistenzpunkte offenlegen. Eine beschreibbare `authorized_keys`-Datei oder Shell-Startdatei eines privilegierteren Kontos sollte überprüft werden. Die [Post-Exploitation-Seite](../post-exploitation/README.md) behandelt die Verlagerung des GPG-Homedir und die Suche nach Zugangsdaten; [Linux Active Directory](linux-active-directory.md) behandelt die Wiederverwendung von Kerberos-Caches und Keytabs. Die [PAM-Seite](../software-information/pam-pluggable-authentication-modules.md) erläutert Risiken von Authentifizierungsrichtlinien.
{{#include ../../banners/hacktricks-training.md}}
