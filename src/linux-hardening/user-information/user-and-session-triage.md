# Benutzer, Sitzungen und Zugangsdaten-Artefakte

{{#include ../../banners/hacktricks-training.md}}

Beginne mit der Identität, der die aktuelle Shell gehört, und ermittle anschließend weitere Benutzer, Gruppen, aktive Sitzungen und Anmeldedatenspeicher. Die Seite [reale, effektive und gespeicherte Benutzer-ID](euid-ruid-suid.md) erklärt, warum sich die effektiven Berechtigungen eines Prozesses von seinem Anmeldekonto unterscheiden können.

## Identitäten und gruppenbasierten Zugriff ermitteln

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` berücksichtigt auch konten aus Verzeichnisdiensten, die beim einfachen Auslesen von `/etc/passwd` möglicherweise fehlen. Prüfe Konten mit UID 0, Login-Shells, Home-Verzeichnisse, ergänzende Gruppen und Konten, deren Konfiguration unerwartet interaktiven Login erlaubt. Die Seite [interessante Gruppen](interesting-groups-linux-pe/README.md) behandelt delegierte Zugriffe wie `sudo`, `docker`, `disk` und `shadow`. Prüfe die tatsächlichen Dateisystem-ACLs und lokalen Richtlinien, bevor du aus einem Gruppennamen auf Berechtigungen schließt.

Wenn [NSS `passwd`-, `group`- oder `shadow`-Abfragen](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) an eine Datenbank weiterleitet, prüfe den aktiven Provider und seinen Konfigurationspfad, bevor du datenbankgestützte Identitäten bewertest. Bei PostgreSQL-NSS-Installationen sind `/etc/nss-pgsql.conf` und `/etc/nss-pgsql-root.conf` lediglich Hinweise auf Dateipfade, da Verbindungseinstellungen Zugangsdaten enthalten können. Eine Datenbankrolle ist nur dann relevant, wenn sie Datensätze ändern kann, die der aktive NSS-Provider tatsächlich zurückgibt, und sich ein Konto damit authentifizieren kann. Eine primäre GID von 0 bedeutet Mitgliedschaft in der Root-Gruppe, nicht UID 0; eine Zuordnung zur sudo-Gruppe erfordert eine wirksame [sudoers-Gruppenregel](https://man7.org/linux/man-pages/man5/sudoers.5.html) und gegebenenfalls die erforderliche Authentifizierung. Eine UID-0-Zuordnung stellt eine andere Identitätsgrenze dar. Gib bei der passiven Aufzählung keine Verbindungszeichenfolgen aus und ändere keine Kontodatensätze.

Vergleiche außerdem numerische UIDs über lokale Kontonamen hinweg. Zwei Namen in [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) können auf dieselbe Unix-Dateiidentität verweisen, während sich ihre Login-Authentifizierungsdatensätze unterscheiden. Ein neu hinzugefügter Alias mit einer gemeinsam genutzten, von null verschiedenen UID kann daher nach erfolgreicher Authentifizierung Zugriff auf Dateien oder Prozesse eines anderen Benutzers ermöglichen; Root-Zugriff gewährt er nicht, außer diese UID oder ein separater Berechtigungspfad ermöglicht ihn. Gemeinsam genutzte UIDs können beabsichtigt sein. Überprüfe die Kontoquelle (`/etc/passwd` oder NSS), die Erstellungshistorie, Shell und Home-Verzeichnis, die tatsächliche Authentifizierungsrichtlinie sowie, ob die Konten berechtigt sind, die Identität gemeinsam zu nutzen. Eine ausschließlich lokale Prüfung auf doppelte Konten kann keinen Alias aus einem Verzeichnisdienst ausschließen.

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

Ein `screen`- oder `tmux`-Socket kann eine vorhandene Shell zugänglich machen, wenn seine Berechtigungen dem aktuellen Benutzer das Anhängen erlauben. Prüfe vor dem Zugriff den Eigentümer und den Socket-Modus; an eine Sitzung eines anderen Benutzers kann nicht automatisch angehängt werden. Auch ein aktiver sudo-Zeitstempel oder ein SSH-Agent-Socket kann relevant sein, doch ihre Wiederverwendung hängt von Benutzeridentität, Berechtigungen und Richtlinien ab. Informationen zum Missbrauch von Agent-Forwarding findest du unter [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

Ein [OpenSSH-Multiplex-Control-Socket](https://man.openbsd.org/ssh_config#ControlMaster) ist von `SSH_AUTH_SOCK` getrennt: `ControlMaster` und `ControlPath` ermöglichen späteren SSH-Clients, eine bestehende authentifizierte Verbindung gemeinsam zu nutzen, während `ControlPersist` den Master nach Ende der ersten Sitzung verfügbar halten kann. Prüfe die `.ssh/config` des aktuellen Benutzers sowie flach verschachtelte Socket-Pfade unter `.ssh`, einschließlich Eigentümer und Berechtigungen. Ein Socket-Dateiname allein beweist weder, dass der Master aktiv ist, noch, dass der aktuelle Benutzer eine Verbindung herstellen darf oder welches Remote-Konto er verwendet.

## Benutzerartefakte überprüfen

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell-Verlauf, Startdateien, SSH-Schlüssel, Anwendungskonfigurationen, GPG-Schlüsselbunde und Kerberos-Caches können Zugangsdaten oder beschreibbare Persistenzpunkte offenlegen. Eine beschreibbare `authorized_keys`-Datei oder Shell-Startdatei eines privilegierteren Kontos sollte überprüft werden. Die [Post-Exploitation-Seite](../post-exploitation/README.md) behandelt die Verlagerung des GPG-Homedir und die Suche nach Zugangsdaten; [Linux Active Directory](linux-active-directory.md) behandelt die Wiederverwendung von Kerberos-Caches und Keytabs. Die [PAM-Seite](../software-information/pam-pluggable-authentication-modules.md) erläutert Risiken von Authentifizierungsrichtlinien.
{{#include ../../banners/hacktricks-training.md}}
