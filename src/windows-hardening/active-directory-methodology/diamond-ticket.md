# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Golden ticket gibi**, bir diamond ticket herhangi bir hizmete herhangi bir kullanıcı olarak erişmek için kullanılabilecek bir TGT'dir. Bir golden ticket tamamen çevrimdışı olarak sahte olarak üretilir, o domainin krbtgt hash'i ile şifrelenir ve sonra kullanım için bir oturum açma oturumuna geçirilir. Domain controller'lar onların (veya onların) yasal olarak verdiği TGT'leri takip etmediği için, kendi krbtgt hash'i ile şifrelenmiş TGT'leri memnuniyetle kabul ederler.

Golden ticket kullanımını tespit etmek için iki yaygın teknik vardır:

- Karşılık gelen bir AS-REQ olmayan TGS-REQ'lere bakın.
- Mimikatz'ın varsayılan 10-year lifetime gibi saçma değerler içeren TGT'lere bakın.

Bir **diamond ticket**, bir DC tarafından verilmiş meşru bir TGT'nin alanlarının **değiştirilmesiyle** oluşturulur. Bu, bir **TGT talep edilerek**, domain'in krbtgt hash'i ile **şifresi çözülerek**, biletin istenen alanları **değiştirilerek**, ardından **tekrar şifrelenerek** gerçekleştirilir. Bu, bir golden ticket'in yukarıda bahsedilen iki eksikliğini aşar çünkü:

- TGS-REQ'lerin öncesinde bir AS-REQ olacaktır.
- TGT bir DC tarafından verilmiş olduğu için domain'in Kerberos politikasından gelen tüm doğru detaylara sahip olacaktır. Bu bilgiler golden ticket'te doğru şekilde taklit edilebilse de, bunu yapmak daha karmaşıktır ve hata yapmaya açıktır.

### Requirements & workflow

- **Cryptographic material**: TGT'yi çözmek ve yeniden imzalamak için krbtgt AES256 key (tercih edilen) veya NTLM hash.
- **Legitimate TGT blob**: `/tgtdeleg`, `asktgt`, `s4u` ile elde edilmiş veya bellekten export edilmiş ticket'lar.
- **Context data**: hedef kullanıcı RID'si, grup RID/SID'leri ve (isteğe bağlı) LDAP'dan türetilmiş PAC attributes.
- **Service keys** (sadece service ticket'leri yeniden oluşturmayı planlıyorsanız): taklit edilecek service SPN'nin AES key'i.

1. AS-REQ ile kontrolünüzdeki herhangi bir kullanıcı için bir TGT elde edin (Rubeus `/tgtdeleg` Kerberos GSS-API dansını kimlik bilgisi olmadan zorladığı için kullanışlıdır).
2. Dönen TGT'yi krbtgt key ile çözün, PAC attributes'ları (kullanıcı, gruplar, logon bilgisi, SIDs, device claims vb.) yama yapın.
3. Aynı krbtgt key ile bileti tekrar şifreleyin/imzalayın ve mevcut oturum açma oturumuna enjekte edin (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. İsteğe bağlı olarak, telgraf üzerinde gizli kalmak için geçerli bir TGT blob ve hedef service key sağlayarak aynı işlemi bir service ticket üzerinde tekrarlayın.

### Updated Rubeus tradecraft (2024+)

Huntress tarafından yapılan yakın zamanda yapılan çalışmalar, Rubeus içindeki `diamond` action'ını, daha önce sadece golden/silver ticket'lar için var olan `/ldap` ve `/opsec` iyileştirmelerini aktararak modernize etti. `/ldap` artık AD'den doğrudan doğru PAC attributes'ları otomatik dolduruyor (kullanıcı profili, logon hours, sidHistory, domain policies), `/opsec` ise iki adımlı pre-auth dizisini gerçekleştirip sadece AES kriptosunu zorunlu kılarak AS-REQ/AS-REP akışını bir Windows istemcisinden ayırt edilemez hale getiriyor. Bu, boş device ID'leri veya gerçekçi olmayan geçerlilik pencereleri gibi belirgin göstergeleri dramatik şekilde azaltır.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) hedef kullanıcının PAC politika verilerini yansıtmak için AD ve SYSVOL'u sorgular.
- `/opsec` Windows-benzeri bir AS-REQ yeniden denemesini zorlar, gürültülü bayrakları sıfırlar ve AES256'ya sadık kalır.
- `/tgtdeleg` mağdurun düz metin parolasına veya NTLM/AES anahtarına dokunmadan yine de şifresi çözülebilir bir TGT döndürür.

### Service-ticket recutting

Aynı Rubeus güncellemesi, diamond tekniğini TGS blob'larına uygulama yeteneğini ekledi. `diamond` için **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), **service SPN**, ve **service AES key** sağladığınızda, KDC'ye dokunmadan gerçekçi service tickets oluşturabilirsiniz — fiilen daha gizli bir silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Bu iş akışı, zaten bir service account anahtarına sahip olduğunuzda (ör. `lsadump::lsa /inject` veya `secretsdump.py` ile döküm alınmış) ve yeni AS/TGS trafiği oluşturmadan AD politikalarına, zaman çizelgelerine ve PAC verilerine tam uyan tek seferlik bir TGS kesmek istediğinizde idealdir.

### OPSEC & tespit notları

- Geleneksel hunter heuristics (TGS without AS, decade-long lifetimes) hala golden tickets için geçerlidir, ancak diamond tickets esas olarak **PAC content or group mapping looks impossible** durumlarında ortaya çıkar. Otomatik karşılaştırmalar sahteliği hemen işaretlemesin diye her PAC alanını (logon hours, user profile paths, device IDs) doldurun.
- **Do not oversubscribe groups/RIDs**. Sadece `512` (Domain Admins) ve `519` (Enterprise Admins) gerekiyorsa orada durun ve hedef hesabın AD'de başka yerlerde makul şekilde bu gruplara ait olduğundan emin olun. Aşırı `ExtraSids` ele verir.
- Splunk's Security Content project, diamond tickets için attack-range telemetry ve *Windows Domain Admin Impersonation Indicator* gibi detections dağıtır; bu, sıra dışı Event ID 4768/4769/4624 dizilerini ve PAC grup değişikliklerini korele eder. Bu veri kümesini tekrar oynatmak (veya yukarıdaki komutlarla kendi verinizi üretmek), SOC kapsamını T1558.001 için doğrulamaya yardımcı olurken kaçınmanız gereken somut alarm mantığını da sağlar.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
