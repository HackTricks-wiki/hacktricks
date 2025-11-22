# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, bir diamond ticket, herhangi bir kullanıcı olarak herhangi bir servise **erişim sağlamak için kullanılabilecek bir TGT**'dir. Golden ticket tamamen çevrimdışı olarak sahte olarak oluşturulur, o domain'in krbtgt hash'i ile şifrelenir ve kullanım için bir oturum açma oturumuna yerleştirilir. Domain denetleyicileri, kendileri tarafından meşru olarak verilen TGT'leri takip etmedikleri için, kendi krbtgt hash'i ile şifrelenmiş TGT'leri memnuniyetle kabul ederler.

Golden ticket kullanımını tespit etmek için iki yaygın teknik vardır:

- Eşleşen bir AS-REQ'si olmayan TGS-REQ'leri arayın.
- Mimikatz'ın varsayılan 10 yıllık geçerlilik süresi gibi saçma değerlere sahip TGT'leri arayın.

Bir **diamond ticket**, **bir DC tarafından verilmiş meşru bir TGT'nin alanlarını değiştirerek** oluşturulur. Bu, bir **TGT** isteyerek, domain'in krbtgt hash'i ile **şifresini çözerek**, biletin istenen alanlarını **değiştirerek** ve ardından **yeniden şifreleyerek** gerçekleştirilir. Bu, bir golden ticket'in bahsedilen iki dezavantajını şu şekilde aşar:

- TGS-REQ'lerin öncesinde bir AS-REQ bulunacaktır.
- TGT bir DC tarafından verildiği için domain'in Kerberos politikasından gelen tüm doğru detaylara sahip olacaktır. Bu alanlar golden ticket'te doğru şekilde taklit edilebilse de, bu daha karmaşıktır ve hataya açıktır.

### Gereksinimler ve iş akışı

- Cryptographic material: krbtgt AES256 key (tercih edilen) veya TGT'yi çözmek ve yeniden imzalamak için NTLM hash.
- Legitimate TGT blob: `/tgtdeleg`, `asktgt`, `s4u` ile elde edilmiş veya bellekten ticket'lar dışa aktarılmış.
- Context data: hedef kullanıcı RID, grup RIDs/SIDs ve (isteğe bağlı) LDAP kaynaklı PAC öznitelikleri.
- Service keys (yalnızca service ticket'ları yeniden oluşturmayı planlıyorsanız): taklit edilecek servis SPN'sinin AES anahtarı.

1. Kontrolünüzdeki herhangi bir kullanıcı için AS-REQ yoluyla bir TGT elde edin (Rubeus `/tgtdeleg` kullanışlıdır çünkü kimlik bilgisi olmadan istemciyi Kerberos GSS-API dansını gerçekleştirmeye zorlar).
2. Dönen TGT'yi krbtgt anahtarı ile çözün, PAC özniteliklerini yama yapın (kullanıcı, gruplar, oturum açma bilgileri, SIDs, cihaz claim'leri vb.).
3. Aynı krbtgt anahtarı ile bileti yeniden şifreleyin/ima ile imzalayın ve mevcut oturum açma oturumuna enjekte edin (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. İsteğe bağlı olarak, ağ üzerinde stealth kalmak için geçerli bir TGT blob'u artı hedef servis anahtarını sağlayarak işlemi bir service ticket üzerinde tekrarlayın.

### Güncellenmiş Rubeus tradecraft (2024+)

Huntress tarafından yapılan son çalışmalar, Rubeus içindeki `diamond` action'ını, daha önce sadece golden/silver ticket'lar için var olan `/ldap` ve `/opsec` iyileştirmelerini taşımak suretiyle modernize etti. `/ldap` artık AD'den doğrudan doğru PAC özniteliklerini otomatik dolduruyor (kullanıcı profili, oturum açma saatleri, sidHistory, domain politikaları), `/opsec` ise iki adımlı pre-auth dizisini gerçekleştirip yalnızca AES kriptoyu zorunlu kılarak AS-REQ/AS-REP akışını bir Windows istemcisinden ayırt edilemez hale getiriyor. Bu, boş cihaz ID'leri veya gerçekçi olmayan geçerlilik pencereleri gibi belirgin göstergeleri dramatik şekilde azaltır.
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
- `/ldap` (isteğe bağlı `/ldapuser` & `/ldappassword` ile) hedef kullanıcının PAC politika verilerini yansıtmak için AD ve SYSVOL'u sorgular.
- `/opsec` Windows-benzeri bir AS-REQ yeniden denemesini zorlar, gürültülü bayrakları sıfırlar ve AES256'ya bağlı kalır.
- `/tgtdeleg` hedefin cleartext password veya NTLM/AES anahtarına dokunmadan yine de decryptable TGT döndürür.

### Servis bileti yeniden oluşturma

Aynı Rubeus güncellemesi, diamond tekniğini TGS blobs üzerinde uygulama yeteneğini ekledi. `diamond`'a **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key** besleyerek, KDC'ye dokunmadan gerçekçi servis biletleri oluşturabilirsiniz — pratikte daha gizli bir silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Bu iş akışı, zaten bir servis hesabı anahtarını kontrol ediyorsanız (ör. örn. `lsadump::lsa /inject` veya `secretsdump.py` ile dump'landıysa) ve yeni AS/TGS trafiği oluşturmadan AD politikası, zamanlamalar ve PAC verileriyle tam uyumlu tek seferlik bir TGS oluşturmak istiyorsanız idealdir.

### OPSEC ve tespit notları

- Geleneksel hunter heuristikleri (TGS without AS, decade-long lifetimes) hala golden tickets için geçerlidir, ancak diamond tickets esasen **PAC içeriği veya grup eşlemesi imkânsız görünüyorsa** ortaya çıkar. Otomatik karşılaştırmalar taklidi hemen işaretlemesin diye her PAC alanını (oturum açma saatleri, kullanıcı profil yolları, cihaz kimlikleri) doldurun.
- **Do not oversubscribe groups/RIDs**. Eğer sadece `512` (Domain Admins) ve `519` (Enterprise Admins) gerekiyorsa, orada durun ve hedef hesabın AD içinde başka yerlerde makul şekilde bu gruplara ait olduğundan emin olun. Aşırı `ExtraSids` ele verir.
- Splunk's Security Content project, diamond tickets için attack-range telemetrisi ve *Windows Domain Admin Impersonation Indicator* gibi algılamaları dağıtır; bu gösterge sıradışı Event ID 4768/4769/4624 dizilerini ve PAC grup değişikliklerini ilişkilendirir. Bu veri kümesini yeniden oynatmak (veya yukarıdaki komutlarla kendi veri kümenizi oluşturmak), T1558.001 için SOC kapsama alanını doğrulamaya yardımcı olurken, kaçınmak için somut uyarı mantığı sağlar.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
