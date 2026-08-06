# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Golden ticket gibi**, diamond ticket **herhangi bir kullanıcı olarak herhangi bir servise erişmek** için kullanılabilen bir TGT'dir. Golden ticket tamamen offline olarak forge edilir, ilgili domain'in krbtgt hash'i ile şifrelenir ve ardından kullanılmak üzere bir logon session'a aktarılır. Domain controller'lar kendilerinin (veya kendisinin) meşru olarak yayınladığı TGT'leri takip etmediğinden, kendi krbtgt hash'i ile şifrelenmiş TGT'leri memnuniyetle kabul ederler.<sup>[[1]](#references)</sup>

Golden ticket kullanımını tespit etmek için kullanılan iki yaygın teknik vardır:

- Karşılık gelen bir AS-REQ'si olmayan TGS-REQ'leri arayın.
- Mimikatz'ın varsayılan 10 yıllık lifetime değeri gibi anlamsız değerlere sahip TGT'leri arayın.

Bir **diamond ticket**, **bir DC tarafından yayınlanmış meşru bir TGT'nin alanları değiştirilerek** oluşturulur. Bu işlem, bir **TGT istemek**, bunu domain'in krbtgt hash'i ile **decrypt etmek**, ticket'ın istenen alanlarını **değiştirmek** ve ardından **yeniden encrypt etmek** yoluyla gerçekleştirilir. Bu yöntem, golden ticket'ın yukarıda belirtilen iki eksikliğini giderir çünkü:<sup>[[1]](#references)</sup>

- TGS-REQ'lerin öncesinde bir AS-REQ bulunur.
- TGT bir DC tarafından yayınlandığından, domain'in Kerberos policy'sinden gelen tüm doğru ayrıntılara sahip olur. Bunlar golden ticket içinde doğru şekilde forge edilebilse de süreç daha karmaşıktır ve hatalara daha açıktır.

### Requirements & workflow

- **Cryptographic material**: TGT'nin decrypt edilmesi ve yeniden imzalanması için krbtgt AES256 key'i (tercih edilir) veya NTLM hash'i.
- **Legitimate TGT blob**: `/tgtdeleg`, `asktgt`, `s4u` ile veya memory'den ticket'lar export edilerek elde edilir.
- **Context data**: hedef kullanıcının RID'i, group RID'leri/SID'leri ve (isteğe bağlı olarak) LDAP'tan elde edilen PAC attribute'ları.
- **Service keys** (yalnızca service ticket'ları yeniden oluşturmayı planlıyorsanız): impersonate edilecek service SPN'nin AES key'i.

1. AS-REQ üzerinden kontrolünüzdeki herhangi bir kullanıcı için bir TGT elde edin (Rubeus `/tgtdeleg`, client'ı credential olmadan Kerberos GSS-API dance'i gerçekleştirmeye zorladığı için kullanışlıdır).
2. Döndürülen TGT'yi krbtgt key'i ile decrypt edin ve PAC attribute'larını (user, group'lar, logon info, SID'ler, device claims vb.) patch edin.
3. Ticket'ı aynı krbtgt key'i ile yeniden encrypt/imzala ve mevcut logon session'a inject edin (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. İsteğe bağlı olarak, wire üzerinde stealthy kalmak için geçerli bir TGT blob'u ile hedef service key'ini sağlayarak işlemi bir service ticket üzerinde tekrarlayın.

### Updated Rubeus tradecraft (2024+)

Huntress tarafından gerçekleştirilen güncel çalışmalar, daha önce yalnızca golden/silver ticket'larda bulunan `/ldap` ve `/opsec` iyileştirmelerini port ederek Rubeus içindeki `diamond` action'ını modernleştirdi. `/ldap` artık LDAP sorgulayarak ve account/group attribute'larını ve Kerberos/password policy'sini (ör. `GptTmpl.inf`) çıkarmak için SYSVOL'u mount ederek gerçek PAC context'i elde ediyor; `/opsec` ise iki aşamalı preauth exchange'i gerçekleştirip yalnızca AES kullanımını ve gerçekçi KDCOptions değerlerini zorunlu kılarak AS-REQ/AS-REP flow'unu Windows ile eşleştiriyor. Bu, eksik PAC field'ları veya policy ile uyuşmayan lifetime'lar gibi belirgin indicator'ları büyük ölçüde azaltır.<sup>[[3]](#references)</sup>
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
- `/ldap` (isteğe bağlı `/ldapuser` ve `/ldappassword` ile) hedef kullanıcının PAC policy verilerini taklit etmek için AD ve SYSVOL'u sorgular.
- `/opsec`, Windows benzeri bir AS-REQ retry işlemini zorunlu kılar, gürültülü flag'leri sıfırlar ve AES256 ile sınırlı kalır.
- `/tgtdeleg`, decrypt edilebilir bir TGT döndürmeye devam ederken victim'ın cleartext password veya NTLM/AES key bilgilerine dokunmaz.

### Service-ticket recutting

Aynı Rubeus güncellemesi, diamond tekniğini TGS blob'larına uygulama özelliğini de ekledi. `diamond` komutuna **base64-encoded TGT** (`asktgt`, `/tgtdeleg` veya daha önce forged edilmiş bir TGT'den), **service SPN** ve **service AES key** sağlanarak KDC'ye dokunmadan gerçekçi service ticket'lar mint edilebilir; bu, daha stealthy bir silver ticket işlevi görür.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Bu iş akışı, bir service account key'i (ör. `lsadump::lsa /inject` veya `secretsdump.py` ile dump edilmiş) zaten kontrol ettiğinizde ve yeni AS/TGS trafiği oluşturmadan AD policy'si, zaman çizelgeleri ve PAC verileriyle tamamen uyumlu tek seferlik bir TGS kesmek istediğinizde idealdir.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Bazen **sapphire ticket** olarak adlandırılan daha yeni bir yaklaşım, Diamond'ın "real TGT" temelini **S4U2self+U2U** ile birleştirerek ayrıcalıklı bir PAC'i çalar ve bunu kendi TGT'nizin içine yerleştirir. Ek SID'ler uydurmak yerine, `sname` alanının düşük ayrıcalıklı requester'ı hedeflediği yüksek ayrıcalıklı bir kullanıcı için U2U S4U2self ticket'ı istersiniz; KRB_TGS_REQ, requester'ın TGT'sini `additional-tickets` içinde taşır ve `ENC-TKT-IN-SKEY` değerini ayarlar. Böylece service ticket, bu kullanıcının key'i ile decrypt edilebilir. Ardından ayrıcalıklı PAC'i çıkarır ve krbtgt key'i ile yeniden imzalamadan önce meşru TGT'nizin içine splice edersiniz.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket'in `ticketer.py` aracı artık `-impersonate` + `-request` (live KDC exchange) aracılığıyla sapphire desteği sunuyor:<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate`, bir kullanıcı adı veya SID kabul eder; `-request`, ticket'ları decrypt/patch etmek için canlı kullanıcı kimlik bilgileri ile krbtgt key material'ı (AES/NTLM) gerektirir.

Bu varyantı kullanırken dikkat edilmesi gereken temel OPSEC göstergeleri:<sup>[[5]](#references)</sup>

- TGS-REQ, `ENC-TKT-IN-SKEY` ve `additional-tickets` (victim TGT) taşıyacaktır; bu, normal traffic içinde nadir görülür.
- `sname` genellikle requesting user ile eşleşir (self-service access) ve Event ID 4769, caller ile target'ın aynı SPN/user olduğunu gösterir.
- Aynı client computer ile ancak farklı CNAME'lere sahip eşleşmiş 4768/4769 kayıtları bekleyin (low-priv requester ile privileged PAC owner).

### OPSEC & detection notes

- Geleneksel hunter heuristics (AS olmadan TGS, on yıllar süren lifetimelar) golden tickets için hâlâ geçerlidir; ancak diamond tickets çoğunlukla **PAC içeriği veya group mapping imkansız göründüğünde** ortaya çıkar. Otomatik karşılaştırmaların forgery'yi hemen işaretlememesi için her PAC field'ını (logon hours, user profile paths, device IDs) doldurun.<sup>[[3]](#references)</sup>
- **Grupları/RID'leri aşırı yüklemeyin**. Yalnızca `512` (Domain Admins) ve `519` (Enterprise Admins) gerekiyorsa burada durun ve target account'un AD'nin başka bölümlerinde makul biçimde bu gruplara ait olduğundan emin olun. Aşırı `ExtraSids` kullanımı ele verir.
- Sapphire-style swaps, U2U fingerprints bırakır: 4769 içinde `ENC-TKT-IN-SKEY` + `additional-tickets` ve bir user'a (çoğunlukla requester'a) işaret eden bir `sname`; ardından forged ticket'tan kaynaklanan bir 4624 logon. Yalnızca no-AS-REQ boşluklarını aramak yerine bu field'ları correlate edin.<sup>[[5]](#references)</sup>
- Microsoft, CVE-2026-20833 nedeniyle **RC4 service ticket issuance** kullanımını aşamalı olarak sona erdirmeye başladı; KDC üzerinde yalnızca AES etypes uygulanması hem domain'i harden eder hem de diamond/sapphire tooling ile uyum sağlar (/opsec zaten AES'i zorunlu kılar). Forged PAC'lere RC4 eklemek giderek daha fazla dikkat çekecektir.<sup>[[6]](#references)</sup>
- Splunk'ın Security Content projesi, diamond tickets için attack-range telemetry ve *Windows Domain Admin Impersonation Indicator* gibi detection'lar dağıtır; bunlar olağandışı Event ID 4768/4769/4624 sequence'lerini ve PAC group değişikliklerini correlate eder. Bu dataset'i yeniden oynatmak (veya yukarıdaki command'lerle kendiniz oluşturmak), T1558.001 için SOC coverage'ını doğrulamanıza ve kaçınabileceğiniz somut alert logic elde etmenize yardımcı olur.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
