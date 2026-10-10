# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Golden ticket gibi**, diamond ticket de **herhangi bir kullanıcı olarak herhangi bir hizmete erişmek** için kullanılabilen bir TGT'dir. Golden ticket tamamen çevrimdışı olarak sahte şekilde oluşturulur, etki alanının krbtgt hash'iyle şifrelenir ve ardından kullanılmak üzere bir logon session'a aktarılır. Domain controller'lar kendilerinin (veya başka bir DC'nin) meşru olarak verdiği TGT'leri takip etmediğinden, kendi krbtgt hash'iyle şifrelenmiş TGT'leri memnuniyetle kabul ederler.<sup>[[1]](#references)</sup>

Golden ticket kullanımını tespit etmek için yaygın olarak kullanılan iki teknik vardır:

- Karşılık gelen bir AS-REQ'si olmayan TGS-REQ'leri arayın.
- Mimikatz'in varsayılan 10 yıllık ömrü gibi, gerçek dışı değerlere sahip TGT'leri arayın.

**Diamond ticket**, **bir DC tarafından verilmiş meşru bir TGT'nin alanları değiştirilerek** oluşturulur. Bunun için **bir TGT istenir**, etki alanının krbtgt hash'iyle **şifresi çözülür**, biletin istenen alanları **değiştirilir** ve ardından bilet **yeniden şifrelenir**. Bu yöntem, golden ticket'ın yukarıda belirtilen iki eksikliğini giderir çünkü:<sup>[[1]](#references)</sup>

- TGS-REQ'lerden önce bir AS-REQ bulunur.
- TGT bir DC tarafından verilmiştir; bu da etki alanının Kerberos ilkesindeki tüm doğru ayrıntıları içereceği anlamına gelir. Bunlar golden ticket'ta doğru şekilde taklit edilebilse de işlem daha karmaşıktır ve hataya daha açıktır.

### Gereksinimler ve iş akışı

- **Kriptografik materyal**: TGT'nin şifresini çözmek ve yeniden imzalamak için krbtgt AES256 anahtarı (tercih edilir) veya NTLM hash'i.
- **Meşru TGT blob'u**: `/tgtdeleg`, `asktgt`, `s4u` kullanılarak ya da bellekten ticket'lar dışa aktarılarak elde edilir.
- **Bağlam verileri**: hedef kullanıcının RID'si, grup RID'leri/SID'leri ve (isteğe bağlı olarak) LDAP'ten alınan PAC öznitelikleri.
- **Hizmet anahtarları** (yalnızca hizmet ticket'larını yeniden oluşturmayı planlıyorsanız): taklit edilecek hizmet SPN'sinin AES anahtarı.

1. AS-REQ aracılığıyla kontrol ettiğiniz herhangi bir kullanıcı için TGT alın (Rubeus `/tgtdeleg`, kimlik bilgileri olmadan Kerberos GSS-API alışverişini gerçekleştirmesi için istemciyi zorladığından kullanışlıdır).
2. Döndürülen TGT'nin şifresini krbtgt anahtarıyla çözün ve PAC özniteliklerini (kullanıcı, gruplar, logon bilgileri, SID'ler, cihaz talepleri vb.) yamalayın.
3. Ticket'ı aynı krbtgt anahtarıyla yeniden şifreleyip/imzalayın ve geçerli logon session'a enjekte edin (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. İsteğe bağlı olarak, ağ trafiğinde gizliliği korumak için geçerli bir TGT blob'u ile hedef hizmet anahtarını sağlayarak işlemi bir hizmet ticket'ı üzerinde tekrarlayın.

### Güncel Rubeus tradecraft'i (2024+)

Huntress'in yakın tarihli çalışmaları, daha önce yalnızca golden/silver ticket'larda bulunan `/ldap` ve `/opsec` iyileştirmelerini Rubeus'taki `diamond` eylemine taşıyarak bu yöntemi güncelledi. `/ldap` artık LDAP sorguları yaparak **ve** hesap/grup öznitelikleriyle Kerberos/parola ilkesini (ör. `GptTmpl.inf`) çıkarmak için SYSVOL'u bağlayarak gerçek PAC bağlamını alıyor. `/opsec` ise iki aşamalı preauth alışverişini gerçekleştirip yalnızca AES kullanımını ve gerçekçi KDCOptions değerlerini zorunlu kılarak AS-REQ/AS-REP akışını Windows'un davranışına uygun hâle getiriyor. Bu, eksik PAC alanları veya ilkeyle uyuşmayan ömürler gibi belirgin göstergeleri önemli ölçüde azaltıyor.<sup>[[3]](#references)</sup>

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

- `/ldap` (isteğe bağlı `/ldapuser` ve `/ldappassword` ile) AD ve SYSVOL'u sorgulayarak hedef kullanıcının PAC ilke verilerini taklit eder.
- `/opsec`, Windows benzeri bir AS-REQ yeniden denemesini zorlar, gürültülü flag'leri sıfırlar ve AES256 kullanır.
- `/tgtdeleg`, kurbanın açık metin parolasına veya NTLM/AES anahtarına dokunmadan çözülebilir bir TGT döndürür.

### Service-ticket yeniden oluşturma

Aynı Rubeus güncellemesi, diamond tekniğini TGS blob'larına uygulama özelliğini de ekledi. `diamond` komutuna **base64 kodlu bir TGT** (`asktgt`, `/tgtdeleg` veya önceden forge edilmiş bir TGT'den), **service SPN**'i ve **service AES key**'ini vererek KDC'ye dokunmadan gerçekçi service ticket'lar oluşturabilirsiniz; bu, etkili biçimde daha gizli bir silver ticket'tır.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Bu workflow, bir service account key'i zaten kontrol ettiğinizde (ör. `lsadump::lsa /inject` veya `secretsdump.py` ile dump edilmişse) ve yeni AS/TGS trafiği oluşturmadan AD policy, zaman çizelgeleri ve PAC verileriyle kusursuz biçimde eşleşen tek seferlik bir TGS oluşturmak istediğinizde idealdir.<sup>[[3]](#references)</sup>

### Sapphire tarzı PAC takasları (2025)

Bazen **sapphire ticket** olarak adlandırılan daha yeni bir yöntem, Diamond'ın "gerçek TGT" temelini **S4U2self+U2U** ile birleştirerek ayrıcalıklı bir PAC'i çalar ve kendi TGT'nize ekler. Ek SID'ler uydurmak yerine, `sname`'in düşük ayrıcalıklı istekte bulunanı hedeflediği, yüksek ayrıcalıklı bir kullanıcı için U2U S4U2self ticket istersiniz; KRB_TGS_REQ, istekte bulunanın TGT'sini `additional-tickets` içinde taşır ve `ENC-TKT-IN-SKEY` ayarını yaparak service ticket'ın bu kullanıcının anahtarıyla çözülmesini sağlar. Ardından ayrıcalıklı PAC'i çıkarır ve krbtgt key ile yeniden imzalamadan önce meşru TGT'nize eklem yaparsınız.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket'in `ticketer.py` aracı artık `-impersonate` + `-request` (canlı KDC alışverişi) üzerinden sapphire desteği sunuyor:<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` bir kullanıcı adı veya SID kabul eder; `-request`, biletleri şifre çözmek/düzenlemek için canlı kullanıcı kimlik bilgileriyle birlikte krbtgt anahtar materyali (AES/NTLM) gerektirir.

Bu varyantı kullanırken dikkat edilmesi gereken temel OPSEC göstergeleri:<sup>[[5]](#references)</sup>

- TGS-REQ, `ENC-TKT-IN-SKEY` ve `additional-tickets` (kurbanın TGT'si) içerir — normal trafikte nadir görülür.
- `sname` genellikle istekte bulunan kullanıcıyla aynıdır (self-service access); Event ID 4769'da çağıran ve hedef, aynı SPN/kullanıcı olarak görünür.
- Aynı istemci bilgisayarını, ancak farklı CNAMES değerlerini (düşük ayrıcalıklı istekte bulunan kullanıcıya karşı ayrıcalıklı PAC sahibi) içeren eşleştirilmiş 4768/4769 kayıtları bekleyin.

### OPSEC ve tespit notları

- Geleneksel avcı sezgisel kuralları (AS olmadan TGS, on yıllık ömürler) golden ticket'lar için hâlâ geçerlidir; ancak diamond ticket'lar çoğunlukla **PAC içeriği veya grup eşlemesi imkânsız göründüğünde** ortaya çıkar. Otomatik karşılaştırmaların sahteciliği hemen işaretlememesi için her PAC alanını (oturum açma saatleri, kullanıcı profili yolları, cihaz kimlikleri) doldurun.<sup>[[3]](#references)</sup>
- **Grupları/RID'leri gereğinden fazla eklemeyin**. Yalnızca `512` (Domain Admins) ve `519` (Enterprise Admins) gerekiyorsa bunlarla yetinin ve hedef hesabın AD'nin başka yerlerinde de makul biçimde bu gruplara ait olduğundan emin olun. Aşırı `ExtraSids` kullanımı şüphe uyandırır.
- Sapphire tarzı değişimler U2U izleri bırakır: `ENC-TKT-IN-SKEY` + `additional-tickets` ve 4769'da bir kullanıcıyı (genellikle istekte bulunanı) gösteren `sname`; ardından sahte biletten kaynaklanan bir 4624 oturumu açma olayı gelir. Yalnızca AS-REQ olmayan boşlukları aramak yerine bu alanları ilişkilendirin.<sup>[[5]](#references)</sup>
- Microsoft, CVE-2026-20833 nedeniyle **RC4 service ticket issuance** kullanımını aşamalı olarak sonlandırmaya başladı; KDC'de yalnızca AES etypes kullanımını zorunlu kılmak hem etki alanını güçlendirir hem de diamond/sapphire araçlarıyla uyumludur (/opsec zaten AES kullanımını zorunlu kılar). Sahte PAC'lere RC4 eklemek giderek daha fazla dikkat çekecektir.<sup>[[6]](#references)</sup>
- Splunk's Security Content projesi, diamond ticket'lar için attack-range telemetrisinin yanı sıra *Windows Domain Admin Impersonation Indicator* gibi; olağandışı Event ID 4768/4769/4624 dizilerini ve PAC grup değişikliklerini ilişkilendiren tespitler dağıtır. Bu veri kümesini yeniden oynatmak (veya yukarıdaki komutlarla kendinizinkini oluşturmak), T1558.001 için SOC kapsamını doğrulamanıza ve kaçınabileceğiniz somut uyarı mantığı edinmenize yardımcı olur.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Değerli Taşlar: Kerberos Saldırılarının Yeni Nesli (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Biletlerle Oynamayı Seviyoruz (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Kerberos Diamond Ticket'ı Yeniden Şekillendirmek (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket saldırı verileri ve tespitleri (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Mücevherlerin karanlık yüzü: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – CVE-2026-20833 için RC4 service ticket zorunluluğu](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
