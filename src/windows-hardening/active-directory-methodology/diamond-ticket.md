# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Golden ticket gibi**, diamond ticket, **herhangi bir kullanıcı olarak herhangi bir servise erişmek** için kullanılabilen bir TGT'dir. Golden ticket tamamen çevrimdışı olarak oluşturulur, ilgili domain'in krbtgt hash'iyle şifrelenir ve ardından kullanılmak üzere bir logon session'a aktarılır. Domain controller'lar meşru olarak verdikleri TGT'leri izlemediğinden, kendi krbtgt hash'iyle şifrelenmiş TGT'leri memnuniyetle kabul ederler.<sup>[[1]](#references)</sup>

Golden ticket kullanımını tespit etmek için yaygın olarak kullanılan iki teknik vardır:

- Karşılık gelen bir AS-REQ'si olmayan TGS-REQ'leri arayın.
- Mimikatz'in varsayılan 10 yıllık ömrü gibi mantıksız değerler içeren TGT'leri arayın.

**Diamond ticket**, **bir DC tarafından verilmiş meşru bir TGT'nin alanları değiştirilerek** oluşturulur. Bunun için bir **TGT istenir**, domain'in krbtgt hash'iyle **şifresi çözülür**, ticket'ın istenen alanları **değiştirilir** ve ardından ticket **yeniden şifrelenir**. Bu yöntem, golden ticket'ın yukarıda belirtilen iki eksiğini giderir; çünkü:<sup>[[1]](#references)</sup>

- TGS-REQ'lerden önce bir AS-REQ bulunur.
- TGT bir DC tarafından verildiği için domain'in Kerberos politikasındaki tüm doğru ayrıntıları içerir. Golden ticket'ta bunlar doğru şekilde taklit edilebilse de süreç daha karmaşıktır ve hataya daha açıktır.

### Gereksinimler ve iş akışı

- **Kriptografik materyal**: TGT'nin şifresini çözmek ve yeniden imzalamak için krbtgt AES256 anahtarı (tercih edilir) veya NTLM hash'i.
- **Meşru TGT blob'u**: `/tgtdeleg`, `asktgt`, `s4u` kullanılarak ya da bellekten ticket'lar dışa aktarılarak elde edilir.
- **Bağlam verileri**: hedef kullanıcının RID'si, grup RID'leri/SID'leri ve (isteğe bağlı olarak) LDAP'tan türetilmiş PAC öznitelikleri.
- **Servis anahtarları** (yalnızca service ticket'ları yeniden oluşturmayı planlıyorsanız): kimliğine bürünülecek servis SPN'sinin AES anahtarı.

1. AS-REQ aracılığıyla kontrolünüzdeki herhangi bir kullanıcı için TGT alın (Rubeus `/tgtdeleg`, istemciyi kimlik bilgileri olmadan Kerberos GSS-API el sıkışmasını yapmaya zorladığı için kullanışlıdır).
2. Döndürülen TGT'nin şifresini krbtgt anahtarıyla çözün ve PAC özniteliklerini (kullanıcı, gruplar, logon bilgileri, SID'ler, cihaz claim'leri vb.) değiştirin.
3. Ticket'ı aynı krbtgt anahtarıyla yeniden şifreleyip imzalayın ve mevcut logon session'a enjekte edin (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Ağ üzerindeki etkinliği gizli tutmak için, geçerli bir TGT blob'u ve hedef servis anahtarını sağlayarak bu işlemi bir service ticket üzerinde isteğe bağlı olarak tekrarlayın.

### Güncellenmiş Rubeus tradecraft'i (2024+)

Huntress'in yakın tarihli çalışmaları, daha önce yalnızca golden/silver ticket'larda bulunan `/ldap` ve `/opsec` iyileştirmelerini Rubeus içindeki `diamond` eylemine taşıyarak bu yöntemi modernleştirdi. `/ldap`, LDAP'ı sorgulayarak **ve** hesap/grup öznitelikleriyle Kerberos/parola politikasını (ör. `GptTmpl.inf`) çıkarmak için SYSVOL'u bağlayarak gerçek PAC bağlamını alır. `/opsec` ise iki aşamalı preauth alışverişini yapıp yalnızca AES kullanımını ve gerçekçi KDCOptions değerlerini zorunlu kılarak AS-REQ/AS-REP akışının Windows'taki gibi olmasını sağlar. Bu, eksik PAC alanları veya politikayla uyuşmayan ömürler gibi açık göstergeleri büyük ölçüde azaltır.<sup>[[3]](#references)</sup>

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

- `/ldap` (`/ldapuser` ve `/ldappassword` seçenekleriyle) AD ve SYSVOL'u sorgulayarak hedef kullanıcının PAC policy verilerini kopyalar.
- `/opsec`, Windows benzeri bir AS-REQ yeniden denemesi yapar; gürültülü flag'leri sıfırlar ve AES256 kullanır.
- `/tgtdeleg`, çözümlenebilir bir TGT döndürürken kurbanın açık metin parolasına veya NTLM/AES key'ine dokunmamanızı sağlar.

### Service-ticket yeniden oluşturma

Aynı Rubeus güncellemesi, diamond tekniğini TGS blob'larına uygulama özelliğini de ekledi. `diamond` komutuna **base64 ile kodlanmış bir TGT** (`asktgt`, `/tgtdeleg` veya daha önce forge edilmiş bir TGT'den), **service SPN** ve **service AES key** vererek KDC'ye dokunmadan gerçekçi service ticket'lar oluşturabilirsiniz; böylece daha gizli bir silver ticket elde edersiniz.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Bu iş akışı, bir service account key'i (ör. `lsadump::lsa /inject` veya `secretsdump.py` ile dump edilmiş) zaten kontrol ettiğinizde ve yeni AS/TGS trafiği oluşturmadan AD policy, zaman çizelgeleri ve PAC verileriyle tam olarak eşleşen tek seferlik bir TGS üretmek istediğinizde idealdir.<sup>[[3]](#references)</sup>

### Sapphire tarzı PAC değişimleri (2025)

Bazen **sapphire ticket** olarak adlandırılan daha yeni bir yöntem, Diamond'ın "gerçek TGT" temelini **S4U2self+U2U** ile birleştirerek ayrıcalıklı bir PAC'i ele geçirir ve kendi TGT'nize ekler. Ek SID'ler uydurmak yerine, `sname` düşük ayrıcalıklı istekte bulunanı hedefleyecek şekilde, yüksek ayrıcalıklı bir kullanıcı için U2U S4U2self ticket talep edersiniz; KRB_TGS_REQ, istekte bulunanın TGT'sini `additional-tickets` alanında taşır ve `ENC-TKT-IN-SKEY` ayarını yapar. Böylece service ticket, o kullanıcının key'i ile çözülebilir. Ardından ayrıcalıklı PAC'i çıkarıp krbtgt key'i ile yeniden imzalamadan önce meşru TGT'nize eklersiniz.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket'ın `ticketer.py` aracı artık `-impersonate` + `-request` ile sapphire desteği sunuyor (canlı KDC alışverişi):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` bir kullanıcı adı veya SID kabul eder; `-request`, biletleri çözmek/patch etmek için canlı kullanıcı kimlik bilgileriyle birlikte krbtgt anahtar malzemesi (AES/NTLM) gerektirir.

Bu varyantı kullanırken dikkat edilmesi gereken temel OPSEC işaretleri:<sup>[[5]](#references)</sup>

- TGS-REQ, `ENC-TKT-IN-SKEY` ve `additional-tickets` (kurbanın TGT’si) içerir — normal trafikte nadir görülür.
- `sname` çoğu zaman istekte bulunan kullanıcıyla (self-service erişim) aynıdır ve Event ID 4769, çağıran ile hedefin aynı SPN/kullanıcı olduğunu gösterir.
- Aynı istemci bilgisayarı, ancak farklı CNAME’ler (düşük ayrıcalıklı istekte bulunan kullanıcı ile ayrıcalıklı PAC sahibi) içeren eşleşen 4768/4769 kayıtları bekleyin.

### OPSEC ve tespit notları

- Geleneksel avcı sezgileri (AS olmadan TGS, onlarca yıl süren geçerlilik süreleri) golden ticket'lar için hâlâ geçerlidir; ancak diamond ticket'lar çoğunlukla **PAC içeriği veya grup eşlemesi imkânsız göründüğünde** ortaya çıkar. Otomatik karşılaştırmaların sahteciliği hemen işaretlememesi için tüm PAC alanlarını (oturum açma saatleri, kullanıcı profili yolları, cihaz kimlikleri) doldurun.<sup>[[3]](#references)</sup>
- **Gruplara/RID’lere gereğinden fazla ekleme yapmayın**. Yalnızca `512` (Domain Admins) ve `519` (Enterprise Admins) gerekiyorsa, bunlarla yetinin ve hedef hesabın AD’nin başka yerlerinde makul biçimde bu gruplara ait olduğundan emin olun. Aşırı `ExtraSids` kullanımı dikkat çeker.
- Sapphire tarzı değişimler U2U izleri bırakır: 4769’da `ENC-TKT-IN-SKEY` + `additional-tickets` ve bir kullanıcıyı (çoğu zaman istekte bulunanı) gösteren `sname`; ardından sahte biletten kaynaklanan bir 4624 oturumu açılır. Yalnızca AS-REQ eksikliklerine bakmak yerine bu alanları ilişkilendirin.<sup>[[5]](#references)</sup>
- Microsoft, CVE-2026-20833 nedeniyle **RC4 hizmet bileti oluşturma** desteğini aşamalı olarak kaldırmaya başladı; KDC’de yalnızca AES etype’larını zorunlu kılmak hem etki alanını güçlendirir hem de diamond/sapphire araçlarıyla uyumludur (/opsec zaten AES’i zorunlu kılar). Sahte PAC’lere RC4 eklemek giderek daha fazla dikkat çekecektir.<sup>[[6]](#references)</sup>
- Splunk Security Content projesi, diamond ticket’lar için attack-range telemetrisi ve *Windows Domain Admin Impersonation Indicator* gibi; olağandışı Event ID 4768/4769/4624 dizilerini ve PAC grup değişikliklerini ilişkilendiren tespitler dağıtır. Bu veri kümesini yeniden oynatmak (veya yukarıdaki komutlarla kendinizinkini oluşturmak), T1558.001 için SOC kapsamını doğrulamaya ve kaçınmanız gereken somut uyarı mantığını görmeye yardımcı olur.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Kerberos Saldırılarının Yeni Nesli: Değerli Taşlar (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Biletlerle Oynamayı Seviyoruz (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Kerberos Diamond Ticket’ı Yeniden Kesmek (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket saldırı verileri ve tespitleri (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Değerli taşların gölge tarafı: Diamond ve Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – CVE-2026-20833 için RC4 hizmet bileti zorunluluğu](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
