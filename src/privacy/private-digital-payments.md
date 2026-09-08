# Özel Dijital Ödemeler

Ödeme gizliliği, işlem verilerinin kontrollü şekilde açıklanmasıdır. Yasa dışı fonları meşru hale getirmenin, vergi veya yaptırımlardan kaçınmanın, KYC'yi aşmanın, sahte kimlik kullanmanın ya da yetkisiz bir katılımı gizlemenin bir yolu değildir. Bir ödeme, satıcıdan gizli kalırken kartı çıkaran kuruluş, ağ, işveren, vergi makamı veya soruşturmacı tarafından tamamen görülebilir.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md), her aile için `Pros`, `Cons`, hukuka uygun adım adım `Procedure` ve `Detection` içeren normalize edilmiş envanterdir. Bu sayfa, geleneksel ödeme yöntemlerini genişletir.

{% hint style="danger" %}
Çalınmış hesapları, sentetik kimlikleri, para kuryelerini, hayali ikamet veya fon kaynağı beyanlarını, işlemleri bölmeyi ("structuring") ya da şeffaf olmayan "no-KYC card" broker'larını asla kullanmayın. İlgili her yargı alanındaki güncel yasaları ve sağlayıcı şartlarını kontrol edin.
{% endhint %}

## Gizlilik özelliğini tanımlama

Bir ödeme kanalı seçmeden önce gözlemciyi belirleyin:

| Gözlemci | Tipik veriler | Yararlı kontrol | Geriye kalan |
|---|---|---|---|
| Satıcı | Ad, e-posta, adres, card token, IP/cihaz, sepet | Misafir olarak ödeme, minimum isteğe bağlı veri, satıcıya özel sanal kart | Teslimat, hesap ve fraud telemetrisi |
| Kartı çıkaran kuruluş/ödeme işlemcisi | Yasal kimlik, fon kaynağı, satıcı, tutar, zaman, cihaz | İyi gizlilik/security şartlarına sahip, düzenlemeye tabi bir sağlayıcı seçmek | Sağlayıcı kayıtları hâlâ işler ve saklayabilir/açıklayabilir |
| İşveren/katılım sahibi | Gider, operatör ve amaç | Ayrı katılım bütçesi ve erişim kontrollü ledger | Meşru yönetişim, dahili ilişkilendirme gerektirir |
| Public blockchain gözlemcisi | Zincire bağlı olarak adresler, akışlar, tutarlar ve zaman | Uygun protocol ve wallet disiplini | Edinim, uç noktalar ve sonraki harcama etkinliği yeniden ilişkilendirebilir |
| Ağ/RPC/node operatörü | IP, wallet sorguları, işlem yayınları | Local node veya uygun privacy network | Zamanlama ve uç nokta davranışı yine de ilişkilendirilebilir |
| Fiziksel gözlemci | Yüz, konum, araç, CCTV, makbuz | Olağan durumsal gizlilik | Nakit, kişiyi fiziksel olarak görünmez kılmaz |

CFPB, ödeme uygulamalarının kimlik, cihaz, konum, kişiler, işlem ve davranış verilerini toplayabildiğini belirtir; eyalet gizlilik kuralları para kazanmayı veya tüm ikincil kullanımları zorunlu olarak engellemez.<sup>[[1]](#references)</sup> Gizliliği bir ürün adından çıkarsamak yerine gerçek sağlayıcı bildirimini okuyun.

## Ödeme yöntemlerini karşılaştırma

| Yöntem | Gizlilik avantajı | Ana gözlemciler/bağlantılar | Uygun kullanım |
|---|---|---|---|
| Nakit | Payment network ledger bulunmaz | Alıcı, kameralar, tanıklar, nakit bildirim kuralları | Kabul edildiği yerlerde yasal yerel alışverişler |
| Open-loop prepaid/gift card | Kart numarasını ana karttan ayırır | Satıcı, aktivasyon/kayıt sağlayıcısı, fon kaynağı, merchant | Bütçeleme veya sınırlı merchant compartmentalization |
| Virtual/one-time card number | Yeniden kullanılabilir PAN'ı merchant'tan gizler; kolayca iptal edilebilir | Issuer kimliği ve işlemi hâlâ bilir | Online merchant compartmentalization |
| Mobile-wallet token | Cihaz/merchant, temel PAN yerine token alır | Wallet sağlayıcısı, issuer, payment network ve merchant | Credential security, anonimlik değil |
| Bank transfer/app | Kullanışlı audit trail | Banka/app, karşı taraf ve bağlı kimlik | Hesap verebilir kurumsal ödemeler |
| Cryptocurrency | Protocol'e göre değişir; self-custody, custodian maruziyetini azaltabilir | Public ledger veya privacy protocol, exchange, uç nokta, karşı taraf | Protocol'e özel analiz sonrasında yasal transferler |

## Nakit

Nakit, gizlilik ve finansal kapsayıcılık açısından hâlâ önemli görülür ve bir payment network kaydını önler.<sup>[[2]](#references)</sup> Ancak CCTV'yi, tanıkları, cihaz konumunu, makbuzları, özel durumlarda seri numarası takibini veya yasal bildirimleri engellemez.

### Hukuka uygun iş akışı

1. İşlemden önce kabul durumunu ve yerel nakit limitlerini kontrol edin. Limitler ülkeye ve taraf türüne göre farklılık gösterir ve zaman içinde değişir.
2. Olağan alışverişi tek ve dürüst bir işlem olarak yapın. Bir eşikten veya bildirimden kaçınmak için **asla bölmeyin**.
3. İsteğe bağlı loyalty tracking veya marketing veri toplamasını reddedin. Garanti, güvenlik, teslimat, vergi veya yasa için gereken verileri doğru şekilde verin.
4. Gerekli satın alma kanıtını ve zorunlu muhasebe kayıtlarını, saklama tarihi belirlenmiş encrypted storage içinde tutun.
5. Bir kuruluş için, onaylı süreç üzerinden geri ödeme yapın ve operatörü, yetkilendirmeyi, amacı, tutarı, tarihi ve makbuzu kaydedin.

Amerika Birleşik Devletleri'nde belirli ticaret veya işletmeler, ilişkili işlemler de dahil olmak üzere 10.000 doların üzerindeki nakit tahsilatları için Form 8300 sunar; işlemleri kasıtlı olarak parçalara ayırmak, kendi başına hukuka aykırı structuring olabilir.<sup>[[3]](#references)</sup> Diğer yargı alanları farklıdır; örneğin İspanya kendi yasal nakit ödeme kısıtlamasını yayımlar.<sup>[[4]](#references)</sup>

## Prepaid ve gift card'lar

"Prepaid" anonim anlamına gelmez. Bir mağaza, issuer, program yöneticisi, funding bank ve merchant; satın alma, aktivasyon, cihaz, IP, konum ve harcama verilerini ilişkilendirebilir. Reload, ATM erişimi, uluslararası kullanım, daha yüksek limitler veya kayıp koruması genellikle kayıt gerektirir.

ABD tüketici rehberliği, issuer'ların yasal doğrulama için kimlik verileri isteyebileceğini ve doğrulama başarısız olduğunda kayıtlı bir kartı reddedebileceğini açıklar.<sup>[[5]](#references)</sup> FinCEN kuralları, hangi prepaid programlarının ve katılımcıların AML yükümlülüklerine sahip olduğunu tanımlar.<sup>[[6]](#references)</sup> AB'de dar kapsamlı anonim e-money istisnaları, Directive (EU) 2018/843 ile azaltılmıştır; Regulation (EU) 2024/1624 çerçeveyi yeniden değiştirir ancak genel olarak **10 July 2027** tarihinden itibaren uygulanır. Bu nedenle 2026'da zaten yürürlükteymiş gibi tanımlamayın.<sup>[[7]](#references)</sup>

Prepaid value'ı yalnızca kimliği belirlenebilir bir issuer'dan hukuka uygun şekilde edinildiğinde, şartları amaçlanan kullanıma izin verdiğinde ve fayda bütçeleme veya birincil payment credential'dan ayırma olduğunda kullanın. Yeniden satış piyasalarından ve doğrulanamayan "no-name" kartların reklamını yapan broker'lardan kaçının: value çalınmış, daha önce kullanılmış, coğrafi olarak kısıtlanmış veya el koymaya tabi olabilir.

## Virtual card'lar ve wallet token'ları

Bir virtual card number (VCN) genellikle gerçek ve doğrulanmış bir hesabın arkasından verilir. Merchant-specific veya single-use numaralar breach riskini ve merchant'lar arası PAN korelasyonunu azaltır; işlemi issuer'dan **gizlemez**. Network tokenization da benzer şekilde bir kart credential'ı yerine kısıtlı bir token koyar.<sup>[[8]](#references)</sup>

### Merchant-compartmentalized iş akışı

1. Düzenlemeye tabi bir issuer'da doğru kimlik, ikamet ve funding verilerini kullanarak hesap açın.
2. Hesabı benzersiz bir parola, mevcutsa phishing-resistant MFA, login alert'leri ve offline saklanan recovery code'ları ile güvenceye alın.
3. Merchant-locked veya one-time VCN oluşturun. Destekleniyorsa makul bir tutar/zaman limiti belirleyin.
4. Misafir olarak ödeme yapın ve yalnızca **isteğe bağlı** profil, loyalty ve marketing alanlarını boş bırakın. Gerektiğinde doğru billing, teslimat ve vergi verilerini sağlayın.
5. İlişkisiz identity provider'larda oturum açmaktan kaçının; bir engagement/account browser compartment ve onaylı network path kullanın.
6. Makbuzu ve VCN-to-purpose eşlemesini encrypted internal ledger'a kaydedin.
7. Refund/chargeback süresinden sonra numarayı dondurun veya iptal edin; beklenmeyen yetkilendirmeler için parent account'ı izleyin.

Capital One ve Google, virtual number'ların temel hesaba bağlı kalmaya devam ettiğini; EMVCo/Visa ise tokenization'ı payer anonymity yerine credential substitution ve domain restriction olarak tanımlar.<sup>[[8]](#references)</sup>

## Teslimat, hesaplar ve refund'lar

Ödeme, linkage graph'teki yalnızca bir kenardır:

- Benzersiz bir kart, kişisel e-posta, telefon, browser profile, IP adresi veya loyalty account yeniden kullanılarak etkisiz hale gelir.
- Fiziksel teslimat normalde yasal bir alıcı ve konum gerektirir. İlgisiz bir kişinin adresini kullanmayın veya bir ikamet sahibinin kimliğine bürünmeyin. Onaylı business receiving services, uydurma bilgilerden daha güvenlidir.
- Digital goods; hesap kimliği, IP, device fingerprint, license activation ve download kayıtlarını tutabilir.
- Refund'lar genellikle original rail'e iade edilir. Fonları alıp başka bir yere göndermeye/iade etmeye yönelik talepler fraud ve money-mule uyarısıdır.
- Merchant descriptor'ları, invoice metni ve shipping notification'ları hassas bir satın almayı hesap delegelerine ifşa edebilir; erişimleri ve alert'leri bilinçli şekilde ayarlayın.

## Yetkili red-team satın alımları

Bir engagement dışarıya karşı gizli, içeride ise hesap verebilir olmalıdır:

1. Yazılı kapsam, amaç, harcama tavanı, onaylayan kişi, izin verilen merchant/assets ve reimbursement kuralını alın.
2. Kuruluş tarafından kontrol edilen bir payment account ve her engagement veya merchant için ayrı bir VCN ya da sub-account kullanın.
3. Sağlayıcılarda doğru billing ve registrant bilgilerini tutun. Public registration privacy maruziyeti azaltabilir ancak yalan söyleme izni değildir.
4. Operatör, onay, amaç, tarih, tutar, karşı taraf, asset identifier ve makbuzdan oluşan encrypted ledger tutun.
5. Gerektiğinde karşı tarafları screen edin ve sağlayıcı, sanctions, vergi ve reporting yükümlülüklerine uyun.
6. Finance'e yalnızca ihtiyaç duyduğu erişimi; operatörlere ise ihtiyaç duydukları sınırlı harcama yetkisini verin.
7. Teardown sırasında payment credential'ları kapatın veya dondurun, bekleyen charge/refund işlemlerini reconcile edin ve kayıtları policy'ye göre saklayın.

Crypto'ya özgü seçimler için [Cryptocurrency Privacy](cryptocurrency-privacy.md) sayfasına devam edin. Bu satın alımların desteklediği infrastructure için [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) sayfasına bakın.

## Doğrulama kontrol listesi

- [ ] İstenen gizlilik özelliği ve gözlemciler yazılı olarak belirlendi.
- [ ] Sağlayıcı, merchant ve yargı alanı kuralları yakın zamanda kontrol edildi.
- [ ] Kimlik ve fon kaynağı beyanları doğru.
- [ ] Zorunlu doğrulamayı engellemeden isteğe bağlı merchant verileri en aza indirildi.
- [ ] Funding, cihaz, ağ, hesap, teslimat ve refund bağlantıları anlaşıldı.
- [ ] Eşiklerden kaçınma, yasaklı karşı taraf, mule, çalınmış credential veya üçüncü taraf kimliği söz konusu değil.
- [ ] Gerekli makbuzlar, onaylar, vergi kayıtları ve recovery bilgileri encrypted ve erişim kontrollü.

## References

- [1] [US CFPB — Tüketici ödeme ve diğer kişisel finansal verilerin toplanması, kullanılması ve monetization'ı hakkında bilgi talebi](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Euro bölgesindeki tüketicilerin ödeme tutumları araştırması (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Form 8300 talimatları](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Nakit ödemelerin bildirilmesi](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Prepaid card'ı etkinleştirmek veya kaydetmek için neden kişisel bilgilerim isteniyor?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) ve [Prepaid card almam reddedilebilir mi?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Prepaid Access hakkında nihai kural](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Virtual credit card'ların kullanılması](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
