# Özel Dijital Ödemeler

{{#include ../banners/hacktricks-training.md}}

Ödeme gizliliği, işlem verilerinin kontrollü şekilde açıklanmasıdır. Yasadışı fonları meşru hale getirmenin, vergi veya yaptırımlardan kaçınmanın, KYC'yi aşmanın, sahte kimlikler kullanmanın ya da yetkisiz bir etkileşimi gizlemenin bir yolu değildir. Bir ödeme, merchant tarafından gizli kalırken issuer, network, işveren, vergi makamı veya investigator tarafından tamamen görünür olabilir.

[Anonymous Payment Technique Catalog](anonymous-payment-techniques.md), her aile için `Pros`, `Cons`, yasal adım adım `Procedure` ve `Detection` bölümlerini içeren normalize edilmiş envanterdir. Bu sayfa geleneksel ödeme yöntemlerini genişletir.

{% hint style="danger" %}
Çalınmış hesapları, sentetik kimlikleri, money mule'ları, hayali ikamet veya fon kaynağı beyanlarını, işlem bölmeyi (“structuring”) ya da şeffaf olmayan “no-KYC card” broker'larını asla kullanmayın. İlgili her yargı alanındaki güncel hukuku ve provider koşullarını kontrol edin.
{% endhint %}

## Gizlilik özelliğini tanımlama

Bir payment rail seçmeden önce gözlemciyi belirleyin:

| Gözlemci | Tipik veriler | Kullanışlı kontrol | Geriye kalanlar |
|---|---|---|---|
| Merchant | Ad, e-posta, adres, card token, IP/device, sepet | Guest checkout, minimum isteğe bağlı veri, merchant'a özel virtual card | Teslimat, hesap ve fraud telemetry |
| Issuer/payment processor | Yasal kimlik, fon kaynağı, merchant, tutar, zaman, device | İyi privacy/security koşullarına sahip regulated provider seçmek | Provider hâlâ kayıtları işleyebilir, saklayabilir ve açıklayabilir |
| İşveren/etkileşim sahibi | Gider, operator ve amaç | Ayrı engagement bütçesi ve erişim kontrollü ledger | Meşru governance, kurum içi attribution gerektirir |
| Public blockchain observer | Zincire bağlı olarak adresler, akışlar, tutarlar ve zaman | Uygun protocol ve wallet disiplini | Acquisition, endpoint'ler ve sonraki harcamalar etkinliği yeniden ilişkilendirebilir |
| Network/RPC/node operator | IP, wallet sorguları, transaction broadcast'leri | Local node veya uygun privacy network | Zamanlama ve endpoint davranışı yine de ilişkilendirilebilir |
| Physical observer | Yüz, konum, araç, CCTV, makbuz | Olağan durumsal gizlilik | Cash, kişiyi fiziksel olarak görünmez hale getirmez |

CFPB, payment app'lerinin kimlik, device, konum, contacts, transaction ve davranış verilerini toplayabildiğini belirtir; eyalet privacy kuralları monetization'ı veya tüm ikincil kullanımları zorunlu olarak engellemez.<sup>[[1]](#references)</sup> Privacy'yi bir ürün adından çıkarsamak yerine gerçek provider bildirimini okuyun.

## Ödeme yöntemlerini karşılaştırma

| Yöntem | Gizlilik faydası | Ana gözlemciler/bağlantılar | Uygun kullanım |
|---|---|---|---|
| Cash | Payment-network ledger'ı yoktur | Recipient, kameralar, tanıklar, cash-reporting kuralları | Kabul edilen yerlerde yasal yerel alışverişler |
| Open-loop prepaid/gift card | Card number'ı ana karttan ayırır | Seller, activation/registration provider, funding source, merchant | Bütçeleme veya sınırlı merchant compartmentalization |
| Virtual/one-time card number | Yeniden kullanılabilir PAN'ı merchant'tan gizler; kolayca iptal edilebilir | Issuer kimliği ve işlemi yine bilir | Online merchant compartmentalization |
| Mobile-wallet token | Device/merchant, temel PAN yerine token alır | Wallet provider, issuer, payment network ve merchant | Credential security, anonimlik değil |
| Bank transfer/app | Kullanışlı audit trail | Banka/app, karşı taraf ve bağlantılı kimlik | Hesap verebilir kurumsal ödemeler |
| Cryptocurrency | Protokole göre değişir; self-custody custodian exposure'ını azaltabilir | Public ledger veya privacy protocol, exchange, endpoint, counterparty | Protocol-specific analiz sonrasında yasal transferler |

## Cash

Cash, privacy ve financial inclusion açısından hâlâ önemli görülür ve bir payment-network kaydını önler.<sup>[[2]](#references)</sup> CCTV'yi, tanıkları, device location'ı, makbuzları, özel durumlarda serial-number tracing'i veya yasal bildirimleri engellemez.

### Yasal workflow

1. İşlemden önce kabul durumunu ve yerel cash limitlerini kontrol edin. Limitler ülkeye ve taraf türüne göre farklılık gösterir ve zamanla değişir.
2. Olağan satın almayı tek ve dürüst bir işlem olarak gerçekleştirin. Bir threshold veya report'tan kaçınmak için **asla bölmeyin**.
3. İsteğe bağlı loyalty tracking veya marketing veri toplamasını reddedin. Warranty, safety, delivery, tax veya law tarafından gerekli kılınan verileri doğru şekilde verin.
4. Gerekli satın alma kanıtını ve muhasebe kayıtlarını retention date içeren encrypted storage'da tutun.
5. Bir kuruluş için approved process üzerinden reimbursement yapın ve operator, authorization, purpose, amount, date ve receipt bilgilerini kaydedin.

Birleşik Devletler'de belirli trade veya business'ler, bağlantılı işlemler de dahil olmak üzere 10.000 doların üzerindeki cash tahsilatları için Form 8300 doldurur; işlemleri kasıtlı olarak parçalara ayırmak başlı başına unlawful structuring olabilir.<sup>[[3]](#references)</sup> Diğer yargı alanları farklıdır; örneğin İspanya kendi yasal cash-payment kısıtlamasını yayımlar.<sup>[[4]](#references)</sup>

## Prepaid ve gift card'lar

“Prepaid” anonim anlamına gelmez. Bir shop, issuer, program manager, funding bank ve merchant; purchase, activation, device, IP, location ve spend bilgilerini ilişkilendirebilir. Reload, ATM erişimi, international use, daha yüksek limitler veya loss protection genellikle registration gerektirir.

ABD consumer guidance, issuer'ların yasal verification için identity data isteyebileceğini ve verification başarısız olduğunda registered card'ı reddedebileceğini açıklar.<sup>[[5]](#references)</sup> FinCEN kuralları, hangi prepaid program'ların ve katılımcıların AML yükümlülüklerine sahip olduğunu tanımlar.<sup>[[6]](#references)</sup> AB'de dar kapsamlı anonymous e-money istisnaları Directive (EU) 2018/843 ile azaltılmıştır; Regulation (EU) 2024/1624 çerçeveyi yeniden değiştirir ancak genel olarak **10 Temmuz 2027** tarihinden itibaren uygulanır. Bu nedenle 2026'da zaten yürürlükteymiş gibi tanımlamayın.<sup>[[7]](#references)</sup>

Prepaid value'yu yalnızca identifiable issuer'dan yasal olarak edinildiğinde, koşulları amaçlanan kullanıma izin verdiğinde ve fayda bütçeleme veya primary payment credential'dan ayrıştırma olduğunda kullanın. Resale market'lerinden ve doğrulanamayan “no-name” card reklamı yapan broker'lardan kaçının: value çalınmış, daha önce redeem edilmiş, coğrafi olarak kısıtlanmış veya seizure'a tabi olabilir.

## Virtual card'lar ve wallet token'ları

Virtual card number (VCN) genellikle gerçek ve doğrulanmış bir hesabın arkasından çıkarılır. Merchant-specific veya single-use number'lar breach ve merchant'lar arası PAN correlation'ı azaltır; işlemi issuer'dan **gizlemez**. Network tokenization da benzer şekilde bir card credential yerine kısıtlı bir token koyar.<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. Accurate identity, residence ve funding data kullanarak regulated issuer'da hesap açın.
2. Benzersiz bir password, mevcutsa phishing-resistant MFA, login alerts ve offline saklanan recovery codes ile hesabı güvenceye alın.
3. Merchant-locked veya one-time VCN oluşturun. Destekleniyorsa makul bir amount/time limit belirleyin.
4. Guest checkout kullanın ve yalnızca **optional** profile, loyalty ve marketing alanlarını doldurmayın. Gerektiğinde accurate billing, delivery ve tax data sağlayın.
5. İlgisiz identity provider'larda oturum açmaktan kaçının; bir engagement/account browser compartment ve approved network path kullanın.
6. Receipt'i ve VCN-to-purpose mapping'i encrypted internal ledger'da saklayın.
7. Refund/chargeback window sonrasında number'ı freeze veya revoke edin; parent account'ı beklenmeyen authorization'lar için izleyin.

Capital One ve Google, virtual number'ların underlying account'a bağlı kalmaya devam ettiğini; EMVCo/Visa ise tokenization'ı payer anonymity yerine credential substitution ve domain restriction olarak açıklar.<sup>[[8]](#references)</sup>

## Delivery, hesaplar ve refund'lar

Ödeme, linkage graph'taki yalnızca bir edge'dir:

- Benzersiz bir card; kişisel e-posta, telefon, browser profile, IP address veya loyalty account yeniden kullanılarak etkisiz hale gelir.
- Physical delivery normalde yasal bir recipient ve location gerektirir. İlgisiz bir kişinin adresini kullanmayın veya bir resident gibi davranmayın. Onaylı business receiving services, fabricated details'tan daha güvenlidir.
- Digital goods; account identity, IP, device fingerprint, license activation ve download bilgilerini log'layabilir.
- Refund'lar genellikle original rail'e iade edilir. Fonların alınarak başka yere gönderilmesi veya iade edilmesi yönündeki talepler fraud ve money-mule uyarısıdır.
- Merchant descriptor'ları, invoice text'i ve shipping notification'lar hassas bir satın almayı account delegate'lerine ifşa edebilir; erişim ve alert'leri bilinçli şekilde ayarlayın.

## Authorized red-team purchases

Bir engagement dışarıya karşı discreet, içeride ise accountable olmalıdır:

1. Yazılı scope, purpose, spending ceiling, approver, permitted merchants/assets ve reimbursement rule alın.
2. Organization-controlled payment account ve her engagement veya merchant için ayrı bir VCN veya sub-account kullanın.
3. Provider'larda accurate billing ve registrant details tutun. Public registration privacy exposure'ı azaltabilir ancak yalan söyleme izni değildir.
4. Operator, approval, purpose, date, amount, counterparty, asset identifier ve receipt bilgilerini içeren encrypted ledger tutun.
5. Gerektiğinde counterparties'leri screen edin ve provider, sanctions, tax ve reporting yükümlülüklerine uyun.
6. Finance'a yalnızca ihtiyaç duyduğu erişimi; operator'lara ise yalnızca ihtiyaç duydukları sınırlı spending capability'yi verin.
7. Teardown sırasında payment credential'ları close veya freeze edin, pending charge/refund'ları reconcile edin ve kayıtları policy'ye göre saklayın.

Crypto-specific seçimler için [Cryptocurrency Privacy](cryptocurrency-privacy.md) sayfasına devam edin. Bu satın alımların desteklediği infrastructure için [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) sayfasına bakın.

## Verification checklist

- [ ] İstenen privacy property ve observer'lar yazılı olarak belirlendi.
- [ ] Provider, merchant ve jurisdiction kuralları yakın zamanda kontrol edildi.
- [ ] Identity ve source-of-funds beyanları doğru.
- [ ] Optional merchant data, required verification'ı engellemeden minimize edildi.
- [ ] Funding, device, network, account, delivery ve refund bağlantıları anlaşıldı.
- [ ] Threshold avoidance, prohibited counterparty, mule, stolen credential veya third-party identity söz konusu değil.
- [ ] Gerekli receipt, approval, tax record ve recovery information encrypted ve access-controlled durumda.

## References

- [1] [US CFPB — Consumer payment ve diğer kişisel finansal verilerin toplanması, kullanılması ve monetization'ı hakkında bilgi talebi](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Euro bölgesindeki tüketicilerin ödeme tutumları araştırması (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Form 8300 talimatları](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Cash payment'lerin bildirilmesi](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Prepaid card'ı aktive etmek veya kaydetmek için neden kişisel bilgilerim isteniyor?](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) ve [Prepaid card başvurum reddedilebilir mi?](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Prepaid Access hakkında nihai kural](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Virtual credit card'ların kullanılması](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
