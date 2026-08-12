# Yatırım Terimleri

{{#include ../banners/hacktricks-training.md}}

## Spot

Spot trading, bir varlığın anında teslim edilmek üzere takas edilmesidir. Limit emri, miktarı ve limit fiyatını belirtir; yalnızca piyasa bu fiyatı veya daha iyisini karşılayabildiğinde gerçekleşir. Buna karşılık piyasa emri, mevcut en iyi fiyatlardan hızlı bir şekilde gerçekleşmeyi hedefler ve slippage yaşayabilir.<sup>[[4]](#references)</sup>

Stop-limit emrinde, bir limit emrini etkinleştiren bir stop fiyatı bulunur. Gerçekleşme fiyatını sınırlayabilir; ancak piyasa limit fiyatını aştığında emrin gerçekleşmesini garanti etmez.<sup>[[4]](#references)</sup>

## Futures

Bir futures sözleşmesi, belirli bir emtia veya finansal aracı gelecekteki bir tarihte satın almak ya da satmak için yapılan standartlaştırılmış bir anlaşmadır. Örneğin iki taraf, bir bitcoin için altı ay sonraki takas işlemi üzere 70.000 $ fiyatında anlaşabilir.<sup>[[1]](#references)</sup>

Takas fiyatı 80.000 $ ise long taraf, 70.000 $ olan sözleşme fiyatına göre kazanç sağlar ve short taraf zarar eder. Fiyat 60.000 $ ise yön tersine döner. Gerçekte borsada işlem gören futures sözleşmeleri piyasa değerine göre düzenli olarak yeniden değerlendirilir ve genellikle vade dolmadan önce kapatılır veya yenilenir; bu nedenle bu yalnızca basitleştirilmiş bir örnektir.<sup>[[2]](#references)</sup>

Üreticiler ve tüketiciler fiyat riskinden korunmak için futures kullanır; diğer katılımcılar bunları kâr elde etmek veya likidite sağlamak için kullanır.<sup>[[1]](#references)</sup>

- **Long pozisyon**, sözleşme fiyatı yükseldiğinde genellikle kâr sağlar.
- **Short pozisyon**, sözleşme fiyatı düştüğünde genellikle kâr sağlar.<sup>[[2]](#references)</sup>

### Futures ile Hedging

Bir fon yöneticisi portföyün düşmesini bekliyorsa, yeterli korelasyona sahip bir hisse senedi endeksi futures sözleşmesinde short pozisyon açabilir. Short hedge işleminden elde edilen kazançlar portföy zararlarının bir kısmını dengeleyebilir; basis risk nedeniyle bu dengeleme nadiren tam olur. Bitcoin future, bitcoin riskini hedge eder; otomatik olarak bir hisse senedi portföyünü hedge etmez.

Hedge edilen piyasa düşerse short futures pozisyonu değer kazanırken varlıkların değeri düşebilir. Piyasa yükselirse varlıklar değer kazanırken hedge zarara uğrayabilir. Hedging, belirli bir riski azaltır; garantili kâr sağlamaz.<sup>[[1]](#references)</sup>

### Perpetual Futures

Perpetual sözleşmeler, sabit bir vade tarihi olmayan türev ürünlerdir. Crypto platformları, fiyatlarını temel alınan spot fiyatına yakın tutmaya yardımcı olmak için genellikle dönemsel funding ödemeleri kullanır; koşullar platforma göre değişir.<sup>[[3]](#references)</sup>

Kâr ve zarar, mark fiyatı hareket ettikçe değişir. Fiyatın %1 hareket etmesi, ücretler ve funding öncesinde pozisyonun nominal değerinde yaklaşık %1'lik bir harekete neden olur; ancak leverage, bunun yatırılan teminatın çok daha büyük bir yüzdesi olmasına yol açabilir.

### Leverage ile Futures

**Leverage**, bir trader'ın daha küçük bir margin yatırımıyla daha büyük nominal değere sahip bir pozisyon kontrol etmesini sağlar. Zararlar her zaman başlangıç margin'iyle sınırlı değildir: liquidation, gap'ler, ücretler ve platform kuralları ek zararlara yol açabilir.<sup>[[3]](#references)</sup>

Örneğin, 50x leverage ile yatırılan 100 $ margin, 5.000 $ değerinde bir pozisyonu kontrol eder. Ücretler, funding ve liquidation mekanizmaları göz ardı edilirse, lehine gerçekleşen %1'lik bir hareket 50 $ kazanç (%50 başlangıç margin'i) sağlarken, aleyhe gerçekleşen %1'lik bir hareket 50 $ zarara yol açar. Aleyhe gerçekleşen %2'lik bir hareket 100 $'a karşılık gelir; ancak bir platform normalde tüm margin tükenmeden önce pozisyonu liquidate eder.

Leverage hem kazançları hem de zararları büyütür ve görece küçük bir aleyhe hareket sonrasında liquidation'ı mümkün kılar.

## Futures ve Options Arasındaki Farklar

Bir option alıcısı, sözleşme koşulları kapsamında kullanma hakkı elde eder; yükümlülük elde etmez. Option yazıcısı, alıcının option'ı kullanması durumunda buna karşılık gelen yükümlülüğe sahiptir. Alıcı bu hak karşılığında yazıcıya bir premium öder.<sup>[[4]](#references)</sup>

### 1. **Yükümlülük ve Hak:**

* **Futures:** Bir futures sözleşmesi aldığınızda veya sattığınızda, gelecekteki bir tarihte bir varlığı belirli bir fiyattan almak ya da satmak için **bağlayıcı bir anlaşmaya** girmiş olursunuz. Hem alıcı hem de satıcı, sözleşme vade tarihinden önce kapatılmadığı sürece, vade tarihinde sözleşmeyi yerine getirmekle **yükümlüdür**.
* **Options:** Options işlemlerinde, belirli bir fiyattan bir varlığı belirli bir vade tarihinden önce veya o tarihte alma ( **call option** durumunda) ya da satma ( **put option** durumunda) **hakkına sahip olursunuz; ancak yükümlülüğünüz yoktur**. **Alıcı** işlemi gerçekleştirme seçeneğine sahiptir; **satıcı** ise alıcı option'ı kullanmaya karar verirse işlemi yerine getirmekle yükümlüdür.

### 2. **Risk:**

* **Futures:** Her iki taraf da önemli zararlarla karşılaşabilir. Zararın matematiksel olarak sınırsız olup olmadığı pozisyona ve temel alınan varlığa bağlıdır: short pozisyon teorik olarak sınırsız zarara yol açabilirken, temel alınan varlık sıfırın altına düşemiyorsa long pozisyon nominal değerden daha fazla zarar edemez.
* **Options:** Başka bir option yazmayan bir alıcı genellikle ödediği premium'ı riske atar. Naked call yazıcısı teorik olarak sınırsız zararla karşılaşabilir; diğer option yazma stratejilerinin riskleri sınırlı veya sınırsız olabilir.

### 3. **Maliyet:**

* **Futures:** Pozisyonu korumak için gereken margin dışında peşin bir maliyet yoktur; çünkü alıcı ve satıcı işlemi tamamlamakla yükümlüdür.
* **Options:** Alıcı, option'ı kullanma hakkı karşılığında peşin olarak bir **option premium'ı** ödemelidir. Bu premium, esas olarak option'ın maliyetidir.

### 4. **Kâr Potansiyeli:**

* **Futures:** Kâr veya zarar, vade tarihindeki piyasa fiyatı ile sözleşmede anlaşılan fiyat arasındaki farka dayanır.
* **Options:** Alıcı, piyasa strike fiyatının ötesine ve ödenen premium'dan daha fazla olacak şekilde lehine hareket ettiğinde kâr eder. Satıcı, option kullanılmazsa premium'ı elinde tutarak kâr eder.

## References

- [1] [CFTC - Futures piyasalarının ekonomik amacı](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Futures piyasalarının temelleri](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Sanal para işlemlerinin risklerini anlayın](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Glossary - Option, premium, and exercise](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
