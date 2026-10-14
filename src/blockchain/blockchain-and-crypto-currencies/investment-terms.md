# Yatırım Terimleri

{{#include ../../banners/hacktricks-training.md}}

## Spot

Spot işlemlerde bir varlık, anında teslim edilmek üzere başka bir varlıkla değiştirilir. Limit emir, miktarı ve limit fiyatını belirtir; yalnızca piyasa bu fiyatı veya daha iyisini karşılayabildiğinde gerçekleşir. Piyasa emri ise mevcut en iyi fiyatlardan hızlıca gerçekleşmeyi hedefler ve fiyat kayması yaşanabilir.<sup>[[4]](#references)</sup>

Stop-limit emir, bir limit emrini etkinleştiren stop fiyatına sahiptir. İşlem fiyatını sınırlayabilir ancak piyasa limit fiyatını aşarsa emrin gerçekleşmesini garanti etmez.<sup>[[4]](#references)</sup>

## Vadeli İşlemler

Vadeli işlem sözleşmesi, belirli bir emtia veya finansal aracı gelecekteki bir tarihte alıp satmaya yönelik standartlaştırılmış bir anlaşmadır. Örneğin iki taraf, altı ay sonra uzlaşma sağlanmak üzere bir bitcoin için 70.000 $ fiyat üzerinde anlaşabilir.<sup>[[1]](#references)</sup>

Uzlaşma fiyatı 80.000 $ ise, 70.000 $ sözleşme fiyatına kıyasla uzun pozisyon kâr eder, kısa pozisyon ise zarar eder. Fiyat 60.000 $ ise durum tersine döner. Borsada işlem gören gerçek vadeli sözleşmeler günlük olarak piyasa değerine göre güncellenir ve genellikle vade dolmadan kapatılır veya sonraki vadeye taşınır; bu nedenle bu örnek basitleştirilmiştir.<sup>[[2]](#references)</sup>

Üreticiler ve tüketiciler fiyat riskinden korunmak için vadeli işlemleri kullanır; diğer katılımcılar ise kâr elde etmeyi veya likidite sağlamayı amaçlar.<sup>[[1]](#references)</sup>

- **Uzun pozisyon** genellikle sözleşme fiyatı yükseldiğinde kâr eder.
- **Kısa pozisyon** genellikle sözleşme fiyatı düştüğünde kâr eder.<sup>[[2]](#references)</sup>

### Vadeli İşlemlerle Riskten Korunma

Bir portföy yöneticisi, portföyün değer kaybetmesini bekliyorsa portföyle yeterince yüksek korelasyona sahip bir hisse senedi endeksi vadeli işlem sözleşmesinde kısa pozisyon açabilir. Kısa pozisyondan elde edilen kazançlar, portföy zararlarının bir kısmını dengeleyebilir; baz riski nedeniyle bu dengeleme nadiren kusursuz olur. Bitcoin vadeli işlemi bitcoin riskine karşı koruma sağlar; hisse senedi portföyünü otomatik olarak korumaz.

Korunulan piyasa düşerse kısa vadeli işlem pozisyonu değer kazanırken portföydeki varlıklar değer kaybedebilir. Piyasa yükselirse portföydeki varlıklar değer kazanırken koruma pozisyonu zarar edebilir. Riskten korunma, seçili riskleri azaltır; garantili kâr sağlamaz.<sup>[[1]](#references)</sup>

### Sürekli Vadeli İşlemler

Sürekli sözleşmeler, sabit bir vade sonu olmayan türev ürünlerdir. Kripto platformları, fiyatlarını dayanak varlığın spot fiyatına yakın tutmaya yardımcı olmak için genellikle dönemsel fonlama ödemeleri kullanır; koşullar platforma göre değişir.<sup>[[3]](#references)</sup>

Mark fiyatı değiştikçe kâr ve zarar da değişir. Ücretler ve fonlama hariç, fiyattaki %1'lik hareket pozisyonun nominal değerinde yaklaşık %1'lik değişime yol açar; ancak kaldıraç bu değişimi yatırılan teminatın yüzdesi olarak çok daha büyük hâle getirebilir.

### Kaldıraçlı Vadeli İşlemler

**Kaldıraç**, yatırımcının daha küçük bir teminat yatırarak daha yüksek nominal değerli bir pozisyonu kontrol etmesini sağlar. Zararlar her zaman başlangıç teminatıyla sınırlı değildir: tasfiye, fiyat boşlukları, ücretler ve platform kuralları ek zararlara yol açabilir.<sup>[[3]](#references)</sup>

Örneğin, 50x kaldıraçla yatırılan 100 $ teminat, 5.000 $ değerinde bir pozisyonu kontrol eder. Ücretler, fonlama ve tasfiye mekanizmaları hesaba katılmazsa, lehte %1'lik bir hareket 50 $ kazanç sağlar (başlangıç teminatının %50'si); aleyhte %1'lik hareket ise 50 $ zarara yol açar. Aleyhte %2'lik hareket 100 $'a karşılık gelir; ancak platform genellikle tüm teminat tükenmeden önce pozisyonu tasfiye eder.

Kaldıraç hem kazançları hem de zararları büyütür ve nispeten küçük bir olumsuz fiyat hareketi sonrasında tasfiyeye yol açabilir.

## Vadeli İşlemler ve Opsiyonlar Arasındaki Farklar

Opsiyon alıcısı, sözleşme koşulları uyarınca kullanma hakkı elde eder; kullanma yükümlülüğü yoktur. Opsiyon satıcısı, alıcı opsiyonu kullanırsa buna karşılık gelen yükümlülüğü üstlenir. Alıcı, bu hak için satıcıya bir prim öder.<sup>[[4]](#references)</sup>

### 1. **Yükümlülük ve Hak:**

* **Vadeli İşlemler:** Bir vadeli işlem sözleşmesi aldığınızda veya sattığınızda, gelecekteki bir tarihte belirli bir fiyattan varlık alıp satmak üzere **bağlayıcı bir anlaşma** yapmış olursunuz. Sözleşme bu tarihten önce kapatılmadıkça, hem alıcı hem de satıcı vade sonunda sözleşmeyi yerine getirmekle **yükümlüdür**.
* **Opsiyonlar:** Opsiyonlarda, belirli bir vade tarihinden önce veya o tarihte, belirli bir fiyattan varlık alma (**alım opsiyonu**) ya da satma (**satım opsiyonu**) **hakkınız vardır, ancak yükümlülüğünüz yoktur**. **Alıcı**, opsiyonu kullanıp kullanmamaya karar verir; alıcı opsiyonu kullanmaya karar verirse **satıcı** işlemi yerine getirmekle yükümlüdür.

### 2. **Risk:**

* **Vadeli İşlemler:** Her iki taraf da önemli zararlara uğrayabilir. Zararın matematiksel olarak sınırsız olup olmaması, pozisyona ve dayanak varlığa bağlıdır: kısa pozisyondaki teorik zarar sınırsız olabilirken, dayanak varlığın değeri sıfırın altına düşemiyorsa uzun pozisyondaki zarar nominal değerle sınırlıdır.
* **Opsiyonlar:** Başka bir opsiyon yazmayan alıcı, genellikle ödediği prim kadar risk alır. Teminatsız alım opsiyonu yazarı teorik olarak sınırsız zarara uğrayabilir; diğer opsiyon yazma stratejilerinde riskin sınırları değişir.

### 3. **Maliyet:**

* **Vadeli İşlemler:** Pozisyonu taşımak için gereken teminat dışında peşin maliyet yoktur; çünkü alıcı ve satıcının ikisi de işlemi tamamlama yükümlülüğü altındadır.
* **Opsiyonlar:** Alıcı, opsiyonu kullanma hakkı için peşin olarak bir **opsiyon primi** ödemelidir. Bu prim, esasen opsiyonun maliyetidir.

### 4. **Kâr Potansiyeli:**

* **Vadeli İşlemler:** Kâr veya zarar, vade sonundaki piyasa fiyatı ile sözleşmede kararlaştırılan fiyat arasındaki farka bağlıdır.
* **Opsiyonlar:** Piyasa, kullanım fiyatının ödenen primden daha fazla olacak ölçüde alıcı lehine hareket ederse alıcı kâr eder. Opsiyon kullanılmazsa satıcı primi elinde tutarak kâr eder.

## References

- [1] [CFTC - Vadeli işlem piyasalarının ekonomik amacı](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Vadeli İşlem Piyasalarının Temelleri](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Sanal para işlemlerinin risklerini anlayın](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Sözlüğü - Opsiyon, prim ve kullanma](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
