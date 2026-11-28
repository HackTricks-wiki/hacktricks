# Yatırım Terimleri

{{#include ../../banners/hacktricks-training.md}}

## Spot

Spot işlemler, bir varlığın anında teslim edilmek üzere takas edilmesidir. Limit emir, miktarı ve limit fiyatını belirtir; yalnızca piyasa bu fiyatı veya daha iyisini karşılayabildiğinde gerçekleşir. Piyasa emri ise mevcut en iyi fiyatlardan hızlıca gerçekleşmeyi hedefler ve fiyat kayması yaşayabilir.<sup>[[4]](#references)</sup>

Stop-limit emrinde, stop fiyatına ulaşıldığında bir limit emir etkinleşir. Bu emir gerçekleşme fiyatını sınırlayabilir; ancak piyasa limit fiyatını aşarsa emrin gerçekleşmesini garanti etmez.<sup>[[4]](#references)</sup>

## Vadeli İşlemler

Vadeli işlem sözleşmesi, belirli bir emtianın veya finansal aracın gelecekteki bir tarihte alınıp satılmasına yönelik standartlaştırılmış bir anlaşmadır. Örneğin iki taraf, altı ay sonra uzlaşmak üzere bir bitcoin için 70.000 $ fiyat üzerinde anlaşabilir.<sup>[[1]](#references)</sup>

Uzlaşma fiyatı 80.000 $ olursa, 70.000 $ sözleşme fiyatına kıyasla uzun taraf kazanç, kısa taraf ise zarar eder. Fiyat 60.000 $ olursa sonuç tersine döner. Borsada işlem gören vadeli işlemlerde pozisyonlar her gün piyasa fiyatına göre değerlenir ve genellikle vade dolmadan kapatılır veya sonraki vadeye taşınır; bu nedenle bu, basitleştirilmiş bir örnektir.<sup>[[2]](#references)</sup>

Üreticiler ve tüketiciler fiyat riskinden korunmak için vadeli işlemleri kullanır; diğer katılımcılar ise kâr elde etmeye çalışmak veya likidite sağlamak için bu işlemlere katılır.<sup>[[1]](#references)</sup>

- **Uzun pozisyon** genellikle sözleşme fiyatı yükseldiğinde kâr sağlar.
- **Kısa pozisyon** genellikle sözleşme fiyatı düştüğünde kâr sağlar.<sup>[[2]](#references)</sup>

### Vadeli İşlemlerle Riskten Korunma

Bir fon yöneticisi portföyünün değer kaybetmesini bekliyorsa, portföyle yeterince yüksek korelasyona sahip bir hisse senedi endeksi vadeli işlem sözleşmesinde kısa pozisyon alabilir. Kısa koruma pozisyonundan elde edilen kazançlar portföydeki bazı kayıpları telafi edebilir; baz riski nedeniyle bu telafi nadiren tam olur. Bitcoin vadeli işlemi bitcoin riskine karşı koruma sağlar; bir hisse senedi portföyüne kendiliğinden koruma sağlamaz.

Korunulan piyasa düşerse, kısa vadeli işlem pozisyonu kazanç sağlarken varlıkların değeri düşebilir. Piyasa yükselirse varlıklar değer kazanırken koruma pozisyonu zarar edebilir. Riskten korunma, belirli riskleri azaltır; garantili kâr sağlamaz.<sup>[[1]](#references)</sup>

### Sürekli Vadeli İşlemler

Sürekli sözleşmeler, sabit bir vade tarihi olmayan türev ürünlerdir. Kripto platformları, fiyatlarını dayanak varlığın spot fiyatına yakın tutmaya yardımcı olmak için genellikle dönemsel fonlama ödemeleri kullanır; koşullar platforma göre değişir.<sup>[[3]](#references)</sup>

Zincir üstü sürekli vadeli işlem protokollerindeki fonlama oranı suistimali testleri için bkz. [Sürekli Vadeli İşlemlerde Fonlama Oranı İstismarı](perpetual-funding-rate-exploitation.md).

Mark fiyatı hareket ettikçe kâr ve zarar da değişir. Ücretler ve fonlama hariç, fiyattaki %1'lik bir hareket pozisyonun nominal değerinde yaklaşık %1'lik bir değişime yol açar; ancak kaldıraç bu değişimi yatırılan teminatın çok daha büyük bir yüzdesine dönüştürebilir.

### Kaldıraçlı Vadeli İşlemler

**Kaldıraç**, yatırımcının daha küçük bir teminat yatırarak daha büyük bir nominal pozisyon kontrol etmesini sağlar. Zararlar her zaman başlangıç teminatıyla sınırlı değildir: tasfiye, fiyat boşlukları, ücretler ve platform kuralları ek zararlara yol açabilir.<sup>[[3]](#references)</sup>

Örneğin, 50x kaldıraçla yatırılan 100 $ teminat, 5.000 $ değerinde bir pozisyonu kontrol eder. Ücretleri, fonlamayı ve tasfiye mekanizmalarını göz ardı edersek, lehte gerçekleşen %1'lik bir hareket 50 $ kazanç (%50 başlangıç teminatı üzerinden) sağlarken, aleyhte gerçekleşen %1'lik bir hareket 50 $ zarar doğurur. Aleyhte gerçekleşen %2'lik bir hareket 100 $ zarara karşılık gelir; ancak platform genellikle teminatın tamamı tükenmeden pozisyonu tasfiye eder.

Kaldıraç hem kazançları hem de zararları büyütür ve nispeten küçük bir olumsuz hareketten sonra tasfiyeye yol açabilir.

## Vadeli İşlemler ile Opsiyonlar Arasındaki Farklar

Opsiyon alıcısı, sözleşme koşullarına göre kullanma hakkı elde eder; ancak bunu kullanmak zorunda değildir. Alıcı opsiyonu kullanırsa, opsiyonu yazan tarafın karşılık gelen yükümlülüğü doğar. Alıcı bu hak için opsiyonu yazan tarafa prim öder.<sup>[[4]](#references)</sup>

### 1. **Yükümlülük ve Hak:**

* **Vadeli İşlemler:** Bir vadeli işlem sözleşmesi alıp sattığınızda, gelecekteki belirli bir tarihte bir varlığı belirli bir fiyattan almak veya satmak için **bağlayıcı bir anlaşma** yapmış olursunuz. Sözleşme bu tarihten önce kapatılmadığı sürece hem alıcı hem de satıcı, vade sonunda sözleşmeyi yerine getirmekle **yükümlüdür**.
* **Opsiyonlar:** Opsiyonlarda, belirli bir fiyat üzerinden ve belirli bir vade tarihinden önce veya bu tarihte bir varlığı alma (**call opsiyonu**) ya da satma (**put opsiyonu**) hakkınız vardır; ancak bunu yapmak zorunda değilsiniz. **Alıcı**, işlemi gerçekleştirme hakkına sahiptir; alıcı opsiyonu kullanmaya karar verirse **satıcı** işlemi yerine getirmekle yükümlüdür.

### 2. **Risk:**

* **Vadeli İşlemler:** Her iki taraf da önemli zararlar edebilir. Zararın matematiksel olarak sınırsız olup olmaması pozisyona ve dayanak varlığa bağlıdır: kısa pozisyonun teorik zararı sınırsız olabilirken dayanak varlığın değeri sıfırın altına düşemiyorsa uzun pozisyondaki zarar nominal değeri aşamaz.
* **Opsiyonlar:** Başka bir opsiyon yazmayan alıcı genellikle ödediği prim kadar risk alır. Teminatsız call opsiyonu yazan taraf teorik olarak sınırsız zararla karşılaşabilir; diğer opsiyon yazma stratejilerinin riskleri ise sınırlı veya sınırsız olabilir.

### 3. **Maliyet:**

* **Vadeli İşlemler:** Pozisyonu sürdürmek için gereken teminat dışında peşin bir maliyet yoktur; çünkü hem alıcı hem de satıcı işlemi tamamlamakla yükümlüdür.
* **Opsiyonlar:** Alıcı, opsiyonu kullanma hakkı için peşin olarak **opsiyon primi** ödemelidir. Bu prim, esasen opsiyonun maliyetidir.

### 4. **Kâr Potansiyeli:**

* **Vadeli İşlemler:** Kâr veya zarar, vade sonundaki piyasa fiyatı ile sözleşmede üzerinde anlaşılmış fiyat arasındaki farka bağlıdır.
* **Opsiyonlar:** Piyasa, kullanım fiyatının ötesinde ve ödenen primden daha fazla lehte hareket ederse alıcı kâr eder. Opsiyon kullanılmazsa satıcı primi elinde tutarak kâr eder.

## References

- [1] [CFTC - Vadeli işlem piyasalarının ekonomik amacı](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Vadeli İşlem Piyasalarının Temelleri](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Sanal para birimi işlemlerinin risklerini anlayın](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Sözlüğü - Opsiyon, prim ve kullanım](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
