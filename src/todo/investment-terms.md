# Yatırım Terimleri

{{#include /banners/hacktricks-training.md}}

## Spot

Bu, bazı ticaret yapmanın en temel yoludur. **Almak veya satmak istediğiniz varlığın miktarını ve fiyatını** belirtebilirsiniz ve o fiyat ulaşıldığında işlem gerçekleştirilir.

Genellikle, işlemi mümkün olan en hızlı şekilde gerçekleştirmek için **mevcut piyasa fiyatını** da kullanabilirsiniz.

**Stop Loss - Limit**: Ayrıca, varlıkların alım veya satım fiyatını belirlerken, ulaşılması durumunda (zararları durdurmak için) alım veya satım için daha düşük bir fiyat da belirtebilirsiniz.

## Vadeli İşlemler

Vadeli işlem, 2 tarafın **gelecekte sabit bir fiyattan bir şey edinme** konusunda anlaştığı bir sözleşmedir. Örneğin, 6 ay içinde 70.000$'a 1 bitcoin satmak.

Elbette, 6 ay içinde bitcoin değeri 80.000$ olursa, satıcı taraf para kaybeder ve alıcı taraf kazanır. 6 ay içinde bitcoin değeri 60.000$ olursa, tersine olur.

Ancak, bu, bir ürün üreten ve maliyetleri karşılayacak bir fiyattan satabileceğinden emin olmak isteyen işletmeler için ilginçtir. Ya da gelecekte bir şey için sabit fiyatlar sağlamak isteyen işletmeler için, hatta daha yüksek olsa bile.

Borsa işlemlerinde ise genellikle kar elde etmeye çalışmak için kullanılır.

* "Uzun pozisyon" birinin fiyatın artacağına bahse girdiği anlamına gelir.
* "Kısa pozisyon" ise birinin fiyatın düşeceğine bahse girdiği anlamına gelir.

### Vadeli İşlemlerle Korunma <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Bir fon yöneticisi bazı hisse senetlerinin düşeceğinden korkuyorsa, bitcoinler veya S&P 500 vadeli işlem sözleşmeleri gibi bazı varlıklar üzerinde kısa pozisyon alabilir. Bu, bazı varlıkları satın almak veya bulundurmak ve bunları gelecekte daha yüksek bir fiyattan satma sözleşmesi oluşturmak gibidir.

Fiyat düşerse, fon yöneticisi varlıkları daha yüksek bir fiyattan satacağı için kazanç elde eder. Varlıkların fiyatı yükselirse, yönetici bu kazancı elde edemez ama yine de varlıklarını korur.

### Sürekli Vadeli İşlemler

**Bunlar, süresiz olarak sürecek "vadeli işlemler"dir** (sonlandırma sözleşme tarihi olmadan). Örneğin, kripto borsalarında, kripto fiyatlarına dayalı olarak vadeli işlemlere girip çıkmak oldukça yaygındır.

Bu durumlarda kazanç ve kayıplar gerçek zamanlı olabilir; fiyat %1 artarsa %1 kazanırsınız, fiyat %1 düşerse kaybedersiniz.

### Kaldıraçlı Vadeli İşlemler

**Kaldıraç**, piyasada daha büyük bir pozisyonu daha az para ile kontrol etmenizi sağlar. Temelde, sahip olduğunuz paradan daha fazla para "bahis" yapmanıza olanak tanır, sadece gerçekten sahip olduğunuz parayı riske atarsınız.

Örneğin, BTC/USDT'de 100$ ile 50x kaldıraçla bir vadeli işlem pozisyonu açarsanız, fiyat %1 artarsa, başlangıç yatırımınızın %50'sini (50$) kazanırsınız. Böylece 150$'ınız olur.\
Ancak, fiyat %1 düşerse, fonlarınızın %50'sini kaybedersiniz (bu durumda 59$). Fiyat %2 düşerse, tüm bahsinizi kaybedersiniz (2x50 = 100%).

Bu nedenle, kaldıraç, bahsettiğiniz para miktarını kontrol etmenizi sağlarken kazançları ve kayıpları artırır.

## Vadeli İşlemler ve Opsiyonlar Arasındaki Farklar

Vadeli işlemler ile opsiyonlar arasındaki ana fark, sözleşmenin alıcı için isteğe bağlı olmasıdır: İsterse bunu uygulamaya karar verebilir (genellikle yalnızca fayda sağlarsa bunu yapar). Satıcı, alıcı opsiyonu kullanmak isterse satmak zorundadır.\
Ancak, alıcı opsiyonu açmak için satıcıya bir ücret ödeyecektir (bu nedenle, görünüşte daha fazla risk alan satıcı, biraz para kazanmaya başlar).

### 1. **Zorunluluk vs. Hak:**

* **Vadeli İşlemler:** Bir vadeli işlem sözleşmesi satın aldığınızda veya sattığınızda, belirli bir tarihte belirli bir fiyattan bir varlık satın alma veya satma konusunda **bağlayıcı bir anlaşma** yapıyorsunuz. Hem alıcı hem de satıcı, sözleşmenin sona erdiğinde yerine getirilmesi için **zorunludur** (sözleşme önceden kapatılmadığı sürece).
* **Opsiyonlar:** Opsiyonlarla, belirli bir tarihten önce veya belirli bir tarihte belirli bir fiyattan bir varlık satın alma (bir **call opsiyonu** durumunda) veya satma (bir **put opsiyonu** durumunda) **hakkına, ancak zorunluluğa sahip** olursunuz. **Alıcı**, opsiyonu uygulama seçeneğine sahiptir, **satıcı** ise alıcı opsiyonu kullanmaya karar verirse ticareti yerine getirmekle yükümlüdür.

### 2. **Risk:**

* **Vadeli İşlemler:** Hem alıcı hem de satıcı, sözleşmeyi tamamlamak zorunda oldukları için **sınırsız risk** alır. Risk, sözleşmedeki kararlaştırılan fiyat ile sona erme tarihindeki piyasa fiyatı arasındaki farktır.
* **Opsiyonlar:** Alıcının riski, opsiyonu satın almak için ödenen **prim** ile sınırlıdır. Piyasa, opsiyon sahibinin lehine hareket etmezse, opsiyonu süresinin dolmasına bırakabilir. Ancak, opsiyonun **satıcısı** (yazarı), piyasa kendilerine karşı önemli ölçüde hareket ederse sınırsız risk taşır.

### 3. **Maliyet:**

* **Vadeli İşlemler:** Pozisyonu tutmak için gereken teminat dışında önceden bir maliyet yoktur, çünkü alıcı ve satıcı ticareti tamamlamak zorundadır.
* **Opsiyonlar:** Alıcı, opsiyonu kullanma hakkı için önceden bir **opsiyon primi** ödemelidir. Bu prim, opsiyonun maliyetidir.

### 4. **Kar Potansiyeli:**

* **Vadeli İşlemler:** Kar veya zarar, sona erme tarihindeki piyasa fiyatı ile sözleşmedeki kararlaştırılan fiyat arasındaki farka dayanır.
* **Opsiyonlar:** Alıcı, piyasa, ödenen primden daha fazla bir fiyatın üzerinde olumlu bir şekilde hareket ettiğinde kar elde eder. Satıcı, opsiyon kullanılmadığında primi tutarak kar elde eder.

{{#include /banners/hacktricks-training.md}}
