# Yatırım Terimleri

## Spot

Bu, bazı ticaret yapmanın en temel yoludur. **Almak veya satmak istediğiniz varlığın miktarını ve fiyatını** belirtebilirsiniz ve o fiyat ulaşıldığında işlem gerçekleştirilir.

Genellikle, işlemi mümkün olan en hızlı şekilde gerçekleştirmek için **mevcut piyasa fiyatını** da kullanabilirsiniz.

**Stop Loss - Limit**: Ayrıca, varlıkların alım veya satım fiyatını belirtirken, ulaşılması durumunda alım veya satım için daha düşük bir fiyat da belirtebilirsiniz (zararları durdurmak için).

## Vadeli İşlemler

Vadeli işlem, 2 tarafın **belirli bir fiyattan gelecekte bir şey edinme konusunda anlaşmaya vardığı** bir sözleşmedir. Örneğin, 6 ay içinde 70.000$'a 1 bitcoin satmak.

Elbette, 6 ay içinde bitcoin değeri 80.000$ olursa, satıcı taraf para kaybeder ve alıcı taraf kazanır. 6 ay içinde bitcoin değeri 60.000$ olursa, tam tersi olur.

Ancak, bu, bir ürün üreten ve maliyetleri karşılayacak bir fiyattan satabileceğinden emin olmak isteyen işletmeler için ilginçtir. Ya da gelecekte bir şey için sabit fiyatlar sağlamak isteyen işletmeler için, hatta daha yüksek olsa bile.

Borsa işlemlerinde bu genellikle kar elde etmeye çalışmak için kullanılır.

* "Uzun pozisyon" birinin fiyatın artacağına bahse girdiği anlamına gelir.
* "Kısa pozisyon" birinin fiyatın düşeceğine bahse girdiği anlamına gelir.

### Vadeli İşlemlerle Korunma <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Bir fon yöneticisi bazı hisse senetlerinin düşeceğinden korkuyorsa, bitcoinler veya S&P 500 vadeli işlem sözleşmeleri gibi bazı varlıklar üzerinde kısa pozisyon alabilir. Bu, bazı varlıkları satın almak veya bulundurmak ve bunları gelecekte daha yüksek bir fiyattan satma sözleşmesi oluşturmakla benzer.

Fiyat düşerse, fon yöneticisi varlıkları daha yüksek bir fiyattan satacağı için kazanç elde eder. Varlıkların fiyatı yükselirse, yönetici bu kazancı elde edemeyecek ancak varlıklarını koruyacaktır.

### Sürekli Vadeli İşlemler

**Bunlar, süresiz olarak sürecek "vadeli işlemler"dir** (sonlandırma sözleşme tarihi olmadan). Örneğin, kripto borsalarında, kripto fiyatlarına dayalı olarak vadeli işlemlere girip çıkmak oldukça yaygındır.

Bu durumlarda kazanç ve kayıplar gerçek zamanlı olabilir; fiyat %1 artarsa %1 kazanırsınız, fiyat %1 düşerse kaybedersiniz.

### Kaldıraçlı Vadeli İşlemler

**Kaldıraç**, piyasada daha büyük bir pozisyonu daha az para ile kontrol etmenizi sağlar. Temelde, sahip olduğunuz paradan daha fazla para "bahis" yapmanıza olanak tanır, sadece gerçekten sahip olduğunuz parayı riske atarsınız.

Örneğin, BTC/USDT'de 100$ ile 50x kaldıraçla bir vadeli işlem pozisyonu açarsanız, bu, fiyat %1 artarsa, başlangıç yatırımınızın %50'sini (50$) kazanacağınız anlamına gelir. Böylece 150$'ınız olur.\
Ancak, fiyat %1 düşerse, fonlarınızın %50'sini kaybedersiniz (bu durumda 59$). Fiyat %2 düşerse, tüm bahsinizi kaybedersiniz (2x50 = 100%).

Bu nedenle, kaldıraç, bahsettiğiniz para miktarını kontrol etmenizi sağlarken kazanç ve kayıpları artırır.

## Vadeli İşlemler ve Opsiyonlar Arasındaki Farklar

Vadeli işlemler ile opsiyonlar arasındaki ana fark, sözleşmenin alıcı için isteğe bağlı olmasıdır: İsterse bunu uygulama kararı alabilir (genellikle yalnızca fayda sağlarsa bunu yapar). Satıcı, alıcı opsiyonu kullanmak isterse satmak zorundadır.\
Ancak, alıcı opsiyonu açmak için satıcıya bir ücret ödeyecektir (bu nedenle, görünüşte daha fazla risk alan satıcı, biraz para kazanmaya başlar).

### 1. **Zorunluluk vs. Hak:**

* **Vadeli İşlemler:** Bir vadeli işlem sözleşmesi satın aldığınızda veya sattığınızda, belirli bir tarihte belirli bir fiyattan bir varlık satın alma veya satma konusunda **bağlayıcı bir anlaşmaya** girmiş olursunuz. Hem alıcı hem de satıcı, sözleşme süresinde sözleşmeyi yerine getirmekle **yükümlüdür** (sözleşme önceden kapatılmadığı sürece).
* **Opsiyonlar:** Opsiyonlarla, belirli bir tarihten önce veya belirli bir tarihte belirli bir fiyattan bir varlık satın alma (bir **call opsiyonu** durumunda) veya satma (bir **put opsiyonu** durumunda) **hakkına, ancak zorunluluğa sahip** olursunuz. **Alıcı**, opsiyonu uygulama seçeneğine sahiptir, **satıcı** ise alıcı opsiyonu kullanmaya karar verirse ticareti yerine getirmekle yükümlüdür.

### 2. **Risk:**

* **Vadeli İşlemler:** Hem alıcı hem de satıcı, sözleşmeyi tamamlama yükümlülüğü nedeniyle **sınırsız risk** alır. Risk, sözleşme süresinde kararlaştırılan fiyat ile piyasa fiyatı arasındaki farktır.
* **Opsiyonlar:** Alıcının riski, opsiyonu satın almak için ödenen **primle** sınırlıdır. Piyasa, opsiyon sahibinin lehine hareket etmezse, opsiyonu süresiz bırakabilir. Ancak, opsiyonun **satıcısı** (yazarı), piyasa kendilerine karşı önemli ölçüde hareket ederse sınırsız risk taşır.

### 3. **Maliyet:**

* **Vadeli İşlemler:** Pozisyonu tutmak için gereken teminat dışında önceden bir maliyet yoktur, çünkü alıcı ve satıcı ticareti tamamlama yükümlülüğündedir.
* **Opsiyonlar:** Alıcı, opsiyonu kullanma hakkı için önceden bir **opsiyon primi** ödemelidir. Bu prim, opsiyonun maliyetidir.

### 4. **Kar Potansiyeli:**

* **Vadeli İşlemler:** Kar veya zarar, sözleşmedeki kararlaştırılan fiyat ile vade sonunda piyasa fiyatı arasındaki farka dayanır.
* **Opsiyonlar:** Alıcı, piyasa, ödenen primden daha fazla bir fiyat hareket ettiğinde kar elde eder. Satıcı, opsiyon kullanılmadığında primi tutarak kar elde eder.
