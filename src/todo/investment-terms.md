# Yatırım Terimleri

{{#include ../banners/hacktricks-training.md}}

## Spot

Bu, trading yapmanın en temel yoludur. **Varlığın miktarını ve satın almak veya satmak istediğiniz fiyatı belirtebilir**, fiyat ulaşıldığında işlem gerçekleştirilir.

Genellikle işlemi mevcut fiyattan mümkün olduğunca hızlı gerçekleştirmek için **güncel piyasa fiyatını** da kullanabilirsiniz.

**Stop Loss - Limit**: Ayrıca varlıkların miktarını ve satın alma veya satış fiyatını belirtebilir, bunun yanında ulaşıldığında satın almak veya satmak için daha düşük bir fiyat da belirtebilirsiniz (zarar durdurmak için).

## Vadeli İşlemler

Vadeli işlem, 2 tarafın **gelecekte bir şeyi sabit bir fiyattan satın almak** üzere anlaşmaya vardığı bir sözleşmedir. Örneğin 1 bitcoin'i 6 ay sonra 70.000$'dan satmak.

Açıkça, 6 ay sonra bitcoin'in değeri 80.000$ olursa satan taraf para kaybeder ve alan taraf kazanır. 6 ay sonra bitcoin'in değeri 60.000$ olursa bunun tersi gerçekleşir.

Ancak bu, örneğin bir ürün üreten ve maliyetlerini karşılayacak bir fiyattan ürünü satabileceğinden emin olmak isteyen işletmeler için ilgi çekicidir. Ya da gelecekte bir şey için, daha yüksek olsa bile, sabit fiyatları güvence altına almak isteyen işletmeler için.

Borsalarda ise bu genellikle kâr elde etmeye çalışmak için kullanılır.

* "Long position", bir kişinin fiyatın yükseleceğine bahis oynadığı anlamına gelir
* "Short position" ise bir kişinin fiyatın düşeceğine bahis oynadığı anlamına gelir

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Bir fon yöneticisi bazı hisselerin düşeceğinden korkuyorsa bitcoin veya S\&P 500 vadeli işlem sözleşmeleri gibi bazı varlıklar üzerinde short position alabilir. Bu, bazı varlıkları satın almaya veya elinde bulundurmaya ve bunları gelecekte daha yüksek bir fiyattan satmak üzere bir sözleşme oluşturmaya benzer.

Fiyat düşerse fon yöneticisi, varlıkları daha yüksek bir fiyattan satacağı için kâr elde eder. Varlıkların fiyatı yükselirse yönetici bu kârı elde edemez, ancak varlıklarını elinde tutmaya devam eder.

### Perpetual Futures

**Bunlar süresiz olarak devam eden "futures" sözleşmeleridir** (sözleşmenin bitiş tarihi yoktur). Örneğin crypto borsalarında bunlara rastlamak oldukça yaygındır; crypto fiyatlarına göre futures işlemlerine girip çıkabilirsiniz.

Bu durumlarda kâr ve zararların gerçek zamanlı olabileceğini unutmayın: Fiyat %1 artarsa %1 kazanırsınız; fiyat %1 düşerse %1 kaybedersiniz.

### Kaldıraçlı Futures

**Kaldıraç**, daha az miktarda parayla piyasada daha büyük bir pozisyonu kontrol etmenizi sağlar. Temel olarak, sahip olduğunuzdan çok daha fazla parayla "bahis" yapmanıza ve yalnızca gerçekten sahip olduğunuz parayı riske atmanıza olanak tanır.

Örneğin BTC/USDT üzerinde 100$ ile 50x kaldıraçlı bir futures pozisyonu açarsanız, fiyat %1 arttığında başlangıç yatırımınızın %1x50 = %50'sini (50$) kazanırsınız. Böylece 150$'ınız olur.\
Ancak fiyat %1 düşerse paranızın %50'sini (bu durumda 59$) kaybedersiniz. Fiyat %2 düşerse tüm bahsinizi kaybedersiniz (%2x50 = %100).

Bu nedenle kaldıraç, kazançları ve kayıpları artırırken bahis yaptığınız para miktarını kontrol etmenizi sağlar.

## Futures ve Options Arasındaki Farklar

Futures ve options arasındaki temel fark, sözleşmenin alıcı için isteğe bağlı olmasıdır: Alıcı sözleşmeyi uygulayıp uygulamamaya karar verebilir (genellikle yalnızca bundan kâr elde edecekse uygular). Alıcı option'ı kullanmak isterse satıcı satış yapmak zorundadır.\
Ancak alıcı, option'ı açtığı için satıcıya bir ücret öder (bu nedenle görünüşte daha fazla risk alan satıcı para kazanmaya başlar).

### 1. **Yükümlülük ve Hak:**

* **Futures:** Bir futures sözleşmesi satın aldığınızda veya sattığınızda, belirli bir tarihte belirli bir fiyattan bir varlığı satın almak veya satmak için **bağlayıcı bir anlaşmaya** girmiş olursunuz. Hem alıcı hem de satıcı, sözleşme sona erdiğinde sözleşmeyi yerine getirmekle **yükümlüdür** (sözleşme bundan önce kapatılmadığı sürece).
* **Options:** Options işlemlerinde, belirli bir fiyattan bir varlığı belirli bir son kullanma tarihinden önce veya o tarihte satın alma (**call option** durumunda) ya da satma (**put option** durumunda) **hakkına, ancak yükümlülüğüne sahip olmazsınız**. **Alıcı** işlemi gerçekleştirme seçeneğine sahiptir; **satıcı** ise alıcı option'ı kullanmaya karar verirse işlemi gerçekleştirmekle yükümlüdür.

### 2. **Risk:**

* **Futures:** Hem alıcı hem de satıcı, sözleşmeyi tamamlamakla yükümlü oldukları için **sınırsız risk** üstlenir. Risk, anlaşılan fiyat ile son kullanma tarihindeki piyasa fiyatı arasındaki farktır.
* **Options:** Alıcının riski, option'ı satın almak için ödenen **prim** ile sınırlıdır. Piyasa option sahibinin lehine hareket etmezse option'ın süresinin dolmasına izin verebilir. Ancak option'ın **satıcısı** (writer), piyasa kendisinin aleyhine önemli ölçüde hareket ederse sınırsız risk taşır.

### 3. **Maliyet:**

* **Futures:** Alıcı ve satıcı işlemi tamamlamakla yükümlü olduğundan, pozisyonu korumak için gereken teminat dışında önceden ödenen bir maliyet yoktur.
* **Options:** Alıcı, option'ı kullanma hakkı için önceden bir **option primi** ödemelidir. Bu prim, temel olarak option'ın maliyetidir.

### 4. **Kâr Potansiyeli:**

* **Futures:** Kâr veya zarar, son kullanma tarihindeki piyasa fiyatı ile sözleşmede anlaşılan fiyat arasındaki farka dayanır.
* **Options:** Alıcı, piyasa strike price'ın ötesinde ve ödenen primden daha fazla lehine hareket ettiğinde kâr eder. Satıcı ise option kullanılmazsa primi elinde tutarak kâr eder.

{{#include ../banners/hacktricks-training.md}}
