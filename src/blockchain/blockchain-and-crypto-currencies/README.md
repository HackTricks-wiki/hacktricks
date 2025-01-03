{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Akıllı Sözleşmeler**, belirli koşullar yerine getirildiğinde bir blok zincirinde yürütülen programlar olarak tanımlanır ve aracılara ihtiyaç duymadan anlaşma yürütmelerini otomatikleştirir.
- **Merkeziyetsiz Uygulamalar (dApps)**, kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç ile akıllı sözleşmeler üzerine inşa edilir.
- **Tokenlar ve Coinler**, coinlerin dijital para olarak hizmet etmesi, tokenların ise belirli bağlamlarda değer veya mülkiyeti temsil etmesi ile ayrılır.
- **Yardımcı Tokenlar**, hizmetlere erişim sağlar ve **Güvenlik Tokenları** varlık mülkiyetini belirtir.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Merkeziyetsiz Finans anlamına gelir.
- **DEX** ve **DAO'lar**, sırasıyla Merkeziyetsiz Borsa Platformları ve Merkeziyetsiz Otonom Organizasyonlar anlamına gelir.

## Konsensüs Mekanizmaları

Konsensüs mekanizmaları, blok zincirinde güvenli ve kabul edilen işlem doğrulamalarını sağlar:

- **İş Kanıtı (PoW)**, işlem doğrulama için hesaplama gücüne dayanır.
- **Hisse Kanıtı (PoS)**, doğrulayıcıların belirli bir miktar token bulundurmasını gerektirir ve PoW'ye kıyasla enerji tüketimini azaltır.

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon transferini içerir. İşlemler, yalnızca özel anahtarın sahibi tarafından transferlerin başlatılmasını sağlamak için dijital imzalarla doğrulanır.

#### Ana Bileşenler:

- **Çok İmzalı İşlemler**, bir işlemi yetkilendirmek için birden fazla imza gerektirir.
- İşlemler, **girdiler** (fon kaynağı), **çıktılar** (hedef), **ücretler** (madencilere ödenen) ve **scriptler** (işlem kuralları) içerir.

### Lightning Ağı

Bitcoin'in ölçeklenebilirliğini artırmayı hedefler, bir kanalda birden fazla işlemi gerçekleştirerek yalnızca nihai durumu blok zincirine yayınlar.

## Bitcoin Gizlilik Endişeleri

Gizlilik saldırıları, **Ortak Girdi Mülkiyeti** ve **UTXO Değişim Adresi Tespiti** gibi, işlem kalıplarını istismar eder. **Mikserler** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Bitcoinleri Anonim Olarak Edinme

Yöntemler arasında nakit ticareti, madencilik ve mikser kullanımı bulunur. **CoinJoin**, birden fazla işlemi karıştırarak izlenebilirliği karmaşıklaştırırken, **PayJoin** CoinJoin'leri normal işlemler olarak gizleyerek gizliliği artırır.

# Bitcoin Gizlilik Saldırıları

# Bitcoin Gizlilik Saldırıları Özeti

Bitcoin dünyasında, işlemlerin gizliliği ve kullanıcıların anonimliği genellikle endişe konusudur. İşte saldırganların Bitcoin gizliliğini tehlikeye atabileceği birkaç yaygın yöntemin basitleştirilmiş bir özeti.

## **Ortak Girdi Mülkiyeti Varsayımı**

Farklı kullanıcıların girdilerinin tek bir işlemde birleştirilmesi genellikle nadirdir, bu nedenle **aynı işlemdeki iki girdi adresinin genellikle aynı sahibine ait olduğu varsayılır**.

## **UTXO Değişim Adresi Tespiti**

Bir UTXO, veya **Harcanmamış İşlem Çıktısı**, bir işlemde tamamen harcanmalıdır. Eğer yalnızca bir kısmı başka bir adrese gönderilirse, geri kalan yeni bir değişim adresine gider. Gözlemciler, bu yeni adresin gönderene ait olduğunu varsayarak gizliliği tehlikeye atabilir.

### Örnek

Bunu hafifletmek için, karıştırma hizmetleri veya birden fazla adres kullanmak mülkiyeti gizlemeye yardımcı olabilir.

## **Sosyal Ağlar ve Forumlar Maruziyeti**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır, bu da **adresin sahibine bağlanmasını kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler, fon akışına dayalı olarak kullanıcılar arasındaki potansiyel bağlantıları ortaya çıkaran grafikler olarak görselleştirilebilir.

## **Gereksiz Girdi Heuristiği (Optimal Değişim Heuristiği)**

Bu heuristik, birden fazla girdi ve çıktı içeren işlemleri analiz ederek hangi çıktının gönderene geri dönen değişim olduğunu tahmin etmeye dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Eğer daha fazla girdi eklemek, değişiklik çıktısını herhangi bir tek girdi kadar büyük yapıyorsa, bu heuristiği karıştırabilir.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının bunları gelecekteki işlemlerde diğer girdilerle birleştirmesini umarak, daha önce kullanılan adreslere küçük miktarlar gönderebilirler ve böylece adresleri birbirine bağlayabilirler.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu gizlilik sızıntısını önlemek için daha önce kullanılmış, boş adreslerde alınan coinleri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analiz Teknikleri**

- **Kesin Ödeme Miktarları:** Değişiklik olmadan yapılan işlemler, muhtemelen aynı kullanıcıya ait iki adres arasında gerçekleşir.
- **Yuvarlak Sayılar:** Bir işlemdaki yuvarlak bir sayı, bunun bir ödeme olduğunu gösterir; yuvarlak olmayan çıktı muhtemelen değişikliktir.
- **Cüzdan Parmak İzi:** Farklı cüzdanlar, analistlerin kullanılan yazılımı ve potansiyel olarak değişiklik adresini tanımlamasına olanak tanıyan benzersiz işlem oluşturma desenlerine sahiptir.
- **Miktar ve Zaman Korelasyonları:** İşlem zamanlarını veya miktarlarını açıklamak, işlemlerin izlenebilir hale gelmesine neden olabilir.

## **Trafik Analizi**

Ağ trafiğini izleyerek, saldırganlar işlemleri veya blokları IP adreslerine bağlayabilir ve kullanıcı gizliliğini tehlikeye atabilir. Bu, bir varlığın birçok Bitcoin düğümü işletmesi durumunda özellikle doğrudur ve işlemleri izleme yeteneklerini artırır.

## Daha Fazla

Gizlilik saldırıları ve savunmaları hakkında kapsamlı bir liste için [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) adresini ziyaret edin.

# Anonim Bitcoin İşlemleri

## Bitcoinleri Anonim Olarak Elde Etmenin Yolları

- **Nakit İşlemler**: Nakit ile bitcoin edinmek.
- **Nakit Alternatifleri**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin ile değiştirmek.
- **Madencilik**: Bitcoin kazanmanın en özel yöntemi madenciliktir, özellikle yalnız yapıldığında çünkü madencilik havuzları madencinin IP adresini bilebilir. [Madencilik Havuzları Bilgisi](https://en.bitcoin.it/wiki/Pooled_mining)
- **Hırsızlık**: Teorik olarak, bitcoin çalmak anonim olarak edinmenin bir başka yöntemi olabilir, ancak bu yasadışıdır ve önerilmez.

## Karıştırma Hizmetleri

Bir karıştırma hizmeti kullanarak, bir kullanıcı **bitcoin gönderebilir** ve **karşılığında farklı bitcoinler alabilir**, bu da orijinal sahibin izlenmesini zorlaştırır. Ancak, bu hizmetin kayıt tutmaması ve gerçekten bitcoinleri geri döndürmesi için güven gerektirir. Alternatif karıştırma seçenekleri arasında Bitcoin kumarhaneleri bulunmaktadır.

## CoinJoin

**CoinJoin**, farklı kullanıcılardan gelen birden fazla işlemi birleştirerek, girdileri çıktılarla eşleştirmeye çalışan herkes için süreci karmaşık hale getirir. Etkinliğine rağmen, benzersiz girdi ve çıktı boyutlarına sahip işlemler hala izlenebilir.

CoinJoin kullanmış olabilecek örnek işlemler arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` bulunmaktadır.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) adresini ziyaret edin. Ethereum'da benzer bir hizmet için [Tornado Cash](https://tornado.cash) adresine göz atın; bu hizmet, madencilerden gelen fonlarla işlemleri anonimleştirir.

## PayJoin

CoinJoin'un bir varyantı olan **PayJoin** (veya P2EP), iki taraf (örneğin, bir müşteri ve bir satıcı) arasında işlemi, CoinJoin'un belirgin eşit çıktılar özelliği olmadan, normal bir işlem olarak gizler. Bu, tespit edilmesini son derece zorlaştırır ve işlem gözetim varlıkları tarafından kullanılan ortak-girdi-sahipliği heuristiğini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Yukarıdaki gibi işlemler PayJoin olabilir, gizliliği artırırken standart bitcoin işlemlerinden ayırt edilemez kalır.

**PayJoin'in kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde bozabilir**, bu da işlem gizliliği arayışında umut verici bir gelişme haline getirir.

# Kripto Para Birimlerinde Gizlilik için En İyi Uygulamalar

## **Cüzdan Senkronizasyon Teknikleri**

Gizliliği ve güvenliği korumak için, cüzdanların blockchain ile senkronize edilmesi kritik öneme sahiptir. İki yöntem öne çıkmaktadır:

- **Tam düğüm**: Tüm blockchain'i indirerek, tam düğüm maksimum gizlilik sağlar. Daha önce yapılmış tüm işlemler yerel olarak saklanır, bu da düşmanların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkansız hale getirir.
- **İstemci tarafı blok filtreleme**: Bu yöntem, blockchain'deki her blok için filtreler oluşturarak cüzdanların belirli ilgi alanlarını ağ gözlemcilerine ifşa etmeden ilgili işlemleri tanımlamasını sağlar. Hafif cüzdanlar bu filtreleri indirir, yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tam blokları alır.

## **Anonimlik için Tor Kullanımı**

Bitcoin'in eşler arası bir ağda çalıştığı göz önüne alındığında, IP adresinizi maskelemek için Tor kullanılması önerilir, bu da ağla etkileşimde gizliliği artırır.

## **Adres Yeniden Kullanımını Önleme**

Gizliliği korumak için her işlem için yeni bir adres kullanmak hayati öneme sahiptir. Adreslerin yeniden kullanılması, işlemleri aynı varlıkla ilişkilendirerek gizliliği tehlikeye atabilir. Modern cüzdanlar, tasarımları aracılığıyla adres yeniden kullanımını teşvik etmez.

## **İşlem Gizliliği için Stratejiler**

- **Birden fazla işlem**: Bir ödemeyi birkaç işleme bölmek, işlem miktarını belirsizleştirerek gizlilik saldırılarını engelleyebilir.
- **Değişimden kaçınma**: Değişim çıktısı gerektirmeyen işlemleri tercih etmek, değişim tespit yöntemlerini bozarak gizliliği artırır.
- **Birden fazla değişim çıktısı**: Değişimden kaçınmak mümkün değilse, birden fazla değişim çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimlik Işığı**

Monero, dijital işlemlerde mutlak anonimlik ihtiyacını karşılar ve gizlilik için yüksek bir standart belirler.

# **Ethereum: Gaz ve İşlemler**

## **Gazı Anlamak**

Gaz, Ethereum'da işlemleri gerçekleştirmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2,310,000 gwei (veya 0.00231 ETH) maliyetli bir işlem, bir gaz limiti ve bir temel ücret içerir, ayrıca madencileri teşvik etmek için bir bahşiş vardır. Kullanıcılar, fazla ödeme yapmamalarını sağlamak için maksimum bir ücret belirleyebilir ve fazlası iade edilir.

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemler bir gönderici ve bir alıcı içerir; bu alıcı ya kullanıcı ya da akıllı sözleşme adresi olabilir. İşlemler bir ücret gerektirir ve madencilik yapılması gerekir. Bir işlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı veri, gaz limiti ve ücretlerdir. Özellikle, göndericinin adresi imzadan çıkarılır, bu da işlem verilerinde bulunmasına gerek kalmaz.

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliği önceliklendiren herkes için kripto para birimleriyle etkileşimde bulunmanın temelini oluşturur.

## Referanslar

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

{{#include ../../banners/hacktricks-training.md}}
