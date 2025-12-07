# Blokzincir ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts** belirli koşullar gerçekleştiğinde bir blockchain üzerinde çalışan programlar olarak tanımlanır, anlaşma yürütmelerini aracısız otomatikleştirir.
- **Decentralized Applications (dApps)** smart contract'ların üzerine kurulur; kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç içerir.
- **Tokens & Coins** ayrımı: coin'ler dijital para olarak hizmet ederken, token'lar belirli bağlamlarda değer veya mülkiyeti temsil eder.
- **Utility Tokens** hizmetlere erişim sağlar, ve **Security Tokens** varlık mülkiyetini gösterir.
- **DeFi** Merkeziyetsiz Finans anlamına gelir; merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAOs** sırasıyla Merkeziyetsiz Borsa Platformları ve Merkeziyetsiz Otonom Organizasyonlar anlamına gelir.

## Konsensüs Mekanizmaları

Konsensüs mekanizmaları, blockchain üzerinde güvenli ve uzlaşılan işlem doğrulamalarını sağlar:

- **Proof of Work (PoW)** işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)** doğrulayıcıların belirli miktarda token bulundurmasını gerektirir ve PoW'e kıyasla enerji tüketimini azaltır.

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri adresler arasında fon transferini içerir. İşlemler dijital imzalarla doğrulanır; bu, yalnızca özel anahtarın sahibi tarafından transfer başlatılabileceğini garanti eder.

#### Temel Bileşenler:

- **Multisignature Transactions** bir işlemi yetkilendirmek için birden fazla imza gerektirir.
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (madencilere ödenir) ve **scripts** (işlem kuralları) içerir.

### Lightning Network

Bitcoin'in ölçeklenebilirliğini artırmayı amaçlar; bir kanal içinde birden fazla işlem yapılmasına izin verir ve yalnızca son durumu blockchain'e yayınlar.

## Bitcoin Gizlilik Endişeleri

Gizlilik saldırıları, **Common Input Ownership** ve **UTXO Change Address Detection** gibi işlem desenlerini istismar eder. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Bitcoin'leri Anonim Olarak Edinme

Yöntemler arasında nakit takaslar, madencilik ve mixer kullanımı bulunur. **CoinJoin** birden fazla işlemi karıştırarak izlenebilirliği zorlaştırır, **PayJoin** ise CoinJoin'leri normal işlemler gibi gizleyerek daha yüksek gizlilik sağlar.

# Bitcoin Gizlilik Saldırıları

# Bitcoin Gizlilik Saldırıları Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sık sık endişe konusudur. İşte saldırganların Bitcoin gizliliğini zayıflatabileceği birkaç yaygın yöntemin basitleştirilmiş bir özeti.

## **Common Input Ownership Assumption**

Farklı kullanıcıların inputs'larının karmaşıklık nedeniyle tek bir işlemde birleştirilmesi genellikle nadirdir. Bu nedenle, **aynı işlemdeki iki input adres genellikle aynı kişiye ait varsayılır**.

## **UTXO Change Address Detection**

Bir UTXO, yani **Unspent Transaction Output**, bir işlemde tamamen harcanmak zorundadır. Sadece bir kısmı başka bir adrese gönderilirse, kalan miktar yeni bir change address'e gider. Gözlemciler bu yeni adresin göndericiye ait olduğunu varsayabilir ve gizliliği tehlikeye atar.

### Örnek

Bunu hafifletmek için mixing servisleri veya birden fazla adres kullanmak mülkiyeti gizlemeye yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu, adresin sahibine **kolayca bağlanmasını** sağlar.

## **Transaction Graph Analysis**

İşlemler grafikler olarak görselleştirilebilir; fon akışına dayanarak kullanıcılar arasında potansiyel bağlantıları ortaya çıkarır.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu sezgi, birden fazla input ve output içeren işlemleri analiz ederek hangi output'un göndericiye dönen change olduğunu tahmin etmeye dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Eğer daha fazla girdi eklemek, değişim çıktısını herhangi bir tek girdiden daha büyük yapıyorsa, bu heuristiği yanıltabilir.

## **Forced Address Reuse**

Saldırganlar, alıcının bunları gelecekteki işlemlerde diğer girdilerle birleştirerek adresleri birbirine bağlamasını umarak, daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu gizlilik leak'ini önlemek için daha önce kullanılmış, boş adreslerde alınan coin'leri kullanmaktan kaçınmalıdır.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Change içermeyen işlemler muhtemelen aynı kullanıcıya ait iki adres arasında gerçekleşir.
- **Round Numbers:** Bir işlemdeki yuvarlak tutar, bunun bir ödeme olduğunu ve yuvarlak olmayan çıktının muhtemelen değişim olduğunu gösterir.
- **Wallet Fingerprinting:** Farklı cüzdanlar benzersiz işlem oluşturma desenlerine sahiptir; bu, analistlerin kullanılan yazılımı ve muhtemelen değişim adresini tespit etmesine olanak tanır.
- **Amount & Timing Correlations:** İşlem zamanları veya tutarlarının açıklanması işlemlerin izlenebilir hâle gelmesine neden olabilir.

## **Traffic Analysis**

Ağ trafiğini izleyerek saldırganlar işlemleri veya blokları IP adreslerine bağlayabilir ve kullanıcı gizliliğini tehlikeye atabilir. Bir varlık çok sayıda Bitcoin node'u çalıştırıyorsa, işlemleri izleme yetenekleri artar; bu özellikle geçerlidir.

## Daha Fazlası

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için, [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonim Bitcoin İşlemleri

## Bitcoinleri Anonim Olarak Elde Etme Yolları

- **Cash Transactions**: Bitcoin'i nakit yoluyla edinme.
- **Cash Alternatives**: Hediye kartları satın alıp çevrimiçi olarak bitcoin'e dönüştürme.
- **Mining**: Bitcoin kazanmanın en özel yöntemi madenciliktir; özellikle tek başına yapıldığında daha gizlidir çünkü mining pool'ları madencinin IP adresini bilebilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak, bitcoin çalmak onu anonim olarak elde etmenin başka bir yolu olabilir; ancak bu yasa dışıdır ve tavsiye edilmez.

## Mixing Services

Bir mixing servisi kullanarak, kullanıcı **bitcoin gönderebilir** ve karşılığında **farklı bitcoinler alabilir**, bu da orijinal sahibin izini zorlaştırır. Ancak bu, servise log tutmama ve gerçekten bitcoinleri geri verme konusunda güvenmeyi gerektirir. Alternatif mixing seçenekleri arasında Bitcoin casinoları bulunur.

## CoinJoin

CoinJoin, farklı kullanıcıların birden fazla işlemini tek bir işlemde birleştirir; bu, girdileri çıktılarla eşleştirmeye çalışanlar için süreci zorlaştırır. Ancak benzersiz girdi ve çıktı boyutlarına sahip işlemler hâlâ izlenebilir.

CoinJoin kullanmış olabilecek örnek işlemler şunlardır: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) adresini ziyaret edin. Ethereum için benzer bir servis olan [Tornado Cash](https://tornado.cash), miner'ların fonlarıyla işlemleri anonimleştirir.

## PayJoin

CoinJoin'ın bir varyantı olan PayJoin (veya P2EP), işlemi iki taraf (ör. müşteri ve satıcı) arasındaki normal bir işlem gibi gizler; CoinJoin'e özgü eşit çıktılar gibi belirgin özelliklere sahip değildir. Bu tespiti son derece zorlaştırır ve işlem gözetim yapan kuruluşların kullandığı common-input-ownership heuristic'i geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# Kripto Para Birimlerinde Gizlilik İçin En İyi Uygulamalar

## **Cüzdan Senkronizasyon Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanların blockchain ile senkronize edilmesi kritik öneme sahiptir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek, bir full node maksimum gizlilik sağlar. Yapılan tüm işlemler yerel olarak saklanır; bu da saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkansız kılar.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her blok için filtreler oluşturmayı içerir; böylece cüzdanlar ağ gözlemcilerine belirli ilgi alanlarını açmadan ilgili işlemleri tespit edebilir. Hafif cüzdanlar bu filtreleri indirir ve kullanıcının adresleriyle eşleşme olduğunda yalnızca tam blokları çeker.

## **Anonimlik İçin Tor Kullanımı**

Bitcoin'in eşler arası bir ağ üzerinde çalışması nedeniyle, IP adresinizi gizlemek ve ağla etkileşim sırasında gizliliği artırmak için Tor kullanılması tavsiye edilir.

## **Adres Tekrar Kullanımını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak hayati önemdedir. Adresleri tekrar kullanmak, işlemleri aynı varlığa bağlayarak gizliliği tehlikeye atabilir. Modern cüzdanlar tasarımları gereği adres tekrar kullanımını caydırır.

## **İşlem Gizliliği İçin Stratejiler**

- Birden çok işlem: Ödemeyi birkaç işleme bölmek, işlem miktarını gizleyebilir ve gizlilik saldırılarını zorlaştırabilir.
- Para üstü (change) çıktılarından kaçınma: Para üstü çıktısı gerektirmeyen işlemleri tercih etmek, para üstü tespiti yöntemlerini bozarak gizliliği artırır.
- Birden çok para üstü çıktısı: Para üstünden kaçınmak mümkün değilse, birden fazla para üstü çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimliğin Sembolü**

Monero, dijital işlemlerde mutlak anonimliğe olan ihtiyacı ele alır ve gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas ve İşlemler**

## **Gas'i Anlamak**

Gas, Ethereum üzerinde işlemleri yürütmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2,310,000 gwei (veya 0.00231 ETH) maliyetli bir işlem gas limit ve base fee içerir; ayrıca madencileri teşvik etmek için bir tip verilir. Kullanıcılar, fazla ödeme yapmamalarını sağlamak için bir max fee belirleyebilir; fazla ödenen kısım iade edilir.

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemler bir gönderici ve bir alıcı içerir; bunlar kullanıcı veya smart contract adresleri olabilir. İşlemler bir ücret gerektirir ve mined (madencilik) edilmelidir. Bir işlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretlerdir. Göndericinin adresi imzadan türetildiği için, işlem verisinde adresin ayrı olarak bulunmasına gerek yoktur.

Bu uygulamalar ve mekanizmalar, gizliliği ve güvenliği ön planda tutarak kripto para birimleriyle etkileşime girmek isteyen herkes için temel oluşturur.

## Akıllı Sözleşme Güvenliği

- Test süitlerindeki kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Referanslar

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM İstismarı

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
