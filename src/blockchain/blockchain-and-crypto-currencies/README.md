# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts** bir blokzincir üzerinde belirli koşullar sağlandığında çalışan programlar olarak tanımlanır; aracı olmadan anlaşmaların otomatik olarak yürütülmesini sağlar.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç içeren smart contract’lar üzerine kurulur.
- **Tokens & Coins** farkı, coin’lerin dijital para olarak hizmet etmesi; token’lar ise belirli bağlamlarda değer veya mülkiyet temsil etmesidir.
- **Utility Tokens** hizmetlere erişim sağlar, **Security Tokens** ise varlık mülkiyetini gösterir.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Decentralized Finance anlamına gelir.
- **DEX** ve **DAOs** sırasıyla Decentralized Exchange Platformları ve Decentralized Autonomous Organizations anlamına gelir.

## Konsensüs Mekanizmaları

Konsensüs mekanizmaları, blokzincirde işlemlerin güvenli ve mutabık şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)** işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)** doğrulayıcıların belirli miktarda token bulundurmasını gerektirir; PoW’ye kıyasla enerji tüketimini azaltır.

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri adresler arasında fon transferini içerir. İşlemler dijital imzalarla doğrulanır; böylece yalnızca özel anahtarın sahibi transfer başlatabilir.

#### Temel Bileşenler:

- **Multisignature Transactions** bir işlemi yetkilendirmek için birden fazla imza gerektirir.
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (madencilere ödenen), ve **scripts** (işlem kuralları) bileşenlerinden oluşur.

### Lightning Network

Bitcoin’in ölçeklenebilirliğini artırmayı hedefler; bir kanalda birden fazla işlem yapılmasına izin vererek sadece son durumu blokzincire yayınlar.

## Bitcoin Gizlilik Endişeleri

Common Input Ownership ve **UTXO Change Address Detection** gibi gizlilik saldırıları işlem desenlerinden yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Bitcoins’i Anonim Olarak Elde Etme

Yöntemler nakit ticareti, madencilik ve mixer kullanımını içerir. **CoinJoin** birden fazla işlemi karıştırarak izlenebilirliği zorlaştırırken, **PayJoin** CoinJoin’leri normal işlemler gibi gizleyerek daha yüksek gizlilik sağlar.

# Bitcoin Privacy Atacks

# Bitcoin Gizlilik Saldırıları Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıkça endişe konusudur. İşte saldırganların Bitcoin gizliliğini zedeleyebileceği birkaç yaygın yöntemin basitleştirilmiş bir özeti.

## **Common Input Ownership Assumption**

Farklı kullanıcıların girdilerinin tek bir işlemde birleştirilmesi genellikle nadirdir; bu nedenle **aynı işlemde bulunan iki input adresinin genellikle aynı sahibi olduğu varsayılır**.

## **UTXO Change Address Detection**

UTXO (Unspent Transaction Output) bir işlemde tamamen harcanmak zorundadır. Sadece bir kısmı başka bir adrese gönderilirse, kalan kısım yeni bir change adresine gider. Gözlemciler bu yeni adresin gönderene ait olduğunu varsayarak gizliliği zedeleyebilir.

### Örnek

Bunu azaltmak için mixing servisleri veya birden çok adres kullanmak mülkiyeti gizlemeye yardımcı olabilir.

## **Sosyal Ağlar ve Forumlar Üzerinden Açığa Çıkma**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu da adresin sahibiyle ilişkilendirilmesini kolaylaştırır.

## **İşlem Grafiği Analizi**

İşlemler grafik olarak görselleştirilebilir; fon akışına göre kullanıcılar arasında potansiyel bağlantıları açığa çıkarabilir.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu heuristic, birden fazla input ve output içeren işlemleri analiz ederek hangi output’un gönderene geri dönen change olduğunu tahmin etmeye dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının gelecekte bu küçük miktarları diğer inputlarla birleştirip adresleri birbirine bağlamasını umut ederek daha önce kullanılmış adreslere küçük miktarlar gönderebilirler.

### Doğru Wallet Davranışı

Cüzdanlar, bu privacy leak'i önlemek için zaten kullanılmış, boş adreslerde alınan coinleri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analizi Teknikleri**

- **Tam Ödeme Tutarları:** change olmayan işlemler muhtemelen aynı kullanıcıya ait iki adres arasındadır.
- **Yuvarlak Sayılar:** Bir işlemde yuvarlak bir sayı ödemeyi işaret eder; yuvarlak olmayan çıktı muhtemelen change'dir.
- **Wallet Fingerprinting:** Farklı cüzdanların işlem oluşturma desenleri benzersizdir; analistler kullanılan yazılımı ve muhtemel change adresini tespit edebilir.
- **Tutar ve Zamanlama Korelasyonları:** İşlem zamanları veya tutarlarının açıklanması işlemleri izlenebilir hale getirebilir.

## **Traffic Analysis**

Ağ trafiğini izleyerek, saldırganlar işlemleri veya blokları IP adreslerine bağlayabilir ve kullanıcı gizliliğini tehlikeye atabilir. Bir varlığın çok sayıda Bitcoin node'u işletmesi, işlemleri izleme yeteneklerini artırır.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Nakit ile bitcoin edinme.
- **Cash Alternatives**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin'e çevirme.
- **Mining**: Bitcoin kazanmanın en özel yöntemi mining'dir; özellikle solo mining yapıldığında en gizlidir, çünkü mining pools madencinin IP adresini bilebilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak, bitcoin çalmak anonim edinme yöntemi olabilir, ancak bu yasadışıdır ve tavsiye edilmez.

## Mixing Services

Bir mixing service kullanarak kullanıcı, bitcoin gönderebilir ve karşılığında farklı bitcoinler alabilir; bu da orijinal sahibin izini zorlaştırır. Yine de, bu servise kayıt tutmama ve bitcoinleri gerçekten geri verme konusunda güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casinoları bulunur.

## CoinJoin

CoinJoin, farklı kullanıcıların işlemlerini tek bir işlemde birleştirir ve girişleri çıkışlarla eşleştirmeyi zorlaştırır. Buna rağmen, benzersiz input ve output boyutlarına sahip işlemler hâlâ takip edilebilir.

CoinJoin kullanmış olabilecek örnek işlemler arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` bulunur.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

CoinJoin'ın bir varyantı olan PayJoin (veya P2EP), işlemi iki taraf (ör. müşteri ve satıcı) arasında normal bir işlem gibi gizler; CoinJoin'a özgü eşit çıktılar özelliği yoktur. Bu, tespit edilmesini son derece zorlaştırır ve transaction surveillance tarafından kullanılan common-input-ownership heuristic'i geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Yukarıdaki gibi işlemler PayJoin olabilir; normal bitcoin işlemlerinden ayırt edilemez halde kalarak gizliliği artırır.

**PayJoin kullanımı, geleneksel gözetim yöntemlerini önemli ölçüde sekteye uğratabilir**, bu da onu işlem gizliliği arayışında umut verici bir gelişme yapar.

# Kripto Para Birimlerinde Gizlilik İçin En İyi Uygulamalar

## **Wallet Synchronization Techniques**

Gizliliği ve güvenliği korumak için cüzdanların blockchain ile senkronize edilmesi çok önemlidir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek, bir full node maksimum gizliliği sağlar. Yapılmış tüm işlemler yerel olarak saklanır; bu da saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini tespit etmesini imkansızlaştırır.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her blok için filtreler oluşturmayı içerir; bu sayede cüzdanlar, ağ gözlemcilerine özel ilgi alanlarını açmadan ilgili işlemleri tespit edebilir. Lightweight cüzdanlar bu filtreleri indirir ve kullanıcının adresleriyle eşleşme olduğunda yalnızca tam blokları çeker.

## **Utilizing Tor for Anonymity**

Bitcoin'in peer-to-peer bir ağ üzerinde çalıştığı göz önüne alındığında, IP adresinizi gizlemek için Tor kullanılması önerilir; bu, ağ ile etkileşimde gizliliği artırır.

## **Preventing Address Reuse**

Gizliliği korumak için her işlemde yeni bir adres kullanmak hayati önem taşır. Adreslerin yeniden kullanılması, işlemleri aynı varlığa bağlayarak gizliliği zayıflatabilir. Modern cüzdanlar tasarımlarıyla adres tekrarını teşvik etmez.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Bir ödemeyi birkaç işleme bölmek, işlem tutarını gizleyerek gizlilik saldırılarını boşa çıkarabilir.
- **Change avoidance**: Change çıktılarına ihtiyaç duymayan işlemleri tercih etmek, change tespit yöntemlerini bozarak gizliliği artırır.
- **Multiple change outputs**: Change'den kaçınmak mümkün değilse, birden fazla change çıktısı oluşturmak yine de gizliliği iyileştirebilir.

# **Monero: A Beacon of Anonymity**

Monero, dijital işlemlerde mutlak anonimlik ihtiyacını ele alır ve gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas, Ethereum üzerinde işlemleri gerçekleştirmek için gereken hesaplama çabasını ölçer ve fiyatlandırması **gwei** cinsindendir. Örneğin, 2,310,000 gwei (veya 0.00231 ETH) maliyetli bir işlem, bir gas limiti ve bir base fee içerir; madencileri teşvik etmek için bir tip de eklenir. Kullanıcılar, fazla ödeme yapmamayı garanti etmek için bir max fee belirleyebilir; fazla olan iade edilir.

## **Executing Transactions**

Ethereum'daki işlemler, gönderici ve alıcıyı içerir; bunlar kullanıcı veya smart contract adresleri olabilir. İşlemler bir ücret gerektirir ve madencilik ile onaylanmalıdır. Bir işlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretlerdir. Göndericinin adresi, imzadan türetildiği için işlem verisinde ayrı olarak yer almasına gerek yoktur.

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliği önceliklendiren herkes için kripto paralarla etkileşimde bulunmanın temelini oluşturur.

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

DEXes ve AMMs'in (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) pratik istismarını araştırıyorsanız, bakınız:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
