# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Akıllı Sözleşmeler** belirli koşullar sağlandığında bir blockchain üzerinde çalışan programlar olarak tanımlanır; aracı olmadan anlaşma yürütmelerini otomatikleştirir.
- **Merkeziyetsiz Uygulamalar (dApps)** akıllı sözleşmeler üzerine kuruludur; kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka yüz sunar.
- **Tokenlar & Coinler** arasındaki fark şu şekildedir: coinler dijital para olarak hizmet ederken, tokenlar belirli bağlamlarda değer veya sahipliği temsil eder.
- **Utility Tokenlar** hizmetlere erişim sağlar ve **Security Tokenlar** varlık sahipliğini gösterir.
- **DeFi**, Merkeziyetsiz Finans anlamına gelir; merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAOs** sırasıyla Merkeziyetsiz Borsa Platformları ve Merkeziyetsiz Otonom Organizasyonlar anlamına gelir.

## Konsensüs Mekanizmaları

Konsensüs mekanizmaları, blockchain üzerinde güvenli ve üzerinde uzlaşılmış işlem doğrulamalarını sağlar:

- **Proof of Work (PoW)** işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)** doğrulayıcıların belirli miktarda token tutmasını gerektirir; PoW'ye kıyasla enerji tüketimini azaltır.

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri adresler arasında fon transferini içerir. İşlemler dijital imzalarla doğrulanır; böylece yalnızca özel anahtarın sahibi transferleri başlatabilir.

#### Temel Bileşenler:

- **Multisignature Transactions** bir işlemi yetkilendirmek için birden fazla imza gerektirir.
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (madencilere ödenir) ve **scripts** (işlem kuralları) içerir.

### Lightning Network

Lightning Network, bir kanalda birden fazla işlem yapılmasına izin vererek Bitcoin'in ölçeklenebilirliğini artırmayı amaçlar; yalnızca son durumu blockchain'e yayınlar.

## Bitcoin Gizlilik Endişeleri

Gizlilik saldırıları, **Common Input Ownership** ve **UTXO Change Address Detection** gibi işlem desenlerini istismar eden yöntemleri içerir. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Bitcoinleri Anonim Olarak Elde Etme

Yöntemler arasında nakit ticareti, mining ve mixers kullanımı yer alır. **CoinJoin** birden fazla işlemi karıştırarak izlenebilirliği zorlaştırır; **PayJoin** ise CoinJoin'leri normal işlemler gibi gizleyerek daha yüksek gizlilik sağlar.

# Bitcoin Gizlilik Saldırıları

# Bitcoin Gizlilik Saldırılarının Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusudur. Aşağıda saldırganların Bitcoin gizliliğini tehlikeye atmak için kullandığı bazı yaygın yöntemlerin basitleştirilmiş bir özeti bulunuyor.

## **Ortak Girdi Sahipliği Varsayımı (Common Input Ownership Assumption)**

Genellikle farklı kullanıcıların girdilerinin tek bir işlemde birleştirilmesi nadirdir; bu nedenle **aynı işlemdeki iki girdi adresinin genellikle aynı kişiye ait olduğu varsayılır**.

## **UTXO Değişim Adresi Tespiti**

Bir UTXO (Unspent Transaction Output / Harcanmamış İşlem Çıkışı) bir işlemde tamamen harcanmak zorundadır. Eğer yalnızca bir kısmı başka bir adrese gönderilirse, kalan kısım yeni bir değişim adresine gider. Gözlemciler bu yeni adresin gönderene ait olduğunu varsayarak gizliliği tehlikeye atabilir.

### Örnek

Bunu hafifletmek için mixing servisleri kullanmak veya birden fazla adres kullanmak sahipliği gizlemeye yardımcı olabilir.

## **Sosyal Ağlar & Forumlar Yoluyla Açığa Çıkma**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **İşlem Grafik Analizi**

İşlemler grafikler olarak görselleştirilebilir ve fon akışına göre kullanıcılar arasında potansiyel bağlantıları ortaya çıkarabilir.

## **Gereksiz Girdi Heuristiği (Optimal Change Heuristic)**

Bu heuristik, birden fazla girdi ve çıktı içeren işlemleri analiz ederek hangi çıktının gönderene geri dönen değişim olduğunu tahmin etmeye dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Eğer daha fazla giriş eklemek, change output'un herhangi bir tek girdiden daha büyük olmasına yol açıyorsa, bu heuristic'i karıştırabilir.

## **Forced Address Reuse**

Saldırganlar, alıcının gelecekte bu küçük miktarları diğer inputlarla birleştirip adresleri birbirine bağlayacağını umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilirler.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu gizlilik leak'ini önlemek için daha önce kullanılmış ve boş adreslerde alınan coinleri kullanmaktan kaçınmalıdır.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** change olmadan yapılan işlemler muhtemelen aynı kullanıcıya ait iki adres arasındadır.
- **Round Numbers:** İşlemdeki yuvarlak bir tutar ödemenin işareti olabilir; yuvarlak olmayan çıktı muhtemelen change'dir.
- **Wallet Fingerprinting:** Farklı cüzdanların işlem oluşturma kalıpları benzersizdir; bu, analistlerin kullanılan yazılımı ve potansiyel olarak change adresini tespit etmesine izin verebilir.
- **Amount & Timing Correlations:** İşlem zamanlarının veya tutarlarının ifşa edilmesi işlemleri izlenebilir hale getirebilir.

## **Traffic Analysis**

Ağ trafiğini izleyerek saldırganlar işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Bu, özellikle çok sayıda Bitcoin node'u işleten bir varlık için geçerlidir; bu durumda işlemleri izleme yetenekleri artar.

## Daha Fazla

Kapsamlı bir gizlilik saldırıları ve savunmaları listesi için [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy)'yi ziyaret edin.

# Anonymous Bitcoin Transactions

## Bitcoinleri Anonim Olarak Elde Etme Yöntemleri

- **Cash Transactions**: Nakitle bitcoin edinme.
- **Cash Alternatives**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoine çevirme.
- **Mining**: Bitcoin kazanmanın en özel yöntemi madenciliktir; özellikle solo madencilik yapıldığında gizlilik daha yüksektir çünkü mining pools madencinin IP adresini bilebilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak bitcoin çalmak da anonim edinme yöntemi olabilir, ancak bu yasa dışıdır ve önerilmez.

## Mixing Services

Bir mixing servisi kullanarak kullanıcı, bitcoin gönderebilir ve farklı bitcoinler alabilir; bu, orijinal sahibin izini zorlaştırır. Ancak bu, servise log tutmama ve gerçekten bitcoinleri geri verme konusunda güvenmeyi gerektirir. Alternatif mixing seçenekleri arasında Bitcoin casinolari bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcıların birden fazla işlemini tek bir işlemde birleştirir ve girdiler ile çıktıları eşleştirmeye çalışan herkes için süreci zorlaştırır. Yine de, benzersiz giriş ve çıkış boyutlarına sahip işlemler hâlâ izlenebilir olabilir.

Örnek olarak CoinJoin kullanmış olabilecek işlemler: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en)'i ziyaret edin. Ethereum üzerinde benzer bir servis için [Tornado Cash](https://tornado.cash)'a bakın; bu servis madencilerden gelen fonlarla işlemleri anonimleştirir.

## PayJoin

CoinJoin'in bir varyantı olan **PayJoin** (veya P2EP), iki taraflı (ör. müşteri ve satıcı) yapılan işlemi, CoinJoin'e özgü eşit çıktılar olmadan normal bir işlem gibi gizler. Bu, tespit edilmeyi son derece zorlaştırır ve işlem gözetleme yapanların kullandığı common-input-ownership heuristic'ini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Yukarıdaki gibi işlemler PayJoin olabilir; standart bitcoin işlemlerinden ayırt edilemez halde gizliliği artırır.

**PayJoin'in kullanımı geleneksel gözetim yöntemlerini önemli ölçüde bozabilir**, bu da işlem gizliliği arayışında bunu umut verici bir gelişme haline getirir.

# Kripto Paralarda Gizlilik İçin En İyi Uygulamalar

## **Cüzdan Senkronizasyonu Teknikleri**

Gizlilik ve güvenliği korumak için cüzdanları blockchain ile senkronize etmek çok önemlidir. İki yöntem öne çıkar:

- **Full node**: Blok zincirinin tamamını indirerek, bir full node maksimum gizlilik sağlar. Tüm gerçekleştirilen işlemler yerel olarak saklanır; bu da saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkansız hale getirir.
- **Client-side block filtering**: Bu yöntem, blok zincirindeki her blok için filtreler oluşturmayı içerir; bu sayede cüzdanlar, ağ gözlemcilerine özel ilgileri açığa çıkarmadan ilgili işlemleri belirleyebilir. Hafif cüzdanlar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda tam blokları çeker.

## **Anonimlik için Tor Kullanımı**

Bitcoin'in eşler arası bir ağ üzerinde çalıştığı göz önüne alındığında, IP adresinizi gizlemek ve ağ ile etkileşimde bulunurken gizliliği artırmak için Tor kullanmanız önerilir.

## **Adres Tekrar Kullanımını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak çok önemlidir. Adreslerin tekrar kullanılması, işlemleri aynı varlığa bağlayarak gizliliği zayıflatabilir. Modern cüzdanlar tasarımlarıyla adres tekrar kullanımını caydırır.

## **İşlem Gizliliği İçin Stratejiler**

- **Birden fazla işlem (multiple transactions)**: Ödemeyi birkaç işleme bölmek, işlem tutarını gizleyebilir ve gizlilik saldırılarını engelleyebilir.
- **Kalan çıktı kaçınma (change avoidance)**: Kalan çıktı gerektirmeyen işlemleri tercih etmek, change tespit yöntemlerini bozarak gizliliği artırır.
- **Birden fazla change çıktısı (multiple change outputs)**: Kalan çıktı kaçınılamıyorsa, birden fazla change çıktısı üretmek yine gizliliği iyileştirebilir.

# **Monero: Anonimliğin Bir Simgesi**

Monero dijital işlemlerde mutlak anonimlik ihtiyacına yönelik çözümler sunar ve gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas ve İşlemler**

## **Gas'i Anlamak**

Gas, Ethereum'da işlemleri yürütmek için gereken hesaplama maliyetini ölçer ve fiyatlandırma **gwei** cinsindendir. Örneğin, 2,310,000 gwei (veya 0.00231 ETH) tutan bir işlem bir gas limiti ve bir base fee içerir; madencileri teşvik etmek için bir tip (tip) bulunur. Kullanıcılar aşırı ödeme yapmamalarını sağlamak için bir max fee belirleyebilir; fazla ücret iade edilir.

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemler bir gönderici ve bir alıcı içerir; bunlar kullanıcı veya smart contract adresleri olabilir. İşlemler ücret gerektirir ve madencilikle onaylanmalıdır. Bir işlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretlerdir. Gönderici adresi imzadan türetildiği için, işlem verisinde ayrıca gönderici adresinin bulunmasına gerek yoktur.

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliği önceliklendiren herkes için kripto paralarla etkileşime girmek adına temel teşkil eder.

## Value-Centric Web3 Red Teaming

- Değer taşıyan bileşenlerin envanterini çıkarın (signers, oracles, bridges, automation) — kimlerin fonları taşıyabileceğini ve nasıl yapabileceklerini anlamak için.
- Her bileşeni ilgili MITRE AADAPT taktiklerine eşleyin; yetki yükseltme yollarını ortaya çıkarmak için.
- Etkiyi doğrulamak ve sömürülebilir önkoşulları belgelemek için flash-loan/oracle/credential/cross-chain saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Smart Contract Güvenliği

- Test setlerindeki kör noktaları bulmak için mutation testing:

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

## DeFi/AMM Sömürüsü

DEX'lerin ve AMM'lerin (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) pratik sömürüsünü araştırıyorsanız, bkz:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri cache'leyen ve `supply == 0` olduğunda zehirlenebilen çok varlıklı ağırlıklı havuzlar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
