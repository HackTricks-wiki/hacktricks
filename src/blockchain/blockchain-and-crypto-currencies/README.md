# Blockchain ve Kripto Paralar

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts** belirli koşullar gerçekleştiğinde bir blockchain üzerinde çalışan programlar olarak tanımlanır; aracılara ihtiyaç duymadan anlaşmaların yürütülmesini otomatikleştirir.
- **Decentralized Applications (dApps)**, akıllı sözleşmeler üzerine kurulur; kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka yüz barındırır.
- **Tokens & Coins** arasında ayrım vardır: coins dijital para olarak hizmet ederken, tokens belirli bağlamlarda değer veya mülkiyeti temsil eder.
- **Utility Tokens** servislere erişim sağlar; **Security Tokens** ise varlık sahipliğini gösterir.
- **DeFi** Merkeziyetsiz Finans anlamına gelir; merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAOs** sırasıyla Merkeziyetsiz Borsa Platformları ve Merkeziyetsiz Otonom Organizasyonlar anlamına gelir.

## Konsensüs Mekanizmaları

Konsensüs mekanizmaları, blockchain üzerinde işlemlerin güvenli ve ortak şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)** işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)** doğrulayıcıların belirli miktarda token tutmasını gerektirir; PoW'e kıyasla enerji tüketimini azaltır.

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri, adresler arasında fon transferini içerir. İşlemler dijital imzalarla doğrulanır; bu sayede sadece özel anahtar sahibi transfer başlatabilir.

#### Temel Bileşenler:

- **Multisignature Transactions** bir işlemi yetkilendirmek için birden fazla imza gerektirir.
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (madencilere ödenir) ve **scripts** (işlem kuralları) içerir.

### Lightning Network

Bir kanal içinde birden çok işlem gerçekleştirilmesine izin vererek Bitcoin'in ölçeklenebilirliğini artırmayı; yalnızca nihai durumu blockchain'e yayınlamayı amaçlar.

## Bitcoin Gizlilik Endişeleri

Gizlilik saldırıları, **Common Input Ownership** ve **UTXO Change Address Detection** gibi, işlem desenlerini sömürür. **Mixers** ve **CoinJoin** gibi stratejiler kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Bitcoinleri Anonim Olarak Elde Etme

Yöntemler nakit takas, madencilik ve mixers kullanmayı içerir. **CoinJoin** izlenebilirliği zorlaştırmak için birden çok işlemi karıştırır; **PayJoin** ise CoinJoin'leri normal işlemler gibi gizleyerek daha yüksek gizlilik sağlar.

# Bitcoin Gizlilik Saldırıları

# Bitcoin Gizlilik Saldırıları Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusudur. İşte saldırganların Bitcoin gizliliğini zedeleyebileceği birkaç yaygın yöntemin basitleştirilmiş bir özeti.

## **Common Input Ownership Assumption**

Farklı kullanıcıların input'larının tek bir işlemde birleştirilmesi genellikle karmaşıklık nedeniyle nadirdir. Bu yüzden aynı işlemdeki **iki input adres genellikle aynı kişiye ait olduğu varsayılır**.

## **UTXO Change Address Detection**

UTXO, yani **Unspent Transaction Output**, bir işlemde tamamen harcanmalıdır. Sadece bir kısmı başka bir adrese gönderilirse, kalan kısım yeni bir change address'e gider. Gözlemciler bu yeni adresin gönderene ait olduğunu varsayabilir ve bu gizliliği tehlikeye atar.

### Örnek

Bunu hafifletmek için mixing servisleri veya birden fazla adres kullanmak sahipliği gizlemeye yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu da adres ile sahibini eşleştirmeyi kolaylaştırır.

## **Transaction Graph Analysis**

İşlemler graf olarak görselleştirilebilir; fon akışına göre kullanıcılar arasında potansiyel bağlantıları ortaya çıkarır.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu heuristik, birden çok input ve output içeren işlemlerin analizine dayanır; hangi output'un gönderene dönen change olduğunu tahmin etmeye çalışır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Zorunlu Adres Yeniden Kullanımı**

Saldırganlar, alıcının gelecekteki işlemlerde bunları diğer girdilerle birleştireceğini umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir ve böylece adresleri birbirine bağlayabilirler.

### Doğru Cüzdan Davranışı

Cüzdanlar, bu privacy leak'i önlemek için zaten kullanılmış ve boş olan adreslerde alınan coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analizi Teknikleri**

- **Exact Payment Amounts:** change olmayan işlemler muhtemelen aynı kullanıcıya ait iki adres arasındadır.
- **Round Numbers:** İşlemdeki yuvarlak bir sayı ödemenin işareti olabilir; yuvarlak olmayan çıktı muhtemelen change'dir.
- **Wallet Fingerprinting:** Farklı cüzdanlar kendilerine özgü işlem oluşturma desenlerine sahiptir; bu, analistlerin kullanılan yazılımı ve potansiyel olarak change adresini tespit etmesine izin verir.
- **Amount & Timing Correlations:** İşlem zamanlarının veya tutarlarının açıklanması işlemleri izlenebilir hale getirebilir.

## **Trafik Analizi**

Ağ trafiğini izleyerek saldırganlar potansiyel olarak işlemleri veya blokları IP adresleriyle ilişkilendirebilir ve böylece kullanıcı gizliliğini tehlikeye atabilir. Bu, bir kuruluşun birçok Bitcoin node'u işletmesi durumunda özellikle doğrudur; bu da işlemleri izleme yeteneklerini artırır.

## More

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonim Bitcoin İşlemleri

## Bitcoinleri Anonim Olarak Elde Etme Yolları

- **Cash Transactions**: Nakit ile bitcoin edinme.
- **Cash Alternatives**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin'e çevirmek.
- **Mining**: Bitcoin kazanmanın en özel yöntemi madenciliktir; özellikle tek başına yapıldığında, çünkü mining pools madencinin IP adresini bilebilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak, bitcoin çalmak anonim olarak edinmenin bir yolu olabilir, ancak bu yasadışıdır ve tavsiye edilmez.

## Karıştırma Servisleri

Bir mixing service kullanarak kullanıcı, bitcoin gönderebilir ve karşılığında farklı bitcoinler alabilir; bu da orijinal sahibin izini sürmeyi zorlaştırır. Yine de bu, servisin log tutmaması ve gerçekten bitcoinleri geri göndereceğine güvenmeyi gerektirir. Alternatif mixing seçenekleri arasında Bitcoin casinoları bulunur.

## CoinJoin

CoinJoin, farklı kullanıcıların birden fazla işlemini tek bir işlemde birleştirir ve girdileri çıktılarla eşleştirmeye çalışanlar için süreci karmaşıklaştırır. Etkili olmasına rağmen, benzersiz input ve output boyutlarına sahip işlemler hâlâ izlenebilir olabilir.

CoinJoin kullanmış olabilecek örnek işlemler arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` yer alır.

Daha fazla bilgi için bakınız [CoinJoin](https://coinjoin.io/en). Ethereum'da benzer bir servis için [Tornado Cash](https://tornado.cash)'a göz atın; Tornado Cash işlemleri madencilerden gelen fonlarla anonimleştirir.

## PayJoin

CoinJoin'in bir çeşidi olan PayJoin (veya P2EP), iki taraf (ör. müşteri ve satıcı) arasındaki işlemi CoinJoin'e özgü eşit çıktılar gibi belirgin özellikler olmadan normal bir işlem gibi gizler. Bu, tespit etmeyi son derece zorlaştırır ve transaction surveillance kuruluşlarının kullandığı common-input-ownership heuristic'i geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin'in kullanımı geleneksel gözetim yöntemlerini önemli ölçüde bozabilir**, bu da işlemsel gizliliğin sağlanmasında ümit verici bir gelişmedir.

# Kripto Parada Gizlilik İçin En İyi Uygulamalar

## **Cüzdan Senkronizasyonu Teknikleri**

Gizliliği ve güvenliği korumak için cüzdanların blockchain ile senkronize edilmesi kritik öneme sahiptir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek, bir full node maksimum gizliliği sağlar. Yapılmış tüm işlemler yerel olarak saklanır; bu, saldırganların kullanıcının hangi işlemler veya adreslerle ilgilendiğini tespit etmesini imkânsız hâle getirir.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her blok için filtreler oluşturmayı içerir; böylece cüzdanlar, ağ gözlemcilerine özel ilgi alanlarını açmadan ilgili işlemleri tespit edebilir. Lightweight cüzdanlar bu filtreleri indirir ve kullanıcının adresleri ile eşleşme bulunduğunda yalnızca o blokların tam hallerini çeker.

## **Anonimlik için Tor Kullanımı**

Bitcoin'in peer-to-peer bir ağ üzerinde çalıştığı göz önüne alındığında, IP adresinizi gizlemek ve ağla etkileşimde bulunurken gizliliği artırmak için Tor kullanılması önerilir.

## **Adres Tekrar Kullanımını Önleme**

Gizliliği korumak için her işlemde yeni bir adres kullanmak hayati önemdedir. Adresleri yeniden kullanmak, işlemleri aynı varlığa bağlayarak gizliliği tehlikeye atabilir. Modern cüzdanlar tasarımlarıyla adres tekrar kullanımını caydırır.

## **İşlem Gizliliği İçin Stratejiler**

- **Multiple transactions**: Bir ödemeyi birkaç işleme bölmek işlem tutarını gizleyebilir ve gizlilik saldırılarını güçleştirir.
- **Change avoidance**: Para üstü (change) çıktısı gerektirmeyen işlemleri tercih etmek, change tespiti yöntemlerini bozarak gizliliği artırır.
- **Multiple change outputs**: Change'den kaçınmak mümkün değilse, birden fazla change çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimliğin Simgesi**

Monero, dijital işlemlerde mutlak anonimlik ihtiyacına yanıt vererek gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas ve İşlemler**

## **Gas'ı Anlamak**

Gas, Ethereum'da işlemleri yürütmek için gereken hesaplama çabasını ölçer ve fiyatlandırma **gwei** cinsindendir. Örneğin, 2,310,000 gwei (veya 0.00231 ETH) tutarındaki bir işlem, bir gas limiti ve bir base fee içerir; madencileri teşvik etmek için bir tip (bahşiş) eklenebilir. Kullanıcılar fazla ödeme yapmamak için bir max fee belirleyebilir; fazla ücret iade edilir.

## **İşlemleri Gerçekleştirme**

Ethereum'daki işlemler bir gönderici ve bir alıcı içerir; bunlar kullanıcı veya smart contract adresleri olabilir. İşlemler bir ücret gerektirir ve mined edilmelidir. Bir işlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı data, gas limiti ve ücretleri içerir. Önemli olarak, göndericinin adresi imzadan türetildiği için işlem verisinde ayrı bir gönderici adresi bulunmasına gerek yoktur.

Bu uygulamalar ve mekanizmalar, gizliliğe ve güvenliğe öncelik veren herkes için kripto paralarla etkileşime girerken temel teşkil eder.

## Value-Centric Web3 Red Teaming

- Değer taşıyan bileşenlerin (signers, oracles, bridges, automation) envanterini çıkarın; kimlerin fonları hareket ettirebileceğini ve nasıl yapacağını anlayın.
- Her bileşeni ilgili MITRE AADAPT taktiklerine eşleyin ve ayrıcalık yükseltme yollarını açığa çıkarın.
- Etkiyi doğrulamak ve istismar edilebilir ön koşulları belgelemek için flash-loan/oracle/credential/cross-chain saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 İmzalama İş Akışı Kompromisi

- Supply-chain tampering of wallet UIs, imzalamadan hemen önce EIP-712 payload'larını değiştirerek delegatecall tabanlı proxy takeoveryer için geçerli imzaları toplamak amacıyla kullanılabilir (ör. slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Güvenliği

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

Eğer DEX'lerin ve AMM'lerin pratik istismarını araştırıyorsanız (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), bakınız:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri cache'leyen ve `supply == 0` olduğunda zehirlenebilen çok varlıklı ağırlıklı havuzlar için inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
