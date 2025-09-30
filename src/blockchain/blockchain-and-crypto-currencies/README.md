# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Akıllı Sözleşmeler (Smart Contracts)**, belirli koşullar yerine geldiğinde bir blok zincirinde çalışan ve anlaşmaların aracı olmadan otomatik olarak yürütülmesini sağlayan programlar olarak tanımlanır.
- **Decentralized Applications (dApps)**, bir kullanıcı dostu ön yüz ve şeffaf, denetlenebilir bir arka uç üzerine inşa edilen uygulamalardır.
- **Tokens & Coins** arasında ayrım şudur: coins dijital para görevi görürken, tokens belirli bağlamlarda değer veya sahipliği temsil eder.
- **Utility Tokens** hizmetlere erişim sağlar, **Security Tokens** ise varlık sahipliğini ifade eder.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Decentralized Finance anlamına gelir.
- **DEX** ve **DAOs**, sırasıyla Decentralized Exchange Platforms ve Decentralized Autonomous Organizations anlamına gelir.

## Consensus Mechanisms

Consensus mekanizmaları, blok zincirinde işlemlerin güvenli ve üzerinde anlaşılmış şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)** işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)** doğrulayıcıların belirli miktarda token tutmasını gerektirir ve PoW'a kıyasla enerji tüketimini azaltır.

## Bitcoin Essentials

### Transactions

Bitcoin işlemleri adresler arasında fon transferini içerir. İşlemler dijital imzalarla doğrulanır, bu da yalnızca private key sahibinin transfer başlatabileceğini garanti eder.

#### Key Components:

- **Multisignature Transactions** bir işlemi yetkilendirmek için birden fazla imza gerektirir.
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (madencilere ödenen ücretler) ve **scripts** (işlem kuralları) bileşenlerinden oluşur.

### Lightning Network

Lightning Network, bir kanal içinde birden fazla işleme izin vererek Bitcoin'in ölçeklenebilirliğini artırmayı hedefler; yalnızca son durum blok zincirine yayınlanır.

## Bitcoin Privacy Concerns

Gizlilik saldırıları, örneğin **Common Input Ownership** ve **UTXO Change Address Detection**, işlem desenlerinden yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Acquiring Bitcoins Anonymously

Yöntemler arasında nakit ticareti, mining ve mixers kullanımı bulunur. **CoinJoin** birden fazla işlemi karıştırarak izlenebilirliği zorlaştırır, **PayJoin** ise CoinJoin işlemlerini normal işlemler gibi göstererek daha yüksek gizlilik sağlar.

# Bitcoin Privacy Saldırıları

# Summary of Bitcoin Privacy Attacks

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusudur. İşte saldırganların Bitcoin gizliliğini tehlikeye atmak için kullandığı birkaç yaygın yöntemin basitleştirilmiş bir özeti.

## **Common Input Ownership Assumption**

Farklı kullanıcıların girdilerinin tek bir işlemde birleştirilmesi genellikle nadirdir çünkü bu ekstra karmaşıklık gerektirir. Bu nedenle, **aynı işlemdeki iki input adresi sıklıkla aynı kişiye ait olarak varsayılır**.

## **UTXO Change Address Detection**

UTXO (Unspent Transaction Output) bir işlemde tamamen harcanmalıdır. Eğer yalnızca bir kısmı başka bir adrese gönderilirse, kalan miktar yeni bir change adresine gider. Gözlemciler bu yeni adresin gönderene ait olduğunu varsayarak gizliliği ihlal edebilir.

### Örnek

Bunu azaltmak için mixing servisleri veya birden fazla adres kullanmak mülkiyeti gizlemeye yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu da adresin sahibine kolayca bağlanmasını sağlar.

## **Transaction Graph Analysis**

İşlemler grafikler olarak görselleştirilebilir ve fon akışına dayalı olarak kullanıcılar arasında potansiyel bağlantıları ortaya çıkarabilir.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu heurisik, birden fazla input ve output içeren işlemleri analiz ederek hangi output'un gönderenin geri dönen change'i olduğunu tahmin etmeye dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions without change are likely between two addresses owned by the same user.
- **Round Numbers:** A round number in a transaction suggests it's a payment, with the non-round output likely being the change.
- **Wallet Fingerprinting:** Different wallets have unique transaction creation patterns, allowing analysts to identify the software used and potentially the change address.
- **Amount & Timing Correlations:** Disclosing transaction times or amounts can make transactions traceable.

## **Traffic Analysis**

By monitoring network traffic, attackers can potentially link transactions or blocks to IP addresses, compromising user privacy. This is especially true if an entity operates many Bitcoin nodes, enhancing their ability to monitor transactions.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquiring bitcoin through cash.
- **Cash Alternatives**: Purchasing gift cards and exchanging them online for bitcoin.
- **Mining**: The most private method to earn bitcoins is through mining, especially when done alone because mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretically, stealing bitcoin could be another method to acquire it anonymously, although it's illegal and not recommended.

## Mixing Services

By using a mixing service, a user can **send bitcoins** and receive **different bitcoins in return**, which makes tracing the original owner difficult. Yet, this requires trust in the service not to keep logs and to actually return the bitcoins. Alternative mixing options include Bitcoin casinos.

## CoinJoin

**CoinJoin** merges multiple transactions from different users into one, complicating the process for anyone trying to match inputs with outputs. Despite its effectiveness, transactions with unique input and output sizes can still potentially be traced.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin kullanımı geleneksel gözetim yöntemlerini önemli ölçüde bozabilir**, bu da işlem gizliliği arayışında umut verici bir gelişme sağlar.

# Kripto Paralarında Gizlilik İçin En İyi Uygulamalar

## **Cüzdan Senkronizasyonu Teknikleri**

Gizlilik ve güvenliği korumak için cüzdanları blockchain ile senkronize etmek önemlidir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek, bir full node azami gizliliği sağlar. Yapılan tüm işlemler yerel olarak depolanır; bu, saldırganların kullanıcının hangi işlem veya adreslerle ilgilendiğini tespit etmesini imkansız hale getirir.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her blok için filtreler oluşturmayı içerir; böylece cüzdanlar belirli ilgi alanlarını ağ gözlemcilerine açmadan ilgili işlemleri belirleyebilir. Hafif cüzdanlar bu filtreleri indirir ve kullanıcının adresleriyle eşleşme olduğunda yalnızca tam blokları çeker.

## **Anonimlik için Tor Kullanımı**

Bitcoin'in peer-to-peer bir ağ üzerinde çalıştığı göz önüne alındığında, IP adresinizi gizlemek ve ağla etkileşim sırasında gizliliği artırmak için Tor kullanılması önerilir.

## **Adres Tekrar Kullanımının Önlenmesi**

Gizliliği korumak için her işlemde yeni bir adres kullanmak hayati önem taşır. Adreslerin tekrar kullanılması, işlemleri aynı varlığa bağlayarak gizliliği tehlikeye atabilir. Modern cüzdanlar tasarımları gereği adres tekrar kullanımını caydırır.

## **İşlem Gizliliği İçin Stratejiler**

- **Multiple transactions**: Bir ödemeyi birkaç işleme bölmek işlem miktarını gizleyerek gizlilik saldırılarını önleyebilir.
- **Change avoidance**: Change çıktısı gerektirmeyen işlemleri tercih etmek, change algılama yöntemlerini bozarak gizliliği artırır.
- **Multiple change outputs**: Change'den kaçınmak mümkün değilse birden fazla change çıktısı oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonimliğin Bir Sembolü**

Monero, dijital işlemlerde mutlak anonimlik ihtiyacına cevap vererek gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas ve İşlemler**

## **Gas'in Anlaşılması**

Gas, Ethereum üzerinde işlemleri yürütmek için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2,310,000 gwei (veya 0.00231 ETH) tutarında bir işlem bir gas limit'i ve bir base fee'yi içerir; ayrıca madencileri teşvik etmek için bir tip bulunur. Kullanıcılar fazla ödememek için bir maksimum ücret belirleyebilir; artan miktar iade edilir.

## **İşlemlerin Gerçekleştirilmesi**

Ethereum'deki işlemler bir gönderici ve bir alıcı içerir; bunlar kullanıcı ya da smart contract adresleri olabilir. İşlemler ücret gerektirir ve madencilikle onaylanmalıdır. Bir işlemdeki temel bilgiler alıcı, gönderici imzası, değer, isteğe bağlı veri, gas limit ve ücretlerdir. Önemle, göndericinin adresi imzadan türetilir; bu nedenle işlem verisinde ayrıca gönderici adresine yer verilmesine gerek yoktur.

Bu uygulama ve mekanizmalar, gizlilik ve güvenliği önceliklendiren herkes için kripto paralarla etkileşime girerken temel teşkil eder.

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

## DeFi/AMM Sömürüsü

DEX'ler ve AMM'lerin (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) pratik sömürü yöntemlerini araştırıyorsanız, bakınız:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
