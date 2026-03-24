# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Akıllı Kontratlar (Smart Contracts)**, belirli koşullar sağlandığında bir blockchain üzerinde yürütülen ve anlaşmaların aracısız şekilde otomatik olarak gerçekleştirilmesini sağlayan programlar olarak tanımlanır.
- **Merkezi Olmayan Uygulamalar (dApps)**, kullanıcı dostu bir ön yüz ve şeffaf, denetlenebilir bir arka uç içeren akıllı kontratlara dayalı uygulamalardır.
- **Tokenlar & Coinler** arasında ayrım vardır: coinler dijital para görevi görürken, tokenlar belirli bağlamlarda değer veya mülkiyeti temsil eder.
- **Utility Tokenlar** hizmetlere erişim sağlar, **Security Tokenlar** ise varlık mülkiyetini simgeler.
- **DeFi** merkeziyetsiz finans anlamına gelir ve merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAOs**, sırasıyla Merkeziyetsiz Exchange Platformları ve Merkeziyetsiz Otonom Organizasyonları ifade eder.

## Konsensüs Mekanizmaları

Konsensüs mekanizmaları, blokzincir üzerinde işlemlerin güvenli ve mutabık şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)**, doğrulayıcıların belirli miktarda token tutmasını gerektirir ve PoW'ye kıyasla enerji tüketimini azaltır.

## Bitcoin Temelleri

### İşlemler

Bitcoin işlemleri, fonların adresler arasında transfer edilmesini içerir. İşlemler dijital imzalarla doğrulanır; yalnızca özel anahtar sahibi transfer başlatabilir.

#### Temel Bileşenler:

- **Multisignature Transactions** bir işlemi yetkilendirmek için birden fazla imza gerektirir.
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (madencilere ödenen ücretler) ve **scripts** (işlem kuralları) bileşenlerinden oluşur.

### Lightning Network

Bitcoin'in ölçeklenebilirliğini artırmayı amaçlar; bir kanal içinde birden fazla işleme izin vererek yalnızca son durumun blokzincire gönderilmesini sağlar.

## Bitcoin Gizlilik Endişeleri

Gizlilik saldırıları, örneğin **Common Input Ownership** ve **UTXO Change Address Detection**, işlem desenlerinden yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonimliği artırır.

## Bitcoin'leri Anonim Olarak Elde Etme

Yöntemler nakit takasları, madencilik ve mixer kullanımı gibi seçenekleri içerir. **CoinJoin** birden fazla işlemi karıştırarak izlenebilirliği zorlaştırır; **PayJoin** ise CoinJoin'leri normal işlemler gibi gizleyerek daha yüksek gizlilik sağlar.

# Bitcoin Gizlilik Saldırıları

# Bitcoin Gizlilik Saldırıları Özeti

Bitcoin dünyasında işlemlerin gizliliği ve kullanıcıların anonimliği sıkça endişe konusu olur. İşte saldırganların Bitcoin gizliliğini zayıflatmak için kullandığı birkaç yaygın yöntemin basitleştirilmiş bir özeti.

## **Ortak Girdi Sahipliği Varsayımı (Common Input Ownership Assumption)**

Farklı kullanıcıların girdilerinin tek bir işlemde birleştirilmesi genellikle nadirdir; bu nedenle **aynı işlemdeki iki giriş adresi genellikle aynı kişiye ait olarak varsayılır**.

## **UTXO Değişim Adresi Tespiti (UTXO Change Address Detection)**

UTXO, yani **Harcanmamış İşlem Çıkışı**, bir işlemde tamamen harcanmak zorundadır. Eğer yalnızca bir kısmı başka bir adrese gönderilirse, kalan kısım yeni bir değişim adresine gider. Gözlemciler bu yeni adresin gönderene ait olduğunu varsayabilir ve böylece gizlilik zedelenir.

### Örnek

Bunu hafifletmek için mixing servisleri kullanmak veya birden fazla adres kullanmak mülkiyeti gizlemeye yardımcı olabilir.

## **Sosyal Ağlar & Forumlar Üzerinden Açığa Çıkma**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi paylaşır; bu da adresi sahibine bağlamayı **kolaylaştırır**.

## **İşlem Grafiği Analizi**

İşlemler graf olarak görselleştirilebilir ve fon akışına dayalı olarak kullanıcılar arasında potansiyel bağlantıları ortaya çıkarabilir.

## **Gereksiz Girdi Heuristiği (Optimal Change Heuristic)**

Bu heuristik, birden fazla girdi ve çıktı içeren işlemleri analiz ederek hangi çıktının gönderene geri dönen değişim olduğunu tahmin etmeye dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Eğer daha fazla input eklemek, change output'un herhangi bir tek input'tan daha büyük olmasına neden oluyorsa, heuristiği yanıltabilir.

## **Forced Address Reuse**

Saldırganlar, alıcının bunları gelecekteki işlemlerde diğer girdilerle birleştirip adresleri birbirine bağlamasını umarak, daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Correct Wallet Behavior

Cüzdanlar, hali hazırda kullanılmış ve boş adreslerde alınmış coinleri kullanmaktan kaçınmalı, böylece bu privacy leak önlenir.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Change olmayan işlemler muhtemelen aynı kullanıcıya ait iki adres arasındadır.
- **Round Numbers:** İşlemdeki yuvarlak bir tutar bunun bir ödeme olduğunu düşündürür; yuvarlak olmayan çıktı muhtemelen değişimdir.
- **Wallet Fingerprinting:** Farklı cüzdanların işlem oluşturma kalıpları benzersizdir; bu, analistlerin kullanılan yazılımı ve potansiyel olarak change adresini tespit etmesine olanak tanır.
- **Amount & Timing Correlations:** İşlem zamanlarının veya tutarlarının ifşa edilmesi işlemlerin izlenebilir hale gelmesine yol açabilir.

## **Traffic Analysis**

Ağ trafiğini izleyerek, saldırganlar işlemleri veya blokları IP adreslerine bağlayabilir ve kullanıcı gizliliğini tehlikeye atabilir. Bu özellikle birinin birçok Bitcoin node'u işletmesi durumunda geçerlidir; bu, işlemleri izleme kabiliyetlerini artırır.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Nakit ile bitcoin edinme.
- **Cash Alternatives**: Hediye kartları satın alıp bunları çevrimiçi olarak bitcoin'e çevirmek.
- **Mining**: Bitcoin kazanmanın en mahrem yöntemi madenciliktir; özellikle yalnız yapıldığında daha gizlidir çünkü mining pool'ları madencinin IP adresini bilebilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak bitcoin çalmak anonim edinme yöntemlerinden biri olabilir, ancak bu yasa dışıdır ve önerilmez.

## Mixing Services

Bir mixing servisi kullanarak, bir kullanıcı **send bitcoins** yapabilir ve karşılığında **different bitcoins in return** alabilir; bu, orijinal sahibin izlenmesini zorlaştırır. Ancak bu, servisin log tutmaması ve gerçekten bitcoinleri geri vermesi konusunda güven gerektirir. Alternatif mixing seçenekleri arasında Bitcoin kumarhaneleri bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcıların birden fazla işlemini tek bir işlemde birleştirir ve girdilerle çıktıları eşleştirmeye çalışanlar için süreci karmaşıklaştırır. Etkili olmasına rağmen, benzersiz girdi ve çıktı boyutlarına sahip işlemler hala izlenebilir.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), iki taraflı (ör. müşteri ve satıcı) işlemi CoinJoin'e özgü eşit çıktılara sahip ayırt edici bir işlem olmaksızın sıradan bir işlem gibi gizler. Bu, tespit edilmesini son derece zorlaştırır ve işlem gözetleme kuruluşlarının kullandığı common-input-ownership heuristiğini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin'in kullanımı, işlem gizliliği arayışında geleneksel gözetim yöntemlerini önemli ölçüde aksatabilir**, bu nedenle işlem gizliliği açısından umut verici bir gelişmedir.

# Kripto Para Birimlerinde Gizlilik İçin En İyi Uygulamalar

## **Wallet Synchronization Techniques**

Gizliliği ve güvenliği korumak için cüzdanları blockchain ile senkronize etmek kritik önemdedir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek, bir full node maksimum gizliliği sağlar. Daha önce yapılmış tüm işlemler yerel olarak depolanır; bu da saldırganların kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkânsız kılar.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her blok için filtreler oluşturmayı içerir; böylece cüzdanlar, ağ gözlemcilerine belirli ilgi alanlarını açığa çıkarmadan ilgili işlemleri tespit edebilir. Hafif cüzdanlar bu filtreleri indirir ve kullanıcının adresleriyle eşleşme bulunduğunda yalnızca tam blokları çeker.

## **Utilizing Tor for Anonymity**

Bitcoin'ın eşler arası bir ağ üzerinde çalıştığı göz önüne alındığında, IP adresinizi gizlemek ve ağla etkileşimde gizliliği artırmak için Tor kullanılması önerilir.

## **Preventing Address Reuse**

Gizliliği korumak için her işlemde yeni bir adres kullanmak hayati önemdedir. Adreslerin yeniden kullanılması, işlemleri aynı varlığa bağlayarak gizliliği tehlikeye atabilir. Modern cüzdanlar tasarımlarıyla adres tekrar kullanımını caydırır.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Ödemeyi birden çok işleme bölmek, işlem tutarını gizleyebilir ve gizlilik saldırılarını engelleyebilir.
- **Change avoidance**: Para üstü çıktısı gerektirmeyen işlemleri tercih etmek, change detection yöntemlerini bozarak gizliliği artırır.
- **Multiple change outputs**: Para üstü çıktısından kaçınmak mümkün değilse, birden fazla para üstü çıktısı üretmek yine de gizliliği artırabilir.

# **Monero: A Beacon of Anonymity**

Monero, dijital işlemlerde mutlak anonimlik ihtiyacını ele alır ve gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas, Ethereum üzerinde işlemleri yürütmek için gereken hesaplama çabasını ölçer ve fiyatlandırma birimi olarak **gwei** kullanılır. Örneğin, 2,310,000 gwei (veya 0.00231 ETH) tutarındaki bir işlem gas limiti ve bir taban ücret (base fee) içerir; ayrıca madencileri teşvik etmek için bir bahşiş (tip) bulunur. Kullanıcılar, fazla ödeme yapmamalarını sağlamak için bir max fee belirleyebilir; fazla ödenen kısım iade edilir.

## **Executing Transactions**

Ethereum işlemleri, gönderici ve alıcı içerir; bunlar kullanıcı veya akıllı sözleşme (smart contract) adresleri olabilir. İşlemler bir ücret gerektirir ve mined edilmelidir. Bir işlemdeki temel bilgiler alıcı, göndericinin imzası, değer, isteğe bağlı veri, gas limiti ve ücretlerdir. Dikkate değerdir ki göndericinin adresi imzadan türetildiği için işlem verisinde açıkça bulunmasına gerek yoktur.

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliği önceliklendiren herkes için kripto para birimleriyle etkileşime girerken temel teşkil eder.

## Value-Centric Web3 Red Teaming

- Değer taşıyan bileşenleri envanterleyin (signers, oracles, bridges, automation) — fonları kimlerin ve nasıl taşıyabileceğini anlamak için.
- Her bileşeni, ayrıcalık yükseltme yollarını ortaya çıkarmak için ilgili MITRE AADAPT taktiklerine eşleyin.
- Etkisini doğrulamak ve sömürülebilir önkoşulları belgelemek için flash-loan/oracle/credential/cross-chain saldırı zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI'larının tedarik zinciri manipülasyonu, imzalamadan hemen önce EIP-712 yüklerini değiştirerek delegatecall tabanlı proxy ele geçirmeleri için geçerli imzalar toplayabilir (ör. Safe masterCopy'in slot-0 üzerine yazılması).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Yaygın smart-account hata modları arasında `EntryPoint` erişim kontrolünün atlanması, imzasız gas alanları, durumlu doğrulama, ERC-1271 replay ve revert-after-validation yoluyla fee-drain yer alır.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suite'lerinde kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Sömürü

DEX'lerin ve AMM'lerin (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) pratik sömürü yöntemlerini araştırıyorsanız, bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Sanal bakiyeleri cacheleyen ve `supply == 0` olduğunda zehirlenebilen çok varlıklı ağırlıklı havuzlar için inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
