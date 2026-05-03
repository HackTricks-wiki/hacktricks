# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** blockchain üzerinde belirli koşullar karşılandığında çalışan programlar olarak tanımlanır ve aracı olmadan anlaşma yürütmelerini otomatikleştirir.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir front-end ve şeffaf, denetlenebilir bir back-end sunarak smart contracts üzerine inşa edilir.
- **Tokens & Coins** arasında ayrım yapar; coins dijital para olarak hizmet ederken, tokens belirli bağlamlarda değer veya sahipliği temsil eder.
- **Utility Tokens** hizmetlere erişim sağlar ve **Security Tokens** varlık sahipliğini ifade eder.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Decentralized Finance anlamına gelir.
- **DEX** ve **DAOs**, sırasıyla Decentralized Exchange Platforms ve Decentralized Autonomous Organizations anlamına gelir.

## Consensus Mechanisms

Consensus mechanisms blockchain üzerinde güvenli ve üzerinde uzlaşılmış işlem doğrulamaları sağlar:

- **Proof of Work (PoW)** işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)** doğrulayıcıların belirli bir miktar tokens tutmasını gerektirir ve PoW'ye kıyasla enerji tüketimini azaltır.

## Bitcoin Essentials

### Transactions

Bitcoin transactions, adresler arasında fon transferini içerir. Transactions, dijital imzalar aracılığıyla doğrulanır ve yalnızca private key sahibinin transfer başlatabilmesini sağlar.

#### Key Components:

- **Multisignature Transactions** bir transaction'ı yetkilendirmek için birden fazla imza gerektirir.
- Transactions, **inputs** (fon kaynağı), **outputs** (varış noktası), **fees** (miner'lara ödenen) ve **scripts** (transaction kuralları) bileşenlerinden oluşur.

### Lightning Network

Channel içinde birden fazla transaction'a izin vererek Bitcoin'in scalability'sini artırmayı amaçlar ve yalnızca son durumu blockchain'e yayınlar.

## Bitcoin Privacy Concerns

**Common Input Ownership** ve **UTXO Change Address Detection** gibi privacy saldırıları, transaction kalıplarını istismar eder. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki transaction bağlantılarını gizleyerek anonimliği artırır.

## Acquiring Bitcoins Anonymously

Yöntemler arasında nakit takaslar, mining ve mixers kullanımı bulunur. **CoinJoin** birden fazla transaction'ı karıştırarak izlenebilirliği zorlaştırır; **PayJoin** ise artırılmış privacy için CoinJoin'leri normal transaction'lar gibi gizler.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin dünyasında, transaction'ların privacy'si ve kullanıcıların anonimliği sıklıkla endişe konusudur. İşte saldırganların Bitcoin privacy'sini nasıl tehlikeye atabileceğine dair birkaç yaygın yöntemin basitleştirilmiş bir özeti.

## **Common Input Ownership Assumption**

Genellikle farklı kullanıcılardan gelen inputs'ların tek bir transaction içinde birleştirilmesi, içerdiği karmaşıklık nedeniyle nadirdir. Bu nedenle, **aynı transaction içindeki iki input address'inin genellikle aynı sahibine ait olduğu varsayılır**.

## **UTXO Change Address Detection**

Bir UTXO veya **Unspent Transaction Output**, bir transaction içinde tamamen harcanmalıdır. Eğer bunun yalnızca bir kısmı başka bir address'e gönderilirse, kalan miktar yeni bir change address'e gider. Gözlemciler bu yeni address'in gönderene ait olduğunu varsayabilir ve privacy'yi tehlikeye atabilir.

### Example

Bunu azaltmak için, mixing services kullanmak veya birden fazla address kullanmak sahipliği gizlemeye yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin address'lerini çevrimiçi paylaşır; bu da **address'i sahibine bağlamayı kolay** hale getirir.

## **Transaction Graph Analysis**

Transactions graph'lar olarak görselleştirilebilir ve fon akışına göre kullanıcılar arasındaki olası bağlantıları ortaya çıkarabilir.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu heuristic, gönderene dönen change'i hangi output'un temsil ettiğini tahmin etmek için birden fazla input ve output içeren transactions'ları analiz etmeye dayanır.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Daha fazla input eklemek change output’u herhangi bir tek input’tan daha büyük hale getirirse, heuristic’i karıştırabilir.

## **Forced Address Reuse**

Attacker’lar, daha önce kullanılmış address’lere küçük miktarlar gönderebilir; alıcının bunları gelecekteki transactions içinde diğer input’larla birleştirerek address’leri birbirine bağlamasını umarlar.

### Correct Wallet Behavior

Wallet’lar, already used, empty address’lerde alınan coin’leri kullanmaktan kaçınmalıdır; böylece bu privacy leak önlenir.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Change olmayan transactions büyük olasılıkla aynı user’a ait iki address arasındadır.
- **Round Numbers:** Transaction içindeki yuvarlak bir sayı bunun bir payment olduğunu, yuvarlak olmayan output’un ise muhtemelen change olduğunu gösterir.
- **Wallet Fingerprinting:** Farklı wallet’ların kendine özgü transaction oluşturma pattern’leri vardır; bu da analistlerin kullanılan software’i ve potansiyel olarak change address’i tespit etmesini sağlar.
- **Amount & Timing Correlations:** Transaction zamanlarını veya miktarlarını ifşa etmek, transactions’ın trace edilebilir olmasını sağlayabilir.

## **Traffic Analysis**

Network traffic’i izleyerek attacker’lar transactions veya blocks’u IP address’lerle ilişkilendirebilir ve user privacy’yi tehlikeye atabilir. Bu özellikle bir entity çok sayıda Bitcoin node’u işletiyorsa geçerlidir; bu da transactions’ı izleme yeteneğini artırır.

## More

Privacy saldırıları ve defense’ların kapsamlı bir listesi için [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) adresine bakın.

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: bitcoin’i cash ile edinmek.
- **Cash Alternatives**: Gift card’ları satın alıp bunları online olarak bitcoin ile değiştirmek.
- **Mining**: Bitcoin kazanmanın en private yöntemi mining’dir, özellikle solo yapıldığında çünkü mining pool’lar miner’ın IP address’ini bilebilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak, bitcoin çalmak onu anonymously elde etmenin başka bir yöntemi olabilir; ancak bu yasadışıdır ve önerilmez.

## Mixing Services

Bir mixing service kullanarak, bir user **bitcoins** gönderebilir ve karşılığında **different bitcoins** alabilir; bu da orijinal owner’ı izlemeyi zorlaştırır. Yine de bunun için service’in log tutmamasına ve bitcoin’leri gerçekten geri göndermesine güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casinos bulunur.

## CoinJoin

**CoinJoin**, farklı user’lardan gelen birden fazla transaction’ı tek bir transaction’da birleştirerek input’ları output’larla eşleştirmeye çalışan herkes için süreci karmaşık hale getirir. Etkisine rağmen, benzersiz input ve output boyutlarına sahip transactions yine de izlenebilir olabilir.

CoinJoin kullanmış olabilecek örnek transactions arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` bulunur.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) adresine bakın. Ethereum’da benzer bir service için, miner’lardan gelen funds ile transactions’ı anonymize eden [Tornado Cash](https://tornado.cash) adresini inceleyin.

## PayJoin

CoinJoin’in bir varyantı olan **PayJoin** (veya P2EP), transaction’ı iki taraf arasında (ör. bir customer ve bir merchant) sıradan bir transaction gibi gizler; CoinJoin’e özgü eşit output’lar olmadan. Bu, onu tespit etmeyi son derece zor hale getirir ve transaction surveillance entity’lerinin kullandığı common-input-ownership heuristic’ini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin kullanımının geleneksel gözetim yöntemlerini önemli ölçüde bozabilmesi**, onu işlem gizliliği arayışında umut verici bir gelişme haline getirir.

# Kripto Paralarda Gizlilik için En İyi Uygulamalar

## **Wallet Senkronizasyon Teknikleri**

Gizlilik ve güvenliği korumak için, wallet’ları blockchain ile senkronize etmek kritik önemdedir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain’i indirerek, full node maksimum gizlilik sağlar. Yapılan tüm işlemler yerel olarak saklanır; bu da saldırganların kullanıcının hangi transaction’lar veya adreslerle ilgilendiğini belirlemesini imkansız hale getirir.
- **Client-side block filtering**: Bu yöntem, blockchain’deki her block için filtreler oluşturmayı içerir ve wallet’ların ağ gözlemcilerine belirli ilgilerini açığa çıkarmadan ilgili transaction’ları belirlemesine olanak tanır. Hafif wallet’lar bu filtreleri indirir ve yalnızca kullanıcının adresleriyle bir eşleşme bulunduğunda tam block’ları çeker.

## **Anonimlik için Tor Kullanımı**

Bitcoin peer-to-peer bir ağ üzerinde çalıştığından, ağ ile etkileşimde IP adresinizi gizlemek ve gizliliği artırmak için Tor kullanılması önerilir.

## **Adres Yeniden Kullanımını Önleme**

Gizliliği korumak için, her transaction için yeni bir adres kullanmak hayati önemdedir. Adresleri yeniden kullanmak, transaction’ları aynı varlıkla ilişkilendirerek gizliliği tehlikeye atabilir. Modern wallet’lar, tasarımları sayesinde adres yeniden kullanımını caydırır.

## **Transaction Gizliliği için Stratejiler**

- **Multiple transactions**: Bir ödemeyi birkaç transaction’a bölmek, transaction miktarını gizleyebilir ve gizlilik saldırılarını engelleyebilir.
- **Change avoidance**: Change output gerektirmeyen transaction’ları seçmek, change detection yöntemlerini bozarak gizliliği artırır.
- **Multiple change outputs**: Change’den kaçınmak mümkün değilse, birden fazla change output oluşturmak yine de gizliliği iyileştirebilir.

# **Monero: Anonimliğin Bir Işığı**

Monero, dijital transaction’larda mutlak anonimlik ihtiyacını ele alır ve gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas ve Transaction’lar**

## **Gas’i Anlamak**

Gas, Ethereum üzerinde operations çalıştırmak için gereken hesaplama çabasını ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2,310,000 gwei (veya 0.00231 ETH) maliyetli bir transaction, bir gas limit ve bir base fee ile birlikte, miner’ları teşvik etmek için bir tip içerir. Kullanıcılar fazla ödeme yapmamak için bir max fee belirleyebilir; fazlası geri ödenir.

## **Transaction’ları Yürütmek**

Ethereum’daki transaction’lar bir gönderici ve bir alıcı içerir; bunlar user veya smart contract adresleri olabilir. Bir ücret gerektirirler ve mined edilmeleri gerekir. Bir transaction’daki temel bilgiler; alıcı, göndericinin signature’ı, value, isteğe bağlı data, gas limit ve fee’leri içerir. Özellikle, göndericinin adresi signature’dan çıkarılır; bu nedenle transaction verisinde yer almasına gerek yoktur.

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliği önceliklendirirken kripto paralarla etkileşime girmek isteyen herkes için temel niteliğindedir.

## Değer Odaklı Web3 Red Teaming

- Kimlerin funds taşıyabildiğini ve bunu nasıl yaptığını anlamak için value taşıyan bileşenleri envanterleyin (signer’lar, oracle’lar, bridge’ler, automation).
- Yetki yükseltme yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT tactic’lerine eşleyin.
- Etkiyi doğrulamak ve istismar edilebilir ön koşulları belgelemek için flash-loan/oracle/credential/cross-chain attack zincirlerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI’larının supply-chain ile manipülasyonu, EIP-712 payload’larını imzalamadan hemen önce değiştirebilir ve delegatecall tabanlı proxy takeover’ları için geçerli signature’lar toplayabilir (ör. Safe masterCopy üzerinde slot-0 overwrite).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Yaygın smart-account failure mode’ları arasında `EntryPoint` access control’ünü atlatma, imzasız gas field’ları, stateful validation, ERC-1271 replay ve revert-after-validation ile fee-drain bulunur.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suite’lerdeki kör noktaları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Bir prover, bir iddiayı doğrulamak için bir **zkVM** veya uygulamaya özel bir proof circuit kullandığında, verifier yalnızca **guest programın yazıldığı gibi çalıştığını** öğrenir. Eğer guest içinde **unsafe deserialization**, **undefined behavior** veya **eksik semantic constraint’ler** varsa, kötü niyetli bir prover **public metric’ler veya iddia edilen invariant yanlış** olmasına rağmen doğrulanan bir proof üretebilir.

### Proof guest’leri içinde unsafe deserialization

- Private witness/circuit byte’larını, proof tarafından gizlenmiş olsalar bile **güvenilmeyen attacker input’u** olarak ele alın.
- Byte’lar zaten dışarıdan doğrulanmadıysa, bunları `rkyv::access_unchecked` gibi kontrolsüz helper’larla deserialize etmeyin.
- Güvenilmeyen serialized data’dan yüklenen enum discriminant’ları, relative pointer’lar, length’ler ve index’ler, control flow veya memory access’i etkilemeden önce doğrulanmalıdır.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Eğer `op.kind` gibi bir alan bir enum ise ve bir saldırgan **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerindeki sonraki her `match` şüpheli hale gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini bir **jump table**’a indirgerse, geçersiz bir enum discriminant **tanımsız kontrol akışı** üretebilir. Tehlikeli bir desen şudur:

1. Bir `match` **güvenlik açısından kritik sayaçları/kısıtları** günceller.
2. İkinci bir `match` **gerçek instruction semantics** işlemini yapar.
3. Aralık dışı bir discriminant, ilk jump table’ı atlayarak ikinciyle ilişkili koda düşer.

Sonuç: operasyon yine çalışır, ancak muhasebe yolu atlanır. Bir zkVM’de bu, daha az gate, daha az pahalı işlem veya diğer uydurulmuş sınırlı kaynaklar gibi imkansız metrikler bildiren proofs üretilebilir.

İnceleme kontrol listesi:

- Witness/private input içinden deserialize edilen saldırgan kontrollü enum’ları arayın.
- Aynı opcode/kind alanı üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + unchecked deserialization + büyük opcode dispatch kombinasyonunu yüksek riskli kabul edin.
- Gerekirse üretilen binary’yi tersine mühendislik ile inceleyin; jump-table düzeni kaynak koddan daha önemli olabilir.

### Reversible/specialized interpreters içinde eksik semantic constraints

Sadece memory safety’yi doğrulamayın; proof’un enforce etmesi gereken **semantic rules**’u da doğrulayın.

Reversible/quantum-like instruction set’ler için, distinct olması gereken operand’ların gerçekten distinct olacak şekilde constrained edildiğinden emin olun. Aşağıdaki gibi implemented bir Toffoli/CCX-like operation:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
misafir reddetmezse güvensiz hale gelir:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Bu durumda geçiş şuna indirgenir:
```text
q = q ^ (q & q) = 0
```
Bu, **deterministic reset primitive** oluşturur, tersine çevrilebilirlik varsayımlarını bozar ve daha ucuz, amaç dışı hesaplamaları mümkün kılar. Kaynak kullanımını doğrulayan proof systems içinde, bu saldırganların işlevsel kontrolleri geçerken doğrulayıcının uygulandığını sandığı maliyet modelini atlatmasına izin verebilir.

### ZK systems içinde ne test edilmeli

- Tüm guest parsers için bozuk witness/private-input encodings ile fuzz yapın.
- Opcode dispatch öncesinde enum range validation doğrulayın.
- Operand aliasing ve diğer geçersiz instruction form’ları için semantic checks ekleyin.
- Reported/public counters değerlerini bağımsız bir reference implementation ile karşılaştırın.
- Geçerli bir proof, guest program buggy ise yine de **yanlış statement**’ı ispatlayabilir.

## DeFi/AMM Exploitation

DEXes ve AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) üzerinde pratik exploitation araştırıyorsanız, şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

` supply == 0` olduğunda cached virtual balances kullanan ve poison edilebilen multi-asset weighted pools için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
