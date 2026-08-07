# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts**, belirli koşullar karşılandığında bir blockchain üzerinde çalışan ve aracı olmadan anlaşmaların yürütülmesini otomatikleştiren programlar olarak tanımlanır.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir front-end ve şeffaf, denetlenebilir bir back-end içeren Smart Contracts üzerine kuruludur.
- **Tokens & Coins**, coin'lerin dijital para olarak, token'ların ise belirli bağlamlarda değer veya mülkiyet temsili olarak kullanılmasını ifade eder.
- **Utility Tokens** hizmetlere erişim sağlar, **Security Tokens** ise varlık sahipliğini belirtir.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Decentralized Finance anlamına gelir.
- **DEX** ve **DAOs**, sırasıyla Decentralized Exchange Platforms ve Decentralized Autonomous Organizations ifadelerini belirtir.

## Consensus Mechanisms

Consensus mechanisms, blockchain üzerindeki transaction doğrulamalarının güvenli ve üzerinde anlaşmaya varılmış olmasını sağlar:

- **Proof of Work (PoW)**, transaction doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)**, validator'ların belirli miktarda token tutmasını gerektirir ve PoW'ye kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin Temelleri

### Transactions

Bitcoin transactions, adresler arasında fon transferini içerir. Transactions, yalnızca private key sahibinin transfer başlatabilmesini sağlayan digital signatures aracılığıyla doğrulanır.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature Transactions**, bir transaction'ı yetkilendirmek için birden fazla signature gerektirir.<sup>[[3]](#references)</sup>
- Transactions; **inputs** (fon kaynağı), **outputs** (hedef), **fees** (miner'lara ödenen ücretler) ve **scripts** (transaction kuralları) içerir.

### Lightning Network

Bir channel içinde birden fazla transaction gerçekleştirilmesine ve yalnızca nihai durumun blockchain'e yayınlanmasına olanak tanıyarak Bitcoin'in ölçeklenebilirliğini artırmayı amaçlar.

## Bitcoin Gizlilik Sorunları

**Common Input Ownership** ve **UTXO Change Address Detection** gibi privacy attacks, transaction kalıplarından yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki transaction bağlantılarını gizleyerek anonimliği artırır.

## Bitcoin'leri Anonim Olarak Edinme

Yöntemler arasında nakit işlemleri, mining ve mixer kullanımı bulunur. **CoinJoin**, izlenebilirliği zorlaştırmak için birden fazla transaction'ı karıştırırken **PayJoin**, daha yüksek gizlilik sağlamak amacıyla CoinJoin'leri normal transaction'lar gibi gösterir.

# Bitcoin Gizlilik Saldırıları

# Bitcoin Gizlilik Saldırılarına Genel Bakış

Bitcoin dünyasında transaction'ların gizliliği ve kullanıcıların anonimliği sıklıkla endişe konusudur. Aşağıda, attacker'ların Bitcoin gizliliğini tehlikeye atabileceği birkaç yaygın yöntemin basitleştirilmiş bir özeti yer almaktadır.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Karmaşıklık nedeniyle farklı kullanıcıların input'larının tek bir transaction'da birleştirilmesi genellikle nadirdir. Bu nedenle, **aynı transaction'daki iki input adresinin genellikle aynı sahibine ait olduğu varsayılır**.

## **UTXO Change Address Detection**

UTXO veya **Unspent Transaction Output**, bir transaction'da tamamen harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse kalan miktar yeni bir change address'e gider. Gözlemciler bu yeni adresin göndericiye ait olduğunu varsayabilir ve bu durum gizliliği tehlikeye atar.

### Örnek

Bunu azaltmak için mixing services kullanmak veya birden fazla adres kullanmak sahipliğin gizlenmesine yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin adreslerini çevrimiçi olarak paylaşır ve bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **Transaction Graph Analysis**

Transactions, grafikler olarak görselleştirilebilir ve fon akışına dayanarak kullanıcılar arasındaki olası bağlantıları ortaya çıkarabilir.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu heuristic, göndericiye geri dönen change'in hangi output olduğunu tahmin etmek için birden fazla input ve output içeren transaction'ların analizine dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Daha fazla input eklemek, change output'unu herhangi bir tek input'tan daha büyük hale getiriyorsa heuristic'i yanıltabilir.

## **Forced Address Reuse**

Saldırganlar, daha önce kullanılmış adreslere küçük miktarlar gönderebilir ve alıcının gelecekteki işlemlerde bunları diğer input'larla birleştirmesini umarak adresleri birbirine bağlayabilir.

### Correct Wallet Behavior

Wallet'lar, bu privacy leak'i önlemek için daha önce kullanılmış ve boş adreslerde alınan coin'leri kullanmaktan kaçınmalıdır.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Change içermeyen işlemler, büyük olasılıkla aynı kullanıcıya ait iki adres arasındadır.
- **Round Numbers:** Bir işlemdeki yuvarlak sayı, bunun bir ödeme olduğunu; yuvarlak olmayan output'un ise muhtemelen change olduğunu gösterir.
- **Wallet Fingerprinting:** Farklı wallet'ların kendilerine özgü işlem oluşturma modelleri vardır. Bu, analyst'lerin kullanılan software'i ve potansiyel olarak change address'i belirlemesini sağlar.
- **Amount & Timing Correlations:** İşlem zamanlarının veya miktarlarının ifşa edilmesi, işlemlerin trace edilebilir hale gelmesine neden olabilir.

## **Traffic Analysis**

Network trafiğini izleyen saldırganlar, işlemleri veya block'ları IP adresleriyle potansiyel olarak ilişkilendirerek kullanıcı privacy'sini tehlikeye atabilir. Bu durum özellikle bir entity'nin çok sayıda Bitcoin node'u çalıştırması halinde geçerlidir; bu, işlemleri izleme kabiliyetini artırır.

## More

Privacy saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Wiki'deki Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin'i nakit kullanarak edinmek.
- **Cash Alternatives**: Gift card satın almak ve bunları online olarak bitcoin ile takas etmek.
- **Mining**: Bitcoin kazanmanın en private yöntemi mining'dir. Bu özellikle tek başına yapıldığında geçerlidir; çünkü mining pool'ları miner'ın IP adresini biliyor olabilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak bitcoin çalmak, onu anonim olarak edinmenin başka bir yöntemi olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Services

Bir mixing service kullanarak kullanıcı **bitcoin gönderebilir** ve karşılığında **farklı bitcoin'ler alabilir**; bu da original owner'ın trace edilmesini zorlaştırır. Ancak bunun için service'e log tutmaması ve bitcoin'leri gerçekten geri göndermesi konusunda güvenmek gerekir. Alternative mixing seçenekleri arasında Bitcoin casino'ları da bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek input'ları output'larla eşleştirmeye çalışan herkesin işini zorlaştırır. Etkili olmasına rağmen, benzersiz input ve output boyutlarına sahip işlemler yine de potansiyel olarak trace edilebilir.

CoinJoin kullanmış olabilecek örnek işlemler arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` bulunur.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Ethereum üzerindeki benzer bir service için, miner'lardan gelen fonlarla işlemleri anonymize eden [Tornado Cash](https://tornado.cash)'e göz atın.

## PayJoin

CoinJoin'in bir varyantı olan **PayJoin** (veya P2EP), iki taraf arasındaki işlemi (örneğin bir müşteri ve merchant arasındaki işlemi), CoinJoin'in ayırt edici eşit output özelliği olmadan normal bir işlem gibi gizler. Bu, tespit edilmesini son derece zorlaştırabilir ve işlem gözetimi yapan entity'lerin kullandığı common-input-ownership heuristic'ini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Yukarıdaki gibi işlemler PayJoin olabilir; standart bitcoin işlemlerinden ayırt edilemezken gizliliği artırır.

**PayJoin kullanımı, geleneksel surveillance yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlemsel gizlilik arayışında umut verici bir gelişme olabilir.

# Cryptocurrencies için Gizlilikte En İyi Uygulamalar

## **Wallet Synchronization Teknikleri**

Gizliliği ve güvenliği korumak için wallet'ları blockchain ile senkronize etmek kritik öneme sahiptir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek full node, maksimum gizlilik sağlar. Şimdiye kadar yapılmış tüm işlemler yerel olarak saklanır; bu da adversary'lerin kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkansız hale getirir.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her block için filter'lar oluşturmayı ve wallet'ların belirli ilgi alanlarını network gözlemcilerine ifşa etmeden ilgili işlemleri belirlemesini içerir. Lightweight wallet'lar bu filter'ları indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda full block'ları getirir.

## **Anonymity için Tor Kullanımı**

Bitcoin bir peer-to-peer network üzerinde çalıştığından, network ile etkileşim sırasında IP adresinizi maskelemek ve gizliliği artırmak için Tor kullanılması önerilir.

## **Address Reuse'ü Önleme**

Gizliliği korumak için her işlemde yeni bir address kullanmak hayati önem taşır. Address'leri yeniden kullanmak, işlemleri aynı entity ile ilişkilendirerek gizliliği tehlikeye atabilir. Modern wallet'lar tasarımları aracılığıyla address reuse'ü engeller.

## **Transaction Gizliliği Stratejileri**

- **Multiple transactions**: Bir ödemeyi birden fazla transaction'a bölmek, transaction miktarını belirsizleştirerek privacy attack'lerini engelleyebilir.
- **Change avoidance**: Change output gerektirmeyen transaction'ları tercih etmek, change detection yöntemlerini bozarak gizliliği artırır.
- **Multiple change outputs**: Change'den kaçınmak mümkün değilse birden fazla change output oluşturmak yine de gizliliği artırabilir.

# **Monero: Anonymity için Bir Beacon**

Monero, dijital işlemlerde mutlak anonymity ihtiyacını ele alarak gizlilik için yüksek bir standart belirler.

# **Ethereum: Gas ve Transactions**

## **Gas'ı Anlamak**

Gas, Ethereum üzerinde işlemleri gerçekleştirmek için gereken computational effort'ı ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei (veya 0,00231 ETH) maliyetindeki bir transaction, bir gas limit ve miner'ları teşvik etmek için bir base fee ile birlikte bir tip içerir. Kullanıcılar fazla ödeme yapmadıklarından emin olmak için bir max fee belirleyebilir; artan miktar iade edilir.<sup>[[5]](#references)</sup>

## **Transactions Gerçekleştirme**

Ethereum'daki transactions, user veya smart contract address'leri olabilen bir sender ve recipient içerir. Bir fee gerektirir ve mined edilmeleri gerekir. Bir transaction'daki temel bilgiler recipient, sender'ın signature'ı, value, isteğe bağlı data, gas limit ve fee'leri içerir. Dikkat çekici olarak sender'ın address'i signature'dan türetilir; bu nedenle transaction data'sında bulunması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliğe öncelik vererek cryptocurrencies ile etkileşim kurmak isteyen herkes için temel niteliktedir.

## Value-Centric Web3 Red Teaming

- Fon taşıyabilen tarafları ve bunun nasıl yapılabildiğini anlamak için value-bearing component'leri (signer'lar, oracle'lar, bridge'ler, automation) envanterleyin.
- Privilege escalation path'lerini ortaya çıkarmak için her component'i ilgili MITRE AADAPT tactic'leriyle eşleştirin.
- Etkiyi doğrulamak ve exploitable precondition'ları belgelemek için flash-loan/oracle/credential/cross-chain attack chain'lerini rehearse edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI'larının supply-chain tampering'e uğraması, signing işleminden hemen önce EIP-712 payload'larını değiştirebilir ve delegatecall-based proxy takeover'ları için geçerli signature'ları toplayabilir (ör. Safe masterCopy'nin slot-0 overwrite edilmesi).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Yaygın smart-account failure mode'ları arasında `EntryPoint` access control'ünün bypass edilmesi, unsigned gas field'ları, stateful validation, ERC-1271 replay ve validation sonrasında revert yoluyla fee-drain bulunur.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suite'lerindeki blind spot'ları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Bir prover bir **zkVM** veya application-specific proof circuit kullanarak bir claim'i doğruladığında verifier yalnızca **guest program'ın yazıldığı şekilde çalıştırıldığını** öğrenir. Guest içerisinde **unsafe deserialization**, **undefined behavior** veya **missing semantic constraints** bulunuyorsa kötü niyetli bir prover, **public metrics veya claimed invariant yanlış** olsa bile doğrulanan bir proof oluşturabilir.<sup>[[7]](#references)</sup>

### Proof guest'leri içinde Unsafe deserialization

- Private witness/circuit byte'larını, proof tarafından gizleniyor olsalar bile **untrusted attacker input** olarak ele alın.
- Byte'lar out-of-band olarak önceden doğrulanmadıkça `rkyv::access_unchecked` gibi unchecked helper'larla bunları deserialize etmekten kaçının.
- Untrusted serialized data'dan yüklenen enum discriminant'ları, relative pointer'lar, length'ler ve index'ler control flow'u veya memory access'i etkilemeden önce doğrulanmalıdır.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
`op.kind` gibi bir alan enum ise ve bir attacker **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerindeki sonraki her `match` şüpheli hale gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini bir **jump table** içine indirgerse, geçersiz bir enum discriminant'ı **tanımsız kontrol akışına** neden olabilir. Tehlikeli bir pattern şöyledir:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **güvenlik açısından kritik sayaçları/kısıtlamaları** günceller.
2. İkinci bir `match`, **gerçek instruction semantics** işlemini gerçekleştirir.
3. Aralık dışı bir discriminant, ilk jump table'ın sonrasını index'ler ve ikincisiyle ilişkili koda ulaşır.

Sonuç: İşlem yine gerçekleştirilir, ancak accounting path atlanır. Bir zkVM'de bu durum; daha az gate, daha az pahalı işlem veya diğer sınırlandırılmış kaynaklar gibi imkansız metrikler bildiren sahte proof'lar oluşturabilir.

İnceleme checklist'i:

- Witness/private input'tan deserialize edilen attacker-controlled enum'ları arayın.
- Aynı opcode/kind alanı üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + unchecked deserialization + large opcode dispatch birleşimini yüksek riskli kabul edin.
- Gerektiğinde emitted binary üzerinde reverse engineering yapın; jump-table düzeni source'tan daha önemli olabilir.

### Reversible/specialized interpreter'larda eksik semantic constraints

Yalnızca memory safety'yi validate etmeyin; proof'un enforce etmesi gereken **semantic rules**'ları da validate edin.

Reversible/quantum-like instruction set'lerde, distinct olması gereken operand'ların gerçekten distinct olacak şekilde constrain edildiğinden emin olun. Şu şekilde implement edilen Toffoli/CCX-like bir operation:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
konuk reddetmezse güvenli olmaktan çıkar:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Bu durumda geçiş şu hâle indirgenir:
```text
q = q ^ (q & q) = 0
```
Bu, **deterministic reset primitive** oluşturarak tersine çevrilebilirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha düşük maliyetle yapılmasını mümkün kılar. Kaynak kullanımını doğrulayan proof sistemlerinde bu durum, saldırganların işlevsel kontrolleri karşılamasına ve aynı zamanda verifier'ın uygulandığını düşündüğü maliyet modelini atlatmasına olanak tanıyabilir.

### ZK sistemlerinde test edilmesi gerekenler

- Tüm guest parser'larını hatalı witness/private-input encoding'leriyle fuzz edin.
- Opcode dispatch işleminden önce enum range validation uygulandığını doğrulayın.
- Operand aliasing ve diğer geçersiz instruction biçimleri için semantic check'ler ekleyin.
- Bildirilen/public counter'ları bağımsız bir reference implementation ile karşılaştırın.
- Geçerli bir proof'un yine de **yanlış statement'i** kanıtlayabileceğini unutmayın; guest program buggy olabilir.

## DeFi/AMM Exploitation

DEX'lerin ve AMM'lerin pratik exploitation'ını araştırıyorsanız (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps), şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Virtual balance'ları cache'leyen ve `supply == 0` olduğunda poison edilebilen multi-asset weighted pool'lar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key Explained - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [What are multi-signature transactions? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas and fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
