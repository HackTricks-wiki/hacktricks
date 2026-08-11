# Blockchain ve Kripto Para Birimleri

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts**, belirli koşullar karşılandığında bir blockchain üzerinde çalışan ve aracı olmadan anlaşmaların yürütülmesini otomatikleştiren programlar olarak tanımlanır.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir front-end ve şeffaf, denetlenebilir bir back-end sunarak smart contracts üzerine kuruludur.
- **Tokens & Coins**, coin'lerin dijital para, token'ların ise belirli bağlamlarda değer veya sahiplik temsil etmesi bakımından birbirinden ayrılır.
- **Utility Tokens** hizmetlere erişim sağlar, **Security Tokens** ise varlık sahipliğini ifade eder.
- **DeFi**, merkezi otoriteler olmadan finansal hizmetler sunan Decentralized Finance anlamına gelir.
- **DEX** ve **DAOs**, sırasıyla Decentralized Exchange Platforms ve Decentralized Autonomous Organizations anlamına gelir.

## Consensus Mechanisms

Consensus mechanisms, blockchain üzerindeki işlemlerin güvenli ve üzerinde anlaşmaya varılmış şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)**, validator'ların belirli miktarda token tutmasını gerektirir ve PoW'ya kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin Temel Bilgileri

### İşlemler

Bitcoin işlemleri, adresler arasında fon transferini içerir. İşlemler, yalnızca private key sahibinin transfer başlatabilmesini sağlayan digital signatures aracılığıyla doğrulanır.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature Transactions**, bir işlemi yetkilendirmek için birden fazla signature gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (miners'a ödenen ücretler) ve **scripts** (işlem kuralları) bileşenlerinden oluşur.

### Lightning Network

Bir channel içinde birden fazla işleme izin vererek Bitcoin'in scalability özelliğini geliştirmeyi amaçlar; yalnızca final state'i blockchain'e yayınlar.

## Bitcoin Privacy Concerns

**Common Input Ownership** ve **UTXO Change Address Detection** gibi privacy attacks, işlem kalıplarından yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonymity'yi artırır.

## Bitcoin'leri Anonim Olarak Edinme

Yöntemler arasında nakit işlemleri, mining ve mixers kullanımı bulunur. **CoinJoin**, izlenebilirliği zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha yüksek privacy sağlamak amacıyla CoinJoin işlemlerini normal işlemler gibi gösterir.

# Bitcoin Privacy Attacks Özeti

Bitcoin dünyasında işlemlerin privacy'si ve kullanıcıların anonymity'si çoğu zaman endişe konusudur. Aşağıda, attackers'ın Bitcoin privacy'sini tehlikeye atabileceği yaygın yöntemlerden bazılarının basitleştirilmiş bir özeti yer almaktadır.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

İşin karmaşıklığı nedeniyle farklı kullanıcıların input'larının tek bir işlemde birleştirilmesi genellikle nadirdir. Bu nedenle, **aynı işlemdeki iki input adresinin genellikle aynı sahibe ait olduğu varsayılır**.

## **UTXO Change Address Detection**

Bir UTXO veya **Unspent Transaction Output**, bir işlemde tamamen harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse kalan miktar yeni bir change address'e gider. Gözlemciler bu yeni adresin gönderene ait olduğunu varsayabilir ve bu durum privacy'yi tehlikeye atar.

### Örnek

Bunu azaltmak için mixing services kullanmak veya birden fazla adres kullanmak sahipliğin gizlenmesine yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin adreslerini çevrim içi paylaşır ve bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **Transaction Graph Analysis**

İşlemler graph olarak görselleştirilebilir ve fon akışına göre kullanıcılar arasındaki olası bağlantılar ortaya çıkarılabilir.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu heuristic, gönderene geri dönen change'in hangi output olduğunu tahmin etmek için birden fazla input ve output içeren işlemlerin analizine dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Daha fazla input eklenmesi, change output'unu herhangi bir tek input'tan daha büyük hâle getiriyorsa heuristic'i yanıltabilir.

## **Forced Address Reuse**

Saldırganlar, daha önce kullanılmış adreslere küçük miktarlar gönderebilir; amaç, alıcının gelecekte bunları diğer input'larla birleştirmesini sağlamak ve böylece adresleri birbirine bağlamaktır.

### Correct Wallet Behavior

Wallet'lar, bu privacy leak'i önlemek için daha önce kullanılmış ve boş adreslerde alınan coin'leri kullanmaktan kaçınmalıdır.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Change içermeyen transaction'lar, aynı kullanıcıya ait iki adres arasında gerçekleşmiş olma ihtimali taşır.
- **Round Numbers:** Bir transaction'daki yuvarlak sayı, bunun bir ödeme olduğunu gösterir; yuvarlak olmayan output ise muhtemelen change'tir.
- **Wallet Fingerprinting:** Farklı wallet'ların kendine özgü transaction oluşturma pattern'leri vardır. Bu, analyst'lerin kullanılan software'i ve potansiyel olarak change adresini belirlemesine olanak tanır.
- **Amount & Timing Correlations:** Transaction zamanlarının veya miktarlarının açığa çıkarılması, transaction'ların izlenebilir hâle gelmesine neden olabilir.

## **Traffic Analysis**

Network trafiğini izleyen saldırganlar, transaction'ları veya block'ları IP adresleriyle potansiyel olarak ilişkilendirebilir ve kullanıcı privacy'sini tehlikeye atabilir. Bu durum, bir entity'nin çok sayıda Bitcoin node'u işletmesi hâlinde özellikle geçerlidir; bu, transaction'ları izleme kapasitesini artırır.

## More

Privacy attack'leri ve savunmalarının kapsamlı bir listesi için [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin'i nakit kullanarak edinmek.
- **Cash Alternatives**: Gift card satın almak ve bunları online olarak bitcoin karşılığında takas etmek.
- **Mining**: Bitcoin kazanmanın en private yöntemi mining'dir; özellikle tek başına yapıldığında. Çünkü mining pool'ları miner'ın IP adresini biliyor olabilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak bitcoin çalmak, onu anonymous şekilde edinmenin başka bir yöntemi olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Services

Bir mixing service kullanıldığında kullanıcı **bitcoin gönderebilir** ve karşılığında **farklı bitcoin'ler alabilir**. Bu, ilk sahibin izini sürmeyi zorlaştırır. Ancak bunun için service'in log tutmayacağına ve bitcoin'leri gerçekten iade edeceğine güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casino'ları bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla transaction'ı tek bir transaction'da birleştirir ve input'ları output'larla eşleştirmeye çalışan herkesin işini zorlaştırır. Etkili olmasına rağmen, benzersiz input ve output boyutlarına sahip transaction'lar yine de potansiyel olarak izlenebilir.

CoinJoin kullanmış olabilecek transaction örnekleri arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` bulunur.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Deposit'leri daha sonraki withdrawal'lar'dan ayıran bir Ethereum smart-contract mixer için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir varyantı olan **PayJoin** (veya P2EP), iki taraf arasındaki transaction'ı (örneğin bir müşteri ve merchant arasındaki transaction'ı), CoinJoin'in ayırt edici eşit output özelliği olmadan normal bir transaction gibi gösterir. Bu, tespit edilmesini son derece zorlaştırır ve transaction surveillance entity'leri tarafından kullanılan common-input-ownership heuristic'ini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Yukarıdaki gibi işlemler, standart bitcoin işlemlerinden ayırt edilemezliğini korurken gizliliği artıran PayJoin olabilir.

**PayJoin kullanımı, geleneksel surveillance yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlemsel gizlilik arayışında umut vadeden bir gelişme olabilir.

# Cryptocurrencies için Gizlilikte En İyi Uygulamalar

## **Wallet Synchronization Teknikleri**

Gizliliği ve güvenliği korumak için wallet'ları blockchain ile senkronize etmek kritik önem taşır. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek bir full node, maksimum gizlilik sağlar. Şimdiye kadar yapılmış tüm işlemler yerel olarak saklanır; bu da adversary'lerin kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkansız hale getirir.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her block için filter'lar oluşturmayı içerir. Böylece wallet'lar, belirli ilgileri network gözlemcilerine açığa çıkarmadan ilgili işlemleri belirleyebilir. Lightweight wallet'lar bu filter'ları indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda full block'ları alır.

## **Anonymity için Tor Kullanımı**

Bitcoin bir peer-to-peer network üzerinde çalıştığından, IP adresinizi maskelemek ve network ile etkileşim sırasında gizliliği artırmak için Tor kullanılması önerilir.

## **Address Reuse'ü Önleme**

Gizliliği korumak için her işlemde yeni bir address kullanmak hayati önem taşır. Address'leri yeniden kullanmak, işlemleri aynı entity ile ilişkilendirerek gizliliği tehlikeye atabilir. Modern wallet'lar tasarımları aracılığıyla address reuse'ü engeller.

## **Transaction Privacy Stratejileri**

- **Multiple transactions**: Bir ödemeyi birden fazla işleme bölmek, işlem tutarını gizleyerek privacy attack'lerini engelleyebilir.
- **Change avoidance**: Change output'ları gerektirmeyen işlemleri tercih etmek, change detection yöntemlerini bozarak gizliliği artırır.
- **Multiple change outputs**: Change'ten kaçınmak mümkün değilse birden fazla change output'u oluşturmak yine de gizliliği iyileştirebilir.

# **Monero: Anonymity'nin Feneri**

Monero, transaction privacy'yi önceliklendirecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve Transactions**

## **Gas'i Anlamak**

Gas, Ethereum üzerinde işlemleri gerçekleştirmek için gereken computational effort'u ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei'ye (veya 0,00231 ETH'ye) mal olan bir işlem; gas limit'i ve base fee'nin yanı sıra validator'ların işlemi dahil etmesini teşvik eden bir priority fee içerir. Kullanıcılar fazla ödeme yapmadıklarından emin olmak için bir max fee belirleyebilir; aşan tutar iade edilir.<sup>[[5]](#references)</sup>

## **Transactions Gerçekleştirme**

Ethereum'daki transactions, user veya smart contract address'leri olabilen bir sender ve recipient içerir. Bir fee gerektirir ve bir block'a dahil edilmeleri gerekir. Bir transaction'daki temel bilgiler recipient, sender'ın signature'ı, value, isteğe bağlı data, gas limit ve fee'leri içerir. Önemli olarak sender'ın address'i signature'dan çıkarılır; bu nedenle transaction data'sında bulunmasına gerek yoktur.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliği önceliklendirerek cryptocurrencies ile etkileşim kurmak isteyen herkes için temel niteliğindedir.

## Value-Centric Web3 Red Teaming

- Kimlerin fonları nasıl hareket ettirebildiğini anlamak için value taşıyan bileşenlerin (signer'lar, oracle'lar, bridge'ler, automation) envanterini çıkarın.
- Privilege escalation yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT tactic'leriyle eşleştirin.
- Etkiyi doğrulamak ve exploit edilebilir ön koşulları belgelemek için flash-loan/oracle/credential/cross-chain attack chain'lerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI'larının supply-chain tampering'e uğraması, signing işleminden hemen önce EIP-712 payload'larını değiştirebilir ve delegatecall tabanlı proxy takeover'ları için geçerli signature'ları toplayabilir (ör. Safe masterCopy'nin slot-0 overwrite edilmesi).

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

Bir prover bir iddiayı doğrulamak için **zkVM** veya application-specific proof circuit kullandığında verifier yalnızca **guest program'ın yazıldığı şekilde çalıştığını** öğrenir. Guest içinde **unsafe deserialization**, **undefined behavior** veya **eksik semantic constraint'ler** varsa, kötü niyetli bir prover doğrulanan ancak **public metrics veya iddia edilen invariant'ın yanlış olduğu** bir proof üretebilir.<sup>[[7]](#references)</sup>

### Proof guest'leri içinde Unsafe deserialization

- Private witness/circuit byte'larını, proof tarafından gizlenmiş olsalar bile **untrusted attacker input** olarak değerlendirin.
- Byte'lar out-of-band olarak önceden doğrulanmadıkça `rkyv::access_unchecked` gibi unchecked helper'larla bunları deserialize etmekten kaçının.
- Untrusted serialized data'dan yüklenen enum discriminant'ları, relative pointer'lar, length'ler ve index'ler control flow'u veya memory access'i etkilemeden önce doğrulanmalıdır.

Pratik audit modeli:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
`op.kind` gibi bir alan enum ise ve bir attacker **aralık dışı bir discriminant** enjekte edebiliyorsa, bu değer üzerinde yapılan her downstream `match` şüpheli hâle gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini **jump table** hâline getiriyorsa, geçersiz bir enum discriminant’ı **undefined control flow** üretebilir. Tehlikeli bir pattern şöyledir:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **security-critical counter/constraint** değerlerini günceller.
2. İkinci bir `match`, **asıl instruction semantics** işlemini gerçekleştirir.
3. Aralık dışı bir discriminant, ilk jump table’ın sonrasını index’leyerek ikinci jump table ile ilişkili koda sıçrar.

Sonuç: İşlem yine yürütülür, ancak accounting path atlanır. Bir zkVM’de bu durum; daha az gate, daha az expensive operation veya diğer sınırlandırılmış resource’lar hakkında yanlış rapor veren, imkânsız metrikleri gösteren proof’ların forge edilmesine yol açabilir.

Review checklist:

- Witness/private input’tan deserialize edilen attacker-controlled enum’ları arayın.
- Aynı opcode/kind field üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + unchecked deserialization + large opcode dispatch kombinasyonunu high-risk olarak değerlendirin.
- Gerektiğinde emitted binary’yi reverse engineer edin; jump-table layout, source kodundan daha önemli olabilir.

### Reversible/specialized interpreter’larda eksik semantic constraint’ler

Yalnızca memory safety’yi doğrulamayın; proof’un enforce etmesi gereken **semantic rules**’ları da doğrulayın.

Reversible/quantum-like instruction set’lerde, birbirinden farklı olması gereken operand’ların gerçekten distinct olacak şekilde constraint edildiğinden emin olun. Şu şekilde implement edilmiş bir Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
konuk reddetmezse güvensiz hale gelir:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Bu durumda geçiş şu biçime indirgenir:
```text
q = q ^ (q & q) = 0
```
Bu, **deterministic reset primitive** oluşturur; tersine çevrilebilirlik varsayımlarını bozar ve amaçlanmamış hesaplamaların daha düşük maliyetle yapılmasını sağlar. Kaynak kullanımını doğrulayan proof sistemlerinde bu durum, saldırganların işlevsel kontrolleri karşılayıp verifier'ın uygulandığına inandığı maliyet modelini atlatmasına olanak tanıyabilir.

### ZK sistemlerinde test edilmesi gerekenler

- Tüm guest parser'larını hatalı witness/private-input encoding'leriyle fuzz edin.
- Opcode dispatch işleminden önce enum aralık doğrulamasını zorunlu kılın.
- Operand aliasing ve diğer geçersiz instruction biçimleri için semantic kontroller ekleyin.
- Bildirilen/public counter'ları bağımsız bir referans implementation ile karşılaştırın.
- Guest program hatalıysa, geçerli bir proof'un yine de **yanlış statement'i** kanıtlayabileceğini unutmayın.

## DeFi/AMM Exploitation

DEX'lerin ve AMM'lerin pratik exploitation'ını (Uniswap v4 hooks, rounding/precision abuse, flash-loan ile güçlendirilmiş threshold-crossing swap'ler) araştırıyorsanız şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Virtual balance'ları cache'leyen ve `supply == 0` olduğunda poison edilebilen multi-asset weighted pool'lar için şunu inceleyin:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key ve Private Key Açıklaması - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Multi-signature transaction'lar nedir? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaction'lar | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas ve ücretler | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Google'ın quantum cryptanalysis zero-knowledge proof'unu yendik](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Elliptic Curve Cryptocurrency'leri Quantum Vulnerability'lerine Karşı Güvence Altına Alma: Resource Estimates ve Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
