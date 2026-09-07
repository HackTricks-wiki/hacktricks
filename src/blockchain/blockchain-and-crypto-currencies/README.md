# Blockchain ve Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Temel Kavramlar

- **Smart Contracts**, belirli koşullar karşılandığında bir blockchain üzerinde çalışan ve aracı olmadan anlaşmaların yürütülmesini otomatikleştiren programlar olarak tanımlanır.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir front-end ve şeffaf, denetlenebilir bir back-end sunarak smart contracts üzerine kuruludur.
- **Tokens & Coins**, coin'lerin dijital para olarak hizmet ettiği, token'ların ise belirli bağlamlarda değeri veya mülkiyeti temsil ettiği ayrımını ifade eder.
- **Utility Tokens** hizmetlere erişim sağlar, **Security Tokens** ise varlık sahipliğini temsil eder.
- **DeFi**, Decentralized Finance anlamına gelir ve merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAOs**, sırasıyla Decentralized Exchange Platforms ve Decentralized Autonomous Organizations anlamına gelir.

## Consensus Mechanisms

Consensus mechanisms, blockchain üzerindeki işlemlerin güvenli ve üzerinde anlaşmaya varılmış şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlem doğrulaması için hesaplama gücüne dayanır.
- **Proof of Stake (PoS)**, validator'ların belirli miktarda token bulundurmasını gerektirir ve PoW'ye kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin Temel Bilgileri

### İşlemler

Bitcoin işlemleri, adresler arasında fon transferini içerir. İşlemler, yalnızca private key sahibinin transferleri başlatabilmesini sağlayan digital signatures aracılığıyla doğrulanır.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature Transactions**, bir işlemi yetkilendirmek için birden fazla signature gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (miner'lara ödenen ücretler) ve **scripts** (işlem kuralları) bileşenlerinden oluşur.

### Lightning Network

Bir channel içinde birden fazla işleme izin vererek ve yalnızca nihai durumu blockchain'e yayınlayarak Bitcoin'in scalability özelliğini geliştirmeyi amaçlar.

## Bitcoin Privacy Concerns

**Common Input Ownership** ve **UTXO Change Address Detection** gibi privacy attacks, işlem kalıplarından yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonymity özelliğini artırır.

## Bitcoin'leri Anonim Olarak Edinme

Yöntemler arasında nakit alım satımı, mining ve mixers kullanımı bulunur. **CoinJoin**, izlenebilirliği zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha yüksek privacy sağlamak amacıyla CoinJoins işlemlerini normal işlemler gibi gösterir.

# Bitcoin Privacy Attacks Özeti

Bitcoin dünyasında işlemlerin privacy'si ve kullanıcıların anonymity'si genellikle endişe konusudur. Aşağıda, attackers'ın Bitcoin privacy'sini tehlikeye atabileceği yaygın yöntemlerden bazılarının basitleştirilmiş bir özeti yer almaktadır.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Karmaşıklığı nedeniyle farklı kullanıcılara ait input'ların tek bir işlemde birleştirilmesi genellikle nadirdir. Bu nedenle, **aynı işlemdeki iki input adresinin genellikle aynı sahibine ait olduğu varsayılır**.

## **UTXO Change Address Detection**

UTXO veya **Unspent Transaction Output**, bir işlemde tamamen harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse kalan miktar yeni bir change address'e gider. Gözlemciler bu yeni adresin göndericiye ait olduğunu varsayabilir ve bu durum privacy'yi tehlikeye atar.

### Örnek

Bunu azaltmak için mixing services kullanmak veya birden fazla adres kullanmak, sahipliğin gizlenmesine yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin adreslerini online olarak paylaşır; bu da **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **Transaction Graph Analysis**

İşlemler graph olarak görselleştirilebilir ve fonların akışına dayanarak kullanıcılar arasındaki olası bağlantılar ortaya çıkarılabilir.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu heuristic, göndericiye geri dönen change'in hangi output olduğunu tahmin etmek için birden fazla input ve output içeren işlemlerin analizine dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Daha fazla input eklemek, change output'unu herhangi bir tekil input'tan daha büyük hâle getirirse heuristic'in kafasını karıştırabilir.

## **Forced Address Reuse**

Saldırganlar, alıcının gelecekteki işlemlerde bunları diğer input'larla birleştirerek adresleri birbirine bağlamasını umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Doğru Wallet Davranışı

Wallet'lar, bu gizlilik leak'ini önlemek için zaten kullanılmış ve boş adreslere alınan coin'leri kullanmaktan kaçınmalıdır.

## **Diğer Blockchain Analysis Teknikleri**

- **Exact Payment Amounts:** Change içermeyen işlemler, aynı kullanıcıya ait iki adres arasında gerçekleşmiş olma ihtimali yüksektir.
- **Round Numbers:** Bir işlemdeki yuvarlak sayı, bunun bir ödeme olduğunu gösterir; yuvarlak olmayan output muhtemelen change'dir.
- **Wallet Fingerprinting:** Farklı wallet'ların benzersiz işlem oluşturma kalıpları vardır. Bu, analyst'lerin kullanılan software'i ve potansiyel olarak change adresini belirlemesine olanak tanır.
- **Amount & Timing Correlations:** İşlem zamanlarının veya miktarlarının ifşa edilmesi, işlemlerin izlenebilir hâle gelmesine neden olabilir.

## **Traffic Analysis**

Network trafiğini izleyerek saldırganlar, işlemleri veya block'ları IP adresleriyle potansiyel olarak ilişkilendirebilir ve kullanıcı gizliliğini tehlikeye atabilir. Bu durum özellikle bir entity çok sayıda Bitcoin node'u işletiyorsa geçerlidir; çünkü bu, işlemleri izleme kabiliyetini artırır.

## Daha Fazla

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) sayfasını ziyaret edin.

# Anonymous Bitcoin Transactions

## Bitcoin'leri Anonim Olarak Edinme Yolları

- **Cash Transactions**: Bitcoin'i nakit kullanarak edinmek.
- **Cash Alternatives**: Gift card satın almak ve bunları online olarak Bitcoin ile takas etmek.
- **Mining**: Bitcoin kazanmanın en gizli yöntemi mining yapmaktır. Bu işlem özellikle tek başına gerçekleştirildiğinde daha gizlidir; çünkü mining pool'ları miner'ın IP adresini biliyor olabilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak Bitcoin çalmak, onu anonim olarak edinmenin başka bir yöntemi olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Services

Bir mixing service kullanarak kullanıcı **Bitcoin gönderebilir** ve karşılığında **farklı Bitcoin'ler alabilir**; bu da ilk sahibin izini sürmeyi zorlaştırır. Ancak bunun için service'e log tutmayacağına ve Bitcoin'leri gerçekten geri göndereceğine güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casino'ları bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden çok işlemi tek bir işlemde birleştirerek input'ları output'larla eşleştirmeye çalışan herkesin işini zorlaştırır. Etkili olmasına rağmen, benzersiz input ve output boyutlarına sahip işlemlerin izini sürmek hâlâ mümkün olabilir.

CoinJoin kullanmış olabilecek örnek işlemler arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` bulunur.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) sayfasını ziyaret edin. Deposit'leri daha sonraki withdrawal'lar'dan ayıran bir Ethereum smart-contract mixer için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir varyantı olan **PayJoin** (veya P2EP), iki taraf arasındaki işlemi (ör. bir müşteri ve merchant) CoinJoin'in ayırt edici eşit output özelliği olmadan normal bir işlem gibi gösterir. Bu, tespit edilmesini son derece zorlaştırır ve transaction surveillance entity'leri tarafından kullanılan common-input-ownership heuristic'ini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Yukarıdakine benzer Transactions, standart bitcoin transactions'larından ayırt edilemezliğini korurken gizliliği artıran PayJoin olabilir.

**PayJoin kullanımı, geleneksel surveillance yöntemlerini önemli ölçüde sekteye uğratabilir** ve transactional privacy arayışında umut verici bir gelişme olabilir.

# Cryptocurrencies'de Privacy için Best Practices

## **Wallet Synchronization Techniques**

Privacy ve security'yi korumak için wallet'ları blockchain ile synchronize etmek kritik öneme sahiptir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek bir full node maksimum privacy sağlar. Şimdiye kadar gerçekleştirilmiş tüm transactions yerel olarak saklanır; bu da adversary'lerin kullanıcının hangi transactions veya addresses'lerle ilgilendiğini belirlemesini imkansız hale getirir.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her block için filters oluşturmayı içerir. Böylece wallet'lar, belirli ilgi alanlarını network gözlemcilerine açığa çıkarmadan ilgili transactions'ları tespit edebilir. Lightweight wallet'lar bu filters'ları indirir ve yalnızca kullanıcının addresses'leriyle eşleşme bulunduğunda full blocks'ları getirir.

## **Anonymity için Tor Kullanımı**

Bitcoin bir peer-to-peer network üzerinde çalıştığından, IP address'inizi maskelemek ve network ile etkileşim sırasında privacy'yi artırmak için Tor kullanmanız önerilir.

## **Address Reuse'ı Önleme**

Privacy'yi korumak için her transaction'da yeni bir address kullanmak hayati önem taşır. Address'leri yeniden kullanmak, transactions'ları aynı entity ile ilişkilendirerek privacy'yi tehlikeye atabilir. Modern wallet'lar tasarımları aracılığıyla address reuse'ı engeller.

## **Transaction Privacy Stratejileri**

- **Multiple transactions**: Bir payment'ı birden fazla transaction'a bölmek, transaction miktarını gizleyerek privacy attacks'lerini engelleyebilir.
- **Change avoidance**: Change outputs gerektirmeyen transactions'ları tercih etmek, change detection yöntemlerini bozarak privacy'yi artırır.
- **Multiple change outputs**: Change'den kaçınmak mümkün değilse, birden fazla change output oluşturmak yine de privacy'yi artırabilir.

# **Monero: Anonymity'nin Sembolü**

Monero, transaction privacy'ye öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve Transactions**

## **Gas'i Anlamak**

Gas, Ethereum'da operations'ları gerçekleştirmek için gereken computational effort'ı ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei'ye (veya 0,00231 ETH'ye) mal olan bir transaction, validator'ların transaction'ı dahil etmesini teşvik etmek için bir gas limit, base fee ve priority fee içerir. Kullanıcılar fazla ödeme yapmadıklarından emin olmak için bir max fee belirleyebilir; aşan miktar iade edilir.<sup>[[5]](#references)</sup>

## **Transactions Gerçekleştirme**

Ethereum'daki transactions, user veya smart contract addresses olabilen bir sender ve recipient içerir. Bir fee gerektirir ve bir block'a dahil edilmeleri gerekir. Bir transaction'daki temel bilgiler recipient, sender's signature, value, optional data, gas limit ve fees'i içerir. Özellikle sender's address signature'dan türetildiğinden, transaction data içinde bulunması gerekmez.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, privacy ve security'ye öncelik verirken cryptocurrencies ile etkileşim kurmak isteyen herkes için temel niteliktedir.

## Value-Centric Web3 Red Teaming

- Fon taşıyabilen bileşenleri (signers, oracles, bridges, automation) envanterleyerek fonları kimin ve nasıl taşıyabildiğini anlayın.
- Privilege escalation yollarını ortaya çıkarmak için her bileşeni ilgili MITRE AADAPT tactics'leriyle eşleyin.
- Etkiyi doğrulamak ve exploit edilebilir preconditions'ı belgelemek için flash-loan/oracle/credential/cross-chain attack chains'lerini rehearse edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI'larının supply-chain tampering'ı, signing işleminden hemen önce EIP-712 payload'larını değiştirebilir ve delegatecall-based proxy takeovers için geçerli signatures'ları ele geçirebilir (ör. Safe masterCopy'nin slot-0 overwrite'ı).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Yaygın smart-account failure modes arasında `EntryPoint` access control'ünün bypass edilmesi, unsigned gas fields, stateful validation, ERC-1271 replay ve revert-after-validation yoluyla fee-drain bulunur.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suite'lerindeki blind spot'ları bulmak için mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Bir prover bir **zkVM** veya application-specific proof circuit kullanarak bir claim'i doğruladığında, verifier yalnızca **guest program'ın yazıldığı şekilde çalıştığını** öğrenir. Guest program **unsafe deserialization**, **undefined behavior** veya **missing semantic constraints** içeriyorsa, malicious prover doğrulanan ancak **public metrics veya claimed invariant'ın yanlış olduğu** bir proof üretebilir.<sup>[[7]](#references)</sup>

### Proof guest'leri içinde Unsafe deserialization

- Private witness/circuit bytes'larını, proof tarafından gizlense bile **untrusted attacker input** olarak değerlendirin.
- Bytes daha önce out-of-band olarak validate edilmedikçe, bunları `rkyv::access_unchecked` gibi unchecked helper'larla deserialize etmekten kaçının.
- Untrusted serialized data'dan yüklenen enum discriminants, relative pointers, lengths ve indexes, control flow'u veya memory access'i etkilemeden önce validate edilmelidir.

Pratik audit pattern'i:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Bir `op.kind` gibi alan bir enum ise ve bir attacker **out-of-range discriminant** enjekte edebiliyorsa, bu değer üzerindeki sonraki her `match` şüpheli hâle gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini **jump table** hâline getiriyorsa, geçersiz bir enum discriminant'ı **undefined control flow** üretebilir. Tehlikeli bir pattern şöyledir:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **security-critical counters/constraints** değerlerini günceller.
2. İkinci bir `match`, **gerçek instruction semantics** işlemini gerçekleştirir.
3. Out-of-range bir discriminant, ilk jump table'ın sonrasındaki bir konumu indeksler ve ikinci jump table ile ilişkili koda ulaşır.

Sonuç: İşlem yine gerçekleştirilir, ancak accounting path atlanır. Bir zkVM'de bu durum; daha az gate, daha az pahalı işlem veya diğer bounded resource'lar gibi imkânsız metrikler bildiren proof'ların forge edilmesine yol açabilir.

İnceleme checklist'i:

- Witness/private input'tan deserialize edilen attacker-controlled enum'ları arayın.
- Aynı opcode/kind field üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + unchecked deserialization + large opcode dispatch kombinasyonunu high-risk olarak değerlendirin.
- Gerektiğinde emitted binary'yi reverse engineer edin; jump-table yerleşimi kaynak koddan daha önemli olabilir.

### Reversible/specialized interpreter'larda eksik semantic constraints

Yalnızca memory safety'yi doğrulamayın; proof'un enforce etmesi gereken **semantic rules**'ı da doğrulayın.

Reversible/quantum-like instruction set'lerde, farklı olması gereken operand'ların gerçekten farklı olmalarının constraint'lerle güvence altına alındığından emin olun. Şu şekilde implement edilmiş bir Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
konuk reddetmezse güvenli olmaktan çıkar:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Bu durumda geçiş şu hale indirgenir:
```text
q = q ^ (q & q) = 0
```
Bu, **deterministik bir sıfırlama primitive'i** oluşturur; tersine çevrilebilirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha düşük maliyetle gerçekleştirilmesini sağlar. Kaynak kullanımını doğrulayan proof sistemlerinde bu, saldırganların işlevsel kontrolleri karşılamasına ve doğrulayıcının uygulandığına inandığı maliyet modelini atlamasına olanak tanıyabilir.

### ZK sistemlerinde test edilmesi gerekenler

- Tüm guest parser'larını hatalı witness/private-input encoding'leriyle fuzz testine tabi tutun.
- Opcode dispatch işleminden önce enum aralık doğrulamasını zorunlu kılın.
- Operand aliasing ve diğer geçersiz instruction biçimleri için semantic kontroller ekleyin.
- Bildirilen/public counter'ları bağımsız bir reference implementation ile karşılaştırın.
- Guest program hatalıysa geçerli bir proof'un yine de **yanlış ifadeyi** kanıtlayabileceğini unutmayın.

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

DEX'lerin ve AMM'lerin pratik exploitation yöntemlerini (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold-crossing swaps) araştırıyorsanız şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Virtual balance'ları cache'leyen ve `supply == 0` olduğunda zehirlenebilen multi-asset weighted pool'lar için şunu inceleyin:

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
