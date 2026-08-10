# Blockchain ve Kripto Para Birimleri

## Temel Kavramlar

- **Smart Contracts**, belirli koşullar karşılandığında bir blockchain üzerinde çalışan ve aracı olmadan anlaşmaların yürütülmesini otomatikleştiren programlar olarak tanımlanır.
- **Decentralized Applications (dApps)**, kullanıcı dostu bir front-end ve şeffaf, denetlenebilir bir back-end sunarak smart contracts üzerine kuruludur.
- **Tokens & Coins**, coin'lerin dijital para olarak hizmet ettiği, token'ların ise belirli bağlamlarda değeri veya mülkiyeti temsil ettiği ayrımını ifade eder.
- **Utility Tokens** hizmetlere erişim sağlar, **Security Tokens** ise varlık sahipliğini ifade eder.
- **DeFi**, Decentralized Finance anlamına gelir ve merkezi otoriteler olmadan finansal hizmetler sunar.
- **DEX** ve **DAOs**, sırasıyla Decentralized Exchange Platforms ve Decentralized Autonomous Organizations anlamına gelir.

## Consensus Mechanisms

Consensus mechanisms, blockchain üzerindeki işlemlerin güvenli ve üzerinde anlaşmaya varılmış şekilde doğrulanmasını sağlar:

- **Proof of Work (PoW)**, işlem doğrulaması için computational power kullanır.
- **Proof of Stake (PoS)**, validator'ların belirli miktarda token tutmasını gerektirir ve PoW'a kıyasla enerji tüketimini azaltır.<sup>[[1]](#references)</sup>

## Bitcoin Temel Bilgileri

### İşlemler

Bitcoin işlemleri, adresler arasında fon transferini içerir. İşlemler digital signatures aracılığıyla doğrulanır ve yalnızca private key sahibinin transfer başlatabilmesi sağlanır.<sup>[[2]](#references)</sup>

#### Temel Bileşenler:

- **Multisignature Transactions**, bir işlemi yetkilendirmek için birden fazla signature gerektirir.<sup>[[3]](#references)</sup>
- İşlemler **inputs** (fon kaynağı), **outputs** (hedef), **fees** (miner'lara ödenen ücretler) ve **scripts** (işlem kuralları) içerir.

### Lightning Network

Bir channel içinde birden fazla işleme izin vererek Bitcoin'in scalability özelliğini geliştirmeyi ve yalnızca final state'i blockchain'e yayınlamayı amaçlar.

## Bitcoin Gizlilik Endişeleri

**Common Input Ownership** ve **UTXO Change Address Detection** gibi privacy attacks, işlem kalıplarından yararlanır. **Mixers** ve **CoinJoin** gibi stratejiler, kullanıcılar arasındaki işlem bağlantılarını gizleyerek anonymity'yi artırır.

## Bitcoin'leri Anonim Olarak Edinme

Yöntemler arasında nakit işlemleri, mining ve mixers kullanımı bulunur. **CoinJoin**, izlenebilirliği zorlaştırmak için birden fazla işlemi karıştırırken **PayJoin**, daha yüksek privacy sağlamak amacıyla CoinJoin işlemlerini normal işlemler gibi gösterir.

# Bitcoin Privacy Attacks Özeti

Bitcoin dünyasında işlemlerin privacy'si ve kullanıcıların anonymity'si sıklıkla endişe konusu olur. Aşağıda, saldırganların Bitcoin privacy'sini tehlikeye atabileceği yaygın yöntemlerden bazılarının basitleştirilmiş bir özeti verilmiştir.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

İlgili karmaşıklık nedeniyle farklı kullanıcılara ait input'ların tek bir işlemde birleştirilmesi genellikle nadirdir. Bu nedenle, **aynı işlemdeki iki input adresinin genellikle aynı sahibine ait olduğu varsayılır**.

## **UTXO Change Address Detection**

UTXO veya **Unspent Transaction Output**, bir işlemde tamamen harcanmalıdır. Yalnızca bir kısmı başka bir adrese gönderilirse, kalan miktar yeni bir change address'e gider. Gözlemciler bu yeni adresin göndericiye ait olduğunu varsayabilir ve bu durum privacy'yi tehlikeye atar.

### Örnek

Bunu azaltmak için mixing services kullanmak veya birden fazla adres kullanmak sahipliğin gizlenmesine yardımcı olabilir.

## **Social Networks & Forums Exposure**

Kullanıcılar bazen Bitcoin adreslerini online olarak paylaşır ve bu durum **adresi sahibiyle ilişkilendirmeyi kolaylaştırır**.

## **Transaction Graph Analysis**

İşlemler graph olarak görselleştirilebilir ve fonların akışına dayanarak kullanıcılar arasındaki olası bağlantılar ortaya çıkarılabilir.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Bu heuristic, göndericiye geri dönen change'in hangi output olduğunu tahmin etmek için birden fazla input ve output içeren işlemlerin analizine dayanır.

### Örnek
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Daha fazla input eklemek, change output'un herhangi bir tek input'tan daha büyük olmasına neden oluyorsa heuristic'i yanıltabilir.

## **Forced Address Reuse**

Saldırganlar, alıcının gelecekteki işlemlerde bunları diğer input'larla birleştirerek adresleri birbirine bağlamasını umarak daha önce kullanılmış adreslere küçük miktarlar gönderebilir.

### Correct Wallet Behavior

Wallet'lar, bu privacy leak'i önlemek için daha önce kullanılmış, boş adreslerde alınan coin'leri kullanmaktan kaçınmalıdır.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Change içermeyen işlemler, büyük olasılıkla aynı kullanıcıya ait iki adres arasındadır.
- **Round Numbers:** Bir işlemdeki yuvarlak bir sayı, bunun bir ödeme olduğunu; yuvarlak olmayan output'un ise büyük olasılıkla change olduğunu gösterir.
- **Wallet Fingerprinting:** Farklı wallet'ların benzersiz işlem oluşturma pattern'leri vardır; bu da analistlerin kullanılan software'i ve potansiyel olarak change address'i belirlemesine olanak tanır.
- **Amount & Timing Correlations:** İşlem zamanlarının veya miktarlarının açıklanması, işlemlerin izlenebilir hale gelmesine neden olabilir.

## **Traffic Analysis**

Network trafiğini izleyerek saldırganlar, işlemleri veya block'ları IP adresleriyle potansiyel olarak ilişkilendirebilir ve kullanıcı privacy'sini tehlikeye atabilir. Bu durum, bir entity'nin çok sayıda Bitcoin node'u işletmesi halinde özellikle geçerlidir; çünkü bu, işlemleri izleme kabiliyetini artırır.

## More

Gizlilik saldırıları ve savunmalarının kapsamlı bir listesi için [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) adresini ziyaret edin.

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin'i nakit kullanarak edinmek.
- **Cash Alternatives**: Gift card satın almak ve bunları online olarak bitcoin ile takas etmek.
- **Mining**: Bitcoin kazanmanın en privacy odaklı yöntemi mining yapmaktır; özellikle tek başına yapıldığında, çünkü mining pool'ları miner'ın IP adresini biliyor olabilir. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teorik olarak bitcoin çalmak, onu anonim olarak edinmenin başka bir yöntemi olabilir; ancak bu yasa dışıdır ve önerilmez.

## Mixing Services

Bir mixing service kullanarak kullanıcı **bitcoin gönderebilir** ve karşılığında **farklı bitcoin'ler alabilir**; bu da orijinal sahibin izini sürmeyi zorlaştırır. Bununla birlikte, service'in log tutmamasına ve bitcoin'leri gerçekten iade etmesine güvenmek gerekir. Alternatif mixing seçenekleri arasında Bitcoin casino'ları da bulunur.

## CoinJoin

**CoinJoin**, farklı kullanıcılara ait birden fazla işlemi tek bir işlemde birleştirerek input'ları output'larla eşleştirmeye çalışan herkesin işini zorlaştırır. Etkili olmasına rağmen, benzersiz input ve output boyutlarına sahip işlemlerin izi yine de potansiyel olarak sürülebilir.

CoinJoin kullanmış olabilecek örnek işlemler arasında `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` ve `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` bulunur.

Daha fazla bilgi için [CoinJoin](https://coinjoin.io/en) adresini ziyaret edin. Deposit'leri daha sonraki withdrawal'larla birbirinden ayıran bir Ethereum smart-contract mixer için [Tornado Cash](https://tornado.cash) sayfasına bakın.

## PayJoin

CoinJoin'in bir varyantı olan **PayJoin** (veya P2EP), iki taraf arasındaki işlemi (örneğin bir müşteri ve merchant arasındaki işlemi), CoinJoin'in ayırt edici eşit output özelliği olmadan normal bir işlem gibi gösterir. Bu durum, işlemi tespit etmeyi son derece zorlaştırabilir ve transaction surveillance entity'leri tarafından kullanılan common-input-ownership heuristic'ini geçersiz kılabilir.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Yukarıdakilere benzer işlemler, standart bitcoin işlemlerinden ayırt edilemezliğini korurken gizliliği artıran PayJoin olabilir.

**PayJoin kullanımı, geleneksel surveillance yöntemlerini önemli ölçüde sekteye uğratabilir** ve işlemsel gizlilik arayışında umut vadeden bir gelişme olabilir.

# Cryptocurrencies için Gizlilikte En İyi Uygulamalar

## **Wallet Synchronization Teknikleri**

Gizlilik ve güvenliği korumak için wallet'ları blockchain ile senkronize etmek kritik öneme sahiptir. İki yöntem öne çıkar:

- **Full node**: Tüm blockchain'i indirerek bir full node, maksimum gizlilik sağlar. Yapılmış tüm işlemler yerel olarak saklanır; bu da adversary'lerin kullanıcının hangi işlemlerle veya adreslerle ilgilendiğini belirlemesini imkansız hale getirir.
- **Client-side block filtering**: Bu yöntem, blockchain'deki her block için filter'lar oluşturmayı ve wallet'ların belirli ilgi alanlarını network gözlemcilerine açığa çıkarmadan ilgili işlemleri belirlemesini içerir. Lightweight wallet'lar bu filter'ları indirir ve yalnızca kullanıcının adresleriyle eşleşme bulunduğunda full block'ları alır.

## **Anonymity için Tor Kullanımı**

Bitcoin bir peer-to-peer network üzerinde çalıştığından, network ile etkileşim sırasında IP adresinizi maskelemek ve gizliliği artırmak için Tor kullanmanız önerilir.

## **Address Reuse'ı Önleme**

Gizliliği korumak için her işlemde yeni bir address kullanmak hayati önem taşır. Address'leri yeniden kullanmak, işlemleri aynı entity ile ilişkilendirerek gizliliği tehlikeye atabilir. Modern wallet'lar tasarımlarıyla address reuse'ı engeller.

## **Transaction Privacy Stratejileri**

- **Multiple transactions**: Bir ödemeyi birkaç işleme bölmek, işlem tutarını belirsizleştirerek privacy attack'lerini engelleyebilir.
- **Change avoidance**: Change output'ları gerektirmeyen işlemleri tercih etmek, change detection yöntemlerini bozarak gizliliği artırır.
- **Multiple change outputs**: Change'ten kaçınmak mümkün değilse birden fazla change output oluşturmak yine de gizliliği iyileştirebilir.

# **Monero: Anonymity'nin Simgesi**

Monero, işlem gizliliğine öncelik verecek şekilde tasarlanmıştır.

# **Ethereum: Gas ve Transactions**

## **Gas'i Anlamak**

Gas, Ethereum üzerinde işlemleri gerçekleştirmek için gereken computational effort'ı ölçer ve **gwei** cinsinden fiyatlandırılır. Örneğin, 2.310.000 gwei'ye (veya 0,00231 ETH'ye) mal olan bir işlem, validator'ün işlemi dahil etmesini teşvik etmek için bir gas limit'i, base fee ve priority fee içerir. Kullanıcılar fazla ödeme yapmadıklarından emin olmak için bir max fee belirleyebilir; fazlalık iade edilir.<sup>[[5]](#references)</sup>

## **Transactions Gerçekleştirme**

Ethereum'daki transactions, user veya smart contract address'i olabilen bir sender ve recipient içerir. Bir fee gerektirir ve bir block'a dahil edilmelidir. Bir transaction'daki temel bilgiler recipient, sender signature'ı, value, isteğe bağlı data, gas limit ve fee'leri içerir. Özellikle sender address'i signature'dan çıkarıldığından transaction data'sında bulunmasına gerek yoktur.<sup>[[4]](#references)</sup>

Bu uygulamalar ve mekanizmalar, gizlilik ve güvenliğe öncelik vererek cryptocurrencies ile etkileşim kurmak isteyen herkes için temel niteliktedir.

## Değer Odaklı Web3 Red Teaming

- Fon taşıyabilen tarafları ve yöntemleri anlamak için value-bearing component'lerin (signer'lar, oracle'lar, bridge'ler, automation) envanterini çıkarın.
- Privilege escalation yollarını ortaya çıkarmak için her component'i ilgili MITRE AADAPT tactic'leriyle eşleyin.
- Etkiyi doğrulamak ve exploit edilebilir ön koşulları belgelemek için flash-loan/oracle/credential/cross-chain attack chain'lerini prova edin.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI'larının supply-chain tampering'ı, signing işleminden hemen önce EIP-712 payload'larını değiştirebilir ve delegatecall-based proxy takeover'ları için geçerli signature'lar toplayabilir (ör. Safe masterCopy'nin slot-0 overwrite'ı).

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

Bir prover bir iddiayı doğrulamak için **zkVM** veya application-specific proof circuit kullandığında, verifier yalnızca **guest program'ın yazıldığı şekilde çalıştırıldığını** öğrenir. Guest içinde **unsafe deserialization**, **undefined behavior** veya **missing semantic constraints** bulunuyorsa, kötü amaçlı bir prover, **public metrics'in veya claim edilen invariant'ın yanlış olmasına rağmen** doğrulanan bir proof üretebilir.<sup>[[7]](#references)</sup>

### Proof guest'leri içinde Unsafe deserialization

- Private witness/circuit byte'larını, proof tarafından gizlenmiş olsalar bile **untrusted attacker input** olarak değerlendirin.
- Byte'lar out-of-band olarak önceden doğrulanmadıkça `rkyv::access_unchecked` gibi unchecked helper'larla bunları deserialize etmekten kaçının.
- Untrusted serialized data'dan yüklenen enum discriminant'ları, relative pointer'lar, length'ler ve index'ler control flow'u veya memory access'i etkilemeden önce doğrulanmalıdır.

Pratik audit pattern'i:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
`op.kind` gibi bir alan enum ise ve bir attacker **out-of-range discriminant** enjekte edebiliyorsa, bu değer üzerindeki her downstream `match` şüpheli hâle gelir.

### Jump-table / UB counter bypass

Rust büyük bir `match` ifadesini **jump table** biçimine dönüştürürse, geçersiz bir enum discriminant'ı **undefined control flow** üretebilir. Tehlikeli bir pattern şöyledir:<sup>[[7]](#references)[[9]](#references)</sup>

1. Bir `match`, **security-critical counters/constraints** değerlerini günceller.
2. İkinci bir `match`, **gerçek instruction semantics** işlemini gerçekleştirir.
3. Out-of-range bir discriminant, ilk jump table'ın sonrasını indeksler ve ikinci jump table ile ilişkili koda ulaşır.

Sonuç: İşlem yine gerçekleştirilir, ancak accounting path atlanır. Bir zkVM'de bu durum; daha az gate, daha az maliyetli işlem veya sınırlandırılmış diğer kaynaklara ilişkin yanlış raporlanan ölçümler gibi imkânsız metrikler bildiren sahte proof'lar oluşturabilir.

İnceleme checklist'i:

- Witness/private input'tan deserialize edilen attacker-controlled enum'ları arayın.
- Aynı opcode/kind alanı üzerinde tekrarlanan `match` ifadelerini inceleyin.
- `unsafe` + unchecked deserialization + large opcode dispatch birleşimini yüksek riskli kabul edin.
- Gerektiğinde oluşturulan binary'yi reverse engineer edin; jump-table yerleşimi source kodundan daha önemli olabilir.

### Reversible/specialized interpreter'larda eksik semantic constraints

Yalnızca memory safety'yi doğrulamayın; proof'un enforce etmesi gereken **semantic rules**'ları da doğrulayın.

Reversible/quantum-like instruction set'lerde, distinct olması gereken operand'ların gerçekten distinct olacak şekilde constraint edildiğinden emin olun. Şu şekilde implement edilen bir Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
konuk reddetmezse güvenli olmaktan çıkar:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Bu durumda geçiş şu biçime indirgenir:
```text
q = q ^ (q & q) = 0
```
Bu, **deterministik bir reset primitive'i** oluşturur; tersine çevrilebilirlik varsayımlarını bozar ve amaçlanmayan hesaplamaların daha düşük maliyetle yapılmasını mümkün kılar. Kaynak kullanımını doğrulayan proof sistemlerinde bu durum, saldırganların işlevsel kontrolleri geçerken verifier'ın uygulandığına inandığı maliyet modelini atlatmasına olanak tanıyabilir.

### ZK sistemlerinde test edilmesi gerekenler

- Tüm guest parser'larını hatalı witness/private-input encoding'leriyle fuzz edin.
- Opcode dispatch işleminden önce enum aralığı doğrulaması yapıldığını doğrulayın.
- Operand aliasing ve diğer geçersiz instruction biçimleri için semantic kontroller ekleyin.
- Bildirilen/public sayaçları bağımsız bir reference implementation ile karşılaştırın.
- Geçerli bir proof'un yine de guest program hatalıysa **yanlış ifadeyi** kanıtlayabileceğini unutmayın.

## DeFi/AMM Exploitation

DEX'ler ve AMM'lerde (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps) pratik exploitation araştırıyorsanız şuraya bakın:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Virtual balance'ları cache'leyen ve `supply == 0` olduğunda zehirlenebilen multi-asset weighted pool'lar için şunu inceleyin:

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
- [8] [Elliptic Curve Cryptocurrency'lerini Quantum Vulnerability'lerine Karşı Güvenceye Alma: Resource Estimates ve Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
