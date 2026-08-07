# Blockchain और Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** ऐसे programs होते हैं जो कुछ conditions पूरी होने पर blockchain पर execute होते हैं और intermediaries के बिना agreements के execution को automate करते हैं।
- **Decentralized Applications (dApps)** smart contracts पर आधारित होते हैं और इनमें user-friendly front-end तथा transparent, auditable back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins digital money के रूप में काम करते हैं, जबकि tokens किसी विशेष context में value या ownership दर्शाते हैं।
- **Utility Tokens** services का access प्रदान करते हैं, जबकि **Security Tokens** asset ownership दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो central authorities के बिना financial services प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को दर्शाते हैं।

## Consensus Mechanisms

Consensus mechanisms blockchain पर secure और agreed transaction validations सुनिश्चित करते हैं:

- **Proof of Work (PoW)** transaction verification के लिए computational power पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators को एक निश्चित मात्रा में tokens रखने होते हैं, जिससे PoW की तुलना में energy consumption कम होता है।<sup>[[1]](#references)</sup>

## Bitcoin Essentials

### Transactions

Bitcoin transactions में addresses के बीच funds transfer किए जाते हैं। Transactions को digital signatures के माध्यम से validate किया जाता है, जिससे यह सुनिश्चित होता है कि केवल private key का owner ही transfers initiate कर सके।<sup>[[2]](#references)</sup>

#### Key Components:

- **Multisignature Transactions** में किसी transaction को authorize करने के लिए multiple signatures आवश्यक होते हैं।<sup>[[3]](#references)</sup>
- Transactions में **inputs** (funds का source), **outputs** (destination), **fees** (miners को भुगतान), और **scripts** (transaction rules) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य एक channel के भीतर multiple transactions की अनुमति देकर Bitcoin की scalability बढ़ाना है, जबकि blockchain पर केवल final state broadcast की जाती है।

## Bitcoin Privacy Concerns

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks transaction patterns का exploit करते हैं। **Mixers** और **CoinJoin** जैसी strategies users के बीच transaction links को obscure करके anonymity में सुधार करती हैं।

## Acquiring Bitcoins Anonymously

Methods में cash trades, mining और mixers का उपयोग शामिल है। **CoinJoin** traceability को जटिल बनाने के लिए multiple transactions को mix करता है, जबकि **PayJoin** heightened privacy के लिए CoinJoins को regular transactions के रूप में disguise करता है।

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin की दुनिया में transactions की privacy और users की anonymity अक्सर चिंता के विषय होते हैं। यहां कुछ common methods का simplified overview दिया गया है, जिनके माध्यम से attackers Bitcoin privacy को compromise कर सकते हैं।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

जटिलता के कारण अलग-अलग users के inputs को एक ही transaction में combine करना सामान्यतः rare होता है। इसलिए, **एक ही transaction में मौजूद two input addresses को अक्सर एक ही owner का माना जाता है**।

## **UTXO Change Address Detection**

एक UTXO, यानी **Unspent Transaction Output**, को transaction में पूरी तरह spend किया जाना आवश्यक है। यदि इसका केवल कुछ भाग किसी अन्य address पर भेजा जाता है, तो शेष राशि एक नए change address पर चली जाती है। Observers यह assume कर सकते हैं कि यह नया address sender का है, जिससे privacy compromise होती है।

### Example

इसे mitigate करने के लिए mixing services या multiple addresses का उपयोग ownership को obscure करने में मदद कर सकता है।

## **Social Networks & Forums Exposure**

Users कभी-कभी अपने Bitcoin addresses online share करते हैं, जिससे **address को उसके owner से link करना आसान हो जाता है**।

## **Transaction Graph Analysis**

Transactions को graphs के रूप में visualize किया जा सकता है, जिससे funds के flow के आधार पर users के बीच potential connections सामने आ सकते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic multiple inputs और outputs वाले transactions का analysis करके यह guess करने पर आधारित है कि कौन-सा output sender को वापस मिलने वाला change है।

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
यदि अधिक inputs जोड़ने से change output किसी एक input से भी बड़ा हो जाता है, तो यह heuristic को भ्रमित कर सकता है।

## **Forced Address Reuse**

Attackers पहले उपयोग किए जा चुके addresses पर छोटी राशियां भेज सकते हैं, इस आशा में कि recipient भविष्य की transactions में इन्हें अन्य inputs के साथ मिला देगा, जिससे addresses आपस में link हो जाएंगे।

### Correct Wallet Behavior

इस privacy leak को रोकने के लिए Wallets को पहले से उपयोग किए जा चुके, खाली addresses पर प्राप्त coins का उपयोग करने से बचना चाहिए।

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** बिना change वाली transactions संभवतः एक ही user के स्वामित्व वाले दो addresses के बीच होती हैं।
- **Round Numbers:** किसी transaction में round number यह संकेत देता है कि वह payment है, जबकि non-round output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction creation के patterns अद्वितीय होते हैं, जिससे analysts उपयोग किए गए software और संभावित change address की पहचान कर सकते हैं।
- **Amount & Timing Correlations:** Transaction times या amounts उजागर करने से transactions को trace करना संभव हो सकता है।

## **Traffic Analysis**

Network traffic की निगरानी करके attackers transactions या blocks को IP addresses से link कर सकते हैं, जिससे user privacy प्रभावित होती है। यह विशेष रूप से तब संभव है जब कोई entity कई Bitcoin nodes संचालित करती हो, जिससे transactions की निगरानी करने की उसकी क्षमता बढ़ जाती है।

## More

Privacy attacks और defenses की व्यापक सूची के लिए [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) पर जाएं।

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Cash के माध्यम से bitcoin प्राप्त करना।
- **Cash Alternatives**: Gift cards खरीदकर उन्हें online bitcoin के लिए exchange करना।
- **Mining**: Bitcoins कमाने का सबसे private तरीका mining है, विशेष रूप से तब जब इसे अकेले किया जाए, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: सैद्धांतिक रूप से, bitcoin चुराना इसे anonymously प्राप्त करने का एक अन्य तरीका हो सकता है, हालांकि यह illegal है और recommended नहीं है।

## Mixing Services

Mixing service का उपयोग करके user **send bitcoins** कर सकता है और बदले में **different bitcoins** प्राप्त कर सकता है, जिससे original owner को trace करना कठिन हो जाता है। फिर भी, इसके लिए service पर भरोसा करना पड़ता है कि वह logs न रखे और वास्तव में bitcoins वापस करे। Mixing के वैकल्पिक options में Bitcoin casinos शामिल हैं।

## CoinJoin

**CoinJoin** अलग-अलग users की multiple transactions को एक transaction में merge करता है, जिससे inputs को outputs से match करने की प्रक्रिया जटिल हो जाती है। इसकी effectiveness के बावजूद, unique input और output sizes वाली transactions को अभी भी संभावित रूप से trace किया जा सकता है।

जिन example transactions में CoinJoin का उपयोग हुआ हो सकता है, उनमें `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` शामिल हैं।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) पर जाएं। Ethereum पर इसी तरह की service के लिए [Tornado Cash](https://tornado.cash) देखें, जो miners से प्राप्त funds के साथ transactions को anonymize करती है।

## PayJoin

CoinJoin का एक variant, **PayJoin** (या P2EP), दो parties (जैसे, customer और merchant) के बीच transaction को एक regular transaction के रूप में disguise करता है, जिसमें CoinJoin की distinctive equal outputs विशेषता नहीं होती। इससे इसका detection अत्यंत कठिन हो जाता है और transaction surveillance entities द्वारा उपयोग किए जाने वाले common-input-ownership heuristic को invalid किया जा सकता है।
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
ऊपर दिए गए जैसे transactions PayJoin हो सकते हैं, जो standard bitcoin transactions से अप्रभेद्य रहते हुए privacy को बढ़ाते हैं।

**PayJoin का उपयोग पारंपरिक surveillance methods को महत्वपूर्ण रूप से बाधित कर सकता है**, जिससे यह transactional privacy की दिशा में एक आशाजनक विकास बनता है।

# Cryptocurrencies में Privacy के लिए Best Practices

## **Wallet Synchronization Techniques**

Privacy और security बनाए रखने के लिए wallets को blockchain के साथ synchronize करना महत्वपूर्ण है। दो methods विशेष रूप से उल्लेखनीय हैं:

- **Full node**: पूरी blockchain download करके, full node maximum privacy सुनिश्चित करता है। अब तक किए गए सभी transactions locally store किए जाते हैं, जिससे adversaries के लिए यह पहचानना असंभव हो जाता है कि user किन transactions या addresses में रुचि रखता है।
- **Client-side block filtering**: इस method में blockchain के प्रत्येक block के लिए filters बनाए जाते हैं, जिससे wallets network observers के सामने अपनी specific interests उजागर किए बिना relevant transactions की पहचान कर सकते हैं। Lightweight wallets इन filters को download करते हैं और केवल तब full blocks प्राप्त करते हैं जब user के addresses से match मिलता है।

## **Anonymity के लिए Tor का उपयोग**

चूंकि Bitcoin peer-to-peer network पर operate करता है, इसलिए अपने IP address को छिपाने के लिए Tor का उपयोग recommended है, जिससे network के साथ interact करते समय privacy बढ़ती है।

## **Address Reuse को रोकना**

Privacy की सुरक्षा के लिए हर transaction के लिए एक नया address उपयोग करना महत्वपूर्ण है। Addresses को reuse करने से transactions को एक ही entity से link करके privacy compromise हो सकती है। Modern wallets अपने design के माध्यम से address reuse को हतोत्साहित करते हैं।

## **Transaction Privacy के लिए Strategies**

- **Multiple transactions**: किसी payment को कई transactions में split करने से transaction amount अस्पष्ट हो सकता है और privacy attacks को विफल किया जा सकता है।
- **Change avoidance**: ऐसे transactions चुनना जिनमें change outputs की आवश्यकता न हो, change detection methods को बाधित करके privacy बढ़ाता है।
- **Multiple change outputs**: यदि change से बचना संभव न हो, तो multiple change outputs generate करने से privacy में सुधार हो सकता है।

# **Monero: Anonymity का Beacon**

Monero digital transactions में पूर्ण anonymity की आवश्यकता को address करता है और privacy के लिए एक उच्च standard स्थापित करता है।

# **Ethereum: Gas और Transactions**

## **Gas को समझना**

Gas Ethereum पर operations execute करने के लिए आवश्यक computational effort को मापता है और इसकी pricing **gwei** में होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाला transaction एक gas limit और base fee से संबंधित होता है, जिसमें miners को incentivize करने के लिए एक tip शामिल होती है। Users max fee set कर सकते हैं ताकि वे अधिक payment न करें; अतिरिक्त राशि refund कर दी जाती है।<sup>[[5]](#references)</sup>

## **Transactions को Execute करना**

Ethereum में transactions में एक sender और recipient शामिल होते हैं, जो user या smart contract addresses हो सकते हैं। इनके लिए fee आवश्यक होती है और इन्हें mine किया जाना चाहिए। Transaction में आवश्यक information में recipient, sender's signature, value, optional data, gas limit और fees शामिल होते हैं। विशेष रूप से, sender's address signature से deduce किया जाता है, इसलिए transaction data में इसकी आवश्यकता नहीं होती।<sup>[[4]](#references)</sup>

ये practices और mechanisms उन सभी लोगों के लिए foundational हैं जो privacy और security को प्राथमिकता देते हुए cryptocurrencies के साथ engage करना चाहते हैं।

## Value-Centric Web3 Red Teaming

- यह समझने के लिए value-bearing components (signers, oracles, bridges, automation) की inventory बनाएँ कि funds को कौन और किस प्रकार move कर सकता है।
- privilege escalation paths को उजागर करने के लिए प्रत्येक component को relevant MITRE AADAPT tactics से map करें।
- impact को validate करने और exploitable preconditions को document करने के लिए flash-loan/oracle/credential/cross-chain attack chains का rehearsal करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UIs के supply-chain tampering से signing से ठीक पहले EIP-712 payloads mutate किए जा सकते हैं, जिससे delegatecall-based proxy takeovers (जैसे Safe masterCopy का slot-0 overwrite) के लिए valid signatures harvest किए जा सकते हैं।

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes में `EntryPoint` access control को bypass करना, unsigned gas fields, stateful validation, ERC-1271 replay और revert-after-validation के माध्यम से fee-drain शामिल हैं।

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suites में blind spots खोजने के लिए mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

जब कोई prover किसी claim को attest करने के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier केवल यह जानता है कि **guest program जैसा लिखा गया था, उसी प्रकार execute हुआ**। यदि guest में **unsafe deserialization**, **undefined behavior** या **missing semantic constraints** मौजूद हों, तो malicious prover ऐसा proof generate कर सकता है जो verify हो जाए, जबकि **public metrics या claimed invariant false हों**।<sup>[[7]](#references)</sup>

### Proof guests के अंदर Unsafe deserialization

- Private witness/circuit bytes को **untrusted attacker input** मानें, भले ही वे proof द्वारा hidden हों।
- जब तक bytes को पहले out-of-band validate न किया गया हो, उन्हें `rkyv::access_unchecked` जैसे unchecked helpers से deserialize करने से बचें।
- Untrusted serialized data से load किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access को प्रभावित करने से पहले validate किया जाना चाहिए।

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
यदि `op.kind` जैसा कोई field एक enum है और कोई attacker **out-of-range discriminant** inject कर सकता है, तो उस value पर होने वाला हर downstream `match` संदिग्ध हो जाता है।

### Jump-table / UB counter bypass

यदि Rust किसी बड़े `match` को **jump table** में lower करता है, तो invalid enum discriminant **undefined control flow** उत्पन्न कर सकता है। एक खतरनाक pattern इस प्रकार है:<sup>[[7]](#references)[[9]](#references)</sup>

1. एक `match` **security-critical counters/constraints** को update करता है।
2. दूसरा `match` **वास्तविक instruction semantics** को execute करता है।
3. एक out-of-range discriminant पहले jump table के past index करता है और दूसरे jump table से जुड़े code पर पहुंच जाता है।

परिणाम: operation फिर भी execute होता है, लेकिन accounting path skip हो जाता है। zkVM में इससे ऐसे proofs forge किए जा सकते हैं जो असंभव metrics report करते हैं, जैसे कम gates, कम expensive operations, या अन्य falsified bounded resources।

Review checklist:

- Witness/private input से deserialize किए गए attacker-controlled enums खोजें।
- उसी opcode/kind field पर दोहराए गए `match` statements का निरीक्षण करें।
- `unsafe` + unchecked deserialization + large opcode dispatch के संयोजन को high-risk मानें।
- आवश्यकता होने पर emitted binary को reverse engineer करें; jump-table layout कभी-कभी source से अधिक महत्वपूर्ण हो सकता है।

### Reversible/specialized interpreters में missing semantic constraints

केवल memory safety को validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof द्वारा enforce किया जाना है।

Reversible/quantum-like instruction sets के लिए सुनिश्चित करें कि जिन operands का distinct होना आवश्यक है, उन्हें वास्तव में distinct रहने के लिए constrain किया गया हो। इस प्रकार implemented Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
असुरक्षित हो जाता है यदि guest reject नहीं करता:
```text
op.q_control1 == op.q_control2 == op.q_target
```
उस स्थिति में transition सिमटकर यह रह जाता है:
```text
q = q ^ (q & q) = 0
```
यह एक **deterministic reset primitive** बनाता है, reversibility की assumptions को तोड़ता है और कम लागत वाली unintended computations को सक्षम करता है। ऐसे proof systems में जो resource usage का attest करते हैं, इससे attackers functional checks को पूरा करते हुए उस cost model को bypass कर सकते हैं, जिसे verifier लागू किया हुआ मानता है।

### ZK systems में क्या test करें

- malformed witness/private-input encodings के साथ सभी guest parsers को fuzz करें।
- opcode dispatch से पहले enum range validation सुनिश्चित करें।
- operand aliasing और अन्य invalid instruction forms के लिए semantic checks जोड़ें।
- reported/public counters की तुलना एक independent reference implementation से करें।
- याद रखें कि यदि guest program buggy है, तो valid proof भी **गलत statement** को prove कर सकता है।

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps) के practical exploitation पर research कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

उन multi-asset weighted pools के लिए, जो virtual balances को cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, अध्ययन करें:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key और Private Key की व्याख्या - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Multi-signature transactions क्या हैं? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas और fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
