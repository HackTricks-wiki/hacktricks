# Blockchain और Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## मूल अवधारणाएँ

- **Smart Contracts** ऐसे programs के रूप में परिभाषित किए जाते हैं जो कुछ शर्तें पूरी होने पर blockchain पर execute होते हैं और intermediaries के बिना agreements के execution को automate करते हैं।
- **Decentralized Applications (dApps)** smart contracts पर आधारित होते हैं और इनमें user-friendly front-end तथा transparent, auditable back-end शामिल होते हैं।
- **Tokens & Coins** में अंतर यह है कि coins digital money के रूप में काम करते हैं, जबकि tokens विशिष्ट contexts में value या ownership को दर्शाते हैं।
- **Utility Tokens** services तक access प्रदान करते हैं, जबकि **Security Tokens** asset ownership को दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो central authorities के बिना financial services प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को संदर्भित करते हैं।

## Consensus Mechanisms

Consensus mechanisms blockchain पर secure और agreed transaction validations सुनिश्चित करते हैं:

- **Proof of Work (PoW)** transaction verification के लिए computational power पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators के पास tokens की एक निश्चित मात्रा होना आवश्यक है, जिससे PoW की तुलना में energy consumption कम होता है।<sup>[[1]](#references)</sup>

## Bitcoin की आवश्यक बातें

### Transactions

Bitcoin transactions में addresses के बीच funds transfer करना शामिल होता है। Transactions को digital signatures के माध्यम से validate किया जाता है, जिससे यह सुनिश्चित होता है कि केवल private key का owner ही transfers शुरू कर सके।<sup>[[2]](#references)</sup>

#### मुख्य Components:

- **Multisignature Transactions** में transaction को authorize करने के लिए multiple signatures आवश्यक होते हैं।<sup>[[3]](#references)</sup>
- Transactions में **inputs** (funds का source), **outputs** (destination), **fees** (miners को भुगतान), और **scripts** (transaction rules) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य एक channel के भीतर multiple transactions की अनुमति देकर Bitcoin की scalability बढ़ाना है, जिसमें केवल final state को blockchain पर broadcast किया जाता है।

## Bitcoin की Privacy से जुड़ी चिंताएँ

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks transaction patterns का exploitation करते हैं। **Mixers** और **CoinJoin** जैसी strategies users के बीच transaction links को obscure करके anonymity में सुधार करती हैं।

## Bitcoins को Anonymously प्राप्त करना

Methods में cash trades, mining और mixers का उपयोग शामिल है। **CoinJoin** traceability को जटिल बनाने के लिए multiple transactions को mix करता है, जबकि **PayJoin** अधिक privacy के लिए CoinJoins को regular transactions के रूप में disguise करता है।

# Bitcoin Privacy Attacks का सारांश

Bitcoin की दुनिया में transactions की privacy और users की anonymity अक्सर चिंता के विषय होते हैं। यहाँ कई common methods का simplified overview दिया गया है, जिनके माध्यम से attackers Bitcoin privacy को compromise कर सकते हैं।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

जटिलता के कारण अलग-अलग users के inputs को एक ही transaction में combine करना सामान्यतः दुर्लभ होता है। इसलिए, **एक ही transaction में मौजूद two input addresses को अक्सर एक ही owner का माना जाता है**।

## **UTXO Change Address Detection**

एक UTXO, या **Unspent Transaction Output**, को transaction में पूरी तरह spend करना आवश्यक होता है। यदि इसका केवल कुछ भाग किसी अन्य address पर भेजा जाता है, तो शेष भाग एक नए change address पर चला जाता है। Observers यह मान सकते हैं कि यह नया address sender का है, जिससे privacy compromise होती है।

### उदाहरण

इसे mitigate करने के लिए mixing services या multiple addresses का उपयोग ownership को obscure करने में मदद कर सकता है।

## **Social Networks & Forums Exposure**

Users कभी-कभी अपने Bitcoin addresses online share करते हैं, जिससे **address को उसके owner से link करना आसान हो जाता है**।

## **Transaction Graph Analysis**

Transactions को graphs के रूप में visualize किया जा सकता है, जिससे funds के flow के आधार पर users के बीच संभावित connections सामने आते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic multiple inputs और outputs वाले transactions का analysis करके यह अनुमान लगाने पर आधारित है कि कौन-सा output sender को वापस मिलने वाला change है।

### उदाहरण
```bash
2 btc --> 4 btc
3 btc     1 btc
```
यदि अधिक inputs जोड़ने से change output किसी एक input से बड़ा हो जाता है, तो यह heuristic को भ्रमित कर सकता है।

## **Forced Address Reuse**

Attackers पहले इस्तेमाल किए गए addresses पर छोटी राशियां भेज सकते हैं, इस उम्मीद में कि प्राप्तकर्ता भविष्य की transactions में इन्हें अन्य inputs के साथ मिला देगा और इस प्रकार addresses आपस में link हो जाएंगे।

### Correct Wallet Behavior

इस privacy leak को रोकने के लिए Wallets को पहले से इस्तेमाल किए गए, खाली addresses पर प्राप्त coins का उपयोग करने से बचना चाहिए।

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** बिना change वाली transactions संभवतः एक ही user के स्वामित्व वाले दो addresses के बीच होती हैं।
- **Round Numbers:** किसी transaction में round number यह संकेत देता है कि वह payment है, जबकि non-round output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction creation के विशिष्ट patterns होते हैं, जिससे analysts इस्तेमाल किए गए software और संभावित change address की पहचान कर सकते हैं।
- **Amount & Timing Correlations:** transaction times या amounts उजागर करने से transactions को trace करना संभव हो सकता है।

## **Traffic Analysis**

Network traffic की निगरानी करके attackers transactions या blocks को IP addresses से link कर सकते हैं, जिससे user privacy प्रभावित होती है। यह विशेष रूप से तब संभव है जब कोई entity कई Bitcoin nodes संचालित करती हो, जिससे transactions की निगरानी करने की उसकी क्षमता बढ़ जाती है।

## More

Privacy attacks और defenses की व्यापक सूची के लिए [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Cash के माध्यम से bitcoin प्राप्त करना।
- **Cash Alternatives**: Gift cards खरीदकर उन्हें online bitcoin के लिए exchange करना।
- **Mining**: Bitcoins कमाने का सबसे private तरीका Mining है, खासकर जब यह अकेले किया जाए, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: सैद्धांतिक रूप से, bitcoin चुराना इसे anonymously प्राप्त करने का एक अन्य तरीका हो सकता है, हालांकि यह illegal और recommended नहीं है।

## Mixing Services

Mixing service का उपयोग करके user **send bitcoins** कर सकता है और बदले में **different bitcoins** प्राप्त कर सकता है, जिससे original owner को trace करना कठिन हो जाता है। फिर भी, इसके लिए service पर यह भरोसा करना पड़ता है कि वह logs नहीं रखेगी और वास्तव में bitcoins वापस करेगी। Mixing के वैकल्पिक विकल्पों में Bitcoin casinos शामिल हैं।

## CoinJoin

**CoinJoin** अलग-अलग users की multiple transactions को एक transaction में merge करता है, जिससे inputs को outputs से match करने की प्रक्रिया जटिल हो जाती है। अपनी effectiveness के बावजूद, unique input और output sizes वाली transactions को फिर भी trace किया जा सकता है।

CoinJoin का उपयोग करने वाली संभावित example transactions में `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` शामिल हैं।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। ऐसे Ethereum smart-contract mixer के लिए, जो deposits को बाद के withdrawals से अलग करता है, [Tornado Cash](https://tornado.cash) देखें।

## PayJoin

CoinJoin का एक variant, **PayJoin** (या P2EP), दो parties (जैसे, customer और merchant) के बीच की transaction को regular transaction के रूप में disguise करता है, जिसमें CoinJoin की विशिष्ट equal outputs विशेषता नहीं होती। इससे इसका detection बेहद कठिन हो जाता है और transaction surveillance entities द्वारा उपयोग किए जाने वाले common-input-ownership heuristic को invalid किया जा सकता है।
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
उपरोक्त जैसे Transactions PayJoin हो सकते हैं, जो standard bitcoin transactions से अलग पहचाने बिना privacy को बढ़ाते हैं।

**PayJoin का उपयोग traditional surveillance methods को महत्वपूर्ण रूप से बाधित कर सकता है**, जिससे यह transactional privacy की दिशा में एक promising development बनता है।

# Cryptocurrencies में Privacy के लिए Best Practices

## **Wallet Synchronization Techniques**

Privacy और security बनाए रखने के लिए wallets को blockchain के साथ synchronize करना महत्वपूर्ण है। दो methods विशेष रूप से उपयोगी हैं:

- **Full node**: पूरी blockchain download करके, full node maximum privacy सुनिश्चित करता है। अब तक किए गए सभी transactions locally store होते हैं, जिससे adversaries के लिए यह पहचानना असंभव हो जाता है कि user किन transactions या addresses में रुचि रखता है।
- **Client-side block filtering**: इस method में blockchain के प्रत्येक block के लिए filters बनाए जाते हैं, जिससे wallets network observers के सामने अपनी specific interests उजागर किए बिना relevant transactions की पहचान कर सकते हैं। Lightweight wallets इन filters को download करते हैं और user के addresses के साथ match मिलने पर ही full blocks fetch करते हैं।

## **Anonymity के लिए Tor का उपयोग**

चूंकि Bitcoin peer-to-peer network पर operate करता है, इसलिए अपने IP address को छिपाने के लिए Tor का उपयोग recommended है। इससे network के साथ interact करते समय privacy बेहतर होती है।

## **Address Reuse को रोकना**

Privacy की सुरक्षा के लिए प्रत्येक transaction के लिए एक नया address उपयोग करना महत्वपूर्ण है। Addresses को reuse करने से transactions को एक ही entity से link करके privacy compromise हो सकती है। Modern wallets अपने design के माध्यम से address reuse को हतोत्साहित करते हैं।

## **Transaction Privacy के लिए Strategies**

- **Multiple transactions**: किसी payment को कई transactions में split करने से transaction amount अस्पष्ट हो सकता है और privacy attacks को रोका जा सकता है।
- **Change avoidance**: ऐसे transactions चुनना जिनमें change outputs की आवश्यकता न हो, change detection methods को बाधित करके privacy बेहतर करता है।
- **Multiple change outputs**: यदि change से बचना संभव न हो, तो multiple change outputs generate करने से privacy में सुधार हो सकता है।

# **Monero: Anonymity का Beacon**

Monero को transaction privacy को प्राथमिकता देने के लिए design किया गया है।

# **Ethereum: Gas और Transactions**

## **Gas को समझना**

Gas Ethereum पर operations execute करने के लिए आवश्यक computational effort को मापता है और इसकी कीमत **gwei** में निर्धारित होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाला transaction gas limit और base fee के साथ priority fee भी शामिल करता है, जो validator inclusion को incentivize करती है। Users max fee set कर सकते हैं ताकि वे अधिक भुगतान न करें; अतिरिक्त राशि refund कर दी जाती है।<sup>[[5]](#references)</sup>

## **Transactions को Execute करना**

Ethereum में transactions में एक sender और recipient शामिल होते हैं, जो user या smart contract addresses हो सकते हैं। इनके लिए fee आवश्यक होती है और इन्हें किसी block में शामिल किया जाना चाहिए। Transaction में essential information में recipient, sender's signature, value, optional data, gas limit और fees शामिल होते हैं। उल्लेखनीय रूप से, sender's address signature से deduce किया जाता है, इसलिए transaction data में इसे शामिल करने की आवश्यकता नहीं होती।<sup>[[4]](#references)</sup>

ये practices और mechanisms उन सभी लोगों के लिए foundational हैं जो privacy और security को प्राथमिकता देते हुए cryptocurrencies के साथ engage करना चाहते हैं।

## Value-Centric Web3 Red Teaming

- Value-bearing components (signers, oracles, bridges, automation) की inventory बनाएं, ताकि यह समझा जा सके कि funds को कौन move कर सकता है और कैसे।
- प्रत्येक component को relevant MITRE AADAPT tactics से map करें, ताकि privilege escalation paths उजागर हो सकें।
- Impact को validate करने और exploitable preconditions को document करने के लिए flash-loan/oracle/credential/cross-chain attack chains का rehearsal करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UIs के supply-chain tampering से signing से ठीक पहले EIP-712 payloads mutate किए जा सकते हैं, जिससे delegatecall-based proxy takeovers के लिए valid signatures harvest की जा सकती हैं (जैसे Safe masterCopy का slot-0 overwrite)।

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

जब कोई prover किसी claim को attest करने के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier केवल यह जान रहा होता है कि **guest program जैसा लिखा गया था, उसी प्रकार execute हुआ**। यदि guest में **unsafe deserialization**, **undefined behavior** या **missing semantic constraints** मौजूद हों, तो malicious prover ऐसा proof generate कर सकता है जो verify हो जाए, जबकि **public metrics या claimed invariant false हों**।<sup>[[7]](#references)</sup>

### Proof guests के अंदर Unsafe deserialization

- Private witness/circuit bytes को **untrusted attacker input** मानें, भले ही वे proof द्वारा hidden हों।
- जब तक bytes को out-of-band पहले से validate न किया गया हो, उन्हें `rkyv::access_unchecked` जैसे unchecked helpers से deserialize करने से बचें।
- Untrusted serialized data से load किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access को प्रभावित करने से पहले validate किया जाना चाहिए।

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
यदि `op.kind` जैसा कोई field एक enum है और attacker एक **out-of-range discriminant** inject कर सकता है, तो उस value पर होने वाला हर downstream `match` संदिग्ध हो जाता है।

### Jump-table / UB counter bypass

यदि Rust किसी बड़े `match` को **jump table** में बदल देता है, तो invalid enum discriminant के कारण **undefined control flow** उत्पन्न हो सकता है। एक खतरनाक pattern इस प्रकार है:<sup>[[7]](#references)[[9]](#references)</sup>

1. एक `match` **security-critical counters/constraints** को update करता है।
2. दूसरा `match` **real instruction semantics** को execute करता है।
3. एक out-of-range discriminant पहली jump table के बाद के स्थान को index करता है और दूसरी jump table से जुड़े code पर पहुंच जाता है।

परिणाम: operation फिर भी execute होता है, लेकिन accounting path skip हो जाता है। zkVM में इससे ऐसे proofs forge किए जा सकते हैं जो असंभव metrics report करते हैं, जैसे कम gates, कम expensive operations या अन्य falsified bounded resources।

Review checklist:

- Witness/private input से deserialized attacker-controlled enums खोजें।
- उसी opcode/kind field पर repeated `match` statements की जांच करें।
- `unsafe` + unchecked deserialization + large opcode dispatch के संयोजन को high-risk मानें।
- आवश्यकता पड़ने पर emitted binary को reverse engineer करें; jump-table layout source से अधिक महत्वपूर्ण हो सकता है।

### Reversible/specialized interpreters में missing semantic constraints

केवल memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof द्वारा enforce किया जाना है।

Reversible/quantum-like instruction sets के लिए सुनिश्चित करें कि जिन operands का distinct होना आवश्यक है, उन्हें वास्तव में distinct होने के लिए constrained किया गया हो। इस प्रकार implement किया गया Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
असुरक्षित हो जाता है यदि guest अस्वीकार नहीं करता:
```text
op.q_control1 == op.q_control2 == op.q_target
```
उस स्थिति में transition इस रूप में सिमट जाता है:
```text
q = q ^ (q & q) = 0
```
यह एक **deterministic reset primitive** बनाता है, reversibility की धारणाओं को तोड़ता है और कम लागत वाली non-intended computations को सक्षम करता है। उन proof systems में जो resource usage का attestation करते हैं, इससे attackers functional checks को पूरा करते हुए उस cost model को bypass कर सकते हैं, जिसे verifier लागू किया हुआ मानता है।

### ZK systems में क्या test करें

- सभी guest parsers को malformed witness/private-input encodings के साथ fuzz करें।
- opcode dispatch से पहले enum range validation सुनिश्चित करें।
- operand aliasing और अन्य invalid instruction forms के लिए semantic checks जोड़ें।
- reported/public counters की तुलना एक independent reference implementation से करें।
- याद रखें कि यदि guest program buggy है, तो एक valid proof भी **गलत statement** को prove कर सकता है।

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs के practical exploitation (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps) पर research कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

उन multi-asset weighted pools के लिए, जो virtual balances को cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, अध्ययन करें:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [स्टेक का प्रमाण - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key और Private Key की व्याख्या - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [multi-signature transactions क्या हैं? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas और fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - हमने Google's zero-knowledge proof of quantum cryptanalysis को हरा दिया](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Elliptic Curve Cryptocurrencies को Quantum Vulnerabilities से सुरक्षित करना: Resource Estimates और Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
