# Blockchain और Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **Smart Contracts** ऐसे प्रोग्राम होते हैं जो कुछ शर्तें पूरी होने पर blockchain पर चलते हैं और मध्यस्थों के बिना समझौतों के निष्पादन को स्वचालित करते हैं।
- **Decentralized Applications (dApps)**, smart contracts पर आधारित होते हैं और इनमें उपयोगकर्ता-अनुकूल front-end तथा पारदर्शी, ऑडिट किए जा सकने वाला back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल मुद्रा के रूप में काम करते हैं, जबकि tokens विशिष्ट संदर्भों में मूल्य या स्वामित्व दर्शाते हैं।
  - **Utility Tokens** सेवाओं का उपयोग करने की अनुमति देते हैं, जबकि **Security Tokens** किसी परिसंपत्ति के स्वामित्व को दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** का अर्थ क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations है।

## Consensus Mechanisms

Consensus mechanisms blockchain पर लेन-देन के सुरक्षित और सर्वसम्मत सत्यापन को सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेन-देन के सत्यापन के लिए computational power पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators को एक निश्चित मात्रा में tokens रखने होते हैं, जिससे PoW की तुलना में ऊर्जा की खपत कम होती है।<sup>[[1]](#references)</sup>

## Bitcoin की मूल बातें

### लेन-देन

Bitcoin लेन-देन में addresses के बीच धनराशि स्थानांतरित की जाती है। लेन-देन को digital signatures के माध्यम से सत्यापित किया जाता है, जिससे यह सुनिश्चित होता है कि केवल private key का स्वामी ही स्थानांतरण शुरू कर सकता है।<sup>[[2]](#references)</sup>

#### मुख्य घटक:

- **Multisignature Transactions** में लेन-देन को अधिकृत करने के लिए कई signatures की आवश्यकता होती है।<sup>[[3]](#references)</sup>
- लेन-देन में **inputs** (धनराशि का स्रोत), **outputs** (गंतव्य), **fees** (miners को दिए जाते हैं) और **scripts** (लेन-देन के नियम) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य किसी channel में कई लेन-देन करने की अनुमति देकर Bitcoin की scalability को बेहतर बनाना है। केवल अंतिम स्थिति blockchain पर प्रसारित होती है।

## Bitcoin की गोपनीयता संबंधी चिंताएँ

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks, लेन-देन के पैटर्न का फ़ायदा उठाते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच लेन-देन के संबंधों को छिपाकर गुमनामी बढ़ाती हैं।

## गुमनाम रूप से Bitcoins प्राप्त करना

इसके तरीकों में नकद लेन-देन, mining और mixers का उपयोग शामिल है। **CoinJoin** कई लेन-देन को मिलाकर उनका पता लगाना कठिन बनाता है, जबकि **PayJoin** अधिक गोपनीयता के लिए CoinJoins को सामान्य लेन-देन जैसा दिखाता है।

# Bitcoin Privacy Attacks का सारांश

Bitcoin की दुनिया में, लेन-देन की गोपनीयता और उपयोगकर्ताओं की गुमनामी अक्सर चिंता का विषय होती है। Bitcoin की गोपनीयता से समझौता करने के लिए हमलावर जिन कई सामान्य तरीकों का उपयोग कर सकते हैं, उनका सरल विवरण यहाँ दिया गया है।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

अलग-अलग उपयोगकर्ताओं के inputs को एक ही लेन-देन में मिलाना आम तौर पर दुर्लभ है, क्योंकि इसमें जटिलता होती है। इसलिए, **एक ही लेन-देन में मौजूद दो input addresses को अक्सर एक ही स्वामी का माना जाता है**।

## **UTXO Change Address Detection**

UTXO, यानी **Unspent Transaction Output**, को किसी लेन-देन में पूरी तरह खर्च करना होता है। यदि इसका केवल कुछ हिस्सा किसी दूसरे address पर भेजा जाता है, तो बची हुई राशि एक नए change address पर जाती है। देखने वाले यह मान सकते हैं कि यह नया address भेजने वाले का है, जिससे उसकी गोपनीयता से समझौता होता है।

### उदाहरण

इसे कम करने के लिए mixing services या कई addresses का उपयोग स्वामित्व को छिपाने में मदद कर सकता है।

## **Social Networks & Forums पर जानकारी का खुलासा**

उपयोगकर्ता कभी-कभी अपने Bitcoin addresses ऑनलाइन साझा करते हैं, जिससे **उस address को उसके स्वामी से जोड़ना आसान हो जाता है**।

## **Transaction Graph Analysis**

लेन-देन को graphs के रूप में दिखाया जा सकता है, जिससे धनराशि के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित संबंध सामने आ सकते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले लेन-देन का विश्लेषण करके अनुमान लगाता है कि कौन-सा output भेजने वाले को लौटाया गया change है।

### उदाहरण

```bash
2 btc --> 4 btc
3 btc     1 btc
```

यदि अधिक inputs जोड़ने से change output किसी भी एक input से बड़ा हो जाता है, तो heuristic भ्रमित हो सकती है।

## **Forced Address Reuse**

हमलावर पहले इस्तेमाल किए गए addresses पर छोटी रकम भेज सकते हैं, इस उम्मीद में कि प्राप्तकर्ता भविष्य के लेन-देन में इन रकमों को अन्य inputs के साथ जोड़ देगा, जिससे addresses आपस में link हो जाएंगे।

### Wallet का सही व्यवहार

इस privacy leak से बचने के लिए Wallets को पहले से इस्तेमाल किए गए, खाली addresses पर प्राप्त coins का इस्तेमाल नहीं करना चाहिए।

## **Blockchain Analysis की अन्य तकनीकें**

- **सटीक भुगतान राशि:** बिना change वाले लेन-देन संभवतः एक ही उपयोगकर्ता के स्वामित्व वाले दो addresses के बीच होते हैं।
- **गोल संख्याएँ:** लेन-देन में गोल संख्या होने से संकेत मिलता है कि यह भुगतान है और गैर-गोल output संभवतः change है।
- **Wallet Fingerprinting:** अलग-अलग wallets में लेन-देन बनाने के अनूठे पैटर्न होते हैं, जिनसे analysts इस्तेमाल किए गए software और संभवतः change address की पहचान कर सकते हैं।
- **राशि और समय का सहसंबंध:** लेन-देन का समय या राशि उजागर करने से लेन-देन trace किए जा सकते हैं।

## **Traffic Analysis**

Network traffic की निगरानी करके हमलावर लेन-देन या blocks को IP addresses से जोड़ सकते हैं, जिससे उपयोगकर्ता की privacy प्रभावित होती है। यह विशेष रूप से तब होता है जब कोई entity कई Bitcoin nodes संचालित करती है, जिससे लेन-देन की निगरानी करने की उसकी क्षमता बढ़ जाती है।

## और जानकारी

Privacy attacks और defenses की व्यापक सूची के लिए [Bitcoin Wiki पर Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin लेन-देन

## Anonymous तरीके से Bitcoins प्राप्त करने के उपाय

- **नकद लेन-देन**: नकद के ज़रिए bitcoin प्राप्त करना।
- **नकद के विकल्प**: Gift cards खरीदना और उन्हें online bitcoin के बदले exchange करना।
- **Mining**: Bitcoins कमाने का सबसे निजी तरीका mining है, खासकर अकेले mining करने पर, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools की जानकारी](https://en.bitcoin.it/wiki/Pooled_mining)
- **चोरी**: सैद्धांतिक रूप से, bitcoin चुराना इसे anonymous तरीके से प्राप्त करने का एक और उपाय हो सकता है, हालाँकि यह गैर-कानूनी है और इसकी सलाह नहीं दी जाती।

## Mixing Services

Mixing service का इस्तेमाल करके, उपयोगकर्ता **bitcoins भेज सकता है** और बदले में **अलग bitcoins प्राप्त कर सकता है**, जिससे मूल मालिक का पता लगाना मुश्किल हो जाता है। हालाँकि, इसके लिए service पर भरोसा करना पड़ता है कि वह logs न रखे और वास्तव में bitcoins लौटाए। Mixing के अन्य विकल्पों में Bitcoin casinos शामिल हैं।

## CoinJoin

**CoinJoin** अलग-अलग उपयोगकर्ताओं के कई लेन-देन को एक में मिला देता है, जिससे inputs को outputs से मिलाने की कोशिश करने वाले किसी भी व्यक्ति के लिए यह प्रक्रिया जटिल हो जाती है। प्रभावी होने के बावजूद, अनूठे आकार वाले inputs और outputs के लेन-देन trace किए जा सकते हैं।

CoinJoin का इस्तेमाल करने वाले संभावित उदाहरण लेन-देन में `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` शामिल हैं।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। Deposits को बाद में किए गए withdrawals से अलग करने वाले Ethereum smart-contract mixer के लिए [Tornado Cash](https://tornado.cash) देखें।

## PayJoin

CoinJoin का एक रूप, **PayJoin** (या P2EP), दो पक्षों (जैसे, ग्राहक और व्यापारी) के बीच के लेन-देन को सामान्य लेन-देन जैसा दिखाता है, जिसमें CoinJoin की पहचान बताने वाले समान outputs नहीं होते। इससे इसका पता लगाना बेहद मुश्किल हो जाता है और यह transaction surveillance entities द्वारा इस्तेमाल किए जाने वाले common-input-ownership heuristic को अमान्य कर सकता है।

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

ऊपर दिए गए जैसे transactions PayJoin हो सकते हैं, जो standard bitcoin transactions से अलग पहचाने बिना privacy को बेहतर बनाते हैं।

**PayJoin का उपयोग पारंपरिक surveillance methods को काफ़ी हद तक बाधित कर सकता है**, जिससे यह transactional privacy की दिशा में एक आशाजनक विकास बन जाता है।

# Cryptocurrencies में Privacy के लिए सर्वोत्तम प्रथाएँ

## **Wallet Synchronization Techniques**

Privacy और security बनाए रखने के लिए wallets को blockchain के साथ synchronize करना महत्वपूर्ण है। दो methods उल्लेखनीय हैं:

- **Full node**: पूरी blockchain डाउनलोड करके, full node अधिकतम privacy सुनिश्चित करता है। अब तक किए गए सभी transactions स्थानीय रूप से संग्रहित होते हैं, जिससे adversaries के लिए यह पहचानना असंभव हो जाता है कि user किन transactions या addresses में रुचि रखता है।
- **Client-side block filtering**: इस method में blockchain के हर block के लिए filters बनाए जाते हैं, जिससे wallets network observers के सामने अपनी विशिष्ट रुचियाँ उजागर किए बिना प्रासंगिक transactions पहचान सकते हैं। Lightweight wallets ये filters डाउनलोड करते हैं और केवल तभी full blocks प्राप्त करते हैं, जब user के addresses से कोई match मिलता है।

## **Anonymity के लिए Tor का उपयोग**

चूँकि Bitcoin peer-to-peer network पर काम करता है, इसलिए अपना IP address छिपाने के लिए Tor का उपयोग करने की सलाह दी जाती है। इससे network के साथ interact करते समय privacy बेहतर होती है।

## **Address Reuse रोकना**

Privacy सुरक्षित रखने के लिए हर transaction में नया address इस्तेमाल करना ज़रूरी है। Addresses को दोबारा इस्तेमाल करने से transactions एक ही entity से जुड़ सकते हैं और privacy से समझौता हो सकता है। आधुनिक wallets का design address reuse को हतोत्साहित करता है।

## **Transaction Privacy की रणनीतियाँ**

- **Multiple transactions**: Payment को कई transactions में बाँटने से transaction की राशि छिप सकती है और privacy attacks विफल हो सकते हैं।
- **Change से बचना**: ऐसे transactions चुनना जिनमें change outputs की ज़रूरत न हो, change detection methods को बाधित करके privacy बेहतर करता है।
- **Multiple change outputs**: यदि change से बचना संभव न हो, तो कई change outputs बनाने से भी privacy बेहतर हो सकती है।

# **Monero: Anonymity का प्रतीक**

Monero को transaction privacy को प्राथमिकता देने के लिए बनाया गया है।

# **Ethereum: Gas और Transactions**

## **Gas को समझना**

Gas, Ethereum पर operations निष्पादित करने के लिए आवश्यक computational effort को मापता है और इसकी कीमत **gwei** में होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाले transaction में gas limit और base fee होती है, साथ ही validator को उसे शामिल करने के लिए प्रोत्साहित करने हेतु priority fee भी होती है। Users अधिकतम शुल्क तय कर सकते हैं, ताकि वे ज़रूरत से ज़्यादा भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।<sup>[[5]](#references)</sup>

## **Transactions निष्पादित करना**

Ethereum में transactions में sender और recipient शामिल होते हैं, जो user या smart contract addresses हो सकते हैं। इनके लिए fee आवश्यक होती है और इन्हें किसी block में शामिल किया जाना चाहिए। Transaction की आवश्यक जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit और fees शामिल हैं। विशेष रूप से, sender का address signature से निकाला जाता है, इसलिए transaction data में इसकी ज़रूरत नहीं होती।<sup>[[4]](#references)</sup>

ये practices और mechanisms उन सभी लोगों के लिए बुनियादी हैं जो privacy और security को प्राथमिकता देते हुए cryptocurrencies का उपयोग करना चाहते हैं।

## Value-केंद्रित Web3 Red Teaming

- यह समझने के लिए कि कौन funds को स्थानांतरित कर सकता है और कैसे, value रखने वाले components (signers, oracles, bridges, automation) की सूची बनाएँ।
- privilege escalation paths उजागर करने के लिए हर component को प्रासंगिक MITRE AADAPT tactics से map करें।
- प्रभाव की पुष्टि करने और exploit की जा सकने वाली preconditions का दस्तावेज़ बनाने के लिए flash-loan/oracle/credential/cross-chain attack chains का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow से समझौता

- Wallet UIs के supply-chain tampering से signing से ठीक पहले EIP-712 payloads बदले जा सकते हैं, जिससे delegatecall-based proxy takeovers (जैसे Safe masterCopy का slot-0 overwrite) के लिए valid signatures हासिल किए जा सकते हैं।

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Smart-account की आम failure modes में `EntryPoint` access control को bypass करना, unsigned gas fields, stateful validation, ERC-1271 replay और validation के बाद revert के ज़रिए fee-drain शामिल हैं।

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suites में blind spots खोजने के लिए mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

जब कोई prover किसी दावे की पुष्टि के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier को केवल यह पता चलता है कि **guest program लिखे गए निर्देशों के अनुसार निष्पादित हुआ**। यदि guest में **unsafe deserialization**, **undefined behavior**, या **missing semantic constraints** हों, तो malicious prover ऐसा proof बना सकता है जो verify तो हो जाए, जबकि **public metrics या दावा किया गया invariant गलत हो**।<sup>[[7]](#references)</sup>

### Proof guests के भीतर unsafe deserialization

- Private witness/circuit bytes को **untrusted attacker input** मानें, भले ही वे proof से छिपे हों।
- उन्हें `rkyv::access_unchecked` जैसे बिना जाँच वाले helpers से deserialize न करें, जब तक कि bytes को पहले किसी बाहरी प्रक्रिया से validate न किया गया हो।
- Untrusted serialized data से लोड किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access पर प्रभाव डालने से पहले validate करना ज़रूरी है।

व्यावहारिक audit pattern:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

यदि `op.kind` जैसा कोई field enum है और attacker उसमें **out-of-range discriminant** inject कर सकता है, तो उस value पर होने वाला हर downstream `match` संदिग्ध हो जाता है।

### Jump-table / UB counter bypass

यदि Rust किसी बड़े `match` को **jump table** में बदलता है, तो invalid enum discriminant से **undefined control flow** हो सकता है। एक खतरनाक pattern है:<sup>[[7]](#references)[[9]](#references)</sup>

1. एक `match` **security-critical counters/constraints** अपडेट करता है।
2. दूसरा `match` **वास्तविक instruction semantics** लागू करता है।
3. Out-of-range discriminant पहली jump table के आगे index करता है और दूसरी table से जुड़े code पर पहुंच जाता है।

परिणाम: operation फिर भी execute होता है, लेकिन accounting path skip हो जाता है। zkVM में इससे ऐसे proofs forge किए जा सकते हैं जो असंभव metrics रिपोर्ट करते हैं, जैसे कम gates, कम expensive operations या अन्य falsified bounded resources।

Review checklist:

- Witness/private input से deserialize किए गए attacker-controlled enums खोजें।
- एक ही opcode/kind field पर बार-बार होने वाले `match` statements की जांच करें।
- `unsafe` + unchecked deserialization + large opcode dispatch के संयोजन को high-risk मानें।
- जरूरत पड़ने पर emitted binary को reverse engineer करें; jump-table layout, source से अधिक महत्वपूर्ण हो सकता है।

### Reversible/specialized interpreters में semantic constraints का अभाव

सिर्फ memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof को लागू करना है।

Reversible/quantum-like instruction sets के लिए सुनिश्चित करें कि जिन operands का distinct होना जरूरी है, उन्हें वास्तव में distinct होने के लिए constrain किया गया है। Toffoli/CCX-जैसा operation, जिसे इस तरह implement किया गया हो:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

यदि guest इसे अस्वीकार नहीं करता, तो यह असुरक्षित हो जाता है:

```text
op.q_control1 == op.q_control2 == op.q_target
```

उस स्थिति में संक्रमण सिमटकर यह बन जाता है:

```text
q = q ^ (q & q) = 0
```

यह एक **deterministic reset primitive** बनाता है, जो reversibility की धारणाओं को तोड़ता है और कम लागत वाली unintended computations को संभव बनाता है। ऐसे proof systems में, जो resource usage को attest करते हैं, हमलावर इससे functional checks पास कर सकते हैं, जबकि verifier जिस cost model को लागू मानता है, उसे दरकिनार कर सकते हैं।

### ZK systems में क्या जाँचें

- सभी guest parsers को malformed witness/private-input encodings के साथ fuzz करें।
- opcode dispatch से पहले enum range validation की पुष्टि करें।
- operand aliasing और instruction के अन्य अमान्य रूपों के लिए semantic checks जोड़ें।
- रिपोर्ट किए गए/public counters की तुलना स्वतंत्र reference implementation से करें।
- याद रखें कि guest program में bug होने पर valid proof भी **गलत statement** साबित कर सकता है।

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM का शोषण

यदि आप DEXes और AMMs के व्यावहारिक शोषण (Uniswap v4 hooks, rounding/precision का दुरुपयोग, flash-loan से threshold-crossing swaps को बढ़ाना) पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

ऐसे multi-asset weighted pools के लिए, जो virtual balances को cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, यह देखें:

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
- [7] [Trail of Bits - हमने Google के zero-knowledge proof of quantum cryptanalysis को हरा दिया](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum Vulnerabilities के विरुद्ध Elliptic Curve Cryptocurrencies को सुरक्षित करना: Resource Estimates और Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
