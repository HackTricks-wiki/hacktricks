# Blockchain और Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **Smart Contracts** ऐसे प्रोग्राम होते हैं जो कुछ शर्तें पूरी होने पर blockchain पर चलते हैं और बिचौलियों के बिना समझौतों के क्रियान्वयन को स्वचालित करते हैं।
- **Decentralized Applications (dApps)**, smart contracts पर आधारित होते हैं और इनमें उपयोगकर्ता-अनुकूल front-end तथा पारदर्शी, ऑडिट किए जा सकने वाला back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल मुद्रा के रूप में काम करते हैं, जबकि tokens किसी विशिष्ट संदर्भ में मूल्य या स्वामित्व दर्शाते हैं।
  - **Utility Tokens** सेवाओं का उपयोग करने की सुविधा देते हैं, और **Security Tokens** किसी परिसंपत्ति का स्वामित्व दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को कहते हैं।

## Consensus Mechanisms

Consensus mechanisms blockchain पर लेन-देन के सुरक्षित और सर्वसम्मत सत्यापन को सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेन-देन सत्यापित करने के लिए computational power पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators को एक निश्चित मात्रा में tokens अपने पास रखने होते हैं, जिससे PoW की तुलना में ऊर्जा की खपत कम होती है।<sup>[[1]](#references)</sup>

## Bitcoin की बुनियादी बातें

### Transactions

Bitcoin transactions में addresses के बीच funds ट्रांसफ़र किए जाते हैं। Transactions को digital signatures के ज़रिए validate किया जाता है, जिससे यह सुनिश्चित होता है कि केवल private key का मालिक ही ट्रांसफ़र शुरू कर सकता है।<sup>[[2]](#references)</sup>

#### मुख्य घटक:

- **Multisignature Transactions** में transaction को अधिकृत करने के लिए कई signatures की आवश्यकता होती है।<sup>[[3]](#references)</sup>
- Transactions में **inputs** (funds का स्रोत), **outputs** (गंतव्य), **fees** (miners को दिया गया शुल्क) और **scripts** (transaction के नियम) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य एक channel में कई transactions की अनुमति देकर Bitcoin की scalability बढ़ाना है। केवल अंतिम स्थिति blockchain पर प्रसारित की जाती है।

## Bitcoin की गोपनीयता संबंधी चिंताएँ

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks, transaction patterns का फ़ायदा उठाते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच transaction links को छिपाकर anonymity बेहतर करती हैं।

## गुमनाम रूप से Bitcoins प्राप्त करना

इन तरीकों में नकद लेन-देन, mining और mixers का उपयोग शामिल है। **CoinJoin** traceability को जटिल बनाने के लिए कई transactions को मिलाता है, जबकि **PayJoin** बेहतर privacy के लिए CoinJoins को सामान्य transactions जैसा दिखाता है।

# Bitcoin Privacy Attacks का सारांश

Bitcoin की दुनिया में, transactions की privacy और उपयोगकर्ताओं की anonymity अक्सर चिंता का विषय होती हैं। यहाँ उन कई सामान्य तरीकों का सरल विवरण दिया गया है जिनसे attackers Bitcoin की privacy से समझौता कर सकते हैं।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

जटिलता के कारण, अलग-अलग उपयोगकर्ताओं के inputs का एक ही transaction में शामिल होना आम तौर पर दुर्लभ है। इसलिए, **एक ही transaction में मौजूद दो input addresses को अक्सर एक ही मालिक का माना जाता है**।

## **UTXO Change Address Detection**

UTXO, यानी **Unspent Transaction Output**, को किसी transaction में पूरी तरह खर्च करना होता है। अगर इसका केवल एक हिस्सा किसी दूसरे address पर भेजा जाता है, तो बाकी राशि एक नए change address पर जाती है। देखने वाले यह मान सकते हैं कि यह नया address भेजने वाले का है, जिससे privacy से समझौता हो सकता है।

### उदाहरण

इस जोखिम को कम करने के लिए mixing services का उपयोग करना या कई addresses रखना स्वामित्व को छिपाने में मदद कर सकता है।

## **Social Networks & Forums पर जानकारी का खुलासा**

कभी-कभी उपयोगकर्ता अपने Bitcoin addresses ऑनलाइन साझा करते हैं, जिससे **address को उसके मालिक से जोड़ना आसान हो जाता है**।

## **Transaction Graph Analysis**

Transactions को graphs के रूप में दिखाया जा सकता है। इससे funds के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित संबंध सामने आ सकते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले transactions का विश्लेषण करके यह अनुमान लगाती है कि कौन-सा output भेजने वाले को वापस मिलने वाला change है।

### उदाहरण

```bash
2 btc --> 4 btc
3 btc     1 btc
```

अगर अधिक inputs जोड़ने से change output किसी भी एक input से बड़ा हो जाता है, तो heuristic भ्रमित हो सकती है।

## **Forced Address Reuse**

Attackers पहले इस्तेमाल किए गए addresses पर छोटी रकम भेज सकते हैं, इस उम्मीद में कि recipient भविष्य के transactions में इन्हें अन्य inputs के साथ जोड़ देगा, जिससे addresses आपस में link हो जाएंगे।

### Wallet का सही व्यवहार

इस privacy leak से बचने के लिए Wallets को पहले इस्तेमाल किए जा चुके, खाली addresses पर प्राप्त coins का इस्तेमाल नहीं करना चाहिए।

## **Blockchain Analysis की अन्य तकनीकें**

- **भुगतान की सटीक रकम:** बिना change वाले transactions संभवतः एक ही user के स्वामित्व वाले दो addresses के बीच होते हैं।
- **गोल रकम:** किसी transaction में गोल रकम से संकेत मिलता है कि वह payment है; non-round output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction बनाने के अनूठे patterns होते हैं। इससे analysts इस्तेमाल किए गए software और संभवतः change address की पहचान कर सकते हैं।
- **रकम और समय का संबंध:** Transaction के समय या रकम का खुलासा करने से transactions को trace किया जा सकता है।

## **Traffic Analysis**

Network traffic की निगरानी करके attackers संभावित रूप से transactions या blocks को IP addresses से link कर सकते हैं, जिससे user privacy खतरे में पड़ सकती है। यह खास तौर पर तब होता है जब कोई entity कई Bitcoin nodes चलाती है, जिससे transactions की निगरानी करने की उसकी क्षमता बढ़ जाती है।

## अधिक जानकारी

Privacy attacks और बचाव की विस्तृत सूची के लिए [Bitcoin Wiki पर Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin Transactions

## Anonymous तरीके से Bitcoins पाने के तरीके

- **नकद लेन-देन**: नकद के ज़रिए bitcoin प्राप्त करना।
- **नकद के विकल्प**: Gift cards खरीदकर उन्हें online bitcoin के बदले exchange करना।
- **Mining**: Bitcoins कमाने का सबसे निजी तरीका mining है, खासकर अकेले mining करना, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools की जानकारी](https://en.bitcoin.it/wiki/Pooled_mining)
- **चोरी**: सैद्धांतिक रूप से, bitcoin चुराना उसे anonymous तरीके से पाने का एक और तरीका हो सकता है, हालांकि यह गैरकानूनी है और इसकी सलाह नहीं दी जाती।

## Mixing Services

Mixing service का इस्तेमाल करके user **bitcoins भेज** सकता है और बदले में **अलग bitcoins प्राप्त कर** सकता है, जिससे मूल owner को trace करना मुश्किल हो जाता है। लेकिन इसके लिए service पर भरोसा करना पड़ता है कि वह logs नहीं रखेगी और वास्तव में bitcoins लौटाएगी। Bitcoin casinos भी mixing का एक विकल्प हैं।

## CoinJoin

**CoinJoin** अलग-अलग users के कई transactions को एक में मिला देता है, जिससे inputs को outputs से match करना मुश्किल हो जाता है। प्रभावी होने के बावजूद, unique input और output sizes वाले transactions को अब भी संभावित रूप से trace किया जा सकता है।

ऐसे transactions के उदाहरण जिनमें CoinJoin का इस्तेमाल हुआ हो सकता है: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। Deposits को बाद में किए गए withdrawals से अलग रखने वाले Ethereum smart-contract mixer के लिए [Tornado Cash](https://tornado.cash) देखें।

## PayJoin

CoinJoin का एक रूप, **PayJoin** (या P2EP), दो पक्षों (जैसे, ग्राहक और व्यापारी) के बीच होने वाले transaction को सामान्य transaction जैसा दिखाता है, जिसमें CoinJoin के समान outputs की विशिष्ट विशेषता नहीं होती। इससे इसका पता लगाना बेहद मुश्किल हो जाता है और transaction surveillance entities द्वारा इस्तेमाल की जाने वाली common-input-ownership heuristic अमान्य हो सकती है।

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

ऊपर दिए गए जैसे transactions, PayJoin हो सकते हैं, जो standard bitcoin transactions से अलग पहचाने बिना गोपनीयता बढ़ाते हैं।

**PayJoin का उपयोग पारंपरिक surveillance तरीकों को काफ़ी बाधित कर सकता है**, जिससे transactional privacy की दिशा में यह एक आशाजनक विकास बन जाता है।

# क्रिप्टोकरेंसी में गोपनीयता के लिए सर्वोत्तम तरीके

## **Wallet Synchronization Techniques**

गोपनीयता और सुरक्षा बनाए रखने के लिए, wallets को blockchain के साथ synchronize करना ज़रूरी है। दो तरीके उल्लेखनीय हैं:

- **Full node**: पूरी blockchain डाउनलोड करके, full node अधिकतम गोपनीयता सुनिश्चित करता है। अब तक किए गए सभी transactions स्थानीय रूप से संग्रहीत होते हैं, जिससे adversaries के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किन transactions या addresses में दिलचस्पी रखता है।
- **Client-side block filtering**: इस तरीके में blockchain के हर block के लिए filters बनाए जाते हैं, जिससे wallets नेटवर्क observers के सामने अपनी विशिष्ट दिलचस्पी उजागर किए बिना प्रासंगिक transactions पहचान सकते हैं। Lightweight wallets ये filters डाउनलोड करते हैं और केवल तभी पूरे blocks प्राप्त करते हैं, जब उपयोगकर्ता के addresses से कोई match मिलता है।

## **गुमनामी के लिए Tor का उपयोग**

चूँकि Bitcoin peer-to-peer नेटवर्क पर काम करता है, इसलिए अपने IP address को छिपाने और नेटवर्क के साथ संवाद करते समय गोपनीयता बढ़ाने के लिए Tor का उपयोग करने की सलाह दी जाती है।

## **Address Reuse रोकना**

गोपनीयता सुरक्षित रखने के लिए, हर transaction में नया address इस्तेमाल करना ज़रूरी है। Addresses का दोबारा उपयोग transactions को एक ही entity से जोड़कर गोपनीयता से समझौता कर सकता है। आधुनिक wallets अपने design के ज़रिए address reuse को हतोत्साहित करते हैं।

## **Transaction Privacy के लिए रणनीतियाँ**

- **Multiple transactions**: भुगतान को कई transactions में बाँटने से transaction की राशि छिप सकती है और privacy attacks विफल हो सकते हैं।
- **Change से बचना**: ऐसे transactions चुनने से जिनमें change outputs की ज़रूरत न हो, change detection के तरीकों को बाधित करके गोपनीयता बढ़ती है।
- **Multiple change outputs**: अगर change से बचना संभव न हो, तो कई change outputs बनाने से भी गोपनीयता बेहतर हो सकती है।

# **Monero: गुमनामी का प्रतीक**

Monero को transaction privacy को प्राथमिकता देने के लिए बनाया गया है।

# **Ethereum: Gas और Transactions**

## **Gas को समझना**

Gas, Ethereum पर operations निष्पादित करने के लिए आवश्यक computational effort को मापता है और इसकी कीमत **gwei** में तय होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाले transaction में gas limit और base fee के साथ validator को इसे शामिल करने के लिए प्रोत्साहित करने वाली priority fee होती है। उपयोगकर्ता यह सुनिश्चित करने के लिए max fee तय कर सकते हैं कि वे ज़रूरत से ज़्यादा भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।<sup>[[5]](#references)</sup>

## **Transactions निष्पादित करना**

Ethereum में transactions में एक sender और recipient शामिल होते हैं, जो user या smart contract addresses हो सकते हैं। इनके लिए fee देना और block में शामिल होना ज़रूरी है। Transaction में आवश्यक जानकारी में recipient, sender का signature, value, optional data, gas limit और fees शामिल हैं। विशेष रूप से, sender का address signature से निकाला जाता है, इसलिए transaction data में उसे शामिल करने की आवश्यकता नहीं होती।<sup>[[4]](#references)</sup>

गोपनीयता और सुरक्षा को प्राथमिकता देते हुए क्रिप्टोकरेंसी के साथ काम करने के इच्छुक लोगों के लिए ये तरीके और तंत्र बुनियादी महत्व रखते हैं।

## Value-Centric Web3 Red Teaming

- यह समझने के लिए कि कौन funds को स्थानांतरित कर सकता है और कैसे, value रखने वाले components (signers, oracles, bridges, automation) की सूची बनाएँ।
- Privilege escalation paths उजागर करने के लिए हर component को संबंधित MITRE AADAPT tactics से map करें।
- प्रभाव की पुष्टि करने और exploit की जा सकने वाली पूर्वशर्तों का दस्तावेज़ बनाने के लिए flash-loan/oracle/credential/cross-chain attack chains का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI की supply-chain tampering, signing से ठीक पहले EIP-712 payloads को बदल सकती है और delegatecall-based proxy takeovers के लिए valid signatures हासिल कर सकती है (उदाहरण के लिए, Safe masterCopy का slot-0 overwrite)।

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

जब कोई prover किसी दावे की पुष्टि के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier को केवल यह पता चलता है कि **guest program लिखे गए निर्देशों के अनुसार चला**। यदि guest में **unsafe deserialization**, **undefined behavior**, या **semantic constraints की कमी** हो, तो malicious prover ऐसा proof बना सकता है जो verify हो जाए, जबकि **public metrics या दावा किया गया invariant गलत हो**।<sup>[[7]](#references)</sup>

### Proof guests के भीतर Unsafe deserialization

- Private witness/circuit bytes को **अविश्वसनीय attacker input** मानें, भले ही वे proof में छिपे हों।
- उन्हें `rkyv::access_unchecked` जैसे unchecked helpers से deserialize न करें, जब तक कि bytes को पहले किसी अलग प्रक्रिया से validate न किया गया हो।
- Untrusted serialized data से लोड किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access पर असर डालने से पहले validate करना ज़रूरी है।

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

1. एक `match` **security-critical counters/constraints** को अपडेट करता है।
2. दूसरा `match` **वास्तविक instruction semantics** को लागू करता है।
3. out-of-range discriminant पहली jump table के आगे index करता है और दूसरी jump table से जुड़े code पर पहुँच जाता है।

नतीजा: operation फिर भी execute होता है, लेकिन accounting path छूट जाता है। zkVM में इससे ऐसे forged proofs बन सकते हैं जो असंभव metrics की रिपोर्ट करें—जैसे कम gates, कम महँगे operations या अन्य झूठे bounded resources।

Review checklist:

- ऐसे attacker-controlled enums खोजें जिन्हें witness/private input से deserialize किया गया हो।
- एक ही opcode/kind field पर बार-बार होने वाले `match` statements की जाँच करें।
- `unsafe` + unchecked deserialization + बड़ा opcode dispatch—इस संयोजन को high-risk मानें।
- ज़रूरत पड़ने पर emitted binary को reverse engineer करें; jump-table layout, source से अधिक मायने रख सकता है।

### Reversible/specialized interpreters में semantic constraints का अभाव

सिर्फ memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof enforce करने के लिए बनाया गया है।

Reversible/quantum-like instruction sets के लिए, सुनिश्चित करें कि जिन operands का अलग होना ज़रूरी है, उन पर वास्तव में distinct होने की constraint लागू हो। उदाहरण के लिए, Toffoli/CCX-जैसे operation को इस तरह implement किया गया हो:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

यदि guest इसे अस्वीकार नहीं करता, तो यह असुरक्षित हो जाता है:

```text
op.q_control1 == op.q_control2 == op.q_target
```

ऐसे में संक्रमण सिमटकर यह बन जाता है:

```text
q = q ^ (q & q) = 0
```

यह एक **deterministic reset primitive** बनाता है, reversibility की धारणाओं को तोड़ता है और कम लागत वाली, अनपेक्षित computations को संभव बनाता है। ऐसे proof systems में, जो resource usage का प्रमाण देते हैं, इससे attackers verifier द्वारा लागू माने जा रहे cost model को दरकिनार करते हुए functional checks पास कर सकते हैं।

### ZK systems में क्या टेस्ट करें

- malformed witness/private-input encodings के साथ सभी guest parsers को fuzz करें।
- opcode dispatch से पहले enum range validation की पुष्टि करें।
- operand aliasing और instruction के अन्य अमान्य रूपों के लिए semantic checks जोड़ें।
- रिपोर्ट किए गए/public counters की तुलना किसी स्वतंत्र reference implementation से करें।
- याद रखें कि यदि guest program में bug है, तो valid proof भी **गलत statement** को साबित कर सकता है।

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold-crossing swaps) के व्यावहारिक exploitation पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

multi-asset weighted pools के लिए, जो virtual balances को cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, यह पढ़ें:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - विकिपीडिया](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key की व्याख्या - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Multi-signature transactions क्या हैं? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas और fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - हमने Google के zero-knowledge proof of quantum cryptanalysis को मात दी](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum Vulnerabilities के विरुद्ध Elliptic Curve Cryptocurrencies को सुरक्षित करना: Resource Estimates और Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
