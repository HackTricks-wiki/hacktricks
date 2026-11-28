# Blockchain और Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

इस अध्याय में blockchain की अवधारणाओं और on-chain सुरक्षा को शामिल किया गया है। किसी exposed Bitcoin peer के लिए, [Bitcoin P2P service enumeration](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md) से शुरुआत करें; browser frontend, wallet connection या off-chain backend के लिए [DApp pentesting](../../pentesting-web/dapps-DecentralizedApplications.md) का उपयोग करें। Cryptocurrency privacy operations और उनकी सीमाओं के लिए [cryptocurrency privacy chapter](../../privacy/cryptocurrency-privacy.md) देखें।

## मूल अवधारणाएँ

- **Smart Contracts** ऐसे प्रोग्राम हैं जो कुछ शर्तें पूरी होने पर blockchain पर execute होते हैं और बिना किसी मध्यस्थ के समझौतों के निष्पादन को स्वचालित करते हैं।
- **Decentralized Applications (dApps)** smart contracts पर आधारित होती हैं और इनमें user-friendly front-end तथा पारदर्शी, audit किए जा सकने वाला back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल मुद्रा के रूप में काम करते हैं, जबकि tokens विशिष्ट संदर्भों में मूल्य या स्वामित्व दर्शाते हैं।
  - **Utility Tokens** सेवाओं तक पहुँच देते हैं, जबकि **Security Tokens** asset ownership दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को कहते हैं।

Crypto markets में spot orders, futures, leverage और options से जुड़ी शब्दावली के लिए [Investment Terms](investment-terms.md) देखें। Perpetual protocols में funding-rate के दुरुपयोग के लिए [Perpetual Funding-Rate Exploitation](perpetual-funding-rate-exploitation.md) देखें।

## Consensus Mechanisms

Consensus mechanisms blockchain पर लेन-देन के सुरक्षित और सहमतिपूर्वक सत्यापन को सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेन-देन के सत्यापन के लिए computational power पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators को एक निश्चित मात्रा में tokens रखने होते हैं, जिससे PoW की तुलना में ऊर्जा की खपत कम होती है।<sup>[[1]](#references)</sup>

## Bitcoin की मूल बातें

### लेन-देन

Bitcoin transactions में addresses के बीच funds का हस्तांतरण होता है। Transactions को digital signatures के ज़रिए validate किया जाता है, जिससे यह सुनिश्चित होता है कि केवल private key का मालिक ही हस्तांतरण शुरू कर सकता है।<sup>[[2]](#references)</sup>

#### मुख्य घटक:

- **Multisignature Transactions** में किसी transaction को अधिकृत करने के लिए कई signatures की आवश्यकता होती है।<sup>[[3]](#references)</sup>
- Transactions में **inputs** (funds का स्रोत), **outputs** (गंतव्य), **fees** (miners को दी जाने वाली राशि) और **scripts** (transaction के नियम) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य एक channel में कई transactions की अनुमति देकर Bitcoin की scalability बढ़ाना है; blockchain पर केवल अंतिम स्थिति broadcast की जाती है।

## Bitcoin Privacy से जुड़ी चिंताएँ

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks transaction patterns का फायदा उठाते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ users के बीच transaction links को छिपाकर anonymity बेहतर करती हैं।

## गुमनाम रूप से Bitcoins प्राप्त करना

तरीकों में नकद लेन-देन, mining और mixers का उपयोग शामिल है। **CoinJoin** traceability को कठिन बनाने के लिए कई transactions को mix करता है, जबकि **PayJoin** अधिक privacy के लिए CoinJoins को सामान्य transactions जैसा दिखाता है।

# Bitcoin Privacy Attacks का सारांश

Bitcoin की दुनिया में transactions की privacy और users की anonymity अक्सर चिंता का विषय होती हैं। नीचे कुछ आम तरीकों का सरल विवरण दिया गया है जिनसे attackers Bitcoin privacy से समझौता कर सकते हैं।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

जटिलता के कारण, अलग-अलग users के inputs को एक ही transaction में जोड़ना आम तौर पर दुर्लभ होता है। इसलिए, **एक ही transaction में मौजूद दो input addresses को अक्सर एक ही owner का माना जाता है**।

## **UTXO Change Address Detection**

UTXO, यानी **Unspent Transaction Output**, को किसी transaction में पूरी तरह खर्च करना होता है। यदि उसका केवल एक हिस्सा किसी दूसरे address पर भेजा जाता है, तो बाकी राशि एक नए change address पर चली जाती है। Observers मान सकते हैं कि यह नया address sender का है, जिससे privacy से समझौता हो सकता है।

### उदाहरण

इस जोखिम को कम करने के लिए mixing services या कई addresses का उपयोग ownership को छिपाने में मदद कर सकता है।

## **Social Networks & Forums पर जानकारी उजागर होना**

Users कभी-कभी अपने Bitcoin addresses ऑनलाइन साझा करते हैं, जिससे **address को उसके owner से जोड़ना आसान हो जाता है**।

## **Transaction Graph Analysis**

Transactions को graphs के रूप में दिखाया जा सकता है, जिससे funds के प्रवाह के आधार पर users के बीच संभावित संबंध सामने आ सकते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले transactions का विश्लेषण करके अनुमान लगाती है कि कौन-सा output sender को लौटाया गया change है।

### उदाहरण

```bash
2 btc --> 4 btc
3 btc     1 btc
```

यदि अधिक inputs जोड़ने से change output किसी भी एक input से बड़ा हो जाता है, तो इससे heuristic भ्रमित हो सकती है।

## **Forced Address Reuse**

हमलावर पहले इस्तेमाल किए गए addresses पर छोटी रकम भेज सकते हैं, इस उम्मीद में कि प्राप्तकर्ता भविष्य के लेन-देन में इन्हें अन्य inputs के साथ जोड़ देगा, जिससे addresses आपस में link हो जाएंगे।

### सही Wallet व्यवहार

इस privacy leak से बचने के लिए wallets को पहले से इस्तेमाल किए गए, खाली addresses पर प्राप्त coins का उपयोग नहीं करना चाहिए।

## **Blockchain Analysis की अन्य तकनीकें**

- **सटीक भुगतान राशि:** जिन transactions में change नहीं होता, वे संभवतः एक ही उपयोगकर्ता के स्वामित्व वाले दो addresses के बीच होते हैं।
- **गोल संख्याएं:** किसी transaction में गोल संख्या इस बात का संकेत हो सकती है कि वह भुगतान है; गैर-गोल output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction बनाने के विशिष्ट पैटर्न होते हैं, जिनसे analysts इस्तेमाल किए गए software और संभावित change address की पहचान कर सकते हैं।
- **राशि और समय का सहसंबंध:** transaction के समय या राशि का खुलासा करने से transactions को trace करना संभव हो सकता है।

## **Traffic Analysis**

Network traffic की निगरानी करके हमलावर transactions या blocks को IP addresses से link कर सकते हैं, जिससे उपयोगकर्ता की privacy से समझौता हो सकता है। यह खास तौर पर तब होता है जब कोई इकाई कई Bitcoin nodes चलाती है, जिससे transactions की निगरानी करने की उसकी क्षमता बढ़ जाती है।

## अधिक जानकारी

Privacy attacks और बचावों की विस्तृत सूची के लिए [Bitcoin Wiki पर Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin Transactions

## गुमनाम रूप से Bitcoins पाने के तरीके

- **नकद लेन-देन**: नकद के ज़रिए bitcoin प्राप्त करना।
- **नकद के विकल्प**: Gift cards खरीदकर उन्हें online bitcoin के बदले exchange करना।
- **Mining**: bitcoins कमाने का सबसे निजी तरीका mining है, खासकर अकेले mining करना, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools की जानकारी](https://en.bitcoin.it/wiki/Pooled_mining)
- **चोरी**: सैद्धांतिक रूप से, bitcoin चुराना उसे गुमनाम रूप से हासिल करने का एक और तरीका हो सकता है, हालांकि यह गैरकानूनी है और इसकी सलाह नहीं दी जाती।

## Mixing Services

Mixing service का उपयोग करके, उपयोगकर्ता **bitcoins भेज सकता है** और बदले में **अलग bitcoins प्राप्त कर सकता है**, जिससे मूल मालिक को trace करना मुश्किल हो जाता है। हालांकि, इसके लिए इस भरोसे की ज़रूरत होती है कि service logs नहीं रखेगी और वास्तव में bitcoins वापस करेगी। Bitcoin casinos भी mixing के वैकल्पिक विकल्प हैं।

## CoinJoin

**CoinJoin** अलग-अलग उपयोगकर्ताओं के कई transactions को एक में मिला देता है, जिससे inputs को outputs से match करना मुश्किल हो जाता है। प्रभावी होने के बावजूद, अनोखे input और output आकार वाले transactions को फिर भी trace किया जा सकता है।

CoinJoin का उपयोग करने वाले संभावित उदाहरण transactions में `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` शामिल हैं।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। ऐसे Ethereum smart-contract mixer के लिए, जो deposits को बाद में होने वाली withdrawals से अलग करता है, [Tornado Cash](https://tornado.cash) देखें।

## PayJoin

CoinJoin का एक प्रकार, **PayJoin** (या P2EP), दो पक्षों (जैसे, ग्राहक और व्यापारी) के बीच के transaction को सामान्य transaction जैसा दिखाता है, जिसमें CoinJoin की पहचान बताने वाले समान outputs नहीं होते। इससे इसका पता लगाना बेहद मुश्किल हो जाता है और transaction surveillance entities द्वारा इस्तेमाल की जाने वाली common-input-ownership heuristic अमान्य हो सकती है।

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

ऊपर जैसे लेन-देन PayJoin हो सकते हैं, जो गोपनीयता बढ़ाते हैं और साथ ही सामान्य bitcoin लेन-देन से अलग पहचान में नहीं आते।

**PayJoin का उपयोग पारंपरिक निगरानी विधियों को काफ़ी बाधित कर सकता है**, इसलिए लेन-देन की गोपनीयता की दिशा में यह एक आशाजनक विकास है।

# क्रिप्टोकरेंसी में गोपनीयता के लिए सर्वोत्तम तरीके

## **Wallet Synchronization Techniques**

गोपनीयता और सुरक्षा बनाए रखने के लिए, वॉलेट को blockchain के साथ सिंक्रनाइज़ करना महत्वपूर्ण है। दो तरीके विशेष रूप से उल्लेखनीय हैं:

- **Full node**: पूरी blockchain डाउनलोड करने से full node अधिकतम गोपनीयता सुनिश्चित करता है। अब तक किए गए सभी लेन-देन स्थानीय रूप से संग्रहित होते हैं, जिससे विरोधियों के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किन लेन-देन या एड्रेस में रुचि रखता है।
- **Client-side block filtering**: इस तरीके में blockchain के हर block के लिए फ़िल्टर बनाए जाते हैं, जिससे वॉलेट नेटवर्क पर नज़र रखने वालों के सामने अपनी विशिष्ट रुचि उजागर किए बिना प्रासंगिक लेन-देन पहचान सकते हैं। Lightweight वॉलेट ये फ़िल्टर डाउनलोड करते हैं और उपयोगकर्ता के एड्रेस से मेल मिलने पर ही पूरे block डाउनलोड करते हैं।

## **गुमनामी के लिए Tor का उपयोग**

चूंकि Bitcoin peer-to-peer नेटवर्क पर चलता है, इसलिए अपने IP एड्रेस को छिपाने और नेटवर्क से जुड़ते समय गोपनीयता बढ़ाने के लिए Tor का उपयोग करने की सलाह दी जाती है।

## **एड्रेस का दोबारा उपयोग रोकना**

गोपनीयता सुरक्षित रखने के लिए हर लेन-देन में नया एड्रेस इस्तेमाल करना ज़रूरी है। एड्रेस का दोबारा उपयोग करने से लेन-देन एक ही इकाई से जुड़ सकते हैं और गोपनीयता से समझौता हो सकता है। आधुनिक वॉलेट अपने डिज़ाइन के ज़रिए एड्रेस का दोबारा उपयोग हतोत्साहित करते हैं।

## **लेन-देन की गोपनीयता के लिए रणनीतियां**

- **कई लेन-देन**: भुगतान को कई लेन-देन में बांटने से लेन-देन की राशि छिप सकती है और गोपनीयता पर होने वाले हमलों को विफल किया जा सकता है।
- **Change से बचना**: ऐसे लेन-देन चुनने से जिनमें change outputs की ज़रूरत न हो, change का पता लगाने के तरीकों में बाधा आती है और गोपनीयता बढ़ती है।
- **कई change outputs**: अगर change से बचना संभव न हो, तो कई change outputs बनाने से फिर भी गोपनीयता बेहतर हो सकती है।

# **Monero: गुमनामी की मिसाल**

Monero को लेन-देन की गोपनीयता को प्राथमिकता देने के लिए डिज़ाइन किया गया है।

# **Ethereum: Gas और लेन-देन**

## **Gas को समझना**

Gas, Ethereum पर ऑपरेशन चलाने के लिए आवश्यक कंप्यूटेशनल प्रयास को मापता है और इसकी कीमत **gwei** में तय होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाले लेन-देन में gas limit और base fee शामिल होते हैं, साथ ही validator को उसे शामिल करने के लिए प्रोत्साहित करने हेतु priority fee भी होती है। उपयोगकर्ता यह सुनिश्चित करने के लिए अधिकतम fee सेट कर सकते हैं कि वे ज़रूरत से ज़्यादा भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।<sup>[[5]](#references)</sup>

## **लेन-देन निष्पादित करना**

Ethereum में लेन-देन में sender और recipient शामिल होते हैं, जो user या smart contract एड्रेस हो सकते हैं। इनके लिए fee देना और block में शामिल होना आवश्यक है। लेन-देन की ज़रूरी जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit और fees शामिल हैं। ध्यान देने योग्य बात यह है कि sender का एड्रेस signature से निकाला जाता है, इसलिए इसे लेन-देन के data में शामिल करने की ज़रूरत नहीं होती।<sup>[[4]](#references)</sup>

गोपनीयता और सुरक्षा को प्राथमिकता देते हुए क्रिप्टोकरेंसी का उपयोग करने के इच्छुक किसी भी व्यक्ति के लिए ये तरीके और तंत्र बुनियादी हैं।

## मूल्य-केंद्रित Web3 Red Teaming

- यह समझने के लिए कि कौन funds स्थानांतरित कर सकता है और कैसे, value-bearing components (signers, oracles, bridges, automation) की सूची बनाएं।
- privilege escalation के रास्ते उजागर करने के लिए हर component को प्रासंगिक MITRE AADAPT tactics से मैप करें।
- प्रभाव की पुष्टि करने और exploitable preconditions दर्ज करने के लिए flash-loan/oracle/credential/cross-chain attack chains का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow से समझौता

- Wallet UI में supply-chain tampering, signing से ठीक पहले EIP-712 payloads में बदलाव करके delegatecall-आधारित proxy takeovers के लिए मान्य signatures हासिल कर सकती है (उदाहरण के लिए, Safe masterCopy का slot-0 overwrite)।

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Smart-account की आम विफलताओं में `EntryPoint` access control को bypass करना, unsigned gas fields, stateful validation, ERC-1271 replay और validation के बाद revert के ज़रिए fee-drain शामिल हैं।

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract सुरक्षा

- Test suites में blind spots खोजने के लिए mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest की अखंडता

जब कोई prover किसी दावे की पुष्टि के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier को केवल यह पता चलता है कि **guest program को लिखे गए तरीके से चलाया गया**। यदि guest में **unsafe deserialization**, **undefined behavior**, या **semantic constraints की कमी** है, तो malicious prover ऐसा proof बना सकता है जो verify हो जाए, जबकि **public metrics या दावा किया गया invariant गलत हो**।<sup>[[7]](#references)</sup>

### Proof guests के अंदर unsafe deserialization

- Private witness/circuit bytes को **untrusted attacker input** मानें, भले ही वे proof से छिपे हों।
- इन्हें `rkyv::access_unchecked` जैसे unchecked helpers से deserialize न करें, जब तक bytes को पहले out-of-band validate न किया गया हो।
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

1. एक `match`, **security-critical counters/constraints** को update करता है।
2. दूसरा `match`, **वास्तविक instruction semantics** लागू करता है।
3. out-of-range discriminant पहली jump table के past index करता है और दूसरी table से जुड़े code पर पहुँच जाता है।

नतीजा: operation फिर भी execute होता है, लेकिन accounting path छूट जाता है। zkVM में इससे ऐसे forged proofs बनाए जा सकते हैं जो असंभव metrics रिपोर्ट करते हैं, जैसे कम gates, कम expensive operations या अन्य falsified bounded resources।

Review checklist:

- Witness/private input से deserialized attacker-controlled enums खोजें।
- एक ही opcode/kind field पर बार-बार होने वाले `match` statements की जाँच करें।
- `unsafe` + unchecked deserialization + बड़े opcode dispatch के संयोजन को high-risk मानें।
- ज़रूरत पड़ने पर emitted binary को reverse engineer करें; jump-table layout, source से ज़्यादा मायने रख सकता है।

### Reversible/specialized interpreters में semantic constraints का अभाव

केवल memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof लागू करने के लिए है।

Reversible/quantum-like instruction sets के लिए, सुनिश्चित करें कि जिन operands का distinct होना ज़रूरी है, उन पर वास्तव में distinct होने की constraint लगाई गई है। Toffoli/CCX-जैसा operation, जिसे इस तरह implement किया गया हो:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

असुरक्षित हो जाता है यदि गेस्ट अस्वीकार नहीं करता:

```text
op.q_control1 == op.q_control2 == op.q_target
```

उस स्थिति में संक्रमण इस रूप में बदल जाता है:

```text
q = q ^ (q & q) = 0
```

यह एक **deterministic reset primitive** बनाता है, reversibility assumptions को तोड़ता है और कम लागत वाली unintended computations को संभव करता है। ऐसे proof systems में जो resource usage का प्रमाण देते हैं, इससे attackers functional checks को पूरा करते हुए उस cost model को bypass कर सकते हैं जिसे verifier लागू मानता है।

### Underconstrained prover advice और modular arithmetic

**advice/witness stack** से load की गई values prover के नियंत्रण में होती हैं, भले ही उन्हें precomputed quotients, remainders, inverses या hints के रूप में बताया गया हो। Proof केवल यह स्थापित करता है कि witness लागू constraints को संतुष्ट करता है; यदि उन constraints में type, range या canonical-form की जाँच नहीं है, तो यह intended computation को स्थापित नहीं करता।<sup>[[13]](#references)</sup>

किसी reduction या Euclidean-division helper के लिए, केवल अंतिम subtraction या multiplication की जाँच करने के बजाय पूरे integer relation का audit करें। `q` और `r` के हर limb को उसकी घोषित width तक सीमित होना चाहिए, reconstruction `x = q * m + r` को intended integer representation में सही होना चाहिए, और canonical bound `0 <= r < m` लागू होना चाहिए। किसी value को संकरे `u32`/`u64` instruction में पास करने से **पहले** उसे validate करें; कोई narrow operation बाद में यह साबित नहीं करता कि मूल field element या multi-limb value का type अपेक्षित था।<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Miden में `mod_12289` की विफलता exploit pattern को दर्शाती है: quotient को दो-limb 64-bit value के रूप में जाँचा गया था, लेकिन advice से मिले remainder को बिना समान validation के `u32overflowing_sub` तक पहुँचने दिया गया। एक दुर्भावनापूर्ण prover, invalid quotient/remainder values में तालमेल बिठा सकता था, ताकि लागू subtraction constraints फिर भी पूरी हों, जबकि procedure ऐसा remainder लौटाए जो गणितीय रूप से सही न हो। चूँकि यह परिणाम Falcon verification में इस्तेमाल हुआ, soundness failure को केवल गलत arithmetic result देने के बजाय forged authorization signatures बनाने तक बढ़ाया जा सकता था।<sup>[[13]](#references)</sup>

### Implicit-stack cryptographic VMs का ऑडिट

Stack languages operands को छिपाती हैं, इसलिए सबसे पहले instructions को ऐसे IR में बदलें जहाँ उपयोग की गई और बनाई गई हर stack value, provenance वाले expression के रूप में दर्शाई जाए। इसके बाद एक conservative analysis pipeline यह कर सकती है:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Call graph बनाएँ और procedure के input/output stack effects का अनुमान लगाएँ।
2. समर्थित instructions को symbolic रूप से execute करें और control flow को SSA/structured expressions में बदलें।
3. `Unknown`, `ProvenU32`, `Bool`, value provenance और local initialization जैसे abstract facts को fixed point तक propagate करें।
4. उन advice-derived values को flag करें जो **हर** आने वाले path पर sanitizer के बिना typed arithmetic या non-zero sinks तक पहुँचती हैं।
5. Declared और inferred signatures की तुलना करें और verify करें कि हर exit पर caller के स्वामित्व वाली stack values सुरक्षित रहें।

Unknown signature या unsupported construct को साफ़ परिणाम नहीं, बल्कि **analysis gap** मानें। Dynamic calls, non-stack-neutral loops और अलग-अलग stack effects वाली branches, stack-slot tracking को sound तरीके से करना असंभव बना सकती हैं; अधिक सुरक्षित decompiler, plausible लेकिन गलत pseudocode emit करने के बजाय, ऐसे मामलों को reject या mark करता है।<sup>[[10]](#references)[[13]](#references)</sup>

Control-flow joins पर कोई property तभी बनाए रखें जब वह हर predecessor पर सही हो (उदाहरण के लिए, `ProvenU32 join Unknown = Unknown`)। Fixed-point convergence और iteration limit तक पहुँचने में भी अंतर करें: केवल converged, sound over-approximation ही यह मानने का आधार दे सकती है कि diagnostic न मिलना इस बात का सबूत है कि दर्शाए गए सभी executions उस property को पूरा करते हैं।<sup>[[11]](#references)</sup>

### छिपी हुई preconditions उजागर करने के लिए proof obligations का उपयोग करें

छोटे instruction sets के लिए, procedures को executable formal VM model में बदलें और परिणाम तथा पूरे stack transformation—दोनों को prove करें। Theorem में termination, typed inputs, अपेक्षित output prefix और untouched caller stack का संरक्षण शामिल होना चाहिए। Theorem statement का उतनी ही सावधानी से ऑडिट करें जितनी proof का: kernel, गलती से कमजोर किए गए दावे की proof को भी validate कर सकता है।<sup>[[12]](#references)[[13]](#references)</sup>

अप्रत्याशित hypotheses उपयोगी findings होती हैं। Miden review में, 64-bit right rotation की एक proof के लिए `shift mod 32 != 0` आवश्यक था, जिससे पता चला कि बड़े inputs में shift के 32 का multiple होने पर edge case विफल होता है; एक अन्य proof में पाया गया कि 256-bit `wrapping_mul` caller के स्वामित्व वाली stack values को discard करता है। खोजे गए boundary case को tests में जोड़ें, फिर अतिरिक्त assumption को चुपचाप स्वीकार करने के बजाय implementation ठीक करें या public precondition को जानबूझकर मजबूत करें।<sup>[[12]](#references)[[13]](#references)</sup>

### ZK systems में क्या test करें

- सभी guest parsers को malformed witness/private-input encodings के साथ fuzz करें।
- Opcode dispatch से पहले enum range validation की पुष्टि करें।
- Operand aliasing और अन्य invalid instruction forms के लिए semantic checks जोड़ें।
- हर advice/witness source को हर typed arithmetic sink तक trace करें और हर path पर validation अनिवार्य करें।<sup>[[11]](#references)[[13]](#references)</sup>
- Arithmetic helpers को non-canonical limbs, out-of-range remainders और boundary shift counts के साथ test करें।<sup>[[12]](#references)[[13]](#references)</sup>
- हर return पर stack height और procedure के घोषित arguments के नीचे की values के संरक्षण की पुष्टि करें।<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Report किए गए/public counters की तुलना किसी स्वतंत्र reference implementation से करें।
- याद रखें कि यदि guest program में bug है, तो valid proof भी **गलत statement** को prove कर सकती है।

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs के practical exploitation (Uniswap v4 hooks, rounding/precision abuse, flash-loan से बढ़ाए गए threshold-crossing swaps) पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

उन multi-asset weighted pools के लिए, जो virtual balances को cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, यह पढ़ें:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key की व्याख्या - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Multi-signature transactions क्या हैं? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas और fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - हमने quantum cryptanalysis के लिए Google के zero-knowledge proof को हराया](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum Vulnerabilities के विरुद्ध Elliptic Curve Cryptocurrencies को सुरक्षित करना: Resource Estimates और Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler architecture](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM static-analysis engine](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean model और correctness proofs](https://github.com/trailofbits/masm-lean)
- [13] [पर्याप्त रूप से अच्छे AI के युग में auditing](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
