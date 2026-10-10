# Blockchain और Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## मूल अवधारणाएँ

- **Smart Contracts** ऐसे प्रोग्राम हैं जो कुछ शर्तें पूरी होने पर blockchain पर निष्पादित होते हैं और मध्यस्थों के बिना समझौतों को स्वचालित रूप से लागू करते हैं।
- **Decentralized Applications (dApps)**, smart contracts पर आधारित होते हैं और इनमें उपयोगकर्ता-अनुकूल front-end तथा पारदर्शी, ऑडिट किए जा सकने वाला back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल मुद्रा के रूप में काम करते हैं, जबकि tokens किसी विशिष्ट संदर्भ में मूल्य या स्वामित्व दर्शाते हैं।
  - **Utility Tokens** सेवाओं तक पहुँच देते हैं, जबकि **Security Tokens** किसी asset के स्वामित्व का संकेत देते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** का अर्थ क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations है।

## Consensus Mechanisms

Consensus mechanisms, blockchain पर transactions के सुरक्षित और सहमतिपूर्ण validation को सुनिश्चित करते हैं:

- **Proof of Work (PoW)**, transactions को verify करने के लिए computational power पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators के पास tokens की एक निश्चित मात्रा होना आवश्यक है, जिससे PoW की तुलना में ऊर्जा की खपत कम होती है।<sup>[[1]](#references)</sup>

## Bitcoin की मूल बातें

### Transactions

Bitcoin transactions में addresses के बीच funds का स्थानांतरण शामिल होता है। Transactions को digital signatures के ज़रिए validate किया जाता है, जिससे यह सुनिश्चित होता है कि केवल private key का मालिक ही स्थानांतरण शुरू कर सकता है।<sup>[[2]](#references)</sup>

#### मुख्य घटक:

- **Multisignature Transactions** में किसी transaction को अधिकृत करने के लिए कई signatures की आवश्यकता होती है।<sup>[[3]](#references)</sup>
- Transactions में **inputs** (funds का स्रोत), **outputs** (गंतव्य), **fees** (miners को दी जाने वाली राशि) और **scripts** (transaction के नियम) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य एक channel में कई transactions की अनुमति देकर Bitcoin की scalability बढ़ाना है। Blockchain पर केवल अंतिम स्थिति प्रसारित की जाती है।

## Bitcoin की गोपनीयता से जुड़ी चिंताएँ

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks, transaction patterns का फायदा उठाते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच transaction links को छिपाकर anonymity बेहतर बनाती हैं।

## गुमनाम रूप से Bitcoins प्राप्त करना

इन तरीकों में नकद लेनदेन, mining और mixers का उपयोग शामिल है। **CoinJoin** traceability को कठिन बनाने के लिए कई transactions को मिलाता है, जबकि **PayJoin**, अधिक गोपनीयता के लिए CoinJoins को सामान्य transactions जैसा दिखाता है।

# Bitcoin Privacy Attacks का सारांश

Bitcoin की दुनिया में transactions की गोपनीयता और उपयोगकर्ताओं की anonymity अक्सर चिंता का विषय होती है। यहाँ कुछ सामान्य तरीकों का संक्षिप्त विवरण दिया गया है, जिनसे attackers Bitcoin की गोपनीयता से समझौता कर सकते हैं।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

जटिलता के कारण, एक ही transaction में अलग-अलग उपयोगकर्ताओं के inputs का संयोजन आमतौर पर दुर्लभ होता है। इसलिए, **एक ही transaction में मौजूद दो input addresses को अक्सर एक ही मालिक का माना जाता है**।

## **UTXO Change Address Detection**

UTXO, यानी **Unspent Transaction Output**, को किसी transaction में पूरी तरह खर्च करना होता है। यदि इसका केवल एक हिस्सा किसी दूसरे address पर भेजा जाता है, तो बची हुई राशि एक नए change address पर चली जाती है। देखने वाले यह मान सकते हैं कि यह नया address sender का है, जिससे उसकी गोपनीयता से समझौता होता है।

### उदाहरण

इस जोखिम को कम करने के लिए mixing services या कई addresses का उपयोग करने से स्वामित्व छिपाने में मदद मिल सकती है।

## **Social Networks & Forums में खुलासा**

उपयोगकर्ता कभी-कभी अपने Bitcoin addresses ऑनलाइन साझा करते हैं, जिससे **उस address को उसके मालिक से जोड़ना आसान हो जाता है**।

## **Transaction Graph Analysis**

Transactions को graphs के रूप में दिखाया जा सकता है, जिससे funds के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित संबंध उजागर होते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले transactions का विश्लेषण करके अनुमान लगाती है कि कौन-सा output sender को लौटाया गया change है।

### उदाहरण

```bash
2 btc --> 4 btc
3 btc     1 btc
```

यदि अधिक इनपुट जोड़ने से change output किसी भी एक इनपुट से बड़ा हो जाता है, तो heuristic भ्रमित हो सकती है।

## **Forced Address Reuse**

हमलावर पहले इस्तेमाल किए जा चुके पतों पर छोटी रकम भेज सकते हैं, इस उम्मीद में कि प्राप्तकर्ता भविष्य के लेनदेन में इन्हें अन्य इनपुट के साथ जोड़ देगा और इस तरह पतों को आपस में जोड़ देगा।

### Wallet का सही व्यवहार

इस privacy leak से बचने के लिए Wallets को पहले से इस्तेमाल किए गए, खाली पतों पर प्राप्त coins का उपयोग नहीं करना चाहिए।

## **अन्य Blockchain Analysis तकनीकें**

- **सटीक भुगतान राशियाँ:** जिन लेनदेन में change नहीं होता, वे संभवतः एक ही उपयोगकर्ता के स्वामित्व वाले दो पतों के बीच होते हैं।
- **गोल संख्याएँ:** लेनदेन में गोल संख्या भुगतान का संकेत देती है, जबकि गैर-गोल राशि वाला output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग Wallets में लेनदेन बनाने के विशिष्ट पैटर्न होते हैं, जिनसे विश्लेषक इस्तेमाल किए गए software और संभवतः change address की पहचान कर सकते हैं।
- **राशि और समय का सहसंबंध:** लेनदेन का समय या राशि उजागर करने से लेनदेन को trace किया जा सकता है।

## **Traffic Analysis**

Network traffic की निगरानी करके हमलावर लेनदेन या blocks को IP addresses से जोड़ सकते हैं, जिससे उपयोगकर्ता की privacy प्रभावित होती है। यह जोखिम खास तौर पर तब होता है जब कोई इकाई कई Bitcoin nodes चलाती है, जिससे लेनदेन पर निगरानी रखने की उसकी क्षमता बढ़ जाती है।

## अधिक जानकारी

Privacy attacks और बचावों की विस्तृत सूची के लिए [Bitcoin Wiki पर Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin लेनदेन

## गुमनाम रूप से Bitcoins प्राप्त करने के तरीके

- **Cash लेनदेन**: नकद के ज़रिए bitcoin प्राप्त करना।
- **Cash के विकल्प**: gift cards खरीदकर उन्हें online bitcoin के बदले exchange करना।
- **Mining**: Bitcoins कमाने का सबसे निजी तरीका mining है, खासकर जब इसे अकेले किया जाए, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools की जानकारी](https://en.bitcoin.it/wiki/Pooled_mining)
- **चोरी**: सैद्धांतिक रूप से, bitcoin चुराना भी इसे गुमनाम रूप से प्राप्त करने का एक तरीका हो सकता है, हालांकि यह गैरकानूनी है और इसकी अनुशंसा नहीं की जाती।

## Mixing Services

Mixing service का उपयोग करके, उपयोगकर्ता **bitcoins भेज सकता है** और बदले में **अलग bitcoins प्राप्त कर सकता है**, जिससे मूल मालिक का पता लगाना मुश्किल हो जाता है। हालांकि, इसके लिए service पर भरोसा करना पड़ता है कि वह logs नहीं रखेगी और वास्तव में bitcoins लौटाएगी। Bitcoin casinos, mixing के वैकल्पिक विकल्प हैं।

## CoinJoin

**CoinJoin** अलग-अलग उपयोगकर्ताओं के कई लेनदेन को एक में मिला देता है, जिससे inputs को outputs से मिलाने की कोशिश जटिल हो जाती है। प्रभावी होने के बावजूद, विशिष्ट आकार वाले inputs और outputs के लेनदेन को अब भी trace किया जा सकता है।

CoinJoin का उपयोग किए जाने की संभावना वाले उदाहरण लेनदेन हैं: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। Deposits को बाद में किए गए withdrawals से अलग करने वाले Ethereum smart-contract mixer के लिए [Tornado Cash](https://tornado.cash) देखें।

## PayJoin

CoinJoin का एक रूप, **PayJoin** (या P2EP), दो पक्षों (जैसे, ग्राहक और व्यापारी) के बीच के लेनदेन को सामान्य लेनदेन जैसा दिखाता है और CoinJoin की विशिष्ट समान outputs वाली विशेषता से बचता है। इससे इसका पता लगाना बेहद मुश्किल हो जाता है और यह transaction surveillance entities द्वारा इस्तेमाल की जाने वाली common-input-ownership heuristic को अमान्य कर सकता है।

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

ऊपर दिए गए लेन-देन PayJoin हो सकते हैं, जो गोपनीयता बढ़ाते हैं और फिर भी सामान्य bitcoin लेन-देन से अलग नहीं पहचाने जा सकते।

**PayJoin का उपयोग पारंपरिक निगरानी विधियों को गंभीर रूप से बाधित कर सकता है**, जिससे यह लेन-देन की गोपनीयता की दिशा में एक आशाजनक विकास बन जाता है।

# क्रिप्टोकरेंसी में गोपनीयता के लिए सर्वोत्तम अभ्यास

## **Wallet Synchronization Techniques**

गोपनीयता और सुरक्षा बनाए रखने के लिए, blockchain के साथ wallets को सिंक्रनाइज़ करना महत्वपूर्ण है। दो विधियाँ विशेष रूप से उपयोगी हैं:

- **Full node**: पूरी blockchain डाउनलोड करके, full node अधिकतम गोपनीयता सुनिश्चित करता है। अब तक किए गए सभी लेन-देन स्थानीय रूप से संग्रहित होते हैं, जिससे विरोधियों के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किन लेन-देन या पतों में रुचि रखता है।
- **Client-side block filtering**: इस विधि में blockchain के हर block के लिए filters बनाए जाते हैं, ताकि wallets नेटवर्क पर नज़र रखने वालों के सामने अपनी विशिष्ट रुचि उजागर किए बिना प्रासंगिक लेन-देन पहचान सकें। Lightweight wallets ये filters डाउनलोड करते हैं और पूरा block केवल तभी प्राप्त करते हैं, जब उपयोगकर्ता के पतों से मेल मिलता है।

## **गुमनामी के लिए Tor का उपयोग**

चूँकि Bitcoin peer-to-peer नेटवर्क पर काम करता है, इसलिए अपने IP address को छिपाने और नेटवर्क के साथ संवाद करते समय गोपनीयता बढ़ाने के लिए Tor का उपयोग करने की सलाह दी जाती है।

## **पते का दोबारा उपयोग रोकना**

गोपनीयता सुरक्षित रखने के लिए, हर लेन-देन में नया पता इस्तेमाल करना आवश्यक है। पतों का दोबारा उपयोग करने से लेन-देन एक ही इकाई से जुड़ सकते हैं और गोपनीयता भंग हो सकती है। आधुनिक wallets अपने डिज़ाइन के ज़रिए पते के दोबारा उपयोग को हतोत्साहित करते हैं।

## **लेन-देन की गोपनीयता के लिए रणनीतियाँ**

- **कई लेन-देन**: भुगतान को कई लेन-देन में बाँटने से लेन-देन की राशि अस्पष्ट हो सकती है और गोपनीयता पर होने वाले हमले विफल हो सकते हैं।
- **Change से बचना**: ऐसे लेन-देन चुनने से, जिनमें change outputs की आवश्यकता न हो, change का पता लगाने वाली विधियाँ बाधित होती हैं और गोपनीयता बढ़ती है।
- **कई change outputs**: यदि change से बचना संभव न हो, तो कई change outputs बनाने से भी गोपनीयता बेहतर हो सकती है।

# **Monero: गुमनामी का प्रतीक**

Monero को लेन-देन की गोपनीयता को प्राथमिकता देने के लिए डिज़ाइन किया गया है।

# **Ethereum: Gas और लेन-देन**

## **Gas को समझना**

Gas, Ethereum पर कार्रवाइयाँ निष्पादित करने के लिए आवश्यक computational effort को मापता है और इसकी कीमत **gwei** में तय होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाले लेन-देन में gas limit और base fee होती है, साथ ही validator को लेन-देन शामिल करने के लिए प्रोत्साहित करने हेतु priority fee भी होती है। उपयोगकर्ता यह सुनिश्चित करने के लिए max fee सेट कर सकते हैं कि वे ज़रूरत से ज़्यादा भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।<sup>[[5]](#references)</sup>

## **लेन-देन निष्पादित करना**

Ethereum के लेन-देन में sender और recipient होते हैं, जो user या smart contract के पते हो सकते हैं। इनके लिए fee आवश्यक होती है और इन्हें किसी block में शामिल करना होता है। लेन-देन की आवश्यक जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit और fees शामिल हैं। विशेष रूप से, sender का पता signature से निकाला जाता है, इसलिए लेन-देन के data में उसे शामिल करने की ज़रूरत नहीं होती।<sup>[[4]](#references)</sup>

गोपनीयता और सुरक्षा को प्राथमिकता देते हुए क्रिप्टोकरेंसी का उपयोग करने के इच्छुक किसी भी व्यक्ति के लिए ये अभ्यास और तंत्र बुनियादी हैं।

## Value-Centric Web3 Red Teaming

- यह समझने के लिए कि कौन funds स्थानांतरित कर सकता है और कैसे, value रखने वाले घटकों (signers, oracles, bridges, automation) की सूची बनाएँ।
- privilege escalation के रास्ते उजागर करने के लिए हर घटक को प्रासंगिक MITRE AADAPT tactics से मैप करें।
- प्रभाव की पुष्टि करने और शोषण योग्य पूर्वशर्तों का दस्तावेज़ बनाने के लिए flash-loan/oracle/credential/cross-chain हमले की शृंखलाओं का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI में supply-chain tampering, signing से ठीक पहले EIP-712 payloads को बदल सकती है और delegatecall-आधारित proxy takeover (जैसे Safe masterCopy का slot-0 overwrite) के लिए मान्य signatures हासिल कर सकती है।

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Smart-account की आम विफलताओं में `EntryPoint` access control को bypass करना, unsigned gas fields, stateful validation, ERC-1271 replay और validation के बाद revert के ज़रिए fee-drain शामिल हैं।

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suites में कमियों का पता लगाने के लिए mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

जब कोई prover किसी दावे की पुष्टि के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier को केवल यह पता चलता है कि **guest program लिखे गए निर्देशों के अनुसार चला**। यदि guest में **unsafe deserialization**, **undefined behavior** या **semantic constraints की कमी** हो, तो malicious prover ऐसा proof बना सकता है जो सत्यापित हो जाए, जबकि **सार्वजनिक metrics या दावा किया गया invariant गलत हो**।<sup>[[7]](#references)</sup>

### Proof guests में Unsafe deserialization

- Private witness/circuit bytes को **untrusted attacker input** मानें, भले ही वे proof द्वारा छिपाए गए हों।
- `rkyv::access_unchecked` जैसे unchecked helpers से उन्हें deserialize न करें, जब तक bytes को पहले किसी स्वतंत्र प्रक्रिया से validate न किया गया हो।
- Untrusted serialized data से लोड किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access पर असर डालने से पहले validate करना आवश्यक है।

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
3. Out-of-range discriminant पहले jump table के बाहर index करता है और दूसरे jump table से जुड़े code पर पहुँच जाता है।

नतीजा: operation फिर भी execute होता है, लेकिन accounting path छूट जाता है। zkVM में इससे ऐसे proofs forge किए जा सकते हैं जो असंभव metrics रिपोर्ट करते हैं—जैसे कम gates, कम expensive operations या अन्य falsified bounded resources।

Review checklist:

- Witness/private input से deserialize किए गए attacker-controlled enums देखें।
- एक ही opcode/kind field पर बार-बार इस्तेमाल हुए `match` statements की जाँच करें।
- `unsafe` + unchecked deserialization + large opcode dispatch के मेल को high-risk मानें।
- ज़रूरत पड़ने पर emitted binary को reverse engineer करें; jump-table layout, source से ज़्यादा मायने रख सकता है।

### Reversible/specialized interpreters में semantic constraints की कमी

केवल memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof को enforce करना है।

Reversible/quantum-like instruction sets के लिए, सुनिश्चित करें कि जिन operands का distinct होना ज़रूरी है, उन पर distinct होने की constraint वास्तव में लागू हो। इस तरह लागू किया गया Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

यदि guest अस्वीकार नहीं करता है, तो यह असुरक्षित हो जाता है:

```text
op.q_control1 == op.q_control2 == op.q_target
```

उस स्थिति में transition सिमटकर यह बन जाता है:

```text
q = q ^ (q & q) = 0
```

यह एक **deterministic reset primitive** बनाता है, जो reversibility की मान्यताओं को तोड़ता है और कम लागत वाली unintended computations को सक्षम करता है। ऐसे proof systems में, जो resource usage की पुष्टि करते हैं, इससे हमलावर functional checks पास कर सकते हैं और verifier द्वारा लागू समझे जा रहे cost model को दरकिनार कर सकते हैं।

### ZK systems में क्या टेस्ट करें

- malformed witness/private-input encodings के साथ सभी guest parsers को fuzz करें।
- opcode dispatch से पहले enum range validation सुनिश्चित करें।
- operand aliasing और instruction के अन्य invalid forms के लिए semantic checks जोड़ें।
- रिपोर्ट किए गए/public counters की तुलना किसी independent reference implementation से करें।
- याद रखें कि यदि guest program में bug है, तो valid proof भी **गलत कथन** को साबित कर सकता है।

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs के practical exploitation (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps) पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

ऐसे multi-asset weighted pools के लिए, जो virtual balances को cache करते हैं और जिन्हें `supply == 0` होने पर poison किया जा सकता है, अध्ययन करें:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - विकिपीडिया](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key और Private Key की व्याख्या - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Multi-signature transactions क्या हैं? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas और fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - हमने quantum cryptanalysis के Google के zero-knowledge proof को तोड़ दिया](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum vulnerabilities से elliptic curve cryptocurrencies को सुरक्षित करना: resource estimates और mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
