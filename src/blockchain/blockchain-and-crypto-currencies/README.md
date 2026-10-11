# Blockchain और Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **Smart Contracts** ऐसे प्रोग्राम होते हैं जो कुछ शर्तें पूरी होने पर blockchain पर चलते हैं और बिना किसी मध्यस्थ के समझौतों के निष्पादन को स्वचालित करते हैं।
- **Decentralized Applications (dApps)**, smart contracts पर आधारित होते हैं। इनमें उपयोगकर्ता-अनुकूल front-end और पारदर्शी, ऑडिट किए जा सकने वाला back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल मुद्रा के रूप में काम करते हैं, जबकि tokens विशेष संदर्भों में मूल्य या स्वामित्व दर्शाते हैं।
  - **Utility Tokens** सेवाओं का उपयोग करने की सुविधा देते हैं, और **Security Tokens** किसी asset के स्वामित्व को दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को कहते हैं।

## Consensus Mechanisms

Consensus mechanisms यह सुनिश्चित करते हैं कि blockchain पर लेन-देन का सत्यापन सुरक्षित तरीके से और सहमति के साथ हो:

- **Proof of Work (PoW)** लेन-देन सत्यापित करने के लिए computational power का उपयोग करता है।
- **Proof of Stake (PoS)** में validators के पास tokens की एक निश्चित मात्रा होना आवश्यक है। इससे PoW की तुलना में ऊर्जा की खपत कम होती है।<sup>[[1]](#references)</sup>

## Bitcoin की मूल बातें

### लेन-देन

Bitcoin transactions में addresses के बीच धनराशि का हस्तांतरण होता है। लेन-देन को digital signatures के ज़रिए सत्यापित किया जाता है, जिससे यह सुनिश्चित होता है कि केवल private key का मालिक ही हस्तांतरण शुरू कर सकता है।<sup>[[2]](#references)</sup>

#### मुख्य घटक:

- **Multisignature Transactions** में लेन-देन को अधिकृत करने के लिए कई signatures आवश्यक होते हैं।<sup>[[3]](#references)</sup>
- लेन-देन में **inputs** (धनराशि का स्रोत), **outputs** (गंतव्य), **fees** (miners को दिया गया शुल्क) और **scripts** (लेन-देन के नियम) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य एक channel में कई लेन-देन की अनुमति देकर Bitcoin की scalability को बेहतर बनाना है। इसमें केवल अंतिम स्थिति blockchain पर प्रसारित की जाती है।

## Bitcoin की गोपनीयता से जुड़ी चिंताएँ

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks, लेन-देन के पैटर्न का फायदा उठाते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच लेन-देन के संबंध छिपाकर anonymity को बेहतर बनाती हैं।

## गुमनाम रूप से Bitcoins प्राप्त करना

इन तरीकों में नकद लेन-देन, mining और mixers का उपयोग शामिल है। **CoinJoin** कई लेन-देन को मिलाकर उनकी traceability को जटिल बनाता है, जबकि **PayJoin** बेहतर गोपनीयता के लिए CoinJoins को सामान्य लेन-देन जैसा दिखाता है।

# Bitcoin Privacy Attacks का सारांश

Bitcoin की दुनिया में, लेन-देन की गोपनीयता और उपयोगकर्ताओं की anonymity अक्सर चिंता का विषय होते हैं। यहाँ उन कई सामान्य तरीकों का सरल विवरण दिया गया है जिनसे attackers Bitcoin की गोपनीयता से समझौता कर सकते हैं।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

जटिलता के कारण, अलग-अलग उपयोगकर्ताओं के inputs को एक ही लेन-देन में शामिल करना आम तौर पर दुर्लभ है। इसलिए, **एक ही लेन-देन में मौजूद दो input addresses को अक्सर एक ही मालिक का माना जाता है**।

## **UTXO Change Address Detection**

UTXO, यानी **Unspent Transaction Output**, को किसी लेन-देन में पूरा खर्च करना आवश्यक है। अगर इसका केवल एक हिस्सा दूसरे address पर भेजा जाता है, तो बची हुई राशि एक नए change address पर चली जाती है। देखने वाले यह मान सकते हैं कि यह नया address भेजने वाले का है, जिससे उसकी गोपनीयता से समझौता हो सकता है।

### उदाहरण

इसे कम करने के लिए, mixing services या कई addresses का उपयोग करने से स्वामित्व छिपाने में मदद मिल सकती है।

## **Social Networks और Forums पर जानकारी उजागर होना**

उपयोगकर्ता कभी-कभी अपने Bitcoin addresses ऑनलाइन साझा करते हैं, जिससे **address को उसके मालिक से जोड़ना आसान हो जाता है**।

## **Transaction Graph Analysis**

लेन-देन को graphs के रूप में दिखाया जा सकता है, जिससे धनराशि के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित संबंध सामने आ सकते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले लेन-देन का विश्लेषण करके यह अनुमान लगाती है कि कौन-सा output भेजने वाले के पास लौटने वाली change राशि है।

### उदाहरण

```bash
2 btc --> 4 btc
3 btc     1 btc
```

अगर अधिक inputs जोड़ने से change output किसी भी एक input से बड़ा हो जाता है, तो heuristic भ्रमित हो सकती है।

## **Forced Address Reuse**

हमलावर पहले इस्तेमाल किए जा चुके addresses पर छोटी रकम भेज सकते हैं, इस उम्मीद में कि प्राप्तकर्ता भविष्य के transactions में इन्हें अन्य inputs के साथ जोड़ देगा, जिससे addresses आपस में link हो जाएंगे।

### सही Wallet व्यवहार

इस privacy leak से बचने के लिए wallets को पहले इस्तेमाल किए जा चुके और खाली addresses पर प्राप्त coins का उपयोग नहीं करना चाहिए।

## **अन्य Blockchain Analysis Techniques**

- **सटीक Payment Amounts:** जिन transactions में change नहीं होता, वे संभवतः एक ही user के स्वामित्व वाले दो addresses के बीच होते हैं।
- **Round Numbers:** किसी transaction में round number इस बात का संकेत हो सकता है कि वह payment है; non-round output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction बनाने के विशिष्ट patterns होते हैं। इनसे analysts इस्तेमाल किए गए software और संभावित change address की पहचान कर सकते हैं।
- **रकम और समय के Correlations:** transaction के समय या रकम का खुलासा करने से transactions को trace किया जा सकता है।

## **Traffic Analysis**

Network traffic पर नज़र रखकर हमलावर संभावित रूप से transactions या blocks को IP addresses से link कर सकते हैं, जिससे users की privacy से समझौता हो सकता है। यह तब विशेष रूप से सच है जब कोई entity कई Bitcoin nodes चलाती है, जिससे transactions पर नज़र रखने की उसकी क्षमता बढ़ जाती है।

## अधिक जानकारी

Privacy attacks और बचावों की व्यापक सूची के लिए [Bitcoin Wiki पर Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin Transactions

## गुमनाम रूप से Bitcoins पाने के तरीके

- **Cash Transactions**: Cash के ज़रिए bitcoin प्राप्त करना।
- **Cash Alternatives**: Gift cards खरीदकर उन्हें online bitcoin के बदले exchange करना।
- **Mining**: Bitcoins कमाने का सबसे निजी तरीका mining है, खासकर अकेले mining करना, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools की जानकारी](https://en.bitcoin.it/wiki/Pooled_mining)
- **चोरी**: सैद्धांतिक रूप से, bitcoin चुराना उसे गुमनाम रूप से हासिल करने का एक और तरीका हो सकता है, हालांकि यह गैरकानूनी है और इसकी सलाह नहीं दी जाती।

## Mixing Services

Mixing service का उपयोग करके user **bitcoins भेज** सकता है और बदले में **अलग bitcoins प्राप्त** कर सकता है, जिससे मूल owner का पता लगाना मुश्किल हो जाता है। हालांकि, इसके लिए इस बात पर भरोसा करना पड़ता है कि service logs नहीं रखेगी और वास्तव में bitcoins वापस करेगी। Bitcoin casinos, mixing के वैकल्पिक विकल्प हैं।

## CoinJoin

**CoinJoin** अलग-अलग users के कई transactions को एक में मिला देता है, जिससे inputs को outputs से match करने की कोशिश करना मुश्किल हो जाता है। प्रभावी होने के बावजूद, विशिष्ट input और output sizes वाले transactions को फिर भी trace किया जा सकता है।

CoinJoin का उपयोग किए जाने की संभावना वाले उदाहरण transactions में `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` शामिल हैं।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। ऐसे Ethereum smart-contract mixer के लिए, जो deposits को बाद में होने वाले withdrawals से अलग रखता है, [Tornado Cash](https://tornado.cash) देखें।

## PayJoin

CoinJoin का एक variant, **PayJoin** (या P2EP), दो parties (जैसे, customer और merchant) के बीच transaction को एक सामान्य transaction के रूप में छिपाता है। इसमें CoinJoin की विशिष्ट समान outputs वाली विशेषता नहीं होती। इससे इसका पता लगाना बेहद मुश्किल हो जाता है और transaction surveillance entities द्वारा इस्तेमाल की जाने वाली common-input-ownership heuristic अमान्य हो सकती है।

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

ऊपर दिए गए जैसे लेन-देन PayJoin हो सकते हैं, जो मानक bitcoin लेन-देन से अलग पहचाने बिना गोपनीयता बढ़ाते हैं।

**PayJoin का उपयोग पारंपरिक निगरानी विधियों को काफी हद तक बाधित कर सकता है**, जिससे यह लेन-देन की गोपनीयता की दिशा में एक आशाजनक विकास बन जाता है।

# Cryptocurrencies में गोपनीयता के लिए सर्वोत्तम तरीके

## **Wallet Synchronization तकनीकें**

गोपनीयता और सुरक्षा बनाए रखने के लिए, wallets को blockchain के साथ सिंक्रनाइज़ करना महत्वपूर्ण है। दो तरीके खास तौर पर उपयोगी हैं:

- **Full node**: पूरी blockchain डाउनलोड करके, full node अधिकतम गोपनीयता सुनिश्चित करता है। अब तक किए गए सभी लेन-देन स्थानीय रूप से संग्रहीत होते हैं, जिससे विरोधियों के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किन लेन-देन या पतों में रुचि रखता है।
- **Client-side block filtering**: इस तरीके में blockchain के हर block के लिए filters बनाए जाते हैं, जिससे wallets नेटवर्क पर्यवेक्षकों के सामने अपनी विशिष्ट रुचियाँ उजागर किए बिना संबंधित लेन-देन पहचान सकते हैं। Lightweight wallets ये filters डाउनलोड करते हैं और केवल तभी पूरे blocks प्राप्त करते हैं, जब उपयोगकर्ता के पतों से कोई मेल मिलता है।

## **गुमनामी के लिए Tor का उपयोग**

चूँकि Bitcoin peer-to-peer नेटवर्क पर चलता है, इसलिए अपना IP address छिपाने के लिए Tor का उपयोग करने की सलाह दी जाती है। इससे नेटवर्क के साथ इंटरैक्ट करते समय गोपनीयता बढ़ती है।

## **पते के पुनः उपयोग को रोकना**

गोपनीयता सुरक्षित रखने के लिए, हर लेन-देन में एक नए पते का उपयोग करना ज़रूरी है। पतों का पुनः उपयोग करने से लेन-देन एक ही इकाई से जुड़ सकते हैं और गोपनीयता भंग हो सकती है। आधुनिक wallets का डिज़ाइन पतों के पुनः उपयोग को हतोत्साहित करता है।

## **लेन-देन की गोपनीयता के लिए रणनीतियाँ**

- **कई लेन-देन**: भुगतान को कई लेन-देन में बाँटने से लेन-देन की राशि छिप सकती है और गोपनीयता पर होने वाले हमलों को विफल किया जा सकता है।
- **Change से बचना**: ऐसे लेन-देन चुनने से, जिनमें change outputs की आवश्यकता नहीं होती, change का पता लगाने के तरीकों में बाधा डालकर गोपनीयता बढ़ती है।
- **कई change outputs**: यदि change से बचना संभव न हो, तो कई change outputs बनाने से भी गोपनीयता बेहतर हो सकती है।

# **Monero: गुमनामी का एक प्रतीक**

Monero को लेन-देन की गोपनीयता को प्राथमिकता देने के लिए डिज़ाइन किया गया है।

# **Ethereum: Gas और लेन-देन**

## **Gas को समझना**

Gas, Ethereum पर कार्रवाइयाँ निष्पादित करने के लिए आवश्यक computational effort को मापता है और इसकी कीमत **gwei** में तय होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाले लेन-देन में gas limit और base fee होती है, साथ ही validator को लेन-देन शामिल करने के लिए प्रोत्साहित करने हेतु priority fee भी होती है। उपयोगकर्ता max fee निर्धारित कर सकते हैं, ताकि वे ज़रूरत से ज़्यादा भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।<sup>[[5]](#references)</sup>

## **लेन-देन निष्पादित करना**

Ethereum में लेन-देन में एक sender और एक recipient शामिल होते हैं, जो user या smart contract address हो सकते हैं। इनके लिए fee देना और block में शामिल होना आवश्यक है। लेन-देन की आवश्यक जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit और fees शामिल हैं। ध्यान दें कि sender का address signature से निकाला जाता है, इसलिए इसे लेन-देन के data में शामिल करने की आवश्यकता नहीं होती।<sup>[[4]](#references)</sup>

ये तरीके और तंत्र उन सभी लोगों के लिए आधारभूत हैं जो गोपनीयता और सुरक्षा को प्राथमिकता देते हुए cryptocurrencies का उपयोग करना चाहते हैं।

## Value-Centric Web3 Red Teaming

- यह समझने के लिए कि कौन funds स्थानांतरित कर सकता है और कैसे, value रखने वाले components (signers, oracles, bridges, automation) की सूची बनाएँ।
- privilege escalation के रास्तों का पता लगाने के लिए हर component को संबंधित MITRE AADAPT tactics से जोड़ें।
- प्रभाव की पुष्टि करने और exploit की जा सकने वाली पूर्वशर्तों को दर्ज करने के लिए flash-loan/oracle/credential/cross-chain attack chains का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Wallet UI की supply-chain tampering, signing से ठीक पहले EIP-712 payloads में बदलाव कर सकती है और delegatecall-आधारित proxy takeover (उदाहरण के लिए, Safe masterCopy का slot-0 overwrite) के लिए मान्य signatures हासिल कर सकती है।

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Smart-account की सामान्य विफलताओं में `EntryPoint` access control को bypass करना, unsigned gas fields, stateful validation, ERC-1271 replay, और validation के बाद revert करके fee-drain करना शामिल हैं।

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Test suites में छूटे हुए पहलुओं का पता लगाने के लिए mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

जब कोई prover किसी दावे की पुष्टि के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier को केवल यह पता चलता है कि **guest program बताए गए तरीके से निष्पादित हुआ**। यदि guest में **unsafe deserialization**, **undefined behavior**, या **semantic constraints की कमी** हो, तो कोई malicious prover ऐसा proof बना सकता है जो सत्यापित हो जाए, जबकि **public metrics या दावा किया गया invariant गलत हो**।<sup>[[7]](#references)</sup>

### Proof guests के भीतर Unsafe deserialization

- Private witness/circuit bytes को **अविश्वसनीय attacker input** मानें, भले ही वे proof से छिपे हों।
- उन्हें `rkyv::access_unchecked` जैसे बिना जाँच वाले helpers से deserialize न करें, जब तक कि bytes को पहले किसी अलग प्रक्रिया से validate न किया गया हो।
- अविश्वसनीय serialized data से लोड किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access पर असर डालने से पहले validate करना आवश्यक है।

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
3. out-of-range discriminant पहले jump table के आगे index करता है और दूसरे jump table से जुड़े code पर पहुँच जाता है।

नतीजा: operation फिर भी execute होता है, लेकिन accounting path छूट जाता है। zkVM में इससे ऐसे proofs forge किए जा सकते हैं जो असंभव metrics की रिपोर्ट करें—जैसे कम gates, कम expensive operations या अन्य falsified bounded resources।

Review checklist:

- witness/private input से deserialize किए गए attacker-controlled enums खोजें।
- एक ही opcode/kind field पर बार-बार होने वाले `match` statements जाँचें।
- `unsafe` + unchecked deserialization + large opcode dispatch के मेल को high-risk मानें।
- ज़रूरत पड़ने पर emitted binary को reverse engineer करें; jump-table layout, source से ज़्यादा मायने रख सकता है।

### Reversible/specialized interpreters में semantic constraints का अभाव

सिर्फ memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof द्वारा लागू किया जाना है।

Reversible/quantum-like instruction sets के लिए सुनिश्चित करें कि जिन operands का distinct होना ज़रूरी है, उन्हें वास्तव में distinct होने के लिए constrain किया गया है। Toffoli/CCX-जैसा operation इस तरह लागू किया गया हो:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

यदि guest अस्वीकार नहीं करता है, तो यह असुरक्षित हो जाता है:

```text
op.q_control1 == op.q_control2 == op.q_target
```

उस स्थिति में संक्रमण सिमटकर यह बन जाता है:

```text
q = q ^ (q & q) = 0
```

यह एक **deterministic reset primitive** बनाता है, जो reversibility की धारणाओं को तोड़ता है और कम लागत वाली अनपेक्षित computations को संभव बनाता है। ऐसे proof systems में, जो resource usage की पुष्टि करते हैं, इससे attackers functional checks को पूरा करते हुए उस cost model को bypass कर सकते हैं जिसे verifier लागू मानता है।

### Underconstrained prover advice और modular arithmetic

**Advice/witness stack** से लोड की गई values prover के नियंत्रण में होती हैं, भले ही उन्हें पहले से गणना किए गए quotients, remainders, inverses या hints के रूप में बताया गया हो। Proof केवल यह स्थापित करता है कि witness लागू constraints को पूरा करता है; यदि उन constraints में type, range या canonical-form की जाँच शामिल नहीं है, तो यह intended computation को स्थापित नहीं करता।<sup>[[13]](#references)</sup>

किसी reduction या Euclidean-division helper के लिए, केवल अंतिम subtraction या multiplication का नहीं, बल्कि पूरे integer relation का audit करें। `q` और `r` के हर limb को उसकी घोषित width तक सीमित किया जाना चाहिए, reconstruction `x = q * m + r` को intended integer representation में सत्य होना चाहिए, और canonical bound `0 <= r < m` लागू होना चाहिए। किसी value को संकीर्ण `u32`/`u64` instruction में पास करने से **पहले** उसे validate करें; कोई narrow operation बाद में यह साबित नहीं करता कि मूल field element या multi-limb value का अपेक्षित type था।<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Miden में `mod_12289` की विफलता exploit के तरीके को दर्शाती है: quotient को दो-limb 64-bit मान के रूप में जाँचा गया था, लेकिन advice से आया remainder बिना समकक्ष validation के `u32overflowing_sub` तक पहुँच गया। एक दुर्भावनापूर्ण prover अमान्य quotient/remainder मानों को इस तरह साथ मिला सकता था कि लागू subtraction constraints फिर भी पूरी हों, जबकि procedure ऐसा remainder लौटाए जो गणितीय रूप से सही न हो। चूँकि यह परिणाम Falcon verification में इस्तेमाल हुआ, इसलिए soundness की इस विफलता को केवल गलत arithmetic result देने के बजाय forged authorization signatures बनाने तक बढ़ाया जा सकता था।<sup>[[13]](#references)</sup>

### Implicit-stack cryptographic VMs का ऑडिट करना

Stack languages में operands छिपे होते हैं, इसलिए पहले instructions को ऐसे IR में बदलें जहाँ हर consume और produce किया गया stack value provenance वाले expression के रूप में दिखे। इसके बाद एक conservative analysis pipeline यह कर सकती है:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Call graph बनाएँ और procedure के input/output stack effects का अनुमान लगाएँ।
2. समर्थित instructions को symbolic रूप से execute करें और control flow को SSA/structured expressions में बदलें।
3. `Unknown`, `ProvenU32`, `Bool`, value provenance और local initialization जैसे abstract facts को fixed point तक propagate करें।
4. उन advice-derived values को चिह्नित करें जो हर incoming path पर sanitizer के बिना typed arithmetic या non-zero sinks तक पहुँचती हैं।
5. Declared और inferred signatures की तुलना करें और सत्यापित करें कि हर exit पर caller-owned stack values सुरक्षित रहें।

Unknown signature या unsupported construct को साफ़ परिणाम नहीं, बल्कि **analysis gap** मानें। Dynamic calls, non-stack-neutral loops और अलग-अलग stack effects वाली branches के कारण sound stack-slot tracking असंभव हो सकती है; सुरक्षित decompiler plausible लेकिन गलत pseudocode निकालने के बजाय ऐसे मामलों को reject या mark करता है।<sup>[[10]](#references)[[13]](#references)</sup>

Control-flow joins पर कोई property तभी बनाए रखें जब वह हर predecessor पर सही हो (उदाहरण के लिए, `ProvenU32 join Unknown = Unknown`)। Fixed-point convergence और iteration limit तक पहुँचने में भी अंतर करें: केवल converged, sound over-approximation ही इस आधार पर diagnostic न मिलने को प्रमाण मानने का औचित्य दे सकती है कि सभी दर्शाए गए executions उस property को पूरा करते हैं।<sup>[[11]](#references)</sup>

### छिपी हुई preconditions उजागर करने के लिए proof obligations का उपयोग करें

छोटे instruction sets के लिए procedures को executable formal VM model में बदलें और result के साथ-साथ पूरे stack transformation को भी prove करें। Theorem में termination, typed inputs, अपेक्षित output prefix और untouched caller stack का preservation शामिल होना चाहिए। Theorem statement का उतनी ही सावधानी से ऑडिट करें जितनी proof का: kernel किसी अनजाने में कमजोर किए गए दावे की proof को validate कर सकता है।<sup>[[12]](#references)[[13]](#references)</sup>

अप्रत्याशित hypotheses उपयोगी findings होती हैं। Miden review में 64-bit right rotation की proof के लिए `shift mod 32 != 0` आवश्यक था, जिससे पता चला कि shift 32 का गुणज होने पर बड़े inputs के लिए edge case fail होता है; एक दूसरी proof में मिला कि 256-bit `wrapping_mul` caller-owned stack values को discard करता है। खोजे गए boundary case को tests में जोड़ें, फिर implementation ठीक करें या public precondition को जानबूझकर मज़बूत करें—अतिरिक्त assumption को चुपचाप स्वीकार न करें।<sup>[[12]](#references)[[13]](#references)</sup>

### ZK systems में क्या test करें

- सभी guest parsers को malformed witness/private-input encodings के साथ fuzz करें।
- Opcode dispatch से पहले enum range validation की पुष्टि करें।
- Operand aliasing और instruction के अन्य अमान्य रूपों के लिए semantic checks जोड़ें।
- हर advice/witness source को हर typed arithmetic sink तक trace करें और हर path पर validation अनिवार्य करें।<sup>[[11]](#references)[[13]](#references)</sup>
- Arithmetic helpers को non-canonical limbs, range से बाहर के remainders और boundary shift counts के साथ test करें।<sup>[[12]](#references)[[13]](#references)</sup>
- हर return पर stack height और procedure के घोषित arguments से नीचे के values के preservation की पुष्टि करें।<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Report किए गए/public counters की तुलना किसी स्वतंत्र reference implementation से करें।
- याद रखें कि guest program में bug होने पर valid proof भी **गलत कथन** को prove कर सकती है।

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

अगर आप DEXes और AMMs के practical exploitation (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps) पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

उन multi-asset weighted pools के लिए जो virtual balances cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, देखें:

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
- [7] [Trail of Bits - हमने quantum cryptanalysis के Google के zero-knowledge proof को तोड़ा](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum Vulnerabilities के विरुद्ध Elliptic Curve Cryptocurrencies को सुरक्षित करना: Resource Estimates और Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits का proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler architecture](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM static-analysis engine](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean model और correctness proofs](https://github.com/trailofbits/masm-lean)
- [13] [(काफी अच्छी) AI के दौर में auditing](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
