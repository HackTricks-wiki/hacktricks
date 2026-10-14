# ब्लॉकचेन और क्रिप्टोकरेंसी

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **स्मार्ट कॉन्ट्रैक्ट** ऐसे प्रोग्राम होते हैं जो कुछ शर्तें पूरी होने पर ब्लॉकचेन पर चलते हैं और बिचौलियों के बिना समझौतों के निष्पादन को स्वचालित करते हैं।
- **विकेंद्रीकृत एप्लिकेशन (dApps)** स्मार्ट कॉन्ट्रैक्ट पर आधारित होते हैं और इनमें उपयोगकर्ता-अनुकूल फ्रंट-एंड तथा पारदर्शी, ऑडिट किए जा सकने वाला बैक-एंड होता है।
- **टोकन और कॉइन** में अंतर यह है कि कॉइन डिजिटल मुद्रा के रूप में काम करते हैं, जबकि टोकन विशिष्ट संदर्भों में मूल्य या स्वामित्व दर्शाते हैं।
  - **यूटिलिटी टोकन** सेवाओं तक पहुँच देते हैं, जबकि **सिक्योरिटी टोकन** किसी परिसंपत्ति के स्वामित्व को दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः विकेंद्रीकृत एक्सचेंज प्लेटफ़ॉर्म और विकेंद्रीकृत स्वायत्त संगठनों को कहते हैं।

क्रिप्टो बाज़ारों में इस्तेमाल होने वाले स्पॉट ऑर्डर, फ़्यूचर्स, लीवरेज और ऑप्शंस से जुड़े शब्दों के लिए [निवेश संबंधी शब्द](investment-terms.md) देखें।

## कंसेंसस मैकेनिज़्म

कंसेंसस मैकेनिज़्म ब्लॉकचेन पर लेन-देन के सुरक्षित और सहमत सत्यापन को सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेन-देन के सत्यापन के लिए कंप्यूटिंग शक्ति पर निर्भर करता है।
- **Proof of Stake (PoS)** में वैलिडेटर के पास टोकन की एक निश्चित मात्रा होना आवश्यक है। इससे PoW की तुलना में ऊर्जा की खपत कम होती है।<sup>[[1]](#references)</sup>

## Bitcoin की मूल बातें

### लेन-देन

Bitcoin लेन-देन में पतों के बीच धनराशि का हस्तांतरण होता है। लेन-देन का सत्यापन डिजिटल हस्ताक्षरों के ज़रिए होता है, जिससे यह सुनिश्चित होता है कि केवल निजी कुंजी का मालिक ही हस्तांतरण शुरू कर सकता है।<sup>[[2]](#references)</sup>

#### मुख्य घटक:

- **मल्टीसिग्नेचर लेन-देन** के लिए लेन-देन को अधिकृत करने हेतु कई हस्ताक्षरों की आवश्यकता होती है।<sup>[[3]](#references)</sup>
- लेन-देन में **इनपुट** (धन का स्रोत), **आउटपुट** (गंतव्य), **फ़ीस** (माइनर्स को दी जाने वाली राशि) और **स्क्रिप्ट** (लेन-देन के नियम) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य किसी चैनल के भीतर कई लेन-देन की अनुमति देकर Bitcoin की स्केलेबिलिटी बढ़ाना है। ब्लॉकचेन पर केवल अंतिम स्थिति प्रसारित की जाती है।

## Bitcoin की गोपनीयता से जुड़ी चिंताएँ

**सामान्य इनपुट स्वामित्व** और **UTXO चेंज एड्रेस डिटेक्शन** जैसे गोपनीयता पर होने वाले हमले, लेन-देन के पैटर्न का फ़ायदा उठाते हैं। **मिक्सर** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच लेन-देन के संबंधों को छिपाकर गुमनामी बेहतर करती हैं।

## गुमनाम रूप से Bitcoin प्राप्त करना

इन तरीकों में नकद लेन-देन, माइनिंग और मिक्सर का इस्तेमाल शामिल है। **CoinJoin** कई लेन-देन को मिलाकर उनकी ट्रेसबिलिटी को कठिन बनाता है, जबकि **PayJoin** अधिक गोपनीयता के लिए CoinJoin को सामान्य लेन-देन जैसा दिखाता है।

# Bitcoin की गोपनीयता पर होने वाले हमलों का सारांश

Bitcoin की दुनिया में, लेन-देन की गोपनीयता और उपयोगकर्ताओं की गुमनामी अक्सर चिंता का विषय होती है। नीचे कुछ सामान्य तरीकों का सरल सारांश दिया गया है, जिनसे हमलावर Bitcoin की गोपनीयता से समझौता कर सकते हैं।<sup>[[6]](#references)</sup>

## **सामान्य इनपुट स्वामित्व की धारणा**

जटिलता के कारण, अलग-अलग उपयोगकर्ताओं के इनपुट को एक ही लेन-देन में जोड़ना आम तौर पर दुर्लभ होता है। इसलिए, **एक ही लेन-देन में मौजूद दो इनपुट पतों को अक्सर एक ही मालिक का माना जाता है**।

## **UTXO चेंज एड्रेस डिटेक्शन**

UTXO, यानी **Unspent Transaction Output**, को किसी लेन-देन में पूरी तरह खर्च करना होता है। अगर उसका केवल कुछ हिस्सा किसी दूसरे पते पर भेजा जाता है, तो बाकी राशि एक नए चेंज एड्रेस पर जाती है। देखने वाले यह मान सकते हैं कि यह नया पता भेजने वाले का है, जिससे गोपनीयता से समझौता हो सकता है।

### उदाहरण

इसे कम करने के लिए, मिक्सिंग सेवाओं या कई पतों का इस्तेमाल करके स्वामित्व को छिपाने में मदद मिल सकती है।

## **सोशल नेटवर्क और फ़ोरम पर जानकारी उजागर होना**

उपयोगकर्ता कभी-कभी अपने Bitcoin पते ऑनलाइन साझा करते हैं, जिससे **पते को उसके मालिक से जोड़ना आसान हो जाता है**।

## **लेन-देन ग्राफ़ का विश्लेषण**

लेन-देन को ग्राफ़ के रूप में दिखाया जा सकता है, जिससे धन के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित संबंध सामने आ सकते हैं।

## **अनावश्यक इनपुट हीयूरिस्टिक (इष्टतम चेंज हीयूरिस्टिक)**

यह हीयूरिस्टिक कई इनपुट और आउटपुट वाले लेन-देन का विश्लेषण करके यह अनुमान लगाता है कि कौन-सा आउटपुट भेजने वाले को लौटाया गया चेंज है।

### उदाहरण

```bash
2 btc --> 4 btc
3 btc     1 btc
```

यदि अधिक inputs जोड़ने से change output किसी एक input से बड़ा हो जाता है, तो heuristic भ्रमित हो सकती है।

## **Forced Address Reuse**

हमलावर पहले इस्तेमाल किए गए addresses पर छोटी रकम भेज सकते हैं, इस उम्मीद में कि प्राप्तकर्ता भविष्य के transactions में इन्हें अन्य inputs के साथ जोड़ देगा, जिससे addresses आपस में लिंक हो जाएंगे।

### Wallet का सही व्यवहार

इस privacy leak को रोकने के लिए wallets को पहले इस्तेमाल किए जा चुके, खाली addresses पर प्राप्त coins का उपयोग करने से बचना चाहिए।

## **Blockchain Analysis की अन्य तकनीकें**

- **सटीक भुगतान राशि:** बिना change वाले transactions संभवतः एक ही user के स्वामित्व वाले दो addresses के बीच होते हैं।
- **गोल संख्याएँ:** किसी transaction में गोल संख्या से संकेत मिलता है कि वह भुगतान है; गैर-गोल output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction बनाने के विशिष्ट तरीके होते हैं। इससे analysts इस्तेमाल किए गए software की पहचान कर सकते हैं और संभवतः change address का भी पता लगा सकते हैं।
- **राशि और समय का सहसंबंध:** Transaction का समय या राशि उजागर करने से transactions को trace किया जा सकता है।

## **Traffic Analysis**

Network traffic की निगरानी करके हमलावर transactions या blocks को IP addresses से जोड़ सकते हैं, जिससे user privacy खतरे में पड़ सकती है। यह खास तौर पर तब होता है जब कोई entity कई Bitcoin nodes संचालित करती है, जिससे transactions की निगरानी करने की उसकी क्षमता बढ़ जाती है।

## अधिक जानकारी

Privacy attacks और बचाव की पूरी सूची के लिए [Bitcoin Wiki पर Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin Transactions

## Anonymously Bitcoins प्राप्त करने के तरीके

- **नकद लेन-देन**: नकद के ज़रिए bitcoin प्राप्त करना।
- **नकद के विकल्प**: Gift cards खरीदकर उन्हें ऑनलाइन bitcoin के लिए exchange करना।
- **Mining**: Bitcoins कमाने का सबसे निजी तरीका mining है, खासकर अकेले mining करने पर, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools की जानकारी](https://en.bitcoin.it/wiki/Pooled_mining)
- **चोरी**: सैद्धांतिक रूप से, bitcoin चुराना उसे anonymously प्राप्त करने का एक और तरीका हो सकता है, हालांकि यह गैरकानूनी है और इसकी सलाह नहीं दी जाती।

## Mixing Services

Mixing service का उपयोग करके user **bitcoins भेज सकता है** और बदले में **अलग bitcoins प्राप्त कर सकता है**, जिससे मूल मालिक का पता लगाना कठिन हो जाता है। हालांकि, इसके लिए service पर भरोसा करना पड़ता है कि वह logs नहीं रखेगी और वास्तव में bitcoins लौटा देगी। Bitcoin casinos भी mixing के विकल्प हैं।

## CoinJoin

**CoinJoin** अलग-अलग users के कई transactions को मिलाकर एक transaction बना देता है, जिससे inputs को outputs से मिलाने की कोशिश जटिल हो जाती है। प्रभावी होने के बावजूद, अलग आकार वाले inputs और outputs के transactions को फिर भी trace किया जा सकता है।

CoinJoin का उपयोग करने वाले संभावित transactions के उदाहरण हैं `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। ऐसे Ethereum smart-contract mixer के लिए, जो deposits को बाद में होने वाले withdrawals से अलग रखता है, [Tornado Cash](https://tornado.cash) देखें।

## PayJoin

CoinJoin का एक रूप, **PayJoin** (या P2EP), दो पक्षों (जैसे, ग्राहक और व्यापारी) के बीच के transaction को सामान्य transaction जैसा दिखाता है और CoinJoin की विशिष्ट समान outputs वाली विशेषता से बचता है। इससे इसका पता लगाना बेहद कठिन हो जाता है और transaction surveillance entities द्वारा इस्तेमाल की जाने वाली common-input-ownership heuristic अमान्य हो सकती है।

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

ऊपर दिए गए जैसे transactions PayJoin हो सकते हैं, जो standard bitcoin transactions से अलग पहचाने बिना privacy को बेहतर बनाते हैं।

**PayJoin का उपयोग पारंपरिक surveillance methods को काफ़ी हद तक बाधित कर सकता है**, जिससे यह transactional privacy की दिशा में एक आशाजनक विकास बनता है।

# Cryptocurrencies में Privacy के लिए सर्वोत्तम तरीके

## **Wallet Synchronization Techniques**

Privacy और security बनाए रखने के लिए wallets को blockchain के साथ synchronize करना महत्वपूर्ण है। दो methods विशेष रूप से उपयोगी हैं:

- **Full node**: पूरी blockchain डाउनलोड करके, full node अधिकतम privacy सुनिश्चित करता है। अब तक किए गए सभी transactions स्थानीय रूप से संग्रहित होते हैं, जिससे adversaries के लिए यह पहचानना असंभव हो जाता है कि user किन transactions या addresses में रुचि रखता है।
- **Client-side block filtering**: इस method में blockchain के हर block के लिए filters बनाए जाते हैं, जिससे wallets network observers के सामने अपनी खास रुचि उजागर किए बिना relevant transactions पहचान सकते हैं। Lightweight wallets इन filters को डाउनलोड करते हैं और केवल तभी पूरे blocks प्राप्त करते हैं, जब user के addresses से कोई match मिलता है।

## **Anonymity के लिए Tor का उपयोग**

चूंकि Bitcoin peer-to-peer network पर काम करता है, इसलिए अपना IP address छिपाने के लिए Tor का उपयोग करने की सलाह दी जाती है। इससे network के साथ interaction करते समय privacy बेहतर होती है।

## **Address Reuse रोकना**

Privacy की रक्षा के लिए हर transaction में नया address इस्तेमाल करना ज़रूरी है। Addresses को दोबारा इस्तेमाल करने से transactions एक ही entity से जुड़ सकते हैं और privacy से समझौता हो सकता है। आधुनिक wallets अपने design के ज़रिए address reuse को हतोत्साहित करते हैं।

## **Transaction Privacy के लिए Strategies**

- **Multiple transactions**: एक payment को कई transactions में बाँटने से transaction की राशि छिप सकती है और privacy attacks को नाकाम किया जा सकता है।
- **Change से बचना**: ऐसे transactions चुनने से, जिनमें change outputs की ज़रूरत न हो, change detection methods बाधित होते हैं और privacy बेहतर होती है।
- **Multiple change outputs**: अगर change से बचना संभव न हो, तो कई change outputs बनाने से भी privacy बेहतर हो सकती है।

# **Monero: Anonymity का प्रतीक**

Monero को transaction privacy को प्राथमिकता देने के लिए बनाया गया है।

# **Ethereum: Gas और Transactions**

## **Gas को समझना**

Gas, Ethereum पर operations करने के लिए आवश्यक computational effort को मापता है और इसकी कीमत **gwei** में तय होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाले transaction में gas limit और base fee शामिल होते हैं; साथ ही validator द्वारा उसे शामिल किए जाने के लिए प्रोत्साहित करने हेतु priority fee भी होती है। Users यह सुनिश्चित करने के लिए max fee तय कर सकते हैं कि वे ज़रूरत से ज़्यादा भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।<sup>[[5]](#references)</sup>

## **Transactions निष्पादित करना**

Ethereum में transactions में एक sender और recipient शामिल होते हैं, जो user या smart contract addresses हो सकते हैं। इनके लिए fee देनी होती है और इन्हें किसी block में शामिल किया जाना चाहिए। Transaction की आवश्यक जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit और fees शामिल हैं। ध्यान दें कि sender का address signature से निकाला जाता है, इसलिए उसे transaction data में शामिल करने की ज़रूरत नहीं होती।<sup>[[4]](#references)</sup>

ये practices और mechanisms उन सभी लोगों के लिए बुनियादी हैं, जो privacy और security को प्राथमिकता देते हुए cryptocurrencies का उपयोग करना चाहते हैं।

## Value-Centric Web3 Red Teaming

- यह समझने के लिए value रखने वाले components (signers, oracles, bridges, automation) की सूची बनाएँ कि funds कौन और कैसे move कर सकता है।
- privilege escalation paths उजागर करने के लिए हर component को संबंधित MITRE AADAPT tactics से map करें।
- प्रभाव की पुष्टि करने और exploit की जा सकने वाली पूर्व-शर्तों का दस्तावेज़ीकरण करने के लिए flash-loan/oracle/credential/cross-chain attack chains का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow में Compromise

- Wallet UIs की supply-chain tampering से signing से ठीक पहले EIP-712 payloads में बदलाव किया जा सकता है, जिससे delegatecall-based proxy takeovers (उदाहरण के लिए, Safe masterCopy को slot-0 में overwrite करना) के लिए valid signatures हासिल किए जा सकते हैं।

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

जब कोई prover किसी दावे की पुष्टि करने के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier केवल यह जानता है कि **guest program को लिखे गए निर्देशों के अनुसार निष्पादित किया गया**। यदि guest में **unsafe deserialization**, **undefined behavior**, या **missing semantic constraints** हों, तो malicious prover ऐसा proof बना सकता है जो सत्यापित हो जाए, जबकि **public metrics या दावा किया गया invariant गलत हो**।<sup>[[7]](#references)</sup>

### Proof guests के अंदर Unsafe deserialization

- Private witness/circuit bytes को **untrusted attacker input** मानें, भले ही वे proof से छिपे हों।
- `rkyv::access_unchecked` जैसे unchecked helpers से उन्हें deserialize न करें, जब तक कि bytes को पहले out-of-band validate न किया गया हो।
- Untrusted serialized data से लोड किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access पर असर डालने से पहले validate करना ज़रूरी है।

व्यावहारिक audit pattern:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

यदि `op.kind` जैसा कोई field enum है और attacker उसमें **out-of-range discriminant** inject कर सकता है, तो उस value पर किया गया हर downstream `match` संदिग्ध हो जाता है।

### Jump-table / UB counter bypass

यदि Rust किसी बड़े `match` को **jump table** में बदलता है, तो invalid enum discriminant से **undefined control flow** हो सकता है। एक खतरनाक pattern है:<sup>[[7]](#references)[[9]](#references)</sup>

1. एक `match` **security-critical counters/constraints** अपडेट करता है।
2. दूसरा `match` **वास्तविक instruction semantics** लागू करता है।
3. out-of-range discriminant पहली jump table के बाहर index करता है और दूसरी jump table से जुड़े code पर पहुँच जाता है।

परिणाम: operation फिर भी execute होता है, लेकिन accounting path छूट जाता है। zkVM में इससे ऐसे forged proofs बन सकते हैं जो असंभव metrics रिपोर्ट करते हैं—जैसे कम gates, कम expensive operations या अन्य falsified bounded resources।

Review checklist:

- witness/private input से deserialize किए गए attacker-controlled enums खोजें।
- एक ही opcode/kind field पर बार-बार होने वाले `match` statements की जाँच करें।
- `unsafe` + unchecked deserialization + large opcode dispatch के मेल को high-risk मानें।
- ज़रूरत पड़ने पर emitted binary को reverse engineer करें; jump-table layout, source से ज़्यादा मायने रख सकता है।

### Reversible/specialized interpreters में semantic constraints का अभाव

सिर्फ़ memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof को लागू करना है।

Reversible/quantum-like instruction sets में सुनिश्चित करें कि जिन operands का अलग होना आवश्यक है, उन पर वास्तव में अलग होने की constraint लगी हो। Toffoli/CCX-जैसा operation यदि इस तरह implemented हो:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

असुरक्षित हो जाता है यदि guest अस्वीकार नहीं करता:

```text
op.q_control1 == op.q_control2 == op.q_target
```

उस स्थिति में संक्रमण सिमटकर यह बन जाता है:

```text
q = q ^ (q & q) = 0
```

यह एक **deterministic reset primitive** बनाता है, reversibility की धारणाओं को तोड़ता है और कम लागत वाली unintended computations को सक्षम करता है। Resource usage को प्रमाणित करने वाले proof systems में, इससे attackers functional checks पास कर सकते हैं और साथ ही verifier जिस cost model को लागू मानता है, उसे bypass कर सकते हैं।

### Underconstrained prover advice और modular arithmetic

**Advice/witness stack** से लोड की गई values prover के नियंत्रण में होती हैं, भले ही उन्हें precomputed quotients, remainders, inverses या hints के रूप में बताया गया हो। Proof सिर्फ यह स्थापित करता है कि witness लागू की गई constraints को संतुष्ट करता है; अगर उन constraints में type, range या canonical-form check शामिल न हो, तो यह intended computation को स्थापित नहीं करता।<sup>[[13]](#references)</sup>

Reduction या Euclidean-division helper के लिए, केवल अंतिम subtraction या multiplication के बजाय पूरी integer relation का audit करें। `q` और `r` के हर limb को उसकी घोषित width तक constrained होना चाहिए, reconstruction `x = q * m + r` को इच्छित integer representation में सत्य होना चाहिए, और canonical bound `0 <= r < m` लागू होना चाहिए। किसी value को narrower `u32`/`u64` instruction में पास करने **से पहले** उसे validate करें; कोई narrow operation पीछे से यह साबित नहीं करता कि मूल field element या multi-limb value का type अपेक्षित था।<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Miden में `mod_12289` की विफलता exploit pattern को दर्शाती है: quotient को दो-limb 64-bit value के रूप में जाँचा गया था, लेकिन advice से मिला remainder बिना समकक्ष validation के `u32overflowing_sub` तक पहुँच गया। एक malicious prover invalid quotient/remainder values में तालमेल बिठा सकता था, ताकि लागू subtraction constraints फिर भी पूरी हों, जबकि procedure एक गैर-गणितीय remainder लौटाए। चूँकि यह परिणाम Falcon verification में इस्तेमाल हुआ, इसलिए soundness की इस विफलता को केवल गलत arithmetic result देने के बजाय forged authorization signatures बनाने तक बढ़ाया जा सकता था।<sup>[[13]](#references)</sup>

### Implicit-stack cryptographic VMs का ऑडिट करना

Stack languages operands को छिपाती हैं, इसलिए पहले instructions को ऐसे IR में बदलें जहाँ हर consumed और produced stack value provenance के साथ एक expression हो। इसके बाद एक conservative analysis pipeline यह कर सकती है:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Call graph बनाएँ और procedure के input/output stack effects का अनुमान लगाएँ।
2. समर्थित instructions को symbolically execute करें और control flow को SSA/structured expressions में बदलें।
3. `Unknown`, `ProvenU32`, `Bool`, value provenance और local initialization जैसे abstract facts को fixed point तक propagate करें।
4. उन advice-derived values को flag करें जो **हर** incoming path पर sanitizer के बिना typed arithmetic या non-zero sinks तक पहुँचती हैं।
5. Declared और inferred signatures की तुलना करें और सत्यापित करें कि हर exit, caller-owned stack values को सुरक्षित रखता है।

Unknown signature या unsupported construct को साफ़ परिणाम नहीं, बल्कि **analysis gap** मानें। Dynamic calls, non-stack-neutral loops और अलग-अलग stack effects वाली branches sound stack-slot tracking को असंभव बना सकती हैं; सुरक्षित decompiler, विश्वसनीय लेकिन गलत pseudocode देने के बजाय, ऐसे मामलों को अस्वीकार करता है या चिह्नित करता है।<sup>[[10]](#references)[[13]](#references)</sup>

Control-flow joins पर कोई property तभी बनाए रखें जब वह हर predecessor पर सही हो (उदाहरण के लिए, `ProvenU32 join Unknown = Unknown`)। Fixed-point convergence और iteration limit तक पहुँचने के बीच भी अंतर करें: केवल converged, sound over-approximation ही यह मानने का आधार दे सकती है कि diagnostic का न होना इस बात का सबूत है कि दर्शाए गए सभी executions property को पूरा करते हैं।<sup>[[11]](#references)</sup>

### छिपी preconditions उजागर करने के लिए proof obligations का उपयोग करें

छोटे instruction sets के लिए procedures को executable formal VM model में बदलें और result के साथ-साथ पूरे stack transformation को भी prove करें। Theorem में termination, typed inputs, अपेक्षित output prefix और untouched caller stack का संरक्षण शामिल होना चाहिए। Theorem statement का proof जितनी सावधानी से ऑडिट करें: kernel किसी अनजाने में कमजोर किए गए दावे के proof को भी validate कर सकता है।<sup>[[12]](#references)[[13]](#references)</sup>

अप्रत्याशित hypotheses उपयोगी findings हैं। Miden review में, 64-bit right rotation के proof के लिए `shift mod 32 != 0` आवश्यक था, जिससे पता चला कि shift के 32 का multiple होने पर बड़े inputs के लिए edge case विफल होता है; एक अन्य proof में पता चला कि 256-bit `wrapping_mul` caller-owned stack values को discard करता है। खोजे गए boundary case को tests में जोड़ें, फिर चुपचाप अतिरिक्त assumption स्वीकार करने के बजाय implementation ठीक करें या public precondition को स्पष्ट रूप से मजबूत करें।<sup>[[12]](#references)[[13]](#references)</sup>

### ZK systems में क्या जाँचें

- सभी guest parsers को malformed witness/private-input encodings के साथ fuzz करें।
- Opcode dispatch से पहले enum range validation की पुष्टि करें।
- Operand aliasing और अन्य invalid instruction forms के लिए semantic checks जोड़ें।
- हर advice/witness source को हर typed arithmetic sink तक trace करें और हर path पर validation अनिवार्य करें।<sup>[[11]](#references)[[13]](#references)</sup>
- Arithmetic helpers को non-canonical limbs, range से बाहर remainders और boundary shift counts के साथ test करें।<sup>[[12]](#references)[[13]](#references)</sup>
- हर return पर stack height और procedure के घोषित arguments के नीचे मौजूद values के संरक्षण की पुष्टि करें।<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Report किए गए/public counters की तुलना एक independent reference implementation से करें।
- याद रखें कि यदि guest program में bug है, तो valid proof भी **गलत statement** को prove कर सकता है।

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs के practical exploitation पर शोध कर रहे हैं (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps), तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Virtual balances को cache करने वाले multi-asset weighted pools, जिन्हें `supply == 0` होने पर poison किया जा सकता है, उनके लिए देखें:

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
- [7] [Trail of Bits - हमने Google के quantum cryptanalysis के zero-knowledge proof को मात दी](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum vulnerabilities के विरुद्ध elliptic curve cryptocurrencies को सुरक्षित करना: संसाधन अनुमान और mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler architecture](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM static-analysis engine](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean model और correctness proofs](https://github.com/trailofbits/masm-lean)
- [13] [पर्याप्त रूप से अच्छी AI के दौर में auditing](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
