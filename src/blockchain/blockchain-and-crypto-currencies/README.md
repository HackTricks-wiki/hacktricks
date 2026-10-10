# ब्लॉकचेन और क्रिप्टोकरेंसी

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **Smart Contracts** ऐसे प्रोग्राम होते हैं जो कुछ शर्तें पूरी होने पर ब्लॉकचेन पर चलते हैं और मध्यस्थों के बिना समझौतों के निष्पादन को स्वचालित करते हैं।
- **Decentralized Applications (dApps)**, smart contracts पर आधारित होते हैं और इनमें उपयोगकर्ता-अनुकूल front-end तथा पारदर्शी, ऑडिट किए जा सकने वाला back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल मुद्रा के रूप में काम करते हैं, जबकि tokens विशिष्ट संदर्भों में मूल्य या स्वामित्व दर्शाते हैं।
  - **Utility Tokens** सेवाओं का ऐक्सेस देते हैं, जबकि **Security Tokens** परिसंपत्ति का स्वामित्व दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को कहते हैं।

## सहमति तंत्र

सहमति तंत्र ब्लॉकचेन पर सुरक्षित और सर्वसम्मति से लेन-देन के सत्यापन को सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेन-देन के सत्यापन के लिए कंप्यूटेशनल शक्ति पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators को निश्चित मात्रा में tokens रखने होते हैं, जिससे PoW की तुलना में ऊर्जा की खपत कम होती है।<sup>[[1]](#references)</sup>

## Bitcoin की बुनियादी बातें

### लेन-देन

Bitcoin के लेन-देन में addresses के बीच funds का हस्तांतरण होता है। लेन-देन digital signatures से सत्यापित किए जाते हैं, जिससे यह सुनिश्चित होता है कि केवल private key का स्वामी ही हस्तांतरण शुरू कर सकता है।<sup>[[2]](#references)</sup>

#### मुख्य घटक:

- **Multisignature Transactions** में लेन-देन को अधिकृत करने के लिए कई signatures की आवश्यकता होती है।<sup>[[3]](#references)</sup>
- लेन-देन में **inputs** (funds का स्रोत), **outputs** (गंतव्य), **fees** (miners को दिए जाने वाले), और **scripts** (लेन-देन के नियम) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य एक channel में कई लेन-देन की अनुमति देकर Bitcoin की scalability बढ़ाना है; blockchain पर केवल अंतिम स्थिति प्रसारित की जाती है।

## Bitcoin की गोपनीयता संबंधी चिंताएँ

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks, लेन-देन के patterns का फ़ायदा उठाते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच लेन-देन के links को छिपाकर anonymity बेहतर करती हैं।

## गुमनाम रूप से Bitcoins प्राप्त करना

तरीकों में नकद लेन-देन, mining और mixers का उपयोग शामिल है। **CoinJoin** कई लेन-देन को मिलाकर उनकी traceability को कठिन बनाता है, जबकि **PayJoin** अधिक गोपनीयता के लिए CoinJoins को सामान्य लेन-देन जैसा दिखाता है।

# Bitcoin की गोपनीयता पर हमलों का सारांश

Bitcoin की दुनिया में लेन-देन की गोपनीयता और उपयोगकर्ताओं की anonymity अक्सर चिंता का विषय होती है। यहाँ उन कई आम तरीकों का संक्षिप्त विवरण दिया गया है जिनसे attackers Bitcoin की गोपनीयता से समझौता कर सकते हैं।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

जटिलता के कारण, अलग-अलग उपयोगकर्ताओं के inputs को एक ही लेन-देन में मिलाना आम तौर पर दुर्लभ है। इसलिए, **एक ही लेन-देन में मौजूद दो input addresses को अक्सर एक ही स्वामी का माना जाता है**।

## **UTXO Change Address Detection**

UTXO, यानी **Unspent Transaction Output**, को लेन-देन में पूरी तरह खर्च करना होता है। यदि इसका केवल एक हिस्सा किसी दूसरे address पर भेजा जाता है, तो बची हुई राशि एक नए change address पर जाती है। देखने वाले यह मान सकते हैं कि यह नया address भेजने वाले का है, जिससे उसकी गोपनीयता से समझौता हो सकता है।

### उदाहरण

इसे कम करने के लिए mixing services का उपयोग करना या कई addresses रखना स्वामित्व को छिपाने में मदद कर सकता है।

## **सोशल नेटवर्क और फ़ोरम पर जानकारी उजागर होना**

उपयोगकर्ता कभी-कभी अपने Bitcoin addresses ऑनलाइन साझा करते हैं, जिससे **address को उसके स्वामी से जोड़ना आसान हो जाता है**।

## **लेन-देन ग्राफ़ का विश्लेषण**

लेन-देन को graphs के रूप में दिखाया जा सकता है, जिससे funds के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित संबंध सामने आते हैं।

## **अनावश्यक Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले लेन-देन का विश्लेषण करके अनुमान लगाता है कि कौन-सा output भेजने वाले को लौटाया गया change है।

### उदाहरण

```bash
2 btc --> 4 btc
3 btc     1 btc
```

यदि अधिक inputs जोड़ने से change output किसी एक input से बड़ा हो जाता है, तो इससे heuristic भ्रमित हो सकता है।

## **Forced Address Reuse**

हमलावर पहले इस्तेमाल किए जा चुके addresses पर छोटी रकम भेज सकते हैं। उन्हें उम्मीद होती है कि प्राप्तकर्ता भविष्य के transactions में इन्हें दूसरे inputs के साथ जोड़ देगा, जिससे addresses आपस में link हो जाएंगे।

### Wallet का सही व्यवहार

इस privacy leak से बचने के लिए wallets को पहले इस्तेमाल किए जा चुके, खाली addresses पर प्राप्त coins का उपयोग करने से बचना चाहिए।

## **Blockchain Analysis की अन्य तकनीकें**

- **सटीक भुगतान राशियाँ:** जिन transactions में change नहीं होता, वे संभवतः एक ही user के स्वामित्व वाले दो addresses के बीच होते हैं।
- **गोल संख्याएँ:** किसी transaction में गोल संख्या भुगतान का संकेत हो सकती है, और गैर-गोल output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction बनाने के अनूठे तरीके होते हैं। इससे analysts इस्तेमाल किए गए software और संभावित रूप से change address की पहचान कर सकते हैं।
- **राशि और समय का संबंध:** transaction का समय या राशि उजागर करने से transactions को trace किया जा सकता है।

## **Traffic Analysis**

Network traffic पर नज़र रखकर हमलावर transactions या blocks को IP addresses से link कर सकते हैं, जिससे user की privacy से समझौता हो सकता है। ऐसा खासकर तब होता है, जब कोई entity कई Bitcoin nodes चलाती हो, जिससे transactions पर नज़र रखने की उसकी क्षमता बढ़ जाती है।

## More

Privacy attacks और बचाव के बारे में पूरी जानकारी के लिए [Bitcoin Wiki पर Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) देखें।

# Anonymous Bitcoin Transactions

## Bitcoins को गुमनाम रूप से पाने के तरीके

- **नकद लेन-देन**: नकद के ज़रिए bitcoin प्राप्त करना।
- **नकद के विकल्प**: gift cards खरीदना और उन्हें online bitcoin के लिए exchange करना।
- **Mining**: bitcoins कमाने का सबसे निजी तरीका mining है, खासकर अकेले mining करने पर, क्योंकि mining pools को miner का IP address पता चल सकता है। [Mining Pools की जानकारी](https://en.bitcoin.it/wiki/Pooled_mining)
- **चोरी**: सैद्धांतिक रूप से, bitcoin चुराना उसे गुमनाम रूप से पाने का एक और तरीका हो सकता है, लेकिन यह गैर-कानूनी है और इसकी सलाह नहीं दी जाती।

## Mixing Services

Mixing service का इस्तेमाल करके, कोई user **bitcoins भेज** सकता है और बदले में **अलग bitcoins प्राप्त** कर सकता है, जिससे मूल मालिक का पता लगाना मुश्किल हो जाता है। हालांकि, इसके लिए service पर भरोसा करना पड़ता है कि वह logs नहीं रखेगी और वास्तव में bitcoins लौटाएगी। Bitcoin casinos भी mixing के वैकल्पिक विकल्प हैं।

## CoinJoin

**CoinJoin** अलग-अलग users के कई transactions को एक में मिला देता है, जिससे inputs को outputs से match करना कठिन हो जाता है। प्रभावी होने के बावजूद, अनूठे input और output आकार वाले transactions को अब भी trace किया जा सकता है।

CoinJoin का इस्तेमाल किए गए संभावित transactions के उदाहरण हैं: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। ऐसे Ethereum smart-contract mixer के लिए, जो deposits को बाद में होने वाले withdrawals से अलग रखता है, [Tornado Cash](https://tornado.cash) देखें।

## PayJoin

CoinJoin का एक प्रकार, **PayJoin** (या P2EP), दो पक्षों (जैसे, ग्राहक और व्यापारी) के बीच के transaction को एक सामान्य transaction जैसा दिखाता है। इसमें CoinJoin की विशेषता वाले समान outputs नहीं होते। इससे इसका पता लगाना बेहद कठिन हो जाता है और transaction-surveillance entities द्वारा इस्तेमाल की जाने वाली common-input-ownership heuristic अमान्य हो सकती है।

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

ऊपर दिए गए उदाहरण जैसे लेन-देन PayJoin हो सकते हैं, जो मानक bitcoin लेन-देन से अलग पहचाने बिना गोपनीयता बढ़ाते हैं।

**PayJoin का उपयोग पारंपरिक निगरानी के तरीकों को काफी बाधित कर सकता है**, इसलिए लेन-देन की गोपनीयता की दिशा में यह एक आशाजनक विकास है।

# क्रिप्टोकरेंसी में गोपनीयता के लिए सर्वोत्तम तरीके

## **Wallet सिंक्रोनाइज़ेशन तकनीकें**

गोपनीयता और सुरक्षा बनाए रखने के लिए, wallet को blockchain के साथ सिंक्रोनाइज़ करना ज़रूरी है। दो तरीके खास हैं:

- **Full node**: पूरी blockchain डाउनलोड करके, full node अधिकतम गोपनीयता सुनिश्चित करता है। अब तक किए गए सभी लेन-देन स्थानीय रूप से संग्रहीत होते हैं, जिससे हमलावरों के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किन लेन-देन या पतों में दिलचस्पी रखता है।
- **Client-side block filtering**: इस तरीके में blockchain के हर block के लिए filters बनाए जाते हैं, जिससे wallet नेटवर्क पर नज़र रखने वालों के सामने अपनी खास दिलचस्पियाँ उजागर किए बिना प्रासंगिक लेन-देन पहचान सकते हैं। हल्के wallet इन filters को डाउनलोड करते हैं और पूरा block तभी प्राप्त करते हैं, जब उपयोगकर्ता के पतों से मेल मिलता है।

## **गुमनामी के लिए Tor का उपयोग**

चूँकि Bitcoin peer-to-peer नेटवर्क पर काम करता है, इसलिए अपना IP address छिपाने के लिए Tor का उपयोग करने की सलाह दी जाती है। इससे नेटवर्क के साथ संवाद करते समय गोपनीयता बढ़ती है।

## **पता दोबारा इस्तेमाल करने से बचना**

गोपनीयता की सुरक्षा के लिए, हर लेन-देन के लिए नया पता इस्तेमाल करना ज़रूरी है। पते दोबारा इस्तेमाल करने से लेन-देन एक ही इकाई से जुड़ सकते हैं और गोपनीयता भंग हो सकती है। आधुनिक wallet अपने डिज़ाइन के ज़रिए पते दोबारा इस्तेमाल करने से हतोत्साहित करते हैं।

## **लेन-देन की गोपनीयता के लिए रणनीतियाँ**

- **कई लेन-देन**: भुगतान को कई लेन-देन में बाँटने से लेन-देन की राशि छिप सकती है और गोपनीयता पर होने वाले हमले विफल हो सकते हैं।
- **चेंज से बचना**: ऐसे लेन-देन चुनना जिनमें चेंज आउटपुट की ज़रूरत न हो, चेंज का पता लगाने के तरीकों को बाधित करके गोपनीयता बढ़ाता है।
- **कई चेंज आउटपुट**: अगर चेंज से बचना संभव न हो, तो कई चेंज आउटपुट बनाकर भी गोपनीयता बेहतर की जा सकती है।

# **Monero: गुमनामी की मिसाल**

Monero को लेन-देन की गोपनीयता को प्राथमिकता देने के लिए डिज़ाइन किया गया है।

# **Ethereum: Gas और लेन-देन**

## **Gas को समझना**

Gas, Ethereum पर कार्रवाइयाँ करने के लिए आवश्यक कंप्यूटेशनल प्रयास को मापता है और इसकी कीमत **gwei** में तय होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाले लेन-देन में gas limit और base fee शामिल होते हैं। इसके साथ validator को लेन-देन शामिल करने के लिए प्रोत्साहित करने वाली priority fee भी होती है। उपयोगकर्ता अधिकतम शुल्क तय कर सकते हैं, ताकि वे ज़रूरत से ज़्यादा भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।<sup>[[5]](#references)</sup>

## **लेन-देन करना**

Ethereum में लेन-देन में एक प्रेषक और एक प्राप्तकर्ता शामिल होते हैं, जो user या smart contract के पते हो सकते हैं। इनके लिए शुल्क देना होता है और इन्हें किसी block में शामिल किया जाना चाहिए। लेन-देन में आवश्यक जानकारी में प्राप्तकर्ता, प्रेषक का signature, राशि, वैकल्पिक डेटा, gas limit और शुल्क शामिल हैं। ध्यान दें कि प्रेषक का पता signature से निकाला जाता है, इसलिए लेन-देन डेटा में इसे शामिल करने की ज़रूरत नहीं होती।<sup>[[4]](#references)</sup>

ये तरीके और प्रणालियाँ उन सभी लोगों के लिए बुनियादी हैं, जो गोपनीयता और सुरक्षा को प्राथमिकता देते हुए क्रिप्टोकरेंसी का उपयोग करना चाहते हैं।

## Web3 में मूल्य-केंद्रित Red Teaming

- मूल्य रखने वाले घटकों (signers, oracles, bridges, automation) की सूची बनाएँ, ताकि समझ सकें कि कौन धनराशि स्थानांतरित कर सकता है और कैसे।
- privilege escalation के रास्ते उजागर करने के लिए हर घटक को प्रासंगिक MITRE AADAPT tactics से जोड़ें।
- प्रभाव की पुष्टि करने और शोषण योग्य पूर्वशर्तें दर्ज करने के लिए flash-loan/oracle/credential/cross-chain हमले की शृंखलाओं का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow से समझौता

- Wallet UI में supply-chain छेड़छाड़ से signing से ठीक पहले EIP-712 payloads बदले जा सकते हैं। इससे delegatecall-आधारित proxy takeover (जैसे Safe masterCopy का slot-0 overwrite) के लिए मान्य signatures हासिल किए जा सकते हैं।

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Smart account की आम विफलताओं में `EntryPoint` access control को bypass करना, unsigned gas fields, stateful validation, ERC-1271 replay और validation के बाद revert करके शुल्क निकालना शामिल है।

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract सुरक्षा

- Test suite में छूटे हुए मामलों का पता लगाने के लिए mutation testing:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest की अखंडता

जब कोई prover किसी दावे की पुष्टि के लिए **zkVM** या application-specific proof circuit का इस्तेमाल करता है, तो verifier को केवल यह पता चलता है कि **guest program लिखे गए निर्देशों के अनुसार चला**। अगर guest में **unsafe deserialization**, **undefined behavior**, या **semantic constraints की कमी** है, तो कोई दुर्भावनापूर्ण prover ऐसा proof बना सकता है जो सत्यापित हो जाए, जबकि **public metrics या दावा किया गया invariant गलत हो**।<sup>[[7]](#references)</sup>

### Proof guest के भीतर unsafe deserialization

- Private witness/circuit bytes को **अविश्वसनीय attacker input** मानें, भले ही वे proof से छिपे हों।
- `rkyv::access_unchecked` जैसे unchecked helpers से उन्हें deserialize न करें, जब तक कि bytes को पहले किसी अन्य माध्यम से validate न किया गया हो।
- अविश्वसनीय serialized data से लोड किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access पर प्रभाव डालने से पहले validate करना आवश्यक है।

व्यावहारिक audit का तरीका:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

यदि `op.kind` जैसा कोई field enum है और attacker उसमें **out-of-range discriminant** inject कर सकता है, तो उस value पर होने वाला हर downstream `match` संदेहास्पद हो जाता है।

### Jump-table / UB counter bypass

यदि Rust किसी बड़े `match` को **jump table** में बदलता है, तो invalid enum discriminant से **undefined control flow** हो सकता है। एक खतरनाक pattern यह है:<sup>[[7]](#references)[[9]](#references)</sup>

1. एक `match` **security-critical counters/constraints** को update करता है।
2. दूसरा `match` **वास्तविक instruction semantics** लागू करता है।
3. Out-of-range discriminant पहले jump table के बाद के index पर पहुँचता है और दूसरे jump table से जुड़े code पर चला जाता है।

नतीजा: operation फिर भी execute होता है, लेकिन accounting path छोड़ दिया जाता है। zkVM में इससे ऐसे forged proofs बन सकते हैं जो असंभव metrics की रिपोर्ट करते हैं—जैसे कम gates, कम expensive operations या अन्य falsified bounded resources।

जाँच-सूची:

- Witness/private input से deserialize किए गए attacker-controlled enums खोजें।
- एक ही opcode/kind field पर बार-बार किए गए `match` statements की जाँच करें।
- `unsafe` + unchecked deserialization + बड़े opcode dispatch को high-risk combination मानें।
- ज़रूरत पड़ने पर emitted binary को reverse engineer करें; jump-table layout, source से ज़्यादा मायने रख सकता है।

### Reversible/specialized interpreters में semantic constraints का अभाव

सिर्फ memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof को लागू करना है।

Reversible/quantum-like instruction sets में सुनिश्चित करें कि जिन operands का अलग-अलग होना ज़रूरी है, उन पर वास्तव में distinct होने की constraint लागू हो। Toffoli/CCX-like operation को इस तरह implement किया गया हो:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

असुरक्षित हो जाता है यदि guest इसे अस्वीकार नहीं करता:

```text
op.q_control1 == op.q_control2 == op.q_target
```

उस स्थिति में संक्रमण सिमटकर यह हो जाता है:

```text
q = q ^ (q & q) = 0
```

यह एक **deterministic reset primitive** बनाता है, reversibility की धारणाओं को तोड़ता है और कम लागत वाली unintended computations को सक्षम करता है। ऐसे proof systems में जो resource usage की पुष्टि करते हैं, हमलावर इससे functional checks पास कर सकते हैं और साथ ही उस cost model को दरकिनार कर सकते हैं जिसे verifier लागू होता हुआ मानता है।

### ZK systems में क्या test करें

- Malformed witness/private-input encodings के साथ सभी guest parsers को fuzz करें।
- Opcode dispatch से पहले enum range validation सुनिश्चित करें।
- Operand aliasing और अन्य invalid instruction forms के लिए semantic checks जोड़ें।
- Reported/public counters की तुलना किसी independent reference implementation से करें।
- याद रखें कि यदि guest program में bug है, तो valid proof भी **गलत statement** साबित कर सकता है।

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs के practical exploitation (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold-crossing swaps) पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Multi-asset weighted pools के लिए, जो virtual balances cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, अध्ययन करें:

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
- [7] [Trail of Bits - हमने Google के zero-knowledge proof of quantum cryptanalysis को हराया](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum Vulnerabilities के विरुद्ध Elliptic Curve Cryptocurrencies को सुरक्षित करना: Resource Estimates और Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
