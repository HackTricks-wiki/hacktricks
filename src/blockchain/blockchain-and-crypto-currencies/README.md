# Blockchain और Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

इस अध्याय में blockchain की अवधारणाओं और on-chain security को शामिल किया गया है। किसी exposed Bitcoin peer के लिए, [Bitcoin P2P service enumeration](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md) से शुरुआत करें; browser frontend, wallet connection या off-chain backend के लिए, [DApp pentesting](../../pentesting-web/dapps-DecentralizedApplications.md) का उपयोग करें। Cryptocurrency privacy operations और उनकी सीमाओं के लिए, [cryptocurrency privacy chapter](../../privacy/cryptocurrency-privacy.md) देखें।

## मूल अवधारणाएँ

- **Smart Contracts** ऐसे programs होते हैं जो कुछ शर्तें पूरी होने पर blockchain पर execute होते हैं और intermediaries के बिना समझौतों के क्रियान्वयन को स्वचालित बनाते हैं।
- **Decentralized Applications (dApps)**, smart contracts पर आधारित होते हैं और इनमें user-friendly front-end तथा पारदर्शी, auditable back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल मुद्रा के रूप में काम करते हैं, जबकि tokens विशिष्ट संदर्भों में मूल्य या स्वामित्व दर्शाते हैं।
  - **Utility Tokens** सेवाओं तक पहुँच देते हैं, जबकि **Security Tokens** किसी asset के स्वामित्व को दर्शाते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ उपलब्ध कराता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को दर्शाते हैं।

Crypto markets में spot orders, futures, leverage और options से जुड़ी शब्दावली के लिए [Investment Terms](investment-terms.md) देखें।

## Consensus Mechanisms

Consensus mechanisms blockchain पर सुरक्षित और सहमति-आधारित transaction validation सुनिश्चित करते हैं:

- **Proof of Work (PoW)** transaction verification के लिए computational power पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators के पास निश्चित मात्रा में tokens होना आवश्यक है। इससे PoW की तुलना में energy consumption कम होता है।<sup>[[1]](#references)</sup>

## Bitcoin की मूल बातें

### Transactions

Bitcoin transactions में addresses के बीच funds transfer किए जाते हैं। Transactions को digital signatures के ज़रिए validate किया जाता है, जिससे यह सुनिश्चित होता है कि केवल private key का owner ही transfer शुरू कर सकता है।<sup>[[2]](#references)</sup>

#### मुख्य घटक:

- **Multisignature Transactions** में transaction को authorize करने के लिए कई signatures की आवश्यकता होती है।<sup>[[3]](#references)</sup>
- Transactions में **inputs** (funds का स्रोत), **outputs** (गंतव्य), **fees** (miners को भुगतान) और **scripts** (transaction के नियम) शामिल होते हैं।

### Lightning Network

इसका उद्देश्य एक channel में कई transactions की अनुमति देकर Bitcoin की scalability बढ़ाना है। Blockchain पर केवल अंतिम स्थिति प्रसारित की जाती है।

## Bitcoin Privacy से जुड़ी चिंताएँ

**Common Input Ownership** और **UTXO Change Address Detection** जैसे privacy attacks, transaction patterns का फ़ायदा उठाते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ users के बीच transaction links को छिपाकर anonymity बेहतर बनाती हैं।

## गुमनाम रूप से Bitcoins प्राप्त करना

इन तरीकों में नकद लेन-देन, mining और mixers का उपयोग शामिल है। **CoinJoin** traceability को कठिन बनाने के लिए कई transactions को मिलाता है, जबकि **PayJoin** अधिक privacy के लिए CoinJoins को सामान्य transactions जैसा दिखाता है।

# Bitcoin Privacy Attacks का सारांश

Bitcoin की दुनिया में, transactions की privacy और users की anonymity अक्सर चिंता का विषय होती हैं। यहाँ कुछ सामान्य तरीकों का संक्षिप्त विवरण दिया गया है, जिनसे attackers Bitcoin privacy से समझौता कर सकते हैं।<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

जटिलता के कारण, अलग-अलग users के inputs को एक ही transaction में जोड़ना आम तौर पर दुर्लभ होता है। इसलिए, **एक ही transaction में मौजूद दो input addresses को अक्सर एक ही owner का माना जाता है**।

## **UTXO Change Address Detection**

UTXO, यानी **Unspent Transaction Output**, को किसी transaction में पूरी तरह खर्च करना होता है। यदि इसका केवल एक हिस्सा दूसरे address पर भेजा जाता है, तो शेष राशि एक नए change address पर जाती है। Observers मान सकते हैं कि यह नया address sender का है, जिससे privacy से समझौता होता है।

### उदाहरण

इस जोखिम को कम करने के लिए, mixing services या कई addresses का उपयोग ownership को छिपाने में मदद कर सकता है।

## **Social Networks & Forums पर जानकारी उजागर होना**

Users कभी-कभी अपने Bitcoin addresses ऑनलाइन साझा करते हैं, जिससे **address को उसके owner से जोड़ना आसान हो जाता है**।

## **Transaction Graph Analysis**

Transactions को graphs के रूप में दिखाया जा सकता है, जिससे funds के प्रवाह के आधार पर users के बीच संभावित संबंध सामने आ सकते हैं।

## **अनावश्यक Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले transactions का विश्लेषण करके अनुमान लगाती है कि कौन-सा output sender को वापस मिलने वाला change है।

### उदाहरण

```bash
2 btc --> 4 btc
3 btc     1 btc
```

अगर अधिक inputs जोड़ने से change output किसी एक input से बड़ा हो जाता है, तो heuristic भ्रमित हो सकता है।

## **Forced Address Reuse**

Attackers पहले इस्तेमाल किए गए addresses पर छोटी रकम भेज सकते हैं, इस उम्मीद में कि recipient भविष्य के transactions में इन्हें अन्य inputs के साथ जोड़ देगा, जिससे addresses आपस में लिंक हो जाएंगे।

### Wallet का सही व्यवहार

Wallets को इस privacy leak से बचने के लिए, पहले इस्तेमाल किए जा चुके खाली addresses पर मिले coins का उपयोग करने से बचना चाहिए।

## **Blockchain विश्लेषण की अन्य तकनीकें**

- **सटीक भुगतान राशियाँ:** बिना change वाले transactions संभवतः एक ही user के स्वामित्व वाले दो addresses के बीच होते हैं।
- **गोल संख्याएँ:** किसी transaction में गोल संख्या यह संकेत देती है कि वह भुगतान है; गैर-गोल output संभवतः change होता है।
- **Wallet Fingerprinting:** अलग-अलग wallets में transaction बनाने के विशिष्ट patterns होते हैं। इससे analysts इस्तेमाल किए गए software और संभावित रूप से change address की पहचान कर सकते हैं।
- **राशि और समय का सहसंबंध:** transaction का समय या राशि बताने से transactions को trace करना संभव हो सकता है।

## **Traffic Analysis**

Network traffic की निगरानी करके attackers संभावित रूप से transactions या blocks को IP addresses से लिंक कर सकते हैं, जिससे user privacy खतरे में पड़ सकती है। यह खासकर तब होता है जब कोई entity कई Bitcoin nodes चलाती है, जिससे transactions की निगरानी करने की उसकी क्षमता बढ़ जाती है।

## अधिक जानकारी

Privacy attacks और बचाव की पूरी सूची के लिए [Bitcoin Wiki पर Bitcoin Privacy](https://en.bitcoin.it/wiki/Privacy) देखें।

# **Anonymous Bitcoin Transactions**

## **गुमनाम रूप से Bitcoins प्राप्त करने के तरीके**

- **नकद लेनदेन**: नकद के ज़रिए bitcoin प्राप्त करना।
- **नकद के विकल्प**: gift cards खरीदकर उन्हें ऑनलाइन bitcoin के बदले एक्सचेंज करना।
- **Mining**: bitcoins कमाने का सबसे निजी तरीका mining है, खासकर अकेले mining करना, क्योंकि mining pools को miner का IP address पता हो सकता है। [Mining Pools की जानकारी](https://en.bitcoin.it/wiki/Pooled_mining)
- **चोरी**: सैद्धांतिक रूप से, bitcoin चुराना इसे गुमनाम रूप से प्राप्त करने का एक अन्य तरीका हो सकता है, हालांकि यह गैरकानूनी है और इसकी सिफारिश नहीं की जाती।

## **Mixing Services**

Mixing service का उपयोग करके, user **bitcoins भेज** सकता है और बदले में **अलग bitcoins प्राप्त** कर सकता है, जिससे मूल मालिक का पता लगाना मुश्किल हो जाता है। हालांकि, इसके लिए service पर भरोसा करना पड़ता है कि वह logs न रखे और वास्तव में bitcoins वापस करे। Bitcoin casinos भी mixing के वैकल्पिक विकल्प हैं।

## **CoinJoin**

**CoinJoin** अलग-अलग users के कई transactions को एक में मिला देता है, जिससे inputs को outputs से मिलाने की कोशिश करने वालों के लिए प्रक्रिया जटिल हो जाती है। प्रभावी होने के बावजूद, जिन transactions में inputs और outputs के आकार अलग हों, उन्हें फिर भी trace किया जा सकता है।

CoinJoin का उपयोग किए गए संभावित उदाहरण transactions में `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` शामिल हैं।

अधिक जानकारी के लिए [CoinJoin](https://coinjoin.io/en) देखें। ऐसे Ethereum smart-contract mixer के लिए, जो deposits को बाद में किए जाने वाले withdrawals से अलग करता है, [Tornado Cash](https://tornado.cash) देखें।

## **PayJoin**

CoinJoin का एक रूप, **PayJoin** (या P2EP), दो पक्षों (जैसे, ग्राहक और व्यापारी) के बीच के transaction को एक सामान्य transaction जैसा दिखाता है, जिसमें CoinJoin की पहचान बताने वाले समान outputs नहीं होते। इससे इसका पता लगाना बेहद मुश्किल हो जाता है और transaction surveillance entities द्वारा इस्तेमाल किए जाने वाले common-input-ownership heuristic को अमान्य किया जा सकता है।

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

ऊपर दिए गए जैसे transactions PayJoin हो सकते हैं, जो standard bitcoin transactions से अलग पहचाने बिना privacy को बेहतर बनाते हैं।

**PayJoin का उपयोग पारंपरिक surveillance methods को काफ़ी बाधित कर सकता है**, जिससे transactional privacy की दिशा में यह एक आशाजनक विकास बन जाता है।

# Cryptocurrencies में Privacy के लिए सर्वोत्तम अभ्यास

## **Wallet Synchronization Techniques**

Privacy और security बनाए रखने के लिए, wallets को blockchain के साथ synchronize करना अहम है। दो methods विशेष रूप से उपयोगी हैं:

- **Full node**: पूरी blockchain download करके, full node अधिकतम privacy सुनिश्चित करता है। अब तक किए गए सभी transactions स्थानीय रूप से संग्रहीत होते हैं, जिससे adversaries के लिए यह पहचानना असंभव हो जाता है कि user किन transactions या addresses में रुचि रखता है।
- **Client-side block filtering**: इस method में blockchain के हर block के लिए filters बनाए जाते हैं, जिससे wallets network observers के सामने अपनी विशिष्ट रुचि उजागर किए बिना प्रासंगिक transactions पहचान सकते हैं। Lightweight wallets ये filters download करते हैं और केवल तभी पूरे blocks प्राप्त करते हैं, जब user के addresses से कोई match मिलता है।

## **Anonymity के लिए Tor का उपयोग**

चूंकि Bitcoin peer-to-peer network पर काम करता है, इसलिए अपना IP address छिपाने के लिए Tor का उपयोग करने की सलाह दी जाती है। इससे network के साथ संचार करते समय privacy बेहतर होती है।

## **Address Reuse रोकना**

Privacy सुरक्षित रखने के लिए, हर transaction में नया address इस्तेमाल करना ज़रूरी है। Addresses को दोबारा इस्तेमाल करने से transactions एक ही entity से जुड़ सकते हैं और privacy प्रभावित हो सकती है। आधुनिक wallets अपने design के ज़रिए address reuse को हतोत्साहित करते हैं।

## **Transaction Privacy के लिए रणनीतियाँ**

- **Multiple transactions**: Payment को कई transactions में बांटने से transaction की राशि छिप सकती है और privacy attacks को विफल किया जा सकता है।
- **Change से बचना**: ऐसे transactions चुनना जिनमें change outputs की ज़रूरत न हो, change detection methods को बाधित करके privacy बेहतर बनाता है।
- **Multiple change outputs**: अगर change से बचना संभव न हो, तो कई change outputs बनाकर भी privacy बेहतर की जा सकती है।

# **Monero: Anonymity की मिसाल**

Monero को transaction privacy को प्राथमिकता देने के लिए बनाया गया है।

# **Ethereum: Gas और Transactions**

## **Gas को समझना**

Gas, Ethereum पर operations को execute करने के लिए आवश्यक computational effort को मापता है और इसकी कीमत **gwei** में तय होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) की लागत वाले transaction में gas limit और base fee होती है, साथ ही validator द्वारा transaction को शामिल करने के लिए प्रोत्साहित करने वाली priority fee भी होती है। Users अधिकतम fee तय कर सकते हैं, ताकि वे ज़रूरत से ज़्यादा भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।<sup>[[5]](#references)</sup>

## **Transactions को Execute करना**

Ethereum में transactions में एक sender और recipient शामिल होते हैं, जो user या smart contract addresses हो सकते हैं। इनके लिए fee देना ज़रूरी है और इन्हें किसी block में शामिल किया जाना चाहिए। Transaction में recipient, sender का signature, value, optional data, gas limit और fees जैसी आवश्यक जानकारी शामिल होती है। ध्यान दें कि sender का address signature से निकाला जाता है, इसलिए transaction data में इसे शामिल करने की ज़रूरत नहीं होती।<sup>[[4]](#references)</sup>

ये अभ्यास और mechanisms उन सभी लोगों के लिए बुनियादी हैं जो privacy और security को प्राथमिकता देते हुए cryptocurrencies का उपयोग करना चाहते हैं।

## Value-Centric Web3 Red Teaming

- यह समझने के लिए कि funds को कौन और कैसे स्थानांतरित कर सकता है, value रखने वाले components (signers, oracles, bridges, automation) की सूची बनाएं।
- Privilege escalation paths उजागर करने के लिए हर component को संबंधित MITRE AADAPT tactics से map करें।
- Impact की पुष्टि करने और exploit की जा सकने वाली पूर्व-शर्तों को document करने के लिए flash-loan/oracle/credential/cross-chain attack chains का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow का Compromise

- Wallet UI में supply-chain tampering, signing से ठीक पहले EIP-712 payloads को बदल सकती है और delegatecall-based proxy takeovers (जैसे, Safe masterCopy का slot-0 overwrite) के लिए valid signatures हासिल कर सकती है।

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

जब कोई prover किसी दावे की पुष्टि के लिए **zkVM** या application-specific proof circuit का उपयोग करता है, तो verifier को केवल यह पता चलता है कि **guest program बताए गए तरीके से execute हुआ**। यदि guest में **unsafe deserialization**, **undefined behavior**, या **missing semantic constraints** हों, तो malicious prover ऐसा proof बना सकता है जो verify हो जाए, जबकि **public metrics या दावा किया गया invariant गलत हो**।<sup>[[7]](#references)</sup>

### Proof guests के भीतर Unsafe deserialization

- Private witness/circuit bytes को **untrusted attacker input** मानें, भले ही वे proof से छिपे हों।
- उन्हें `rkyv::access_unchecked` जैसे unchecked helpers से deserialize न करें, जब तक कि bytes को पहले किसी बाहरी प्रक्रिया से validate न किया गया हो।
- Untrusted serialized data से load किए गए enum discriminants, relative pointers, lengths और indexes को control flow या memory access पर असर डालने से पहले validate करना ज़रूरी है।

व्यावहारिक audit pattern:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

यदि `op.kind` जैसा कोई field एक enum है और attacker उसमें **out-of-range discriminant** inject कर सकता है, तो उस value पर किए गए हर downstream `match` को संदिग्ध मानें।

### Jump-table / UB के ज़रिए counter bypass

यदि Rust किसी बड़े `match` को **jump table** में बदलता है, तो invalid enum discriminant **undefined control flow** पैदा कर सकता है। एक खतरनाक pattern यह है:<sup>[[7]](#references)[[9]](#references)</sup>

1. एक `match` **security-critical counters/constraints** को अपडेट करता है।
2. दूसरा `match` **वास्तविक instruction semantics** लागू करता है।
3. Out-of-range discriminant पहली jump table की सीमा से बाहर index करता है और दूसरी table से जुड़े code पर पहुँच जाता है।

नतीजा: operation फिर भी execute होता है, लेकिन accounting path छूट जाता है। zkVM में इससे ऐसे forged proofs बन सकते हैं जो gates की कम संख्या, कम महँगे operations या अन्य falsified bounded resources जैसी असंभव metrics रिपोर्ट करते हैं।

समीक्षा checklist:

- Witness/private input से deserialize किए गए attacker-controlled enums खोजें।
- एक ही opcode/kind field पर बार-बार किए गए `match` statements की जाँच करें।
- `unsafe` + unchecked deserialization + बड़ा opcode dispatch—इस संयोजन को high-risk मानें।
- ज़रूरत पड़ने पर emitted binary को reverse engineer करें; jump-table layout, source से ज़्यादा मायने रख सकता है।

### Reversible/specialized interpreters में semantic constraints की कमी

सिर्फ memory safety validate न करें; उन **semantic rules** को भी validate करें जिन्हें proof को लागू करना है।

Reversible/quantum-like instruction sets के लिए, सुनिश्चित करें कि जिन operands का अलग होना ज़रूरी है, उन पर वास्तव में distinct होने की constraint लगाई गई हो। इस तरह implemented Toffoli/CCX-like operation:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

यदि guest इसे अस्वीकार नहीं करता है, तो यह असुरक्षित हो जाता है:

```text
op.q_control1 == op.q_control2 == op.q_target
```

ऐसी स्थिति में, संक्रमण सिमटकर यह बन जाता है:

```text
q = q ^ (q & q) = 0
```

यह एक **deterministic reset primitive** बनाता है, reversibility की धारणाओं को तोड़ता है और कम लागत वाली अनपेक्षित गणनाओं को संभव बनाता है। ऐसे proof systems में, जो resource usage की पुष्टि करते हैं, इससे attackers verifier द्वारा लागू माने जा रहे cost model को दरकिनार करते हुए functional checks पास कर सकते हैं।

### अपर्याप्त रूप से constrained prover advice और modular arithmetic

**Advice/witness stack** से लोड की गई values prover के नियंत्रण में होती हैं, भले ही उन्हें precomputed quotients, remainders, inverses या hints के रूप में बताया गया हो। Proof केवल यह स्थापित करता है कि witness लागू constraints को संतुष्ट करता है; यदि उन constraints में type, range या canonical-form check शामिल न हो, तो यह intended computation को स्थापित नहीं करता।<sup>[[13]](#references)</sup>

किसी reduction या Euclidean-division helper के लिए, केवल अंतिम subtraction या multiplication की जाँच करने के बजाय पूरे integer relation का audit करें। `q` और `r` के हर limb को उसकी घोषित width तक constrain किया जाना चाहिए, reconstruction `x = q * m + r` इच्छित integer representation में सही होना चाहिए, और canonical bound `0 <= r < m` लागू होना चाहिए। किसी value को narrower `u32`/`u64` instruction में पास करने **से पहले** validate करें; narrow operation बाद में यह साबित नहीं करता कि मूल field element या multi-limb value का type अपेक्षित था।<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Miden में `mod_12289` की विफलता exploit pattern को दर्शाती है: quotient को two-limb 64-bit value के रूप में जाँचा गया था, लेकिन advice से दिया गया remainder बिना समकक्ष validation के `u32overflowing_sub` तक पहुँच गया। एक दुर्भावनापूर्ण prover अमान्य quotient/remainder values को इस तरह समन्वित कर सकता था कि लागू subtraction constraints फिर भी पूरी हों, जबकि procedure एक गैर-गणितीय remainder लौटाए। चूँकि यह परिणाम Falcon verification में उपयोग हुआ, soundness failure को केवल गलत arithmetic result देने के बजाय जाली authorization signatures बनाने तक बढ़ाया जा सकता था।<sup>[[13]](#references)</sup>

### Implicit-stack cryptographic VMs का ऑडिट

Stack languages operands को छिपाती हैं, इसलिए पहले instructions को ऐसे IR में बदलें जहाँ consume और produce होने वाली हर stack value, provenance सहित एक expression हो। इसके बाद एक conservative analysis pipeline यह कर सकती है:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Call graph बनाएँ और procedure के input/output stack effects का अनुमान लगाएँ।
2. समर्थित instructions को symbolically execute करें और control flow को SSA/structured expressions में बदलें।
3. `Unknown`, `ProvenU32`, `Bool`, value provenance और local initialization जैसे abstract facts को fixed point तक propagate करें।
4. उन advice-derived values को flag करें जो किसी sanitizer के बिना **हर** incoming path पर typed arithmetic या non-zero sinks तक पहुँचती हैं।
5. Declared और inferred signatures की तुलना करें और सत्यापित करें कि हर exit पर caller-owned stack values सुरक्षित रहें।

Unknown signature या unsupported construct को साफ़ परिणाम नहीं, बल्कि **analysis gap** मानें। Dynamic calls, non-stack-neutral loops और अलग-अलग stack effects वाली branches sound stack-slot tracking को असंभव बना सकती हैं; एक सुरक्षित decompiler ऐसे मामलों में संभावित दिखने वाला, लेकिन गलत pseudocode बनाने के बजाय उन्हें अस्वीकार करता है या mark करता है।<sup>[[10]](#references)[[13]](#references)</sup>

Control-flow joins पर कोई property तभी बनाए रखें जब वह हर predecessor पर लागू हो (उदाहरण के लिए, `ProvenU32 join Unknown = Unknown`)। साथ ही fixed-point convergence और iteration limit तक पहुँचने में अंतर करें: केवल converged, sound over-approximation ही इस आधार पर diagnostic की अनुपस्थिति को प्रमाण मानने का औचित्य दे सकती है कि सभी दर्शाए गए executions उस property को पूरा करते हैं।<sup>[[11]](#references)</sup>

### छिपी हुई preconditions उजागर करने के लिए proof obligations का उपयोग करें

छोटे instruction sets के लिए, procedures को executable formal VM model में बदलें और result तथा पूरी stack transformation—दोनों को prove करें। Theorem में termination, typed inputs, अपेक्षित output prefix और untouched caller stack का संरक्षण शामिल होना चाहिए। Theorem statement का उतनी ही सावधानी से ऑडिट करें जितनी proof का: kernel किसी अनजाने में कमजोर किए गए दावे की proof भी validate कर सकता है।<sup>[[12]](#references)[[13]](#references)</sup>

अनपेक्षित hypotheses उपयोगी निष्कर्ष होते हैं। Miden review में, 64-bit right rotation की proof के लिए `shift mod 32 != 0` आवश्यक था; इससे बड़े inputs में, जब shift 32 का multiple था, एक failing edge case उजागर हुआ। एक अन्य proof में पता चला कि 256-bit `wrapping_mul` caller-owned stack values को discard कर रहा था। खोजे गए boundary case को tests में जोड़ें, फिर implementation ठीक करें या जानबूझकर public precondition को मजबूत करें—अतिरिक्त assumption को चुपचाप स्वीकार न करें।<sup>[[12]](#references)[[13]](#references)</sup>

### ZK systems में क्या test करें

- सभी guest parsers को malformed witness/private-input encodings के साथ fuzz करें।
- Opcode dispatch से पहले enum range validation सुनिश्चित करें।
- Operand aliasing और अन्य अमान्य instruction forms के लिए semantic checks जोड़ें।
- हर advice/witness source से प्रत्येक typed arithmetic sink तक trace करें और हर path पर validation अनिवार्य करें।<sup>[[11]](#references)[[13]](#references)</sup>
- Arithmetic helpers को non-canonical limbs, range से बाहर के remainders और boundary shift counts के साथ test करें।<sup>[[12]](#references)[[13]](#references)</sup>
- हर return पर stack height और procedure के घोषित arguments के नीचे की values का संरक्षण सुनिश्चित करें।<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Report किए गए/public counters की तुलना स्वतंत्र reference implementation से करें।
- याद रखें कि guest program buggy होने पर valid proof भी **गलत कथन** prove कर सकती है।

## State-Dependent Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs के व्यावहारिक exploitation (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps) पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

ऐसे multi-asset weighted pools के लिए, जो virtual balances cache करते हैं और `supply == 0` होने पर poison किए जा सकते हैं, देखें:

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
- [7] [Trail of Bits - हमने Google के zero-knowledge proof of quantum cryptanalysis को हराया](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Quantum Vulnerabilities के विरुद्ध Elliptic Curve Cryptocurrencies को सुरक्षित करना: Resource Estimates और Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM decompiler architecture](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM static-analysis engine](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean model और correctness proofs](https://github.com/trailofbits/masm-lean)
- [13] [(काफी अच्छी) AI के दौर में ऑडिटिंग](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
