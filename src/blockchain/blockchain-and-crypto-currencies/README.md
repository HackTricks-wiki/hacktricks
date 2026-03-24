# ब्लॉकचेन और क्रिप्टो-करेंसीज़

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **Smart Contracts** उन प्रोग्रामों के रूप में परिभाषित होते हैं जो ब्लॉकचेन पर तभी निष्पादित होते हैं जब कुछ शर्तें पूरी होती हैं, जिससे मध्यस्थों के बिना समझौतों का स्वत: क्रियान्वयन संभव होता है।
- **Decentralized Applications (dApps)** स्मार्ट कॉन्ट्रैक्ट्स पर आधारित होते हैं और इनमें एक यूज़र-फ्रेंडली फ्रंट-एंड और पारदर्शी, ऑडिटेबल बैक-एंड होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल मुद्रा के रूप में काम करते हैं, जबकि tokens किसी विशेष संदर्भ में मूल्य या स्वामित्व का प्रतिनिधित्व करते हैं।
- **Utility Tokens** सेवाओं तक पहुंच प्रदान करते हैं, और **Security Tokens** संपत्ति के स्वामित्व को दर्शाते हैं।
- **DeFi** का मतलब Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को दर्शाते हैं।

## Consensus Mechanisms

Consensus mechanisms ब्लॉकचेन पर लेन-देन की सुरक्षित और सहमति-आधारित मान्यताओं को सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेन-देन सत्यापन के लिए कम्प्यूटेशनल पावर पर निर्भर करता है।
- **Proof of Stake (PoS)** validators से एक निश्चित मात्रा में tokens रखने की मांग करता है, जो PoW की तुलना में ऊर्जा खपत घटाता है।

## Bitcoin Essentials

### Transactions

Bitcoin लेन-देन में पतों के बीच फंड्स का स्थानांतरण शामिल होता है। लेन-देन डिजिटल सिग्नेचर के माध्यम से वैध किए जाते हैं, जो सुनिश्चित करते हैं कि केवल private key का मालिक ही ट्रांसफर शुरू कर सकता है।

#### Key Components:

- **Multisignature Transactions** में एक लेन-देन को अधिकृत करने के लिए कई सिग्नेचर्स की आवश्यकता होती है।
- Transactions में **inputs** (फंड्स का स्रोत), **outputs** (गंतव्य), **fees** (miners को दिए जाने वाले), और **scripts** (लेन-देन नियम) शामिल होते हैं।

### Lightning Network

ब्लॉकचेन पर केवल अंतिम स्थिति को प्रसारित करके चैनल के भीतर कई लेन-देन की अनुमति देकर Bitcoin की स्केलेबिलिटी बढ़ाने का लक्ष्य रखता है।

## Bitcoin Privacy Concerns

प्राइवेसी अटैक, जैसे **Common Input Ownership** और **UTXO Change Address Detection**, लेन-देन पैटर्न का शोषण करते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच लेन-देन लिंक को अस्पष्ट करके अनामीकरण बढ़ाती हैं।

## Acquiring Bitcoins Anonymously

तरीकों में कैश ट्रेड्स, माइनिंग, और mixers का उपयोग शामिल है। **CoinJoin** कई लेन-देन को मिलाकर ट्रेसबिलिटी को जटिल बनाता है, जबकि **PayJoin** heightened privacy के लिए CoinJoins को सामान्य लेन-देन के रूप में छुपा देता है।

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin की दुनिया में, लेन-देन की प्राइवेसी और उपयोगकर्ताओं की अनोनिमिटी अक्सर चिंता का विषय होती है। यहाँ कई सामान्य तरीकों का सरल सारांश दिया गया है जिनके जरिए attackers Bitcoin प्राइवेसी को खतरे में डाल सकते हैं।

## **Common Input Ownership Assumption**

अकसर अलग-अलग उपयोगकर्ताओं के inputs को एक ही लेन-देन में मिलाना दुर्लभ होता है क्योंकि यह जटिल होता है। इसलिए, **एक ही लेन-देन में दो input पते अक्सर एक ही मालिक के माने जाते हैं**।

## **UTXO Change Address Detection**

UTXO, या **Unspent Transaction Output**, को लेन-देन में पूरी तरह से खर्च करना होता है। यदि इसका केवल एक भाग किसी अन्य पते पर भेजा जाता है, तो शेष एक नए change address में जाता है। निरीक्षक यह अनुमान लगा सकते हैं कि यह नया पता sender का है, जिससे प्राइवेसी प्रभावित होती है।

### Example

इसे कम करने के लिए, mixing services या कई पतों का उपयोग ownership को अस्पष्ट करने में मदद कर सकता है।

## **Social Networks & Forums Exposure**

उपयोगकर्ता कभी-कभी अपने Bitcoin पते ऑनलाइन साझा करते हैं, जिससे पता आसानी से उसके मालिक से linked किया जा सकता है।

## **Transaction Graph Analysis**

लेन-देन को ग्राफ के रूप में विज़ुअलाइज़ किया जा सकता है, जो फंड के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित कनेक्शनों का खुलासा करता है।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic उन लेन-देन का विश्लेषण करके काम करता है जिनमें कई inputs और outputs होते हैं, ताकि यह अनुमान लगाया जा सके कि किस output में भेजा गया पैसा sender को वापस लौटने वाला change है।

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

हमलावर छोटे amounts पहले से प्रयोग किए गए addresses पर भेज सकते हैं, यह उम्मीद करते हुए कि recipient इन्हें भविष्य की transactions में अन्य inputs के साथ जोड़ देगा, जिससे addresses आपस में link हो जाएँगे।

### Correct Wallet Behavior

Wallets को पहले से उपयोग किए गए, खाली addresses पर प्राप्त coins का उपयोग करने से बचना चाहिए ताकि यह privacy leak न हो।

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions बिना change के अक्सर दो addresses के बीच होती हैं जो एक ही user के मालिक होते हैं।
- **Round Numbers:** किसी transaction में round number होना संकेत देता है कि वह भुगतान है, और non-round output संभवतः change होगा।
- **Wallet Fingerprinting:** अलग-अलग wallets के transaction बनाने के patterns अलग होते हैं, जिससे analysts उस software की पहचान कर सकते हैं और संभवतः change address का पता लगा सकते हैं।
- **Amount & Timing Correlations:** Transaction के times या amounts का खुलासा करने से transactions traceable हो सकते हैं।

## **Traffic Analysis**

Network traffic की निगरानी करके, हमलावर संभावित रूप से transactions या blocks को IP addresses से जोड़ सकते हैं, जिससे user की privacy compromised हो सकती है। यह विशेष रूप से सच है यदि कोई entity कई Bitcoin nodes चलाता है, तब उनकी monitoring क्षमता बढ़ जाती है।

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: नकद के जरिए bitcoin प्राप्त करना।
- **Cash Alternatives**: gift cards खरीदकर उन्हें online बदलकर bitcoin लेना।
- **Mining**: bitcoins कमाने का सबसे private तरीका mining है, खासकर अकेले करने पर क्योंकि mining pools miner का IP पता जान सकते हैं। [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: सैद्धान्तिक रूप से, bitcoin चोरी करना एक तरीका हो सकता है इसे anonymously हासिल करने का, हालांकि यह illegal है और सुझाया नहीं जाता।

## Mixing Services

Mixing service का उपयोग करके, उपयोगकर्ता बिटकॉइन भेजकर अलग बिटकॉइन प्राप्त कर सकता है, जिससे original owner को trace करना मुश्किल हो जाता है। फिर भी, इसके लिए service पर भरोसा करना पड़ता है कि वह logs नहीं रखेगा और वास्तव में bitcoins वापस करेगा। वैकल्पिक mixing विकल्पों में Bitcoin casinos भी शामिल हैं।

## CoinJoin

CoinJoin विभिन्न उपयोगकर्ताओं के multiple transactions को एक में मिला देता है, जिससे inputs को outputs से match करना कठिन हो जाता है। इसके प्रभावी होने के बावजूद, अलग input और output sizes वाले transactions का अभी भी trace किया जा सकता है।

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, PayJoin (or P2EP), दो पार्टियों (उदा., ग्राहक और व्यापारी) के बीच के transaction को एक सामान्य transaction के रूप में disguise करता है, बिना CoinJoin की विशिष्ट समान outputs वाली पहचान के। इससे इसे detect करना अत्यंत कठिन हो जाता है और यह transaction surveillance entities द्वारा उपयोग किए जाने वाले common-input-ownership heuristic को अवैध कर सकता है।
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin के उपयोग से पारंपरिक निगरानी विधियों को काफी प्रभावित किया जा सकता है**, जिससे यह लेन-देन गोपनीयता के प्रयास में एक आशाजनक विकास बनता है।

# क्रिप्टोकरेन्सियों में गोपनीयता के लिए सर्वोत्तम प्रथाएँ

## **Wallet Synchronization Techniques**

गोपनीयता और सुरक्षा बनाए रखने के लिए, वॉलेट्स का blockchain के साथ सिंक्रोनाइज़ेशन आवश्यक है। दो तरीके विशेष रूप से प्रासंगिक हैं:

- **Full node**: पूरी blockchain डाउनलोड करके, एक Full node अधिकतम गोपनीयता सुनिश्चित करता है। किए गए सभी लेन-देन स्थानीय रूप से संग्रहीत होते हैं, जिससे विरोधियों के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किस लेन-देन या पते में रुचि रखता है।
- **Client-side block filtering**: यह विधि blockchain के हर ब्लॉक के लिए फ़िल्टर बनाने पर आधारित है, जिससे वॉलेट नेटवर्क अवलोककों को विशिष्ट रुचियाँ उजागर किए बिना संबंधित लेन-देन की पहचान कर सकते हैं। हल्के वॉलेट इन फ़िल्टरों को डाउनलोड करते हैं और केवल तभी पूर्ण ब्लॉक्स लाते हैं जब उपयोगकर्ता के पते से मेल मिलता है।

## **Utilizing Tor for Anonymity**

चूंकि Bitcoin एक peer-to-peer नेटवर्क पर चलता है, इसलिए नेटवर्क के साथ इंटरैक्ट करते समय आपकी IP पता छिपाने के लिए Tor का उपयोग करने की सिफारिश की जाती है, जिससे गोपनीयता बढ़ती है।

## **Preventing Address Reuse**

गोपनीयता की सुरक्षा के लिए, हर लेन-देन के लिए नया पता उपयोग करना आवश्यक है। पतों का पुन: उपयोग लेन-देन को एक ही इकाई से जोड़कर गोपनीयता से समझौता कर सकता है। आधुनिक वॉलेट अपने डिज़ाइन के माध्यम से पते के पुन: उपयोग को हतोत्साहित करते हैं।

## **Strategies for Transaction Privacy**

- **Multiple transactions**: भुगतान को कई लेन-देन में विभाजित करने से लेन-देन की राशि अस्पष्ट हो सकती है, जिससे गोपनीयता हमलों को विफल किया जा सकता है।
- **Change avoidance**: ऐसे लेन-देन का चुनाव करना जिनमें change outputs की आवश्यकता न हो गोपनीयता बढ़ाता है क्योंकि यह change detection विधियों को बाधित करता है।
- **Multiple change outputs**: यदि change से बचना संभव नहीं है, तो कई change outputs उत्पन्न करने से भी गोपनीयता में सुधार हो सकता है।

# **Monero: A Beacon of Anonymity**

Monero डिजिटल लेन-देन में पूर्ण गुमनामी की आवश्यकता को संबोधित करता है, और गोपनीयता के लिए एक उच्च मानक स्थापित करता है।

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas Ethereum पर ऑपरेशन निष्पादित करने के लिए आवश्यक कम्प्यूटेशनल प्रयास को मापता है, जिसकी कीमत **gwei** में होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) लागत वाला एक लेन-देन एक gas limit और एक base fee शामिल करता है, साथ ही miners को प्रोत्साहित करने के लिए tip भी होता है। उपयोगकर्ता अधिक भुगतान न करने के लिए max fee सेट कर सकते हैं, अतिरिक्त राशि वापस कर दी जाती है।

## **Executing Transactions**

Ethereum में लेन-देन में एक sender और एक recipient शामिल होते हैं, जो उपयोगकर्ता या smart contract addresses दोनों में से हो सकते हैं। इनके लिए एक fee आवश्यक होती है और इन्हें mined किया जाना चाहिए। लेन-देन में निहित आवश्यक जानकारी में recipient, sender की signature, value, वैकल्पिक data, gas limit और fees शामिल हैं। ध्यान देने योग्य बात यह है कि sender का पता signature से निकाला जाता है, इसलिए transaction डेटा में इसे शामिल करने की आवश्यकता नहीं होती।

ये प्रथाएँ और तंत्र उन किसी भी व्यक्ति के लिए बुनियादी हैं जो गोपनीयता और सुरक्षा को प्राथमिकता देते हुए cryptocurrencies के साथ इंटरैक्ट करना चाहते हैं।

## Value-Centric Web3 Red Teaming

- मूल्य-वाहक घटकों (signers, oracles, bridges, automation) का सूचीकरण करें ताकि यह समझा जा सके कि कौन फंड्स को हिला सकता है और कैसे।
- प्रत्येक घटक को संबंधित MITRE AADAPT tactics से मैप करें ताकि privilege escalation paths उजागर हों।
- प्रभाव को मान्य करने और exploitable पूर्व-शर्तों को दस्तावेज़ करने के लिए flash-loan/oracle/credential/cross-chain attack chains का अभ्यास करें।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- वॉलेट UIs की supply-chain छेड़छाड़ signing से ठीक पहले EIP-712 payloads को बदल सकती है, delegatecall-आधारित proxy takeovers (उदा., slot-0 overwrite of Safe masterCopy) के लिए मान्य signatures इकट्ठा करते हुए।

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- सामान्य smart-account failure modes में `EntryPoint` access control को बाइपास करना, unsigned gas fields, stateful validation, ERC-1271 replay, और revert-after-validation के जरिए fee-drain शामिल हैं।

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) के व्यावहारिक शोषण पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

उन multi-asset weighted pools के बारे में अध्ययन करें जो virtual balances cache करते हैं और जब `supply == 0` होने पर संक्रमित किए जा सकते हैं:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
