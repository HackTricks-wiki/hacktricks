# ब्लॉकचेन और क्रिप्टो-करेंसीज़

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** को उन प्रोग्राम्स के रूप में परिभाषित किया जाता है जो ब्लॉकचेन पर तब निष्पादित होते हैं जब कुछ शर्तें पूरी हो जाती हैं, और यह मध्यस्थों के बिना समझौतों के निष्पादन को स्वचालित करता है।
- **Decentralized Applications (dApps)** Smart Contracts के ऊपर बनती हैं, जिनमें एक यूजर-फ्रेंडली front-end और एक पारदर्शी, ऑडिट करने योग्य back-end होता है।
- **Tokens & Coins** में फर्क यह है कि coins डिजिटल पैसे के रूप में काम करते हैं, जबकि tokens किसी विशेष संदर्भ में मूल्य या स्वामित्व का प्रतिनिधित्व करते हैं।
- **Utility Tokens** सेवाओं तक पहुँच प्रदान करते हैं, और **Security Tokens** संपत्ति के स्वामित्व का संकेत देते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रित प्राधिकारियों के बिना वित्तीय सेवाएं प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को संदर्भित करते हैं।

## Consensus Mechanisms

Consensus mechanisms ब्लॉकचेन पर लेनदेन के सुरक्षित और सहमत सत्यापन सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेनदेन सत्यापन के लिए कम्प्यूटेशनल पावर पर निर्भर करता है।
- **Proof of Stake (PoS)** validators को कुछ मात्रा में tokens रखने की मांग करता है, जो PoW की तुलना में ऊर्जा की खपत को कम करता है।

## Bitcoin Essentials

### Transactions

Bitcoin लेनदेन में पतों के बीच फंड ट्रांसफर शामिल होते हैं। लेनदेन डिजिटल signatures के माध्यम से मान्य किए जाते हैं, यह सुनिश्चित करते हुए कि केवल private key का मालिक ही ट्रांसफर आरंभ कर सकता है।

#### Key Components:

- **Multisignature Transactions** किसी लेनदेन को अधिकृत करने के लिए कई signatures की आवश्यकता होती है।
- Transactions में **inputs** (फंड का स्रोत), **outputs** (गंतव्य), **fees** (miners को भुगतान) और **scripts** (लेनदेन नियम) शामिल होते हैं।

### Lightning Network

यह Bitcoin की scalability बढ़ाने का उद्देश्य रखता है, जिससे एक चैनल के भीतर कई लेनदेन किए जा सकें और केवल अंतिम स्थिति को ही ब्लॉकचेन पर प्रसारित किया जाए।

## Bitcoin Privacy Concerns

गोपनीयता हमलों जैसे **Common Input Ownership** और **UTXO Change Address Detection** लेनदेन पैटर्न का फायदा उठाते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच लेनदेन लिंक को अस्पष्ट बनाकर गुमनामी में सुधार करती हैं।

## Acquiring Bitcoins Anonymously

विधियों में नकद ट्रेड, mining, और mixers का उपयोग शामिल है। **CoinJoin** कई लेनदेन मिलाकर ट्रेसबिलिटी को जटिल बनाता है, जबकि **PayJoin** CoinJoins को नियमित लेनदेन के रूप में छुपाकर और अधिक गोपनीयता प्रदान करता है।

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin की दुनिया में, लेनदेन की गोपनीयता और उपयोगकर्ताओं की अनामिता अक्सर चिंता का विषय होते हैं। यहाँ कुछ सामान्य तरीकों का एक सरल सारांश दिया गया है जिनके माध्यम से हमलावर Bitcoin गोपनीयता को समझौता कर सकते हैं।

## **Common Input Ownership Assumption**

अलग-अलग उपयोगकर्ताओं के inputs को एक ही लेनदेन में संयोजित करना आमतौर पर दुर्लभ होता है क्योंकि इसमें जटिलता होती है। इसलिए, **एक ही लेनदेन में दो input पते अक्सर एक ही मालिक के होने का अनुमान लगाए जाते हैं**।

## **UTXO Change Address Detection**

UTXO, या **Unspent Transaction Output**, को एक लेनदेन में पूरी तरह खर्च करना पड़ता है। यदि इसका केवल एक हिस्सा दूसरे पते पर भेजा जाता है, तो शेष राशि एक नए change address पर जाती है। पर्यवेक्षक इस नए पते को sender का माना जा सकता है, जिससे गोपनीयता प्रभावित होती है।

### Example

इसे कम करने के लिए, mixing services या कई पतों का उपयोग ownership को अस्पष्ट करने में मदद कर सकता है।

## **Social Networks & Forums Exposure**

उपयोगकर्ता कभी-कभी अपने Bitcoin पते ऑनलाइन साझा करते हैं, जिससे पता किसी मालिक से जोड़ना आसान हो जाता है।

## **Transaction Graph Analysis**

लेनदेन को ग्राफ के रूप में विज़ुअलाइज़ किया जा सकता है, जो फंड के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित कनेक्शनों को उजागर कर सकता है।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले लेनदेन का विश्लेषण करके अनुमान लगाने पर आधारित है कि कौन सा output sender को लौट रहा change है।

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
यदि अधिक inputs जोड़ने से change output किसी भी single input से बड़ा हो जाता है, तो यह heuristic को भ्रमित कर सकता है।

## **Forced Address Reuse**

हमलावर पहले से उपयोग किए गए पतों पर छोटी राशियाँ भेज सकते हैं, इस आशा में कि प्राप्तकर्ता इन्हें भविष्य के लेन-देन में अन्य inputs के साथ मिला देगा, और इस तरह पतों को आपस में लिंक कर देगा।

### सही वॉलेट व्यवहार

वॉलेट्स को पहले से उपयोग किए जा चुके, खाली पतों पर प्राप्त किए गए coins का उपयोग करने से बचना चाहिए ताकि यह privacy leak न हो।

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** चेंज के बिना लेन-देन अक्सर उसी उपयोगकर्ता के स्वामित्व वाले दो पतों के बीच होते हैं।
- **Round Numbers:** लेन-देन में एक राउंड संख्या यह संकेत देती है कि यह भुगतान है, और गैर-राउंड आउटपुट संभवतः चेंज होगा।
- **Wallet Fingerprinting:** विभिन्न वॉलेट्स के लेन-देन बनाने के पैटर्न अनूठे होते हैं, जिससे विश्लेषक उपयोग किए गए सॉफ़्टवेयर की पहचान कर सकते हैं और संभवतः चेंज पता का पता लगा सकते हैं।
- **Amount & Timing Correlations:** लेन-देन का समय या राशियाँ उजागर करने से लेन-देन का ट्रेस किया जाना आसान हो सकता है।

## **Traffic Analysis**

नेटवर्क ट्रैफ़िक की निगरानी करके, हमलावर संभावित रूप से लेन-देन या ब्लॉकों को IP पतों से जोड़ सकते हैं, जिससे उपयोगकर्ता की गोपनीयता प्रभावित होती है। यदि कोई इकाई कई Bitcoin nodes चलाती है तो यह विशेष रूप से सच है, क्योंकि इससे उनके लिए लेन-देन मॉनिटर करना आसान हो जाता है।

## और अधिक

गोपनीयता हमलों और बचाव की विस्तृत सूची के लिए, देखें [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# अनाम Bitcoin लेन-देन

## बिटकॉइन को अनाम रूप से प्राप्त करने के तरीके

- **Cash Transactions**: नकद के माध्यम से बिटकॉइन प्राप्त करना।
- **Cash Alternatives**: गिफ्ट कार्ड खरीदकर उन्हें ऑनलाइन बिटकॉइन में बदलना।
- **Mining**: बिटकॉइन कमाने का सबसे निजी तरीका माइनिंग है, खासकर अकेले करने पर क्योंकि mining pools मैने होने पर miner का IP पता जान सकते हैं। [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: सैद्धान्तिक रूप से, बिटकॉइन चुराना भी इसे अनाम रूप से हासिल करने का एक तरीका हो सकता है, हालाँकि यह गैरकानूनी है और सुझाया नहीं जाता।

## Mixing Services

Mixing सेवा का उपयोग करके, एक उपयोगकर्ता **बिटकॉइन भेज सकता है** और बदले में **विभिन्न बिटकॉइन प्राप्त कर सकता है**, जिससे मूल मालिक का पता लगाना कठिन हो जाता है। फिर भी, इसके लिए उस सेवा पर भरोसा होना आवश्यक है कि वह लॉग नहीं रखेगी और वास्तव में बिटकॉइन वापस करेगी। वैकल्पिक mixing विकल्पों में Bitcoin casinos शामिल हैं।

## CoinJoin

**CoinJoin** विभिन्न उपयोगकर्ताओं के कई लेन-देन को एक में जोड़ देता है, जिससे किसी के लिए inputs को outputs से मिलाना कठिन हो जाता है। अपनी प्रभावशीलता के बावजूद, अद्वितीय input और output आकार वाले लेन-देन अभी भी ट्रेस किए जा सकते हैं।

उदाहरण लेन-देन जो CoinJoin का उपयोग कर सकते हैं: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` और `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`।

अधिक जानकारी के लिए देखें [CoinJoin](https://coinjoin.io/en). Ethereum पर समान सेवा के लिए देखें [Tornado Cash](https://tornado.cash), जो miners के फंड से लेन-देन को अननाम बनाती है।

## PayJoin

CoinJoin का एक प्रकार, **PayJoin** (या P2EP), दो पक्षों (उदाहरण के लिए, ग्राहक और विक्रेता) के बीच लेन-देन को एक सामान्य लेन-देन के रूप में छिपा देता है, बिना CoinJoin की विशिष्ट समान outputs वाली पहचान के। इससे इसका पता लगाना अत्यंत कठिन हो जाता है और यह transaction surveillance इकाइयों द्वारा उपयोग की जाने वाली common-input-ownership heuristic को अमान्य कर सकता है।
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
ऊपर जैसे लेन-देन PayJoin हो सकते हैं, जो गोपनीयता बढ़ाते हैं जबकि मानक bitcoin लेन-देन से भेद नहीं किए जा सकते।

**PayJoin का उपयोग पारंपरिक निगरानी तरीकों को काफी प्रभावित कर सकता है**, जिससे यह लेन-देन गोपनीयता के प्रयास में एक वादा करने वाला विकास बनता है।

# क्रिप्टोकरेंसी में गोपनीयता के लिए सर्वश्रेष्ठ प्रथाएँ

## **वॉलेट सिंक्रोनाइज़ेशन तकनीकें**

गोपनीयता और सुरक्षा बनाए रखने के लिए, वॉलेट्स को ब्लॉकचेन के साथ सिंक्रोनाइज़ करना आवश्यक है। दो प्रमुख विधियाँ हैं:

- **Full node**: पूरी ब्लॉकचेन को डाउनलोड करके, एक Full node अधिकतम गोपनीयता सुनिश्चित करता है। सभी किए गए लेन-देन स्थानीय रूप से संग्रहित होते हैं, जिससे विरोधियों के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किन लेन-देन या पतों में रुचि रखता है।
- **Client-side block filtering**: यह विधि ब्लॉकचेन के प्रत्येक ब्लॉक के लिए फ़िल्टर बनाने में शामिल है, जिससे वॉलेट्स नेटवर्क पर्यवेक्षकों के सामने उपयोगकर्ता की विशिष्ट रुचियों को उजागर किए बिना संबंधित लेन-देन पहचान सकते हैं। हल्के वॉलेट इन फ़िल्टरों को डाउनलोड करते हैं और केवल तब पूर्ण ब्लॉक्स लाते हैं जब उपयोगकर्ता के पतों से मेल मिलता है।

## **प्राइवेसी के लिए Tor का उपयोग**

चूँकि Bitcoin एक peer-to-peer नेटवर्क पर चलता है, नेटवर्क के साथ इंटरैक्ट करते समय आपकी IP पता छिपाने और गोपनीयता बढ़ाने के लिए Tor का उपयोग सुझाया जाता है।

## **पता पुनः उपयोग रोकना**

गोपनीयता की रक्षा के लिए, हर लेन-देन के लिए नया पता उपयोग करना जरूरी है। पतों का पुनः उपयोग लेन-देन को एक ही इकाई से जोड़कर गोपनीयता को खतरे में डाल सकता है। आधुनिक वॉलेट्स अपने डिज़ाइन के माध्यम से पता पुनः उपयोग को हतोत्साहित करते हैं।

## **लेन-देन गोपनीयता के लिए रणनीतियाँ**

- **Multiple transactions**: भुगतान को कई लेन-देन में विभाजित करने से लेन-देन राशि अस्पष्ट हो सकती है, जिससे गोपनीयता हमलों का निषेध होता है।
- **Change avoidance**: जो लेन-देन change outputs की आवश्यकता नहीं रखते उन्हें चुनने से change detection विधियों को बाधित करके गोपनीयता बढ़ती है।
- **Multiple change outputs**: यदि change से बचना संभव नहीं है, तो कई change outputs उत्पन्न करने से भी गोपनीयता बेहतर हो सकती है।

# **Monero: A Beacon of Anonymity**

Monero डिजिटल लेन-देन में पूर्ण अनामिता की आवश्यकता को पूरा करता है, और गोपनीयता के लिए उच्च मानक सेट करता है।

# **Ethereum: Gas and Transactions**

## **Gas को समझना**

Gas Ethereum पर संचालन निष्पादित करने के लिए आवश्यक कंप्यूटेशनल प्रयास को मापता है, जिसकी कीमत **gwei** में होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) लागत वाला एक लेन-देन gas limit और base fee शामिल करता है, साथ ही miners को प्रोत्साहित करने के लिए tip भी होता है। उपयोगकर्ता max fee सेट कर सकते हैं ताकि वे अधिक भुगतान न करें; अतिरिक्त राशि रिफंड की जाती है।

## **लेन-देन निष्पादित करना**

Ethereum में लेन-देन में एक sender और एक recipient शामिल होते हैं, जो उपयोगकर्ता या smart contract addresses हो सकते हैं। इन्हें fee की आवश्यकता होती है और इन्हें mined होना पड़ता है। एक लेन-देन में आवश्यक जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit, और fees शामिल हैं। उल्लेखनीय है कि sender का पता signature से निकाला जाता है, इसलिए इसे लेन-देन डेटा में शामिल करने की आवश्यकता नहीं होती।

ये प्रथाएँ और तंत्र उन लोगों के लिए बुनियादी हैं जो गोपनीयता और सुरक्षा को प्राथमिकता देते हुए cryptocurrencies में शामिल होना चाहते हैं।

## Value-Centric Web3 Red Teaming

- वैल्यू-धारक घटकों (signers, oracles, bridges, automation) की सूची बनाएं ताकि यह समझा जा सके कि कौन धन को स्थानांतरित कर सकता है और किस तरह।
- प्रत्येक घटक को प्रासंगिक MITRE AADAPT tactics से मैप करें ताकि privilege escalation paths उजागर हो सकें।
- flash-loan/oracle/credential/cross-chain attack chains का rehearsal करें ताकि प्रभाव सत्यापित हो और exploitable preconditions का दस्तावेजीकरण किया जा सके।

{{#ref}}
value-centric-web3-red-teaming.md
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

वे multi-asset weighted pools जो virtual balances को cache करते हैं और जब `supply == 0` होते हैं तो poisoned हो सकते हैं, उनके बारे में अध्ययन करें:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
