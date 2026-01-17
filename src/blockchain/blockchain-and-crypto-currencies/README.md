# ब्लॉकचेन और क्रिप्टो-करेंसीज़

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **Smart Contracts** को ऐसे प्रोग्राम के रूप में परिभाषित किया जाता है जो ब्लॉकचेन पर तब 실행 होते हैं जब कुछ शर्तें पूरी हो जाती हैं, और यह मध्यस्थों के बिना समझौतों को स्वचालित रूप से लागू करते हैं।
- **Decentralized Applications (dApps)** स्मार्ट कॉन्ट्रैक्ट्स पर आधारित होती हैं, जिनमें एक उपयोगकर्ता-अनुकूल फ्रंट-एंड और एक पारदर्शी, ऑडिट योग्य बैक-एंड होता है।
- **Tokens & Coins** में अंतर है: coins डिजिटल पैसे के रूप में काम करते हैं, जबकि tokens किसी विशेष संदर्भ में मूल्य या स्वामित्व का प्रतिनिधित्व करते हैं।
- **Utility Tokens** सेवाओं तक पहुँच देती हैं, और **Security Tokens** संपत्ति के स्वामित्व को दर्शाती हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को दर्शाते हैं।

## सहमति तंत्र

सहमति तंत्र ब्लॉकचेन पर सुरक्षित और सहमति-आधारित लेन-देन सत्यापन सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेन-देन सत्यापन के लिए कम्प्यूटेशनल पावर पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators से अपेक्षा की जाती है कि वे एक निश्चित मात्रा में tokens रखें, जो PoW की तुलना में ऊर्जा खपत को कम करता है।

## Bitcoin के मूल तत्व

### लेन-देन

Bitcoin के लेन-देन में पते के बीच धन का स्थानांतरण शामिल होता है। लेन-देन डिजिटल हस्ताक्षरों के माध्यम से सत्यापित होते हैं, जो सुनिश्चित करते हैं कि केवल निजी कुंजी का मालिक ही स्थानांतरण आरंभ कर सकता है।

#### प्रमुख घटक:

- **Multisignature Transactions** किसी लेन-देन को अधिकृत करने के लिए कई हस्ताक्षर की आवश्यकता होती है।
- लेन-देन **inputs** (धन का स्रोत), **outputs** (गंतव्य), **fees** (miners को दिए जाते हैं), और **scripts** (लेन-देन के नियम) से मिलकर बने होते हैं।

### Lightning Network

यह एक चैनल के भीतर कई लेन-देन की अनुमति देकर Bitcoin की स्केलेबिलिटी को बढ़ाने का उद्देश्य रखता है, और केवल अंतिम स्थिति को ब्लॉकचेन पर प्रसारित करता है।

## Bitcoin की गोपनीयता संबंधी चिंताएँ

गोपनीयता हमले, जैसे **Common Input Ownership** और **UTXO Change Address Detection**, लेन-देन के पैटर्न का शोषण करते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच लेन-देन कड़ियों को अस्पष्ट करके अनामीकरण में सुधार करती हैं।

## Bitcoins को गुमनामी में प्राप्त करना

तरीकों में नकद ट्रेड, mining, और mixers का उपयोग शामिल है। **CoinJoin** कई लेन-देन को मिलाकर ट्रेसिंग को जटिल बनाता है, जबकि **PayJoin** बढ़ी हुई गोपनीयता के लिए CoinJoins को सामान्य लेन-देन के रूप में छिपाता है।

# Bitcoin गोपनीयता हमले

# Bitcoin गोपनीयता हमलों का सारांश

Bitcoin की दुनिया में, लेन-देन की गोपनीयता और उपयोगकर्ताओं की अनामिता अक्सर चिंता का विषय होती है। यहाँ कुछ सामान्य तरीकों का एक सरलीकृत अवलोकन है जिनके माध्यम से हमलावर Bitcoin की गोपनीयता को प्रभावित कर सकते हैं।

## **Common Input Ownership Assumption**

अलग-अलग उपयोगकर्ताओं کے inputs को एक ही लेन-देन में संयोजित करना आमतौर पर जटिलता के कारण दुर्लभ होता है। इसलिए, **एक ही लेन-देन में दो input पते अक्सर उसी मालिक के होने का अनुमान लगाया जाता है**।

## **UTXO Change Address Detection**

एक UTXO, या **Unspent Transaction Output**, को किसी लेन-देन में पूरी तरह खर्च किया जाना चाहिए। यदि इसका केवल एक भाग किसी अन्य पते पर भेजा जाता है, तो शेष राशि एक नए change address में जाती है। पर्यवेक्षक यह मान सकते हैं कि यह नया पता भेजने वाले का है, जिससे गोपनीयता प्रभावित होती है।

### उदाहरण

इसे कम करने के लिए, mixing सेवाओं का उपयोग या कई पते उपयोग करने से स्वामित्व को अस्पष्ट करने में मदद मिल सकती है।

## **Social Networks & Forums Exposure**

उपयोगकर्ता कभी-कभी अपने Bitcoin पते ऑनलाइन साझा करते हैं, जिससे यह **पता को उसके मालिक से जोड़ना आसान हो जाता है**।

## **Transaction Graph Analysis**

लेन-देन को ग्राफ के रूप में दर्शाया जा सकता है, जो धन के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित कनेक्शनों को उजागर करता है।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic ऐसे लेन-देन का विश्लेषण करके आधारित है जिनमें कई inputs और outputs होते हैं, ताकि अनुमान लगाया जा सके कि कौन सा output भेजने वाले को लौटा रहा change है।

### उदाहरण
```bash
2 btc --> 4 btc
3 btc     1 btc
```
यदि अधिक inputs जोड़ने से change output किसी भी single input से बड़ा हो जाए, तो यह heuristic को भ्रमित कर सकता है।

## **Forced Address Reuse**

Attackers पुराने उपयोग किए गए addresses को छोटे-छोटे amounts भेज सकते हैं, इस उम्मीद में कि recipient भविष्य के transactions में इन्हें अन्य inputs के साथ मिलाएगा, और इस तरह addresses को आपस में link कर देगा।

### सही Wallet व्यवहार

Wallets को उन coins का उपयोग करने से बचना चाहिए जो पहले से इस्तेमाल किए गए, खाली addresses पर प्राप्त हुए हों, ताकि इस privacy leak से बचा जा सके।

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions बिना change के संभवतः उसी user के दो addresses के बीच होते हैं।
- **Round Numbers:** एक transaction में round number यह सुझाता है कि यह एक payment है, और non-round output संभवतः change होगा।
- **Wallet Fingerprinting:** Different wallets के transaction बनाने के unique patterns होते हैं, जो analysts को प्रयुक्त software और संभावित change address की पहचान करने में सक्षम बनाते हैं।
- **Amount & Timing Correlations:** यदि transaction के समय या amounts उजागर किए जाएं तो transactions traceable हो सकते हैं।

## **Traffic Analysis**

network traffic की monitoring करके attackers संभवतः transactions या blocks को IP addresses से link कर सकते हैं, जिससे user privacy compromise हो जाती है। यह विशेष रूप से तब सत्य है जब कोई entity कई Bitcoin nodes चलाता है, जिससे उसके लिए transactions की monitoring करना आसान हो जाता है।

## More

privacy attacks और defenses की व्यापक सूची के लिए, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# गुमनाम Bitcoin Transactions

## Bitcoins गुमनाम तरीके से प्राप्त करने के तरीके

- **Cash Transactions**: नकद के माध्यम से bitcoin प्राप्त करना।
- **Cash Alternatives**: gift cards खरीदकर उन्हें ऑनलाइन bitcoin के लिए बदलना।
- **Mining**: bitcoins कमाने का सबसे private तरीका mining है, खासकर अकेले mining करने पर क्योंकि mining pools miner का IP address जान सकती हैं। [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: सिद्धांत रूप में, bitcoin चुराना इसे गुमनाम रूप से प्राप्त करने का एक तरीका हो सकता है, हालांकि यह illegal है और सुझाया नहीं जाता।

## Mixing Services

mixing service का उपयोग करके, एक user **send bitcoins** कर सकता है और बदले में **different bitcoins in return** प्राप्त कर सकता है, जिससे original owner का trace करना मुश्किल हो जाता है। फिर भी, इसके लिए service पर भरोसा करना आवश्यक होता है कि वह logs नहीं रखेगा और वास्तव में bitcoins वापस करेगा। वैकल्पिक mixing विकल्पों में Bitcoin casinos शामिल हैं।

## CoinJoin

**CoinJoin** अलग-अलग users के कई transactions को एक में merge करता है, जिससे inputs और outputs को match करने की प्रक्रिया किसी के लिए भी जटिल हो जाती है। इसकी प्रभावशीलता के बावजूद, unique input और output sizes वाले transactions अभी भी संभावित रूप से trace किए जा सकते हैं।

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

CoinJoin का एक variant, **PayJoin** (या P2EP), transaction को दो पक्षों (जैसे customer और merchant) के बीच एक सामान्य transaction के रूप में disguise कर देता है, बिना CoinJoin की विशिष्ट equal outputs के। यह इसे पहचानना बेहद मुश्किल बना देता है और transaction surveillance entities द्वारा उपयोग किए जाने वाले common-input-ownership heuristic को अमान्य कर सकता है।
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
ऊपर जैसे लेनदेन PayJoin हो सकते हैं, जो गोपनीयता बढ़ाते हैं और मानक bitcoin लेनदेन से अनभेद्य बने रहते हैं।

**PayJoin का उपयोग पारंपरिक निगरानी विधियों को काफी बाधित कर सकता है**, जिससे यह लेनदेन गोपनीयता के लिए एक आशाजनक विकास बनता है।

# क्रिप्टोकरेंसी में गोपनीयता के लिए सर्वोत्तम प्रथाएँ

## **वॉलेट सिंक्रनाइज़ेशन तकनीकें**

गोपनीयता और सुरक्षा बनाए रखने के लिए, वॉलेट्स का blockchain के साथ समकालिक होना महत्वपूर्ण है। दो तरीके प्रमुख हैं:

- **Full node**: पूरे blockchain को डाउनलोड करके, a full node अधिकतम गोपनीयता सुनिश्चित करता है। अब तक किए गए सभी लेनदेन स्थानीय रूप से संग्रहीत रहते हैं, जिससे प्रतिद्वंद्वियों के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किन लेनदेन या पतों में रुचि रखता है।
- **Client-side block filtering**: यह विधि blockchain के हर ब्लॉक के लिए फ़िल्टर बनाने में शामिल है, जिससे वॉलेट्स नेटवर्क ऑब्ज़र्वरों को विशिष्ट रुचियाँ उजागर किए बिना प्रासंगिक लेनदेन पहचान सकते हैं। lightweight wallets ये फ़िल्टर डाउनलोड करते हैं, और केवल तब पूरे ब्लॉक लेते हैं जब उपयोगकर्ता के पतों से मेल मिलता है।

## **अनामिता के लिए Tor का उपयोग**

चूँकि Bitcoin एक peer-to-peer नेटवर्क पर कार्य करता है, इसलिए नेटवर्क के साथ इंटरैक्ट करते समय अपना IP पता छिपाने के लिए Tor का उपयोग करने की सिफारिश की जाती है, जिससे गोपनीयता बढ़ती है।

## **पते के पुन: उपयोग को रोकना**

गोपनीयता की रक्षा के लिए, हर लेनदेन के लिए नया पता उपयोग करना महत्वपूर्ण है। पतों का पुन: उपयोग लेनदेन को एक ही इकाई से जोड़कर गोपनीयता खतरे में डाल सकता है। आधुनिक वॉलेट्स अपने डिज़ाइन के माध्यम से पता पुन: उपयोग को प्रोत्साहित नहीं करते।

## **लेनदेन गोपनीयता के लिए रणनीतियाँ**

- **Multiple transactions**: भुगतान को कई लेनदेन में विभाजित करने से लेनदेन राशि अस्पष्ट हो सकती है, जिससे गोपनीयता हमलों को नाकाम किया जा सकता है।
- **Change avoidance**: ऐसे लेनदेन चुनना जिनमें change outputs की आवश्यकता न हो, change detection विधियों को बाधित करके गोपनीयता बढ़ाता है।
- **Multiple change outputs**: यदि change से बचना संभव न हो, तो कई change outputs उत्पन्न करना तब भी गोपनीयता में सुधार कर सकता है।

# **Monero: गोपनीयता का एक प्रकाशस्तम्भ**

Monero डिजिटल लेनदेन में पूर्ण अनामिता की आवश्यकता को संबोधित करता है, और गोपनीयता के लिए एक उच्च मानक स्थापित करता है।

# **Ethereum: Gas and Transactions**

## **Gas को समझना**

Gas उस कम्प्यूटेशनल प्रयास को मापता है जो Ethereum पर ऑपरेशनों को निष्पादित करने के लिए आवश्यक होता है, और इसकी कीमत **gwei** में होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) खर्च करने वाला एक लेनदेन gas limit और base fee शामिल करता है, साथ में miners को प्रोत्साहित करने के लिए एक tip भी होता है। उपयोगकर्ता एक max fee सेट कर सकते हैं ताकि वे अधिक भुगतान न करें; अतिरिक्त राशि वापस कर दी जाती है।

## **लेनदेन निष्पादन**

Ethereum में लेनदेन एक sender और एक recipient को शामिल करते हैं, जो user या smart contract पतों में से कोई भी हो सकता है। उनके लिए शुल्क आवश्यक है और उन्हें mined होना चाहिए। किसी लेनदेन में आवश्यक जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit, और fees शामिल हैं। विशेष रूप से, sender का पता signature से निकाला जाता है, इसलिए इसे लेनदेन डेटा में शामिल करने की आवश्यकता नहीं होती।

ये प्रथाएँ और मैकेनिज्म उन किसी भी व्यक्ति के लिए आधारभूत हैं जो गोपनीयता और सुरक्षा को प्राथमिकता देते हुए क्रिप्टोकरेंसी के साथ जुड़ना चाहते हैं।

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) की सूची बनाएं ताकि यह समझा जा सके कि कौन फंडों को स्थानांतरित कर सकता है और कैसे।
- प्रत्येक घटक को संबंधित MITRE AADAPT tactics से मैप करें ताकि privilege escalation paths उजागर हों।
- flash-loan/oracle/credential/cross-chain attack chains का अभ्यास करें ताकि प्रभाव सत्यापित हो और exploitable preconditions दस्तावेज़ित हों।

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs वॉलेट UIs के सप्लाई-चेन छेड़छाड़ से EIP-712 payloads साइन करने से ठीक पहले बदल सकते हैं, delegatecall-based proxy takeovers (उदा., slot-0 overwrite of Safe masterCopy) के लिए वैध signatures इकट्ठा करते हुए।

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Security

- Mutation testing से test suites के blind spots खोजें:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## संदर्भ

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) के व्यावहारिक exploitation पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

यदि multi-asset weighted pools जो virtual balances को cache करती हैं और जब `supply == 0` तब उन्हें poison किया जा सकता है, तो अध्ययन करें:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
