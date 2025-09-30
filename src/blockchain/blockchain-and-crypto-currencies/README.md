# ब्लॉकचेन और क्रिप्टो-करेंसी

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **Smart Contracts** ऐसे प्रोग्राम होते हैं जो ब्लॉकचेन पर कुछ शर्तें पूरी होने पर चलते हैं, और मध्यस्थों के बिना समझौतों के निष्पादन को स्वचालित करते हैं।
- **Decentralized Applications (dApps)** Smart Contracts पर आधारित होते हैं, जिनमें उपयोगकर्ता-अनुकूल फ्रंट-एंड और पारदर्शी, ऑडिटेबल बैक-एंड होता है।
- **Tokens & Coins** का अंतर यह है कि coins डिजिटल पैसा के रूप में कार्य करते हैं, जबकि tokens विशिष्ट संदर्भों में मूल्य या स्वामित्व का प्रतिनिधित्व करते हैं।
- **Utility Tokens** सेवाओं तक पहुंच देते हैं, और **Security Tokens** संपत्ति के स्वामित्व का संकेत देते हैं।
- **DeFi** का अर्थ Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को संदर्भित करते हैं।

## सहमति तंत्र

सहमति तंत्र ब्लॉकचेन पर लेन-देन के सत्यापन को सुरक्षित और सहमति आधारित बनाते हैं:

- **Proof of Work (PoW)** लेन-देन सत्यापन के लिए कम्प्यूटेशनल पावर पर निर्भर करता है।
- **Proof of Stake (PoS)** validators से कुछ मात्रा में tokens रखने की मांग करता है, जो PoW की तुलना में ऊर्जा खपत कम करता है।

## Bitcoin मूल बातें

### लेन-देन

Bitcoin लेन-देन पतों के बीच धन स्थानांतरित करने को शामिल करते हैं। लेन-देन डिजिटल हस्ताक्षरों के माध्यम से सत्यापित होते हैं, जो सुनिश्चित करते हैं कि केवल प्राइवेट की का मालिक ही ट्रांसफर आरंभ कर सकता है।

#### मुख्य घटक:

- **Multisignature Transactions** में एक लेन-देन को अधिकृत करने के लिए कई हस्ताक्षरों की आवश्यकता होती है।
- लेन-देन में **inputs** (धन का स्रोत), **outputs** (गंतव्य), **fees** (miners को दिए जाने वाले), और **scripts** (लेन-देन के नियम) शामिल होते हैं।

### Lightning Network

यह चैनल के भीतर कई लेन-देन की अनुमति देकर Bitcoin की स्केलेबिलिटी बढ़ाने का लक्ष्य रखता है, और केवल अंतिम स्थिति को ही ब्लॉकचेन पर प्रसारित करता है।

## Bitcoin गोपनीयता चिंताएँ

गोपनीयता हमले, जैसे **Common Input Ownership** और **UTXO Change Address Detection**, लेन-देन पैटर्न का शोषण करते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ उपयोगकर्ताओं के बीच लेन-देन लिंक छिपाकर अनामिता बढ़ाती हैं।

## Bitcoins को अनाम तरीके से प्राप्त करना

विधियों में कैश ट्रेड, mining, और mixers का उपयोग शामिल है। **CoinJoin** कई लेन-देन मिक्स करता है ताकि ट्रेसबिलिटी जटिल हो जाए, जबकि **PayJoin** CoinJoins को नियमित लेन-देन के रूप में छिपाकर गोपनीयता बढ़ाता है।

# Bitcoin गोपनीयता हमले

# Bitcoin गोपनीयता हमलों का सारांश

Bitcoin की दुनिया में, लेन-देन की गोपनीयता और उपयोगकर्ताओं की अनामिता अक्सर चिंता का विषय होती है। यहाँ कुछ सामान्य तरीकों का संक्षिप्त परिचय है जिनके माध्यम से हमलावर Bitcoin की गोपनीयता को नुकसान पहुँचा सकते हैं।

## **Common Input Ownership Assumption**

विभिन्न उपयोगकर्ताओं के inputs को एक ही लेन-देन में मिलाना आमतौर पर जटिलता के कारण दुर्लभ होता है। इसलिए, एक ही लेन-देन में मौजूद **दो input addresses अक्सर एक ही मालिक के होने का अनुमान लगाया जाता है**।

## **UTXO Change Address Detection**

एक UTXO, या **Unspent Transaction Output**, को लेन-देन में पूरी तरह खर्च किया जाना चाहिए। यदि केवल इसका एक हिस्सा किसी अन्य पते पर भेजा जाता है, तो शेष नया change address में जाता है। पर्यवेक्षक यह मान सकते हैं कि यह नया पता sender का है, जिससे गोपनीयता प्रभावित होती है।

### उदाहरण

इसे कम करने के लिए, mixing services या कई पतों का उपयोग करने से स्वामित्व छिपाने में मदद मिल सकती है।

## **Social Networks & Forums Exposure**

उपयोगकर्ता कभी-कभी अपने Bitcoin addresses ऑनलाइन साझा करते हैं, जिससे यह **आसान हो जाता है कि पते को उसके मालिक से जोड़ा जाए**।

## **Transaction Graph Analysis**

लेन-देन को ग्राफ के रूप में विज़ुअलाइज़ किया जा सकता है, जो फंड के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित संबंध प्रकट करते हैं।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic कई inputs और outputs वाले लेन-देन का विश्लेषण करके अनुमान लगाने पर आधारित है कि कौन सा output sender को लौटने वाला change है।

### उदाहरण
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### सही वॉलेट व्यवहार

वॉलेट्स को इस privacy leak को रोकने के लिए पहले से उपयोग किए जा चुके, खाली पतों पर प्राप्त सिक्कों का उपयोग करने से बचना चाहिए।

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** चेंज के बिना लेनदेन संभवतः एक ही उपयोगकर्ता के स्वामित्व वाले दो पतों के बीच होते हैं।
- **Round Numbers:** किसी लेनदेन में गोल संख्या होने पर यह भुगतान संकेत देता है, और गैर-गोल आउटपुट संभवतः चेंज होता है।
- **Wallet Fingerprinting:** विभिन्न वॉलेट्स के लेनदेन बनाने के अद्वितीय पैटर्न होते हैं, जिससे विश्लेषक प्रयुक्त सॉफ़्टवेयर और संभावित चेंज पता पहचान सकते हैं।
- **Amount & Timing Correlations:** लेनदेन के समय या राशियों का खुलासा लेनदेन को ट्रेस करने योग्य बना सकता है।

## **Traffic Analysis**

नेटवर्क ट्रैफिक की निगरानी करके, हमलावर संभवतः लेनदेन या ब्लॉक्स को IP पतों से जोड़ सकते हैं, जिससे उपयोगकर्ता की गोपनीयता प्रभावित हो सकती है। यह विशेष रूप से तब सच है जब कोई संस्थान कई Bitcoin नोड्स चलाता है, क्योंकि इससे उनके लिए लेनदेन की निगरानी करने की क्षमता बढ़ जाती है।

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: नकद के माध्यम से bitcoin प्राप्त करना।
- **Cash Alternatives**: गिफ्ट कार्ड खरीदकर और उन्हें ऑनलाइन bitcoin के लिए एक्सचेंज करना।
- **Mining**: bitcoins कमाने का सबसे निजी तरीका mining है, खासकर अकेले करने पर क्योंकि mining pools को खनिक का IP पता पता हो सकता है। [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: सैद्धान्तिक रूप से, bitcoin चोरी करके इसे गुमनाम तरीके से प्राप्त किया जा सकता है, हालाँकि यह अवैध है और अनुशंसित नहीं है।

## Mixing Services

Mixing service का उपयोग करके, एक उपयोगकर्ता **bitcoins भेज सकता है** और बदले में **अलग bitcoins प्राप्त कर सकता है**, जिससे मूल मालिक का पता लगाना कठिन हो जाता है। फिर भी, इसके लिए सेवा पर भरोसा करना आवश्यक है कि वह लॉग नहीं रखेगी और वास्तव में bitcoins वापस करेगी। वैकल्पिक mixing विकल्पों में Bitcoin casinos शामिल हैं।

## CoinJoin

**CoinJoin** विभिन्न उपयोगकर्ताओं के कई लेनदेन को एक में मिलाता है, जिससे इनपुट्स को आउटपुट्स से मिलाने की प्रक्रिया जटिल हो जाती है। अपनी प्रभावशीलता के बावजूद, अद्वितीय इनपुट और आउटपुट आकार वाले लेनदेन अभी भी संभावित रूप से ट्रेस किए जा सकते हैं।

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
उपर्युक्त जैसी लेनदेन PayJoin हो सकती हैं, जो गोपनीयता बढ़ाती हैं जबकि मानक bitcoin लेनदेन से अलग पहचाने जाने योग्य नहीं रहतीं।

**PayJoin के उपयोग से पारंपरिक निगरानी विधियों में काफी व्यवधान आ सकता है**, जिससे यह लेनदेन की गोपनीयता सुनिश्चित करने के प्रयासों में एक आशाजनक विकास बनता है।

# क्रिप्टोकरेंसी में गोपनीयता के लिए सर्वोत्तम प्रथाएँ

## **Wallet Synchronization Techniques**

गोपनीयता और सुरक्षा बनाए रखने के लिए, वॉलेट्स का blockchain के साथ सिंक्रोनाइज़ होना महत्वपूर्ण है। दो तरीके विशेष रूप से प्रभावी हैं:

- **Full node**: पूरे blockchain को डाउनलोड करके, a full node अधिकतम गोपनीयता सुनिश्चित करता है। सभी किए गए लेनदेन स्थानीय रूप से संग्रहित होते हैं, जिससे विपक्षियों के लिए यह पहचानना असंभव हो जाता है कि उपयोगकर्ता किन लेनदेन या पतों में रुचि रखता है।
- **Client-side block filtering**: यह विधि blockchain के हर ब्लॉक के लिए फ़िल्टर बनाने में शामिल है, जिससे वॉलेट्स नेटवर्क निरीक्षकों के सामने विशिष्ट रुचियाँ उजागर किए बिना प्रासंगिक लेनदेन पहचान सकें। हल्के वॉलेट्स ये फ़िल्टर डाउनलोड करते हैं और केवल तब पूर्ण ब्लॉक फ़ेच करते हैं जब उपयोगकर्ता के पतों से मेल मिलता है।

## **Utilizing Tor for Anonymity**

चूंकि Bitcoin एक peer-to-peer नेटवर्क पर काम करता है, नेटवर्क के साथ इंटरैक्ट करते समय अपनी IP पता छिपाने के लिए Tor का उपयोग करने की सलाह दी जाती है, जिससे गोपनीयता बढ़ती है।

## **Preventing Address Reuse**

गोपनीयता सुरक्षित रखने के लिए, हर लेनदेन के लिए नया पता उपयोग करना आवश्यक है। पतों का पुनः उपयोग गोपनीयता को कमजोर कर सकता है क्योंकि यह लेनदेन को एक ही इकाई से जोड़ देता है। आधुनिक वॉलेट्स अपने डिज़ाइन के माध्यम से पते के पुनः उपयोग को हतोत्साहित करते हैं।

## **Strategies for Transaction Privacy**

- **Multiple transactions**: भुगतान को कई लेनदेन में विभाजित करने से लेनदेन की राशि अस्पष्ट हो सकती है, जिससे गोपनीयता हमलों को विफल किया जा सकता है।
- **Change avoidance**: चेंज आउटपुट की आवश्यकता नहीं वाले लेनदेन चुनने से गोपनीयता बढ़ती है क्योंकि यह change detection तरीकों को बाधित करता है।
- **Multiple change outputs**: यदि चेंज से बचना संभव नहीं है, तो कई चेंज आउटपुट जनरेट करना फिर भी गोपनीयता में सुधार कर सकता है।

# **Monero: A Beacon of Anonymity**

Monero डिजिटल लेनदेन में पूर्ण गुमनामी की आवश्यकता को पूरा करता है और गोपनीयता के लिए उच्च मानक स्थापित करता है।

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas Ethereum पर ऑपरेशनों को निष्पादित करने के लिए आवश्यक कम्प्यूटेशनल प्रयास को मापता है, जिसका मूल्यांकन **gwei** में होता है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) लागत वाला एक लेनदेन gas limit और base fee शामिल करता है, साथ ही miners को प्रोत्साहित करने के लिए एक tip भी होता है। उपयोगकर्ता अधिक भुगतान न करें इसके लिए max fee सेट कर सकते हैं; अतिरिक्त राशि वापस कर दी जाती है।

## **Executing Transactions**

Ethereum में लेनदेन में एक sender और एक recipient शामिल होते हैं, जो उपयोगकर्ता या smart contract पतों में से कोई भी हो सकते हैं। इनके लिए एक fee आवश्यक है और इन्हें mined होना होता है। किसी लेनदेन की मौलिक जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit और fees शामिल हैं। उल्लेखनीय है कि sender का पता signature से निकाला जाता है, इसलिए वह transaction डेटा में अलग से शामिल करने की आवश्यकता नहीं होती।

ये प्रथाएँ और तंत्र किसी भी व्यक्ति के लिए बुनियादी हैं जो गोपनीयता और सुरक्षा को प्राथमिकता देते हुए क्रिप्टोकरेंसी के साथ जुड़ना चाहते हैं।

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

यदि आप DEXes और AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) के practical exploitation का शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
