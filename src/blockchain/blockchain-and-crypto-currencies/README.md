# ब्लॉकचेन और क्रिप्टो-करेंसियाँ

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी अवधारणाएँ

- **Smart Contracts** उन प्रोग्रामों को कहते हैं जो ब्लॉकचेन पर तब चलेंगे जब कुछ शर्तें पूरी हों, और वे मध्यस्थों के बिना समझौतों को स्वचालित रूप से लागू करते हैं।
- **Decentralized Applications (dApps)** Smart Contracts के ऊपर बने होते हैं, जिनमें एक user-friendly front-end और एक पारदर्शी, auditable back-end होता है।
- **Tokens & Coins** में अंतर यह है कि coins डिजिटल पैसे के रूप में काम करते हैं, जबकि tokens किसी विशेष संदर्भ में मूल्य या स्वामित्व का प्रतिनिधित्व करते हैं।
- **Utility Tokens** सेवाओं तक पहुंच प्रदान करते हैं, और **Security Tokens** संपत्ति के स्वामित्व का संकेत देते हैं।
- **DeFi** का मतलब Decentralized Finance है, जो केंद्रीय प्राधिकरणों के बिना वित्तीय सेवाएँ प्रदान करता है।
- **DEX** और **DAOs** क्रमशः Decentralized Exchange Platforms और Decentralized Autonomous Organizations को संदर्भित करते हैं।

## समन्वय (Consensus) तंत्र

Consensus तंत्र ब्लॉकचेन पर सुरक्षित और सहमति द्वारा लेनदेन सत्यापन सुनिश्चित करते हैं:

- **Proof of Work (PoW)** लेनदेन सत्यापन के लिए कम्प्यूटेशनल पावर पर निर्भर करता है।
- **Proof of Stake (PoS)** में validators को एक निश्चित मात्रा में tokens रखना पड़ता है, जो PoW की तुलना में ऊर्जा खपत कम करता है।

## Bitcoin आवश्यक बातें

### लेनदेन

Bitcoin के लेनदेन में पते के बीच धन का स्थानांतरण शामिल है। लेनदेन डिजिटल सिग्नेचर के माध्यम से मान्य किए जाते हैं, जिससे यह सुनिश्चित होता है कि केवल private key का मालिक ही ट्रांसफर आरंभ कर सकता है।

#### प्रमुख घटक:

- **Multisignature Transactions** में लेनदेन को अधिकृत करने के लिए कई सिग्नेचर की आवश्यकता होती है।
- लेनदेन में **inputs** (फंड का स्रोत), **outputs** (गंतव्य), **fees** (miners को भुगतान) और **scripts** (लेनदेन नियम) शामिल होते हैं।

### Lightning Network

Bitcoin की स्केलेबिलिटी बढ़ाने का उद्देश्य रखता है, जिससे एक चैनल के भीतर कई लेनदेन संभव होते हैं और केवल अंतिम स्थिति को ब्लॉकचेन पर प्रसारित किया जाता है।

## Bitcoin गोपनीयता चिंताएँ

गोपनीयता हमले, जैसे **Common Input Ownership** और **UTXO Change Address Detection**, लेनदेन पैटर्न का शोषण करते हैं। **Mixers** और **CoinJoin** जैसी रणनीतियाँ लेनदेन लिंक को अस्पष्ट बनाकर anonymity में सुधार करती हैं।

## Bitcoins को अनाम रूप से प्राप्त करना

विधियों में नकद ट्रेड, mining, और mixers का उपयोग शामिल है। **CoinJoin** कई लेनदेन मिलाकर ट्रेसबिलिटी को जटिल बनाता है, जबकि **PayJoin** बढ़ी हुई गोपनीयता के लिए CoinJoins को सामान्य लेनदेन के रूप में छुपा देता है।

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Bitcoin की दुनिया में, लेनदेन की गोपनीयता और उपयोगकर्ताओं की anonymity अक्सर चिंता का विषय होते हैं। यहाँ कुछ सामान्य तरीकों का सरलीकृत अवलोकन दिया गया है जिनके माध्यम से आक्रमणकारी Bitcoin गोपनीयता को compromise कर सकते हैं।

## **Common Input Ownership Assumption**

अक्सर अलग-अलग उपयोगकर्ताओं के inputs को एक ही लेनदेन में मिलाने की प्रवृत्ति कम होती है क्योंकि यह जटिल होता है। इसलिए, **एक ही लेनदेन में दो input पते अक्सर एक ही मालिक के होने का अनुमान लगाया जाता है**।

## **UTXO Change Address Detection**

एक UTXO, या **Unspent Transaction Output**, को लेनदेन में पूरी तरह खर्च किया जाना चाहिए। यदि इसका केवल एक हिस्सा किसी अन्य पते को भेजा जाता है, तो शेष नया change address को भेज दिया जाता है। निगरानी करने वाले यह अनुमान लगा सकते हैं कि यह नया पता sender का है, जिससे गोपनीयता प्रभावित होती है।

### Example

इसे कम करने के लिए, mixing सेवाओं का उपयोग या कई पतों का उपयोग ownership को अस्पष्ट करने में मदद कर सकता है।

## **Social Networks & Forums Exposure**

उपयोगकर्ता कभी-कभी अपने Bitcoin पते ऑनलाइन साझा करते हैं, जिससे पता को उसके मालिक से जोड़ना **आसान** हो जाता है।

## **Transaction Graph Analysis**

लेनदेन को ग्राफ़ के रूप में विजुअलाइज़ किया जा सकता है, जो धन के प्रवाह के आधार पर उपयोगकर्ताओं के बीच संभावित कनेक्शनों का खुलासा करता है।

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

यह heuristic उन लेनदेन का विश्लेषण करके काम करता है जिनमें कई inputs और outputs होते हैं, ताकि यह अनुमान लगाया जा सके कि कौन सा output sender को लौटा हुआ change है।

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
यदि अधिक इनपुट जोड़ने से चेंज आउटपुट किसी भी एकल इनपुट से बड़ा हो जाता है, तो यह ह्यूरिस्टिक को भ्रमित कर सकता है।

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** बिना चेंज के लेनदेन संभवतः उसी उपयोगकर्ता के मालिकाना हक वाले दो पतों के बीच होते हैं।
- **Round Numbers:** लेनदेन में गोल संख्या यह संकेत देती है कि यह भुगतान है, और गैर-गोल आउटपुट अक्सर चेंज होता है।
- **Wallet Fingerprinting:** विभिन्न wallets की लेनदेन निर्माण पैटर्न अनोखी होती हैं, जिससे विश्लेषक उपयोग किए गए सॉफ़्टवेयर और सम्भवतः चेंज पता पहचान सकते हैं।
- **Amount & Timing Correlations:** लेनदेन का समय या राशि उजागर करने से लेनदेन ट्रेस करने योग्य हो सकते हैं।

## **Traffic Analysis**

नेटवर्क ट्रैफ़िक की निगरानी करके, हमलावर संभावित रूप से लेनदेन या ब्लॉक्स को IP addresses से जोड़ सकते हैं, जिससे उपयोगकर्ता की गोपनीयता खतरे में पड़ सकती है। यदि कोई इकाई कई Bitcoin नोड्स चलाती है तो यह विशेष रूप से सच है, क्योंकि इससे उनके पास लेनदेन की निगरानी करने की क्षमता बढ़ जाती है।

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: नकद के जरिए bitcoin प्राप्त करना।
- **Cash Alternatives**: गिफ्ट कार्ड खरीदकर और उन्हें ऑनलाइन bitcoin में बदलकर।
- **Mining**: bitcoins कमाने का सबसे निजी तरीका mining है, खासकर जब अकेले किया जाए क्योंकि mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: सैद्धान्तिक रूप से, bitcoin चोरी करना इसे गुमनाम रूप से प्राप्त करने का एक तरीका हो सकता है, हालाँकि यह गैरकानूनी है और अनुशंसित नहीं है।

## Mixing Services

मिक्सिंग सर्विस का उपयोग करके, उपयोगकर्ता **send bitcoins** और बदले में **different bitcoins in return** प्राप्त कर सकता है, जिससे मूल मालिक का पता लगाना कठिन हो जाता है। हालांकि, इसके लिए सर्विस पर भरोसा करना आवश्यक है कि वह लॉग्स न रखे और वास्तव में bitcoins वापस करे। वैकल्पिक मिक्सिंग विकल्पों में Bitcoin casinos शामिल हैं।

## CoinJoin

**CoinJoin** विभिन्न उपयोगकर्ताओं से कई लेनदेन को एक में मर्ज करता है, जिससे किसी के लिए इनपुट्स को आउटपुट्स के साथ मिलाना जटिल हो जाता है। इसकी प्रभावशीलता के बावजूद, अनोखी इनपुट और आउटपुट साइज वाले लेनदेन अभी भी संभावित रूप से ट्रेस किए जा सकते हैं।

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**PayJoin का उपयोग पारंपरिक निगरानी तरीकों को गंभीर रूप से बाधित कर सकता है**, जो लेनदेन गोपनीयता की खोज में इसे एक आशाजनक विकास बनाता है।

# क्रिप्टोकरेंसी में गोपनीयता के लिए सर्वश्रेष्ठ प्रथाएँ

## **वॉलेट सिंक्रनाइज़ेशन तकनीकें**

गोपनीयता और सुरक्षा बनाए रखने के लिए वॉलेट्स का ब्लॉकचेन के साथ सिंक होना महत्वपूर्ण है। दो तरीके विशेष रूप से उल्लेखनीय हैं:

- **Full node**: पूरे ब्लॉकचेन को डाउनलोड करके, एक full node अधिकतम गोपनीयता सुनिश्चित करता है। सभी किए गए लेनदेनों को स्थानीय रूप से संग्रहीत किया जाता है, जिससे प्रतिद्वंद्वियों के लिए यह पहचान पाना असंभव हो जाता है कि उपयोगकर्ता किन लेनदेनों या पतों में रूचि रखता है।
- **Client-side block filtering**: यह विधि ब्लॉकचेन के हर ब्लॉक के लिए फ़िल्टर बनाने में शामिल है, जिससे वॉलेट्स नेटवर्क निरीक्षकों के सामने उपयोगकर्ता की विशिष्ट रुचि उजागर किए बिना संबंधित लेनदेनों की पहचान कर सकें। लाइटवेट वॉलेट्स इन फ़िल्टरों को डाउनलोड करते हैं और केवल तभी पूरे ब्लॉक लाते हैं जब उपयोगकर्ता के पतों के साथ मैच मिलता है।

## **गुमनामी के लिए Tor का उपयोग**

Bitcoin एक पीयर-टू-पीयर नेटवर्क पर चलता है, इसलिए नेटवर्क के साथ बातचीत करते समय आपकी IP पता छिपाने के लिए Tor का उपयोग करने की सिफारिश की जाती है, जो गोपनीयता बढ़ाता है।

## **पते के पुन: उपयोग को रोकना**

गोपनीयता की रक्षा के लिए, हर लेनदेन के लिए नया पता उपयोग करना आवश्यक है। पतों का पुन: उपयोग लेनदेनों को एक ही इकाई से जोड़कर गोपनीयता को खतरे में डाल सकता है। आधुनिक वॉलेट्स अपने डिज़ाइन के जरिए पते के पुन: उपयोग को हतोत्साहित करते हैं।

## **लेनदेन गोपनीयता के लिए रणनीतियाँ**

- **Multiple transactions**: एक भुगतान को कई लेनदेनों में विभाजित करने से लेनदेन की राशि अस्पष्ट हो सकती है, जिससे गोपनीयता हमलों को विफल किया जा सकता है।
- **Change avoidance**: ऐसे लेनदेन चुनना जिनमें change outputs की आवश्यकता न हो, change detection तरीकों को बाधित करके गोपनीयता बढ़ाता है।
- **Multiple change outputs**: अगर change से बचना संभव न हो तो कई change outputs बनाना फिर भी गोपनीयता बेहतर कर सकता है।

# **Monero: एक गुमनामी का प्रकाशस्तंभ**

Monero डिजिटल लेनदेन में पूर्ण गुमनामी की आवश्यकता को संबोधित करता है और गोपनीयता के लिए उच्च मानक स्थापित करता है।

# **Ethereum: Gas और लेनदेन**

## **Gas को समझना**

Gas Ethereum पर ऑपरेशन्स निष्पादित करने के लिए आवश्यक गणनात्मक प्रयास को मापता है, जिसकी कीमत **gwei** में होती है। उदाहरण के लिए, 2,310,000 gwei (या 0.00231 ETH) लागत वाला एक लेनदेन gas limit और base fee शामिल करता है, साथ में miners को प्रेरित करने के लिए एक tip भी होता है। उपयोगकर्ता अधिक भुगतान न करें इसके लिए एक max fee सेट कर सकते हैं, अतिरिक्त राशि वापस कर दी जाती है।

## **लेनदेन निष्पादित करना**

Ethereum में लेनदेन में एक sender और एक recipient शामिल होते हैं, जो उपयोगकर्ता या smart contract पतें हो सकते हैं। इनके लिए fee आवश्यक है और इन्हें mined होना चाहिए। लेनदेन में आवश्यक जानकारी में recipient, sender का signature, value, वैकल्पिक data, gas limit, और fees शामिल हैं। ध्यान दें कि sender का पता signature से निकाला जाता है, इसलिए उसे transaction डेटा में शामिल करने की आवश्यकता नहीं रहती।

ये प्रथाएँ और तंत्र उन सभी के लिए बुनियादी हैं जो गोपनीयता और सुरक्षा को प्राथमिकता देते हुए cryptocurrencies के साथ काम करना चाहते हैं।

## Smart Contract सुरक्षा

- Mutation testing ताकि test suites में blind spots मिल सकें:

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

यदि आप DEXes और AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) के व्यावहारिक शोषण पर शोध कर रहे हैं, तो देखें:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
