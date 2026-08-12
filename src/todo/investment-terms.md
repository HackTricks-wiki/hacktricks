# निवेश की शर्तें

{{#include ../banners/hacktricks-training.md}}

## स्पॉट

स्पॉट ट्रेडिंग में किसी asset का तत्काल delivery के लिए आदान-प्रदान किया जाता है। Limit order में quantity और limit price निर्दिष्ट की जाती है; यह तभी execute होता है जब market उस price या उससे बेहतर price को पूरा कर सके। इसके बजाय market order उपलब्ध सर्वोत्तम prices पर शीघ्र execution का प्रयास करता है और इसमें slippage हो सकती है।<sup>[[4]](#references)</sup>

Stop-limit order में एक stop price होती है, जो limit order को सक्रिय करती है। यह execution price को सीमित कर सकती है, लेकिन यदि market limit से आगे निकल जाए तो execution की गारंटी नहीं देती।<sup>[[4]](#references)</sup>

## फ्यूचर्स

Futures contract किसी निर्दिष्ट commodity या financial instrument को भविष्य की तारीख में खरीदने या बेचने का standardized agreement होता है। उदाहरण के लिए, दो पक्ष छह महीने बाद settlement के लिए एक bitcoin की कीमत $70,000 तय कर सकते हैं।<sup>[[1]](#references)</sup>

यदि settlement price $80,000 है, तो $70,000 की contract price की तुलना में long side को लाभ और short side को हानि होती है। यदि यह $60,000 है, तो दिशा उलट जाती है। वास्तविक exchange-traded futures को market के अनुसार mark किया जाता है और expiration से पहले सामान्यतः बंद या roll कर दिया जाता है, इसलिए यह एक सरल उदाहरण है।<sup>[[2]](#references)</sup>

Producers और consumers price risk को hedge करने के लिए futures का उपयोग करते हैं; अन्य participants profit कमाने या liquidity प्रदान करने के लिए इनका उपयोग करते हैं।<sup>[[1]](#references)</sup>

- **Long position** में सामान्यतः contract price बढ़ने पर लाभ होता है।
- **Short position** में सामान्यतः contract price घटने पर लाभ होता है।<sup>[[2]](#references)</sup>

### Futures के साथ Hedging

यदि कोई fund manager किसी portfolio के गिरने की अपेक्षा करता है, तो वह पर्याप्त रूप से correlated stock-index futures contract को short कर सकता है। Short hedge से होने वाला लाभ portfolio के कुछ losses की भरपाई कर सकता है; basis risk का अर्थ है कि यह offset शायद ही कभी सटीक होता है। Bitcoin future, bitcoin exposure को hedge करेगा, किसी stock portfolio को स्वतः नहीं।

यदि hedged market गिरता है, तो short futures position को लाभ हो सकता है, जबकि holdings का value घट सकता है। यदि market बढ़ता है, तो holdings को लाभ हो सकता है, जबकि hedge में loss हो सकता है। Hedging selected risk को कम करता है, guaranteed profit नहीं बनाता।<sup>[[1]](#references)</sup>

### Perpetual Futures

Perpetual contracts ऐसे derivatives होते हैं जिनकी कोई निश्चित expiration date नहीं होती। Crypto venues सामान्यतः periodic funding payments का उपयोग करके उनकी price को underlying spot price के करीब रखने में सहायता करते हैं; terms venue के अनुसार अलग-अलग होते हैं।<sup>[[3]](#references)</sup>

Mark price बदलने पर profit और loss भी बदलते हैं। Fees और funding से पहले, price में 1% का बदलाव position के notional value में लगभग 1% का बदलाव लाता है, लेकिन leverage के कारण यह posted collateral के प्रतिशत के रूप में बहुत बड़ा हो सकता है।

### Leverage वाले Futures

**Leverage** किसी trader को कम margin deposit के साथ बड़ी notional position नियंत्रित करने की अनुमति देता है। Losses हमेशा initial margin तक सीमित नहीं होते: liquidation, gaps, fees और venue rules अतिरिक्त losses पैदा कर सकते हैं।<sup>[[3]](#references)</sup>

उदाहरण के लिए, 50x leverage पर $100 का margin $5,000 की position को नियंत्रित करता है। Fees, funding और liquidation mechanics को नज़रअंदाज़ करने पर, favorable 1% move से $50 का लाभ होता है (initial margin का 50%), जबकि adverse 1% move से $50 का loss होता है। Adverse 2% move $100 के बराबर होता है, हालांकि कोई venue सामान्यतः पूरा margin समाप्त होने से पहले position को liquidate कर देगा।

Leverage लाभ और हानि दोनों को बढ़ाता है और तुलनात्मक रूप से छोटे adverse move के बाद liquidation को संभव बनाता है।

## Futures और Options के बीच अंतर

Option buyer को contract terms के अंतर्गत exercise करने का अधिकार मिलता है, obligation नहीं। यदि buyer exercise करता है, तो option writer पर corresponding obligation होती है। Buyer उस अधिकार के लिए writer को premium देता है।<sup>[[4]](#references)</sup>

### 1. **Obligation बनाम Right:**

* **Futures:** जब आप futures contract खरीदते या बेचते हैं, तो आप किसी specific price पर future date में asset खरीदने या बेचने के लिए **binding agreement** में प्रवेश करते हैं। Buyer और seller दोनों expiration पर contract पूरा करने के लिए **obligated** होते हैं (जब तक contract को उससे पहले बंद न कर दिया जाए)।
* **Options:** Options में आपको किसी asset को specific price पर किसी निश्चित expiration date से पहले या उस date पर खरीदने ( **call option** के मामले में) या बेचने ( **put option** के मामले में) का **right, but not the obligation** मिलता है। **Buyer** के पास execute करने का option होता है, जबकि यदि buyer option exercise करने का निर्णय लेता है, तो **seller** trade पूरा करने के लिए obligated होता है।

### 2. **Risk:**

* **Futures:** दोनों पक्षों को substantial losses हो सकते हैं। Loss mathematically unlimited है या नहीं, यह position और underlying asset पर निर्भर करता है: short position में theoretical loss unbounded हो सकता है, जबकि यदि underlying zero से नीचे नहीं गिर सकता, तो long position notional value से अधिक नहीं खो सकती।
* **Options:** ऐसा buyer जो कोई अन्य option write नहीं करता, सामान्यतः paid premium को risk में रखता है। Naked call writer को theoretically unlimited loss हो सकता है; अन्य option-writing strategies में bounded या unbounded risk profiles अलग-अलग होते हैं।

### 3. **Cost:**

* **Futures:** Position रखने के लिए आवश्यक margin के अतिरिक्त कोई upfront cost नहीं होती, क्योंकि buyer और seller दोनों trade पूरा करने के लिए obligated होते हैं।
* **Options:** Option exercise करने के अधिकार के लिए buyer को upfront **option premium** देना पड़ता है। यह premium मूलतः option की cost होती है।

### 4. **Profit Potential:**

* **Futures:** Profit या loss expiration पर market price और contract में agreed-upon price के बीच के difference पर आधारित होता है।
* **Options:** Buyer को तब लाभ होता है जब market premium paid से अधिक मात्रा में strike price के आगे favorable दिशा में move करता है। यदि option exercise नहीं किया जाता, तो seller premium रखकर लाभ कमाता है।

## References

- [1] [CFTC - Futures markets का economic purpose](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Futures Market की मूल बातें](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Virtual-currency trading के risks को समझें](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Glossary - Option, premium और exercise](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
