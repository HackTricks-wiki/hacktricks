# निवेश की शर्तें

{{#include ../banners/hacktricks-training.md}}

## Spot

यह trading करने का सबसे बुनियादी तरीका है। आप **asset की मात्रा और वह price बता सकते हैं** जिस पर आप उसे खरीदना या बेचना चाहते हैं, और जब भी वह price पहुंच जाती है, transaction पूरा हो जाता है।

आमतौर पर आप transaction को वर्तमान price पर जितनी जल्दी हो सके पूरा करने के लिए **current market price** का भी उपयोग कर सकते हैं।

**Stop Loss - Limit**: आप खरीदने या बेचने के लिए assets की मात्रा और price बता सकते हैं, साथ ही नुकसान रोकने के लिए एक दूसरी price भी निर्धारित कर सकते हैं, जिस पर पहुंचने पर खरीद या बिक्री हो जाएगी।

## Futures

Future एक contract होता है जिसमें 2 पक्ष **भविष्य में किसी चीज़ को निश्चित price पर प्राप्त करने** के लिए सहमत होते हैं। उदाहरण के लिए, 6 महीनों में 1 bitcoin को 70.000$ पर बेचना।

यदि 6 महीनों बाद bitcoin की value 80.000$ हो जाती है, तो बेचने वाले पक्ष को नुकसान और खरीदने वाले पक्ष को लाभ होता है। यदि 6 महीनों बाद bitcoin की value 60.000$ हो जाती है, तो इसके विपरीत होता है।

हालांकि, यह उन businesses के लिए उपयोगी है जो कोई product बना रहे हैं और यह सुनिश्चित करना चाहते हैं कि वे उसे ऐसी price पर बेच पाएंगे जिससे उनकी लागत पूरी हो सके। यह उन businesses के लिए भी उपयोगी है जो भविष्य में किसी चीज़ के लिए fixed prices सुनिश्चित करना चाहते हैं, भले ही वह price अधिक हो।

हालांकि, exchanges में इसका उपयोग आमतौर पर profit कमाने की कोशिश के लिए किया जाता है।

* ध्यान दें कि "Long position" का अर्थ है कि कोई व्यक्ति यह अनुमान लगा रहा है कि price बढ़ने वाली है।
* जबकि "short position" का अर्थ है कि कोई व्यक्ति यह अनुमान लगा रहा है कि price घटने वाली है।

### Futures के साथ Hedging <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

यदि कोई fund manager इस बात से चिंतित है कि कुछ stocks की price घटने वाली है, तो वह bitcoins या S\&P 500 futures contracts जैसे कुछ assets पर short position ले सकता है। यह कुछ assets को खरीदने या अपने पास रखने और उन्हें भविष्य में अधिक price पर बेचने का contract बनाने के समान होगा।

यदि price घटती है, तो fund manager को लाभ होगा क्योंकि वह assets को अधिक price पर बेच पाएगा। यदि assets की price बढ़ती है, तो manager को वह लाभ नहीं मिलेगा, लेकिन उसके assets उसके पास बने रहेंगे।

### Perpetual Futures

**ये ऐसे "futures" हैं जो अनिश्चितकाल तक चलते हैं** (इनकी कोई समाप्ति तिथि नहीं होती)। इन्हें crypto exchanges में देखना बहुत सामान्य है, जहां आप cryptos की price के आधार पर futures में प्रवेश या उससे बाहर निकल सकते हैं।

ध्यान दें कि इन मामलों में लाभ और नुकसान real time में हो सकते हैं। यदि price 1% बढ़ती है, तो आपको 1% का लाभ होगा; यदि price 1% घटती है, तो आपको 1% का नुकसान होगा।

### Leverage वाले Futures

**Leverage** आपको कम amount of money के साथ market में बड़ी position नियंत्रित करने की सुविधा देता है। मूल रूप से, यह आपको अपनी वास्तविक राशि से कहीं अधिक money "bet" करने की अनुमति देता है, जबकि risk केवल उस money का होता है जो वास्तव में आपके पास है।

उदाहरण के लिए, यदि आप BTC/USDT में 100$ के साथ 50x leverage वाली future position खोलते हैं, तो इसका अर्थ है कि यदि price 1% बढ़ती है, तो आपको अपने initial investment का 1x50 = 50% (50$) लाभ होगा। इसलिए आपके पास 150$ होंगे।\
हालांकि, यदि price 1% घटती है, तो आपके funds का 50% (इस मामले में 59$) कम हो जाएगा। और यदि price 2% घटती है, तो आपका पूरा bet समाप्त हो जाएगा (2x50 = 100%)।

इसलिए, leverage आपको bet की जाने वाली money की amount को नियंत्रित करने की सुविधा देता है, जबकि winnings और losses को बढ़ाता है।

## Futures और Options के बीच अंतर

Futures और options के बीच मुख्य अंतर यह है कि buyer के लिए contract optional होता है: वह इसे execute करने या न करने का निर्णय ले सकता है (आमतौर पर वह तभी execute करेगा जब उसे इससे लाभ होगा)। यदि buyer option का उपयोग करना चाहता है, तो seller को बेचना अनिवार्य होता है।\
हालांकि, buyer option खोलने के लिए seller को कुछ fee देता है (इसलिए seller, जो aparentemente अधिक risk ले रहा है, शुरुआत से ही कुछ money कमाना शुरू कर देता है)।

### 1. **Obligation बनाम Right:**

* **Futures:** जब आप futures contract खरीदते या बेचते हैं, तो आप किसी asset को भविष्य की किसी तारीख पर निश्चित price पर खरीदने या बेचने के लिए **binding agreement** में प्रवेश करते हैं। Buyer और seller दोनों **expiration पर contract पूरा करने के लिए बाध्य** होते हैं (जब तक कि contract को उससे पहले बंद न कर दिया जाए)।
* **Options:** Options में आपके पास किसी asset को निश्चित price पर, किसी निश्चित expiration date से पहले या उस date पर खरीदने (इसे **call option** कहा जाता है) या बेचने (इसे **put option** कहा जाता है) का **अधिकार होता है, लेकिन obligation नहीं**। **Buyer** के पास execute करने का option होता है, जबकि **seller** को trade पूरा करना अनिवार्य होता है यदि buyer option का उपयोग करने का निर्णय लेता है।

### 2. **Risk:**

* **Futures:** Buyer और seller दोनों **unlimited risk** लेते हैं क्योंकि contract पूरा करना उनके लिए अनिवार्य होता है। Risk, agreed-upon price और expiration date पर market price के बीच का अंतर होता है।
* **Options:** Buyer का risk option खरीदने के लिए दिए गए **premium** तक सीमित होता है। यदि market option holder के पक्ष में नहीं बढ़ता, तो वह option को expire होने दे सकता है। हालांकि, option के **seller** (writer) के लिए risk unlimited होता है यदि market उसके विरुद्ध काफी अधिक बढ़ता है।

### 3. **Cost:**

* **Futures:** Position बनाए रखने के लिए आवश्यक margin के अलावा कोई upfront cost नहीं होती, क्योंकि buyer और seller दोनों trade पूरा करने के लिए बाध्य होते हैं।
* **Options:** Buyer को option exercise करने के अधिकार के लिए upfront **option premium** देना पड़ता है। यह premium मूल रूप से option की cost होती है।

### 4. **Profit Potential:**

* **Futures:** Profit या loss expiration पर market price और contract में तय agreed-upon price के बीच के अंतर पर आधारित होता है।
* **Options:** Buyer को तब profit होता है जब market, strike price से आगे और paid premium से अधिक अनुकूल दिशा में बढ़ता है। यदि option exercise नहीं किया जाता, तो seller premium अपने पास रखकर profit कमाता है।

{{#include ../banners/hacktricks-training.md}}
