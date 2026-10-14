# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## गैरेज के दरवाज़े

गैरेज-दरवाज़े के रिमोट में क्षेत्र और उत्पाद के अनुसार अलग-अलग sub-GHz आवृत्ति बैंड इस्तेमाल होते हैं। 300, 310, 315, 390 और 433.92 MHz जैसी आवृत्तियाँ देखने को मिलती हैं, लेकिन गैरेज-दरवाज़ों के लिए कोई सार्वभौमिक “300–190 MHz” बैंड नहीं है। ट्रांसमिट करने से पहले लक्ष्य पर लगे लेबल, नियामक क्षेत्र और देखे गए signal की पहचान करें।<sup>[[1]](#references)</sup>

## कार के दरवाज़े

कई कार key fob में **315 MHz या 433.92 MHz** का उपयोग होता है; क्षेत्रीय नियम और वाहन का डिज़ाइन भी इस चुनाव को प्रभावित करते हैं। केवल आवृत्ति के आधार पर यह नहीं कहा जा सकता कि 433 MHz की रेंज 315 MHz से ज़्यादा होगी: transmit power, antenna efficiency, modulation, receiver sensitivity, propagation और स्थानीय नियम—सभी मायने रखते हैं। यूरोप में आमतौर पर 433.92 MHz, जबकि उत्तरी अमेरिका और जापान में 315 MHz का उपयोग आम है।<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

दिखाए गए fixed-code system में, हर code को पाँच बार के बजाय एक बार भेजने से अनुमानित समय घटकर छह मिनट हो जाता है:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Signals के बीच का 2 ms wait हटाने से इस demonstration का समय घटकर लगभग तीन मिनट हो जाता है।

उम्मीदवार bit strings को overlap करने के लिए De Bruijn sequence इस्तेमाल करने से, जब receiver बिना किसी ज़रूरी preamble या frame reset के continuous sequence स्वीकार करता है, तो दिखाए गए attack का समय घटकर लगभग आठ सेकंड हो जाता है।<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame, संगत fixed-code systems के विरुद्ध इस attack को लागू करता है।<sup>[[5]](#references)</sup>

**Preamble की ज़रूरत होने पर De Bruijn Sequence** optimization काम नहीं करेगा और **rolling codes इस attack को रोक देंगे** (यह मानते हुए कि code इतना लंबा है कि उस पर brute-force attack न किया जा सके)।

## Sub-GHz Attack

Flipper Zero से इन signals पर attack करने के लिए देखें:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes से सुरक्षा

Automatic garage-door opener आमतौर पर गैरेज का दरवाज़ा खोलने और बंद करने के लिए wireless remote control इस्तेमाल करते हैं। Remote control, garage-door opener को **radio frequency (RF) signal भेजता है**, जिससे दरवाज़ा खोलने या बंद करने वाली motor सक्रिय होती है।

कोई व्यक्ति code grabber नाम के device से RF signal को intercept करके बाद में इस्तेमाल के लिए रिकॉर्ड कर सकता है। इसे **replay attack** कहते हैं। इस तरह के attack को रोकने के लिए, कई आधुनिक garage-door opener अधिक सुरक्षित encryption method इस्तेमाल करते हैं, जिसे **rolling code** system कहते हैं।

**RF signal आमतौर पर rolling code का उपयोग करके transmit किया जाता है**, यानी हर बार इस्तेमाल करने पर code बदल जाता है। इससे किसी के लिए signal को **intercept** करके गैरेज तक **अनधिकृत** पहुँच पाने के लिए उसका **इस्तेमाल करना** मुश्किल हो जाता है।

Rolling code system में remote control और garage-door opener के पास एक **साझा algorithm** होता है, जो remote इस्तेमाल किए जाने पर हर बार **नया code बनाता है**। Garage-door opener केवल **सही code** पर प्रतिक्रिया देगा, जिससे किसी के लिए केवल code capture करके गैरेज तक अनधिकृत पहुँच पाना बहुत मुश्किल हो जाता है।

### **Missing Link Attack**

मूल रूप से, आप button press सुनते हैं और **remote के device (जैसे कार या गैरेज) की range से बाहर होने के दौरान signal capture करते हैं**। फिर आप device के पास जाकर **captured code का इस्तेमाल करके उसे खोलते हैं**।<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> जानबूझकर RF interference करना कई क्षेत्रों में गैर-कानूनी है और सुरक्षा-महत्वपूर्ण systems को बाधित कर सकता है। Jamming tests केवल shielded, अधिकृत प्रयोगशाला में और लागू radio नियमों के अनुसार करें।<sup>[[6]](#references)</sup>

कोई attacker **वाहन या receiver के पास signal jam** कर सकता है, ताकि receiver code decode न कर पाए; फिर अवरुद्ध transmission को अलग से capture करके, jamming रोकने के बाद captured code replay कर सकता है।<sup>[[2]](#references)</sup>

किसी समय पीड़ित **कार को lock करने के लिए keys इस्तेमाल करेगा**, लेकिन तब तक attack ने संभवतः इतने “दरवाज़ा बंद करने वाले” codes **record कर लिए होंगे** कि उन्हें दोबारा भेजकर दरवाज़ा खोला जा सके (आवृत्ति बदलने की ज़रूरत पड़ सकती है, क्योंकि कुछ कारें खोलने और बंद करने के लिए एक ही codes इस्तेमाल करती हैं, लेकिन दोनों commands को अलग-अलग frequencies पर सुनती हैं)।

> [!WARNING]
> **Jamming काम करता है**, लेकिन इसका पता चल सकता है: अगर **कार lock करने वाला व्यक्ति यह पक्का करने के लिए दरवाज़े जाँचता है** कि वे lock हैं, तो उसे कार unlocked मिलेगी। इसके अलावा, अगर उसे ऐसे attacks के बारे में पता हो, तो वह यह भी सुन सकता है कि ‘lock’ button दबाने पर दरवाज़ों से lock होने की **आवाज़** नहीं आई या कार की **lights** नहीं चमकीं।

### **Code Grabbing Attack ( aka ‘RollJam’ )**

यह ज़्यादा **stealthy Jamming technique** है। Attacker signal jam करेगा, ताकि पीड़ित जब दरवाज़ा lock करने की कोशिश करे तो वह lock न हो, लेकिन attacker इस **code को record कर लेगा**। फिर पीड़ित button दबाकर **कार को दोबारा lock करने की कोशिश करेगा** और कार इस दूसरे code को **record कर लेगी**।<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
इसके तुरंत बाद **attacker पहला code भेज सकता है** और **कार lock हो जाएगी** (पीड़ित को लगेगा कि दूसरी बार button दबाने से कार lock हुई)। फिर attacker कार खोलने के लिए **चुराया गया दूसरा code भेज सकेगा** (यह मानते हुए कि **“कार बंद करने” वाला code उसे खोलने के लिए भी इस्तेमाल किया जा सकता है**)। आवृत्ति बदलने की ज़रूरत पड़ सकती है (क्योंकि कुछ कारें खोलने और बंद करने के लिए एक ही codes इस्तेमाल करती हैं, लेकिन दोनों commands को अलग-अलग frequencies पर सुनती हैं)।

RollJam के एक implementation में receiver bandwidth का फ़ायदा उठाया जाता है: jammer, remote के carrier के इतने पास transmit करता है कि वाहन का wider receiver desensitize हो जाए, जबकि attacker का narrower receiver remote पर ही tuned रहकर signal record कर सके। सटीक offset और bandwidth लक्ष्य hardware पर निर्भर करते हैं।<sup>[[2]](#references)</sup>

> [!WARNING]
> Specifications में देखे गए अन्य implementations से पता चलता है कि **rolling code, भेजे गए कुल code का एक हिस्सा होता है**। उदाहरण के लिए, भेजा गया code **24-bit key** हो सकता है, जिसमें पहले **12 bits rolling code**, अगले **8 bits command** (जैसे lock या unlock) और आखिरी 4 bits **checksum** होते हैं। इस प्रकार के वाहन भी स्वाभाविक रूप से इसकी चपेट में आ सकते हैं, क्योंकि attacker को दोनों frequencies पर **किसी भी rolling code का इस्तेमाल करने** के लिए केवल rolling-code segment बदलना होता है।

> [!CAUTION]
> ध्यान दें कि अगर attacker के पहला code भेजते समय पीड़ित तीसरा code भेजता है, तो पहला और दूसरा code अमान्य हो जाएँगे।

### Alarm Sounding Jamming Attack

कार में install किए गए aftermarket rolling code system पर परीक्षण के दौरान, **एक ही code दो बार भेजने से** तुरंत **alarm और immobiliser सक्रिय हो गए**, जिससे एक विशिष्ट **denial of service** का अवसर मिला। विडंबना यह है कि **alarm और immobiliser को बंद करने का तरीका** remote को **दबाना** था, जिससे attacker को लगातार **DoS attack करने की क्षमता** मिल गई। या इस attack को **पिछले वाले के साथ मिलाकर और codes हासिल किए जा सकते हैं**, क्योंकि पीड़ित जल्द-से-जल्द attack रोकना चाहेगा।<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero documentation - क्षेत्रीय Sub-GHz आवृत्तियाँ](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Rolling Code Systems को bypass करना - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [कार को hack कैसे करें - YARD Stick One / RTL-SDR के साथ RollJam का पुनर्निर्माण](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame source code](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Jammer Enforcement](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
