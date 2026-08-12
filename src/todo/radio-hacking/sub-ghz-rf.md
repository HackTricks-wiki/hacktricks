# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## गेराज दरवाजे

गेराज-दरवाजे के remotes में क्षेत्र और product के अनुसार अलग-अलग Sub-GHz allocations का उपयोग होता है। 300, 310, 315, 390 और 433.92 MHz जैसी frequencies देखने को मिलती हैं, लेकिन गेराज-दरवाजों के लिए कोई सार्वभौमिक “300–190 MHz” band नहीं है। Transmit करने से पहले target के label, regulatory region और देखे गए signal की पहचान करें।<sup>[[1]](#references)</sup>

## कार के दरवाजे

कई car key fobs **315 MHz या 433.92 MHz** का उपयोग करते हैं, जिसमें regional rules और vehicle design frequency के चुनाव को प्रभावित करते हैं। केवल frequency के आधार पर यह नहीं कहा जा सकता कि 433 MHz की range 315 MHz से अधिक होगी: transmit power, antenna efficiency, modulation, receiver sensitivity, propagation और local regulations सभी महत्वपूर्ण हैं। Europe में आमतौर पर 433.92 MHz का उपयोग होता है, जबकि North America और Japan में 315 MHz आम है।<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

दिखाए गए fixed-code system में, प्रत्येक code को पांच बार भेजने के बजाय एक बार भेजने से अनुमानित समय घटकर छह मिनट हो जाता है:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Signals के बीच 2 ms का wait हटाने से यह demonstration लगभग तीन मिनट तक सीमित हो जाता है।

Candidate bit strings को overlap करने के लिए De Bruijn sequence का उपयोग करने से demonstrated attack लगभग आठ seconds का रह जाता है, जब receiver continuous sequence को required preamble या frame reset के बिना स्वीकार करता है।<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame compatible fixed-code systems के विरुद्ध इस attack को implement करता है।<sup>[[5]](#references)</sup>

**एक preamble की आवश्यकता De Bruijn Sequence optimization को रोक देगी** और **rolling codes इस attack को रोकेंगे** (यह मानते हुए कि code इतना लंबा है कि उसे bruteforce नहीं किया जा सकता)।

## Sub-GHz Attack

इन signals पर Flipper Zero से attack करने के लिए देखें:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatic गेराज door openers आमतौर पर गेराज door को खोलने और बंद करने के लिए wireless remote control का उपयोग करते हैं। Remote control **गेराज door opener को radio frequency (RF) signal भेजता है**, जो door को खोलने या बंद करने के लिए motor को activate करता है।

कोई व्यक्ति code grabber नामक device का उपयोग करके RF signal को intercept कर सकता है और बाद में उपयोग के लिए record कर सकता है। इसे **replay attack** कहा जाता है। इस प्रकार के attack को रोकने के लिए, कई modern गेराज door openers rolling code system नामक अधिक secure encryption method का उपयोग करते हैं।

**RF signal आमतौर पर rolling code का उपयोग करके transmit होता है**, जिसका अर्थ है कि प्रत्येक उपयोग के साथ code बदलता है। इससे किसी व्यक्ति के लिए signal को **intercept** करना और उसे **अनधिकृत** access प्राप्त करने के लिए **उपयोग** करना **कठिन** हो जाता है।

Rolling code system में remote control और गेराज door opener के पास एक **shared algorithm** होता है, जो remote के प्रत्येक उपयोग पर **नया code generate करता है**। गेराज door opener केवल **सही code** पर प्रतिक्रिया देगा, जिससे केवल किसी code को capture करके गेराज में अनधिकृत access प्राप्त करना अधिक कठिन हो जाता है।

### **Missing Link Attack**

मूल रूप से, आप button को listen करते हैं और **signal को तब capture करते हैं जब remote device** (जैसे car या गेराज) की **range से बाहर हो**। इसके बाद आप device के पास जाकर **captured code का उपयोग करके उसे खोलते हैं**।<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> जानबूझकर RF interference कई jurisdictions में illegal है और safety-relevant systems को बाधित कर सकता है। Jamming tests केवल shielded, authorized laboratory में और लागू radio regulations के तहत करें।<sup>[[6]](#references)</sup>

Attacker **vehicle या receiver के पास signal को jam** कर सकता है, ताकि receiver code को decode न कर सके; blocked transmission को अलग से capture कर सकता है; jamming रोक सकता है; और फिर captured code को replay कर सकता है।<sup>[[2]](#references)</sup>

Victim किसी समय **car को lock करने के लिए keys का उपयोग करेगा**, लेकिन तब तक attack ने उम्मीद के अनुसार door खोलने के लिए दोबारा भेजे जा सकने वाले **पर्याप्त "close door" codes record** कर लिए होंगे (एक **frequency change आवश्यक हो सकता है**, क्योंकि कुछ cars open और close के लिए समान codes का उपयोग करती हैं, लेकिन दोनों commands को अलग-अलग frequencies पर listen करती हैं)।

> [!WARNING]
> **Jamming काम करता है**, लेकिन यह ध्यान देने योग्य होता है। यदि **car lock करने वाला व्यक्ति केवल doors को यह सुनिश्चित करने के लिए test करे कि वे locked हैं**, तो उसे car unlocked दिखाई देगी। इसके अतिरिक्त, यदि उसे ऐसे attacks की जानकारी हो, तो वह यह भी सुन सकता है कि ‘lock’ button दबाने पर doors ने lock होने की **sound** नहीं की या car की **lights** नहीं चमकीं।

### **Code Grabbing Attack ( aka ‘RollJam’ )**

यह एक अधिक **stealth Jamming technique** है। Attacker signal को jam करेगा, इसलिए जब victim door lock करने का प्रयास करेगा तो वह काम नहीं करेगा, लेकिन attacker इस **code को record** कर लेगा। इसके बाद victim button दबाकर **car को फिर से lock करने का प्रयास करेगा**, और car इस **दूसरे code को record** करेगी।<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
इसके तुरंत बाद **attacker पहला code भेज सकता है** और **car lock हो जाएगी** (victim सोचेगा कि दूसरे press से car lock हुई)। फिर attacker car को **खोलने के लिए दूसरा stolen code भेज सकेगा** (यह मानते हुए कि **"close car" code का उपयोग उसे खोलने के लिए भी किया जा सकता है**)। एक frequency change आवश्यक हो सकता है (क्योंकि कुछ cars open और close के लिए समान codes का उपयोग करती हैं, लेकिन दोनों commands को अलग-अलग frequencies पर listen करती हैं)।

एक RollJam implementation receiver bandwidth का लाभ उठाता है: jammer remote के carrier के पर्याप्त पास transmit करता है ताकि vehicle के wider receiver को desensitize किया जा सके, जबकि attacker का narrower receiver remote पर centered रहता है और उसे record कर सकता है। Exact offset और bandwidth target hardware पर निर्भर करते हैं।<sup>[[2]](#references)</sup>

> [!WARNING]
> Specifications में देखे गए अन्य implementations से पता चलता है कि **rolling code भेजे गए total code का एक portion होता है**। उदाहरण के लिए, भेजा गया code एक **24 bit key** होता है, जिसमें पहले **12 bits rolling code**, अगले **8 bits command** (जैसे lock या unlock) और अंतिम 4 bits **checksum** होते हैं। इस प्रकार के vehicles भी स्वाभाविक रूप से susceptible होते हैं, क्योंकि attacker को दोनों frequencies पर **किसी भी rolling code का उपयोग** करने के लिए केवल rolling code segment को replace करना होता है।

> [!CAUTION]
> ध्यान दें कि यदि victim attacker के पहला code भेजने के दौरान तीसरा code भेजता है, तो पहला और दूसरा code invalid हो जाएंगे।

### Alarm Sounding Jamming Attack

Car पर installed aftermarket rolling code system के विरुद्ध testing में, **एक ही code को लगातार दो बार भेजने से** alarm और immobiliser तुरंत **activate हो गए**, जिससे unique **denial of service** opportunity मिली। विडंबना यह है कि **alarm** और immobiliser को **disable करने का तरीका** remote को **press करना** था, जिससे attacker को लगातार **DoS attack** करने की क्षमता मिल गई। या इस attack को **पिछले attack के साथ मिलाकर अधिक codes प्राप्त किए जा सकते हैं**, क्योंकि victim attack को जल्द से जल्द रोकना चाहेगा।<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero documentation - क्षेत्रीय Sub-GHz frequencies](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Rolling Code Systems को bypass करना - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: इसे ऐसे चलाएं जैसे आपने इसे hack किया हो (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Car को hack कैसे करें - YARD Stick One / RTL-SDR के साथ RollJam recreation](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame source code](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Jammer Enforcement](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
