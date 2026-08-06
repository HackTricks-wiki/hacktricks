# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Garage door openers आमतौर पर 300-190 MHz range में operate करते हैं, जिसमें सबसे common frequencies 300 MHz, 310 MHz, 315 MHz और 390 MHz हैं। यह frequency range garage door openers के लिए commonly इस्तेमाल की जाती है क्योंकि यह अन्य frequency bands की तुलना में कम crowded होती है और अन्य devices से interference होने की संभावना कम होती है।

## Car Doors

अधिकांश car key fobs **315 MHz या 433 MHz** पर operate करते हैं। ये दोनों radio frequencies हैं और इनका इस्तेमाल विभिन्न applications में किया जाता है। दोनों frequencies के बीच मुख्य अंतर यह है कि 433 MHz की range 315 MHz से अधिक होती है। इसका मतलब है कि 433 MHz उन applications के लिए बेहतर है जिनमें अधिक range की आवश्यकता होती है, जैसे remote keyless entry।\
Europe में 433.92MHz commonly इस्तेमाल होता है और U.S. तथा Japan में 315MHz।<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

यदि प्रत्येक code को 5 बार भेजने के बजाय (receiver को code मिलने की पुष्टि करने के लिए ऐसा भेजा जाता है) उसे केवल एक बार भेजा जाए, तो समय घटकर 6mins हो जाता है:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

और यदि signals के बीच का **2 ms waiting** period **remove** कर दिया जाए, तो आप **समय को 3minutes तक घटा सकते हैं।**

इसके अलावा, De Bruijn Sequence (सभी potential binary numbers को burteforce करने के लिए भेजे जाने वाले bits की संख्या कम करने का एक तरीका) का उपयोग करके यह **समय केवल 8 seconds तक घट जाता है**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

इस attack का एक example [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) में implement किया गया है।

**एक preamble की आवश्यकता De Bruijn Sequence** optimization को रोक देगी और **rolling codes इस attack को रोक देंगे** (यह मानते हुए कि code इतना लंबा है कि उसे bruteforce नहीं किया जा सकता)।

## Sub-GHz Attack

इन signals पर Flipper Zero से attack करने के लिए देखें:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatic garage door openers आमतौर पर garage door को खोलने और बंद करने के लिए wireless remote control का उपयोग करते हैं। Remote control **एक radio frequency (RF) signal भेजता है**, जिसे garage door opener motor को door खोलने या बंद करने के लिए activate करता है।

किसी व्यक्ति के लिए code grabber नामक device का उपयोग करके RF signal को intercept करना और बाद में इस्तेमाल के लिए record करना संभव है। इसे **replay attack** कहा जाता है। इस प्रकार के attack को रोकने के लिए, कई modern garage door openers अधिक secure encryption method का उपयोग करते हैं, जिसे **rolling code** system कहा जाता है।

**RF signal आमतौर पर rolling code का उपयोग करके transmit किया जाता है**, जिसका अर्थ है कि प्रत्येक उपयोग के साथ code बदल जाता है। इससे किसी व्यक्ति के लिए signal को **intercept** करना और garage में **unauthorised** access प्राप्त करने के लिए इसका **use** करना **difficult** हो जाता है।

Rolling code system में remote control और garage door opener के पास एक **shared algorithm** होता है, जो remote के उपयोग किए जाने पर हर बार **एक नया code generate करता है**। Garage door opener केवल **correct code** पर respond करेगा, जिससे केवल किसी code को capture करके garage में unauthorised access प्राप्त करना बहुत अधिक कठिन हो जाता है।

### **Missing Link Attack**

मूल रूप से, आप button को listen करते हैं और **signal को उस समय capture करते हैं जब remote device (जैसे car या garage) की range से बाहर हो**। इसके बाद आप device के पास जाकर **captured code का उपयोग करके उसे open करते हैं**।<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

एक attacker vehicle या receive**r** के पास **signal को jam कर सकता है**, जिससे **receiver code को वास्तव में ‘hear’ नहीं कर पाता**, और ऐसा होने के बाद जब आप jamming रोक दें, तो आसानी से code को **capture और replay** कर सकते हैं।<sup>[[2]](#references)</sup>

किसी समय victim **car को lock करने के लिए keys का उपयोग करेगा**, लेकिन तब तक attack ने उम्मीद के अनुसार door खोलने के लिए दोबारा भेजे जा सकने वाले पर्याप्त **"close door" codes** record कर लिए होंगे (frequency बदलने की **आवश्यकता हो सकती है**, क्योंकि कुछ cars open और close करने के लिए समान codes का उपयोग करती हैं, लेकिन दोनों commands को अलग-अलग frequencies पर listen करती हैं)।

> [!WARNING]
> **Jamming works**, लेकिन यह noticeable है। यदि car को lock करने वाला व्यक्ति doors को केवल यह सुनिश्चित करने के लिए test करे कि वे locked हैं, तो उसे car unlocked दिखाई देगी। इसके अतिरिक्त, यदि उसे ऐसे attacks की जानकारी हो, तो वह यह भी notice कर सकता है कि ‘lock’ button दबाने पर doors ने कभी lock होने की **sound** नहीं की या car की **lights** कभी flash नहीं हुईं।

### **Code Grabbing Attack ( aka ‘RollJam’ )**

यह अधिक **stealth Jamming technique** है। Attacker signal को jam करेगा, इसलिए जब victim door lock करने का प्रयास करेगा तो यह काम नहीं करेगा, लेकिन attacker इस **code को record** कर लेगा। इसके बाद victim button दबाकर car को दोबारा **lock करने का प्रयास करेगा** और car इस second code को **record करेगी**।<sup>[[2]](#references)[[4]](#references)</sup>\
इसके तुरंत बाद **attacker first code भेज सकता है** और **car lock हो जाएगी** (victim सोचेगा कि second press से car lock हुई)। इसके बाद attacker car को open करने के लिए **second stolen code भेज सकेगा** (यह मानते हुए कि **"close car" code का उपयोग car खोलने के लिए भी किया जा सकता है**)। Frequency बदलने की **आवश्यकता हो सकती है** (क्योंकि कुछ cars open और close करने के लिए समान codes का उपयोग करती हैं, लेकिन दोनों commands को अलग-अलग frequencies पर listen करती हैं)।

Attacker **अपने receiver को jam किए बिना car receiver को jam कर सकता है**, क्योंकि यदि car receiver, उदाहरण के लिए, 1MHz broadband को listen कर रहा है, तो attacker remote द्वारा उपयोग की जाने वाली exact frequency को **jam** नहीं करेगा, बल्कि उस spectrum में **एक close frequency को jam करेगा**, जबकि **attacker का receiver एक छोटी range में listening करेगा**, जहाँ वह jam signal के बिना remote signal को listen कर सकता है।

> [!WARNING]
> Specifications में देखे गए अन्य implementations से पता चलता है कि **rolling code भेजे गए total code का केवल एक portion होता है**। यानी भेजा गया code एक **24 bit key** होता है, जिसमें पहले **12 bits rolling code**, अगले **8 bits command** (जैसे lock या unlock) और आखिरी 4 bits **checksum** होते हैं। इस प्रकार को implement करने वाले vehicles भी naturally susceptible होते हैं, क्योंकि attacker को केवल rolling code segment replace करना होता है, जिससे वह **दोनों frequencies पर किसी भी rolling code का उपयोग** कर सकता है।

> [!CAUTION]
> ध्यान दें कि यदि victim attacker के first code को भेजने के दौरान third code भेजता है, तो first और second codes invalidated हो जाएंगे।

### Alarm Sounding Jamming Attack

किसी car पर installed aftermarket rolling code system के विरुद्ध testing में, **same code को दो बार भेजने से** alarm और immobiliser **immediately activate हो गए**, जिससे एक unique **denial of service** opportunity मिली। विडंबना यह है कि **alarm और immobiliser को disable करने का तरीका** remote को **press** करना था, जिससे attacker को लगातार **DoS attack perform करने** की क्षमता मिल गई। या अधिक codes प्राप्त करने के लिए इस attack को **previous attack के साथ mix** किया जा सकता है, क्योंकि victim attack को जल्द से जल्द रोकना चाहेगा।<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
