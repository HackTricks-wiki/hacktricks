# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Garage door openers आमतौर पर 300-190 MHz range की frequencies पर operate करते हैं, जिनमें सबसे common frequencies 300 MHz, 310 MHz, 315 MHz और 390 MHz हैं। यह frequency range garage door openers के लिए सामान्यतः उपयोग की जाती है क्योंकि यह अन्य frequency bands की तुलना में कम crowded होती है और इसमें अन्य devices से interference होने की संभावना कम होती है।

## Car Doors

अधिकांश car key fobs या तो **315 MHz या 433 MHz** पर operate करते हैं। ये दोनों radio frequencies हैं और इनका उपयोग कई अलग-अलग applications में किया जाता है। दोनों frequencies के बीच मुख्य अंतर यह है कि 433 MHz की range 315 MHz से अधिक होती है। इसका अर्थ है कि 433 MHz उन applications के लिए बेहतर है जिनमें अधिक range की आवश्यकता होती है, जैसे remote keyless entry।\
Europe में 433.92MHz का सामान्यतः उपयोग किया जाता है और U.S. तथा Japan में 315MHz का।<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

यदि प्रत्येक code को 5 बार भेजने के बजाय (receiver को code मिलने की पुष्टि करने के लिए ऐसा भेजा जाता है) उसे केवल एक बार भेजा जाए, तो समय घटकर 6mins हो जाता है:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

और यदि signals के बीच की **2 ms waiting** अवधि को **remove** कर दिया जाए, तो आप **समय को 3minutes तक घटा सकते हैं।**

इसके अलावा, De Bruijn Sequence (सभी संभावित binary numbers को burteforce करने के लिए आवश्यक bits की संख्या कम करने का एक तरीका) का उपयोग करके यह **समय केवल 8 seconds तक घट जाता है**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

इस attack का एक example [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) में implement किया गया है।<sup>[[3]](#references)</sup>

**एक preamble की आवश्यकता De Bruijn Sequence** optimization को रोक देगी और **rolling codes इस attack को रोक देंगे** (यह मानते हुए कि code इतना लंबा है कि उसे bruteforce नहीं किया जा सकता)।

## Sub-GHz Attack

इन signals पर Flipper Zero से attack करने के लिए देखें:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatic garage door openers आमतौर पर garage door को खोलने और बंद करने के लिए wireless remote control का उपयोग करते हैं। Remote control **एक radio frequency (RF) signal भेजता है**, जिसे garage door opener receive करता है और motor को door खोलने या बंद करने के लिए activate करता है।

किसी व्यक्ति के लिए code grabber नामक device का उपयोग करके RF signal को intercept करना और बाद में उपयोग के लिए record करना संभव है। इसे **replay attack** कहा जाता है। इस प्रकार के attack को रोकने के लिए कई modern garage door openers rolling code system नामक अधिक secure encryption method का उपयोग करते हैं।

**RF signal आमतौर पर rolling code का उपयोग करके transmit किया जाता है**, जिसका अर्थ है कि प्रत्येक use के साथ code बदलता है। इससे किसी व्यक्ति के लिए signal को **intercept** करना और garage में **unauthorised** access पाने के लिए इसका **use** करना **difficult** हो जाता है।

Rolling code system में remote control और garage door opener के पास एक **shared algorithm** होता है, जो remote के हर use पर **एक नया code generate करता है**। Garage door opener केवल **correct code** पर respond करेगा, जिससे किसी code को capture करके garage में unauthorised access पाना बहुत कठिन हो जाता है।

### **Missing Link Attack**

मूल रूप से, आप button को listen करते हैं और **signal को तब capture करते हैं जब remote device** (जैसे car या garage) की **range से बाहर हो**। इसके बाद आप device के पास जाकर **captured code का उपयोग करके उसे open करते हैं**।<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

कोई attacker vehicle या receive**r** के पास signal को **jam** कर सकता है, ताकि **receiver वास्तव में code को ‘hear’ न कर सके**, और ऐसा होने पर jamming रोकने के बाद आप आसानी से code को **capture और replay** कर सकते हैं।

Victim किसी समय **car को lock करने के लिए keys का उपयोग करेगा**, लेकिन तब तक attack ने उम्मीद के अनुसार पर्याप्त **"close door" codes record** कर लिए होंगे, जिन्हें door खोलने के लिए फिर से भेजा जा सकता है (एक **change of frequency आवश्यक हो सकता है**, क्योंकि कुछ cars open और close करने के लिए समान codes का उपयोग करती हैं, लेकिन दोनों commands को अलग-अलग frequencies पर सुनती हैं)।

> [!WARNING]
> **Jamming works**, लेकिन यह noticeable होता है, क्योंकि यदि **car को lock करने वाला व्यक्ति doors को केवल यह सुनिश्चित करने के लिए test करे कि वे locked हैं**, तो उसे car unlocked दिखाई देगी। इसके अलावा, यदि उसे ऐसे attacks की जानकारी हो, तो वह यह भी notice कर सकता है कि button दबाने पर doors ने कभी lock होने की **sound** नहीं की या car की **lights** कभी flash नहीं हुईं।

### **Code Grabbing Attack ( aka ‘RollJam’ )**

यह एक अधिक **stealth Jamming technique** है। Attacker signal को jam करेगा, इसलिए जब victim door lock करने का प्रयास करेगा तो वह काम नहीं करेगा, लेकिन attacker इस **code को record** कर लेगा। इसके बाद victim button दबाकर **car को फिर से lock करने का प्रयास करेगा** और car इस **दूसरे code को record** कर लेगी।\
इसके तुरंत बाद **attacker पहला code भेज सकता है** और **car lock हो जाएगी** (victim सोचेगा कि दूसरे press से car lock हुई)। इसके बाद attacker car को open करने के लिए **दूसरा stolen code भेज सकेगा** (यह मानते हुए कि **"close car" code का उपयोग उसे open करने के लिए भी किया जा सकता है**)। Frequency में बदलाव आवश्यक हो सकता है (क्योंकि कुछ cars open और close करने के लिए समान codes का उपयोग करती हैं, लेकिन दोनों commands को अलग-अलग frequencies पर सुनती हैं)।<sup>[[3]](#references)[[2]](#references)</sup>

Attacker **car receiver को jam कर सकता है, अपने receiver को नहीं**, क्योंकि यदि car receiver, उदाहरण के लिए, 1MHz broadband को सुन रहा है, तो attacker remote द्वारा उपयोग की जाने वाली exact frequency को **jam** नहीं करेगा, बल्कि उस spectrum में **उसके पास की frequency को jam करेगा**, जबकि **attacker का receiver छोटी range पर listen कर रहा होगा**, जहाँ वह remote signal को **jam signal के बिना सुन सकता है**।

> [!WARNING]
> Specifications में देखे गए अन्य implementations से पता चलता है कि **rolling code भेजे गए total code का एक portion होता है**। अर्थात भेजा गया code एक **24 bit key** होता है, जिसमें पहले **12 bits rolling code**, अगले **8 bits command** (जैसे lock या unlock) और अंतिम 4 bits **checksum** होते हैं। इस प्रकार को implement करने वाले vehicles भी naturally susceptible होते हैं, क्योंकि attacker को केवल rolling code segment को replace करना होता है, ताकि वह **दोनों frequencies पर किसी भी rolling code का use कर सके**।

> [!CAUTION]
> ध्यान दें कि यदि victim attacker द्वारा पहला code भेजे जाने के दौरान तीसरा code भेजता है, तो पहला और दूसरा code invalid हो जाएंगे।

### Alarm Sounding Jamming Attack

एक car पर installed aftermarket rolling code system के विरुद्ध testing में, **एक ही code को लगातार दो बार भेजने से** alarm और immobiliser **तुरंत activate हो गए**, जिससे एक unique **denial of service** opportunity मिली। विडंबना यह थी कि **alarm** और immobiliser को **disable करने का तरीका** remote को **press करना** था, जिससे attacker को लगातार **DoS attack perform करने** की क्षमता मिल गई। या इस attack को **पिछले attack के साथ mix करके अधिक codes प्राप्त किए जा सकते हैं**, क्योंकि victim attack को asap रोकना चाहेगा।<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
