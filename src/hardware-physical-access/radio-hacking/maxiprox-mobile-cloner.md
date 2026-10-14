# पोर्टेबल HID MaxiProx 125 kHz Mobile Cloner बनाना

{{#include ../../banners/hacktricks-training.md}}

## लक्ष्य
मुख्य बिजली से चलने वाले HID MaxiProx 5375 long-range 125 kHz reader को बैटरी से चलने वाले, साइट पर इस्तेमाल किए जा सकने वाले badge cloner में बदलें, जो physical-security assessments के दौरान चुपचाप proximity cards हासिल करता है।

यहाँ बताया गया रूपांतरण TrustedSec की “Let’s Clone a Cloner – Part 3: Putting It All Together” research series पर आधारित है। इसमें mechanical, electrical और RF पहलुओं को शामिल किया गया है, ताकि तैयार डिवाइस को बैकपैक में रखकर साइट पर तुरंत इस्तेमाल किया जा सके।<sup>[[1]](#references)</sup>

> [!warning]
> मुख्य बिजली से चलने वाले उपकरणों और Lithium-ion power-banks के साथ काम करना खतरनाक हो सकता है। सर्किट को **चालू करने से पहले** हर कनेक्शन की जाँच करें और reader को detune होने से बचाने के लिए antennas, coax और ground planes को फैक्टरी डिज़ाइन के अनुसार ही रखें।

## सामग्री सूची (BOM)

* HID MaxiProx 5375 reader (या कोई भी 12 V HID Prox® long-range reader)
* ESP RFID Tool v2.2 (ESP32-आधारित Wiegand sniffer/logger)
* 12 V @ ≥3 A negotiate कर सकने वाला USB-PD (Power-Delivery) trigger module
* 100 W USB-C power-bank (12 V PD profile आउटपुट)
* 26 AWG silicone-insulated hook-up wire – लाल/सफेद
* Panel-mount SPST toggle switch (beeper kill-switch के लिए)
* NKK AT4072 switch-guard / दुर्घटनावश चालू होने से बचाने वाला cap
* Soldering iron, solder wick और desolder pump
* ABS के लिए उपयुक्त hand tools: coping-saw, utility-knife, flat और half-round files
* Drill bits 1/16″ (1.5 mm) और 1/8″ (3 mm)
* 3 M VHB double-sided tape और Zip-ties

## 1. Power Sub-System

1. Logic PCB के लिए 5 V बनाने वाले factory buck-converter daughter-board को desolder करके निकालें।
2. USB-PD trigger को ESP RFID Tool के पास लगाएँ और trigger का USB-C receptacle enclosure के बाहर तक पहुँचाएँ।
3. PD trigger power-bank से 12 V negotiate करता है और उसे सीधे MaxiProx तक पहुँचाता है (reader को सामान्यतः 10–14 V चाहिए)। किसी भी accessories को power देने के लिए ESP board से दूसरी 5 V rail ली जाती है।
4. 100 W battery pack को अंदरूनी standoff के साथ सटाकर रखें, ताकि ferrite antenna के ऊपर **कोई** power cable न पड़े और RF performance बनी रहे।

## 2. Beeper Kill-Switch – बिना आवाज़ के काम करना

1. MaxiProx logic board पर speaker के दो pads खोजें।
2. *दोनों* pads को solder wick से साफ करें, फिर केवल **negative** pad को दोबारा solder करें।
3. Beeper pads पर 26 AWG wires (सफेद = negative, लाल = positive) solder करें और उन्हें नए काटे गए slot से होते हुए panel-mount SPST switch तक ले जाएँ।
4. Switch खुला होने पर beeper circuit टूट जाता है और reader पूरी तरह बिना आवाज़ के काम करता है – गुप्त रूप से badge हासिल करने के लिए आदर्श।
5. Toggle के ऊपर NKK AT4072 spring-loaded safety cap लगाएँ। Coping-saw / file से छेद को सावधानीपूर्वक बड़ा करें, जब तक cap switch body पर कसकर न बैठ जाए। यह guard बैकपैक के भीतर switch को गलती से चालू होने से रोकता है।

## 3. Enclosure और Mechanical Work

• Flush cutters, फिर knife और file का उपयोग करके अंदरूनी ABS “bump-out” को *हटाएँ*, ताकि बड़ा USB-C battery pack standoff पर सपाट बैठ सके।
• USB-C cable के लिए enclosure की दीवार में दो समानांतर channels काटें; इससे battery अपनी जगह पर लॉक रहेगी और हिलेगी या कंपन नहीं करेगी।
• Battery के **power** button के लिए आयताकार aperture बनाएँ:
  1. उस जगह पर कागज़ का stencil टेप से चिपकाएँ।
  2. चारों कोनों में 1/16″ के pilot holes drill करें।
  3. 1/8″ bit से छेदों को बड़ा करें।
  4. Coping saw से छेदों को जोड़ें; file से किनारों को साफ करें।  
  ✱ Rotary Dremel का उपयोग *नहीं किया गया* – इसकी तेज़ गति वाली bit मोटे ABS को पिघला देती है और किनारा भद्दा छोड़ती है।

## 4. अंतिम Assembly

1. MaxiProx logic board को वापस लगाएँ और SMA pigtail को reader के PCB ground pad पर दोबारा solder करें।
2. ESP RFID Tool और USB-PD trigger को 3 M VHB से लगाएँ।
3. सभी wiring को zip-ties से व्यवस्थित करें और power leads को antenna loop से **दूर** रखें।
4. Enclosure के screws तब तक कसें, जब तक battery हल्का-सा दब न जाए; अंदरूनी घर्षण से pack हर card read के बाद device के झटके खाने पर भी अपनी जगह पर रहता है।

## 5. Range और Shielding Tests

* 125 kHz **Pupa** test card के साथ, portable cloner ने खुली हवा में **≈ 8 cm** पर लगातार reads हासिल किए – mains-powered operation जितने ही।<sup>[[1]](#references)</sup>
* Reader को पतली दीवार वाले धातु के cash box के अंदर रखने से (बैंक की लॉबी के desk का अनुकरण करने के लिए) range घटकर ≤ 2 cm रह गई। इससे पुष्टि हुई कि धातु के बड़े enclosures प्रभावी RF shields का काम करते हैं।<sup>[[1]](#references)</sup>

## इस्तेमाल की प्रक्रिया

1. USB-C battery को charge करके जोड़ें और मुख्य power switch चालू करें।
2. (वैकल्पिक) Bench-testing के दौरान आवाज़ वाला feedback चालू करने के लिए beeper guard खोलें; गुप्त रूप से साइट पर इस्तेमाल करने से पहले इसे लॉक कर दें।
3. Target badge holder के पास से चलकर गुज़रें – MaxiProx card को energize करेगा और ESP RFID Tool Wiegand stream capture करेगा।
4. Captured credentials को Wi-Fi या USB-UART से dump करें और ज़रूरत के अनुसार replay/clone करें।

## समस्या निवारण

| लक्षण | संभावित कारण | समाधान |
|---------|--------------|------|
| Card दिखाने पर reader reboot होता है | PD trigger ने 12 V के बजाय 9 V negotiate किया | Trigger jumpers जाँचें / अधिक power वाला USB-C cable आज़माएँ |
| Read range नहीं है | Battery या wiring antenna के *ऊपर* रखी है | Cables को दूसरी जगह से ले जाएँ और ferrite loop के चारों ओर 2 cm की दूरी रखें |
| Beeper अब भी chirp करता है | Switch को negative के बजाय positive lead पर जोड़ा गया है | Kill-switch को इस तरह लगाएँ कि **negative** speaker trace टूटे |

## References

- [1] [क्लोनर का क्लोन बनाएं – भाग 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)
{{#include ../../banners/hacktricks-training.md}}