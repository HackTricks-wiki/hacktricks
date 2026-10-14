# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

किसी ऐसे device के लिए जिसकी physical access उपलब्ध हो, शुरुआत उसके board या signals पर मौजूद interface से करें: [UART serial consoles](uart.md), [JTAG/SWD debug access](jtag.md), [I²C](i2c.md) और [SPI flash](spi.md) buses। [Side-channel analysis](side_channel_analysis.md) और [fault injection](fault_injection_attacks.md) अलग-अलग measurement और glitching कार्यों के लिए हैं; [radio signal analysis](radio.md) over-the-air entry point को कवर करता है। Target-specific RFID/NFC, sub-GHz, infrared, BLE, LoRaWAN और iButton प्रक्रियाओं के लिए [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md) देखें। Tools जोड़ने से पहले target के electrical levels और संबंधित chapter में बताई गई सीमाएँ जाँचें।

## JTAG

JTAG (IEEE 1149.1) device के I/O pins के आसपास रखे गए cells के माध्यम से boundary-scan testing का समर्थन करता है। कई processors उसी Test Access Port (TAP) के ज़रिए vendor-specific debug functions भी उपलब्ध कराते हैं; boundary scan और CPU debugging, JTAG के परस्पर संबंधित उपयोग हैं, समानार्थी नहीं।<sup>[[1]](#references)</sup>

JTAG standard **boundary scans करने के लिए विशिष्ट commands** परिभाषित करता है, जिनमें शामिल हैं:

- **BYPASS** एक one-bit bypass register चुनता है, जिससे scan chain में मौजूद अन्य devices तक न्यूनतम overhead के साथ पहुँचा जा सकता है।
- **SAMPLE/PRELOAD** सामान्य operation के दौरान pin values को capture करता है और किसी दूसरे instruction से पहले boundary-scan register में values preload कर सकता है।
- **EXTEST** pin states को set और read करता है।

यह अन्य commands को भी support कर सकता है, जैसे:

- device की पहचान के लिए **IDCODE**
- device की internal testing के लिए **INTEST**

JTAGulator जैसे tool का उपयोग करते समय आपको ये instructions दिख सकते हैं।

### Test Access Port

**Test Access Port (TAP)** किसी component के JTAG test logic तक access देता है। चार signals ज़रूरी हैं और `TRST` optional है:<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) वह **clock** है जो तय करता है कि TAP controller कितनी बार एक action करेगा (दूसरे शब्दों में, state machine में अगली state पर जाएगा)।
- Test mode select (**TMS**) input **finite state machine** को control करता है। Clock के हर beat पर, device का JTAG TAP controller TMS pin पर voltage जाँचता है। यदि voltage एक निश्चित threshold से कम हो, तो signal को low मानकर 0 समझा जाता है; और यदि voltage threshold से अधिक हो, तो signal को high मानकर 1 समझा जाता है।
- Test data input (**TDI**) चुने गए TAP register में serial instruction या test data shift करता है। IEEE 1149.1, TAP transfer behavior परिभाषित करता है, जबकि vendors optional instructions और debug registers परिभाषित करते हैं।
- Test data output (**TDO**) वह pin है जो **chip से data बाहर भेजता है**।
- Test reset (**TRST**) input optional TRST, finite state machine को **एक ज्ञात और सही state में** reset करता है। वैकल्पिक रूप से, यदि TMS को लगातार पाँच clock cycles तक 1 पर रखा जाए, तो reset शुरू हो जाता है—ठीक वैसे ही जैसे TRST pin से होता है। इसी कारण TRST optional है।

कभी-कभी आपको PCB पर ये pins चिह्नित मिल सकते हैं। अन्य मामलों में आपको इन्हें **ढूँढ़ना** पड़ सकता है।

### JTAG pins की पहचान करना

JTAG ports का पता लगाने के लिए एक तेज़, इसी काम के लिए बना—लेकिन तुलनात्मक रूप से महँगा—विकल्प **JTAGulator** है। यह UART pinouts की पहचान भी कर सकता है।<sup>[[2]](#references)</sup>

इसमें **24 channels** होते हैं जिन्हें board के test points से जोड़ा जा सकता है। यह **IDCODE** और **BYPASS** scans का उपयोग करके संभावित pin combinations की जाँच करता है और detected JTAG signals से संबंधित channels बताता है।

JTAG pinouts की पहचान करने का एक सस्ता, लेकिन बहुत धीमा तरीका है Arduino-compatible microcontroller पर [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) load करना।

**JTAGenum** के साथ, पहले enumeration के लिए उपयोग होने वाले probing microcontroller pins तय करें। उसका pinout देखें, फिर उन pins को target board के संभावित test points से जोड़ें।<sup>[[3]](#references)</sup>

JTAG pins की पहचान करने का **तीसरा तरीका** PCB को **किसी ज्ञात footprint के लिए देखना** है। कुछ boards पर **Tag-Connect** footprint होता है, हालाँकि Tag-Connect एक connector system है जिसमें JTAG, SWD, UART या कोई अन्य interface हो सकता है—सिर्फ़ इससे यह साबित नहीं होता कि pins JTAG के हैं। इसके बाद component datasheets और continuity measurements से वास्तविक signals की पहचान की जा सकती है।<sup>[[5]](#references)</sup>

## SDW

SWD, Arm का two-pin, packet-based debug interface है।<sup>[[4]](#references)</sup>

यह interface data के लिए bidirectional **SWDIO** और clock के लिए **SWCLK** का उपयोग करता है। कई devices **Serial Wire/JTAG Debug Port (SWJ-DP)** लागू करते हैं, जो shared pins पर SWD और JTAG के बीच चयन करने देता है।<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 working group — JTAG और boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator documentation](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG pin enumeration](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Multi-device systems के लिए low pin-count debug interfaces](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Debug और programming cable footprints](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
