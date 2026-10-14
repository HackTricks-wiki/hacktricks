# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

जिस device तक physical access हो, उसकी board या signals द्वारा उपलब्ध कराए गए interface से शुरुआत करें: [UART serial consoles](uart.md), [JTAG/SWD debug access](jtag.md), [I²C](i2c.md) और [SPI flash](spi.md) buses। [Side-channel analysis](side_channel_analysis.md) और [fault injection](fault_injection_attacks.md) अलग-अलग measurement और glitching कार्यों के लिए हैं; [radio signal analysis](radio.md) over-the-air entry point को कवर करता है। Tools जोड़ने से पहले target के electrical levels और संबंधित chapter में दी गई सीमाओं की जाँच करें।

## JTAG

JTAG (IEEE 1149.1) device के I/O pins के चारों ओर मौजूद cells के ज़रिए boundary-scan testing को समर्थन देता है। कई processors इसी Test Access Port (TAP) के माध्यम से vendor-specific debug functions भी उपलब्ध कराते हैं; boundary scan और CPU debugging, JTAG के संबंधित उपयोग हैं, समानार्थी नहीं।<sup>[[1]](#references)</sup>

JTAG standard **boundary scans करने के लिए विशिष्ट commands** परिभाषित करता है, जिनमें ये शामिल हैं:

- **BYPASS** एक one-bit bypass register चुनता है, ताकि scan chain में मौजूद अन्य devices तक न्यूनतम overhead के साथ पहुँचा जा सके।
- **SAMPLE/PRELOAD** सामान्य operation के दौरान pin values कैप्चर करता है और किसी दूसरे instruction से पहले boundary-scan register में values preload कर सकता है।
- **EXTEST** pin states सेट और पढ़ता है।

यह अन्य commands को भी समर्थन दे सकता है, जैसे:

- device की पहचान करने के लिए **IDCODE**
- device की internal testing के लिए **INTEST**

JTAGulator जैसे tool का उपयोग करते समय आपको ये instructions दिख सकती हैं।

### Test Access Port

**Test Access Port (TAP)** किसी component के JTAG test logic तक पहुँच देता है। चार signals आवश्यक हैं और `TRST` वैकल्पिक है:<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK वह **clock** है जो तय करता है कि TAP controller कितनी बार कोई एक action करेगा (दूसरे शब्दों में, state machine में अगली state पर जाएगा)।
- Test mode select (**TMS**) input TMS **finite state machine** को नियंत्रित करता है। Clock के हर beat पर, device का JTAG TAP controller TMS pin पर voltage जाँचता है। यदि voltage एक निश्चित threshold से कम हो, तो signal को low मानकर 0 के रूप में समझा जाता है; और यदि voltage उस threshold से अधिक हो, तो signal को high मानकर 1 के रूप में समझा जाता है।
- Test data input (**TDI**) चुने गए TAP register में serial instruction या test data shift करता है। IEEE 1149.1 TAP transfer behavior को परिभाषित करता है, जबकि vendors optional instructions और debug registers परिभाषित करते हैं।
- Test data output (**TDO**) वह pin है जो **chip से data बाहर भेजता है**।
- Test reset (**TRST**) input वैकल्पिक TRST finite state machine को **एक ज्ञात और सही state में** reset करता है। इसके बजाय, यदि TMS को लगातार पाँच clock cycles तक 1 पर रखा जाए, तो reset लागू होता है—ठीक वैसे ही जैसे TRST pin से होता है। इसीलिए TRST वैकल्पिक है।

कभी-कभी आपको PCB पर इन pins के label मिल सकते हैं। अन्य स्थितियों में आपको इन्हें **खोजना** पड़ सकता है।

### JTAG pins की पहचान करना

JTAG ports का पता लगाने के लिए एक तेज़, विशेष रूप से इसी काम के लिए बना—लेकिन तुलनात्मक रूप से महँगा—विकल्प **JTAGulator** है, जो UART pinouts की पहचान भी कर सकता है।<sup>[[2]](#references)</sup>

इसमें **24 channels** हैं जिन्हें board के test points से जोड़ा जा सकता है। यह **IDCODE** और **BYPASS** scans का उपयोग करके संभावित pin combinations जाँचता है और पहचाने गए JTAG signals से संबंधित channels की जानकारी देता है।

JTAG pinouts की पहचान करने का एक सस्ता, लेकिन बहुत धीमा तरीका Arduino-संगत microcontroller पर [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) चलाना है।

**JTAGenum** के साथ, पहले enumeration के लिए इस्तेमाल होने वाले probing microcontroller pins तय करें। इसका pinout देखें, फिर उन pins को target board के संभावित test points से जोड़ें।<sup>[[3]](#references)</sup>

JTAG pins की पहचान करने का **तीसरा तरीका** किसी ज्ञात footprint के लिए **PCB का निरीक्षण करना** है। कुछ boards पर **Tag-Connect** footprint मिलता है, हालाँकि Tag-Connect एक connector system है जो JTAG, SWD, UART या कोई अन्य interface ले जा सकता है—सिर्फ इसके होने से यह साबित नहीं होता कि pins JTAG के हैं। इसके बाद component datasheets और continuity measurements से वास्तविक signals की पहचान की जा सकती है।<sup>[[5]](#references)</sup>

## SDW

SWD, Arm का दो-pin वाला, packet-based debug interface है।<sup>[[4]](#references)</sup>

यह interface data के लिए bidirectional **SWDIO** और clock के लिए **SWCLK** का उपयोग करता है। कई devices **Serial Wire/JTAG Debug Port (SWJ-DP)** लागू करते हैं, जो shared pins पर SWD और JTAG के बीच चयन की सुविधा देता है।<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 कार्य समूह — JTAG और boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator दस्तावेज़](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG pin enumeration](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Multi-device Systems के लिए कम pin-count वाले Debug Interfaces](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Debug और programming cable footprints](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
