# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

किसी ऐसे डिवाइस पर जिसके भौतिक हिस्से तक पहुँच हो, उसके बोर्ड या सिग्नलों से उपलब्ध इंटरफ़ेस से शुरुआत करें: [UART serial consoles](uart.md), [JTAG/SWD debug access](jtag.md), [CoreSight instruction tracing](arm-coresight-instruction-tracing.md), [I²C](i2c.md) और [SPI flash](spi.md) buses। [Side-channel analysis](side_channel_analysis.md) और [fault injection](fault_injection_attacks.md) अलग-अलग मापन और glitching के काम आते हैं; [radio signal analysis](radio.md) हवा के माध्यम से प्रवेश बिंदु को कवर करता है। लक्ष्य-विशिष्ट RFID/NFC, sub-GHz, infrared, BLE, LoRaWAN और iButton प्रक्रियाओं के लिए [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md) देखें। टूल जोड़ने से पहले, लक्ष्य के electrical levels और संबंधित अध्याय में बताई गई सीमाओं की जाँच करें।

## JTAG

JTAG (IEEE 1149.1) डिवाइस के I/O pins के चारों ओर स्थित cells के ज़रिए boundary-scan testing का समर्थन करता है। कई processors इसी Test Access Port (TAP) के ज़रिए vendor-specific debug functions भी उपलब्ध कराते हैं; boundary scan और CPU debugging, JTAG के आपस में संबंधित उपयोग हैं, समानार्थी नहीं।<sup>[[1]](#references)</sup>

JTAG standard **boundary scans करने के लिए विशेष commands** परिभाषित करता है, जिनमें शामिल हैं:

- **BYPASS** एक-bit bypass register चुनता है, ताकि scan chain में दूसरे devices तक न्यूनतम अतिरिक्त काम के साथ पहुँचा जा सके।
- **SAMPLE/PRELOAD** सामान्य संचालन के दौरान pin values को capture करता है और किसी अन्य instruction से पहले boundary-scan register में values preload कर सकता है।
- **EXTEST** pin states सेट और पढ़ता है।

यह अन्य commands का भी समर्थन कर सकता है, जैसे:

- डिवाइस की पहचान के लिए **IDCODE**
- डिवाइस की आंतरिक जाँच के लिए **INTEST**

JTAGulator जैसे tool का उपयोग करते समय आपको ये instructions मिल सकती हैं।

### The Test Access Port

**Test Access Port (TAP)** किसी component के JTAG test logic तक पहुँच देता है। चार signals आवश्यक हैं और `TRST` वैकल्पिक है:<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK वह **clock** है जो तय करता है कि TAP controller कितनी बार कोई एक action करेगा (दूसरे शब्दों में, state machine में अगली state पर जाएगा)।
- Test mode select (**TMS**) input TMS, **finite state machine** को नियंत्रित करता है। हर clock cycle पर, डिवाइस का JTAG TAP controller TMS pin पर voltage जाँचता है। यदि voltage एक निश्चित threshold से नीचे हो, तो signal को low मानकर 0 समझा जाता है; यदि voltage उस threshold से ऊपर हो, तो signal को high मानकर 1 समझा जाता है।
- Test data input (**TDI**) चुने हुए TAP register में serial instruction या test data shift करता है। IEEE 1149.1 TAP transfer के व्यवहार को परिभाषित करता है, जबकि vendors वैकल्पिक instructions और debug registers परिभाषित करते हैं।
- Test data output (**TDO**) TDO वह pin है जो **chip से data बाहर भेजता है**।
- Test reset (**TRST**) input वैकल्पिक TRST finite state machine को **एक ज्ञात, सही स्थिति में** reset करता है। इसके बजाय, यदि TMS को लगातार पाँच clock cycles तक 1 पर रखा जाए, तो reset होता है—ठीक वैसे ही जैसे TRST pin से होता है। इसी कारण TRST वैकल्पिक है।

कभी-कभी आपको PCB पर ये pins चिह्नित मिल सकते हैं। अन्य मामलों में आपको इन्हें **खोजना** पड़ सकता है।

### Identifying JTAG pins

JTAG ports का पता लगाने के लिए एक तेज़, इसी काम के लिए बनाया गया—लेकिन तुलनात्मक रूप से महँगा—विकल्प **JTAGulator** है, जो UART pinouts की भी पहचान कर सकता है।<sup>[[2]](#references)</sup>

इसमें **24 channels** होते हैं, जिन्हें board के test points से जोड़ा जा सकता है। यह **IDCODE** और **BYPASS** scans का उपयोग करके संभावित pin combinations जाँचता है और पहचाने गए JTAG signals से संबंधित channels बताता है।

JTAG pinouts की पहचान करने का एक सस्ता, लेकिन बहुत धीमा तरीका है Arduino-संगत microcontroller पर [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) चलाना।

**JTAGenum** के साथ, पहले उन probing microcontroller pins को तय करें जिनका enumeration के लिए उपयोग होगा। उसका pinout देखें, फिर उन pins को target board के संभावित test points से जोड़ें।<sup>[[3]](#references)</sup>

JTAG pins की पहचान करने का **तीसरा तरीका** है **PCB का निरीक्षण करके** किसी ज्ञात footprint को ढूँढ़ना। कुछ boards पर **Tag-Connect** footprint मिलता है। हालाँकि, Tag-Connect एक connector system है जिसमें JTAG, SWD, UART या कोई अन्य interface हो सकता है—सिर्फ़ इससे यह साबित नहीं होता कि pins JTAG के हैं। इसके बाद component datasheets और continuity measurements से वास्तविक signals की पहचान की जा सकती है।<sup>[[5]](#references)</sup>

## SDW

SWD, Arm का two-pin, packet-based debug interface है।<sup>[[4]](#references)</sup>

यह interface data के लिए bidirectional **SWDIO** और clock के लिए **SWCLK** का उपयोग करता है। कई devices **Serial Wire/JTAG Debug Port (SWJ-DP)** लागू करते हैं, जो साझा pins पर SWD और JTAG के बीच चयन की अनुमति देता है।<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 कार्य समूह — JTAG और boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator का दस्तावेज़ीकरण](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG pin enumeration](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Multi-device Systems के लिए कम-pin वाले Debug Interfaces](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Debug और programming cable footprints](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
