# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) किसी device के I/O pins के चारों ओर रखी गई cells के माध्यम से boundary-scan testing का समर्थन करता है। कई processors इसी Test Access Port (TAP) के माध्यम से vendor-specific debug functions भी उपलब्ध कराते हैं; boundary scan और CPU debugging, JTAG के संबंधित उपयोग हैं, समानार्थी नहीं।<sup>[[1]](#references)</sup>

JTAG standard **boundary scans करने के लिए specific commands** परिभाषित करता है, जिनमें निम्नलिखित शामिल हैं:

- **BYPASS** एक one-bit bypass register चुनता है, ताकि scan chain में मौजूद अन्य devices तक न्यूनतम overhead के साथ पहुँचा जा सके।
- **SAMPLE/PRELOAD** normal operation के दौरान pin values capture करता है और किसी अन्य instruction से पहले boundary-scan register को preload कर सकता है।
- **EXTEST** pin states set और read करता है।

यह अन्य commands का भी समर्थन कर सकता है, जैसे:

- **IDCODE** किसी device की पहचान करने के लिए
- **INTEST** device की internal testing के लिए

JTAGulator जैसे tool का उपयोग करते समय आपको इन instructions का सामना करना पड़ सकता है।

### The Test Access Port

**Test Access Port (TAP)** किसी component के JTAG test logic तक access प्रदान करता है। चार signals आवश्यक हैं और `TRST` optional है:<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK वह **clock** है जो निर्धारित करती है कि TAP controller कितनी बार कोई single action करेगा (दूसरे शब्दों में, state machine में next state पर jump करेगा)।
- Test mode select (**TMS**) input TMS **finite state machine** को control करता है। Clock के प्रत्येक beat पर, device का JTAG TAP controller TMS pin पर voltage को check करता है। यदि voltage किसी निश्चित threshold से कम है, तो signal को low माना जाता है और 0 के रूप में interpret किया जाता है, जबकि यदि voltage किसी निश्चित threshold से अधिक है, तो signal को high माना जाता है और 1 के रूप में interpret किया जाता है।
- Test data input (**TDI**) serial instruction या test data को selected TAP register में shift करता है। IEEE 1149.1 TAP transfer behavior को define करता है, जबकि vendors optional instructions और debug registers define करते हैं।
- Test data output (**TDO**) वह pin है जो **chip से data बाहर भेजता है**।
- Test reset (**TRST**) input Optional TRST finite state machine को **एक known good state में reset** करता है। वैकल्पिक रूप से, यदि TMS को लगातार पाँच clock cycles तक 1 पर रखा जाए, तो reset invoke होता है, ठीक उसी तरह जैसे TRST pin करता है; इसी कारण TRST optional है।

कभी-कभी आप PCB पर इन pins को marked पा सकेंगे। अन्य अवसरों पर आपको **उन्हें find करना** पड़ सकता है।

### Identifying JTAG pins

JTAG ports detect करने के लिए एक तेज, purpose-built—लेकिन तुलनात्मक रूप से महँगा—option **JTAGulator** है, जो UART pinouts की पहचान भी कर सकता है।<sup>[[2]](#references)</sup>

इसमें **24 channels** होते हैं जिन्हें board test points से connect किया जा सकता है। यह **IDCODE** और **BYPASS** scans का उपयोग करके candidate pin combinations enumerate करता है और detected JTAG signals के अनुरूप channels report करता है।

JTAG pinouts identify करने का एक सस्ता लेकिन बहुत धीमा तरीका Arduino-compatible microcontroller पर loaded [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) का उपयोग करना है।

**JTAGenum** के साथ, पहले enumeration के लिए उपयोग किए जाने वाले probing microcontroller pins define करें। इसके pinout को देखें, फिर उन pins को target board पर candidate test points से connect करें।<sup>[[3]](#references)</sup>

JTAG pins identify करने का **तीसरा तरीका** किसी known footprint के लिए **PCB का निरीक्षण करना** है। कुछ boards **Tag-Connect** footprint expose करते हैं, हालांकि Tag-Connect एक connector system है जो JTAG, SWD, UART या किसी अन्य interface को carry कर सकता है—यह अपने-आप में इस बात का proof नहीं है कि pins JTAG हैं। इसके बाद component datasheets और continuity measurements वास्तविक signals की पहचान कर सकते हैं।<sup>[[5]](#references)</sup>

## SDW

SWD, Arm का two-pin, packet-based debug interface है।<sup>[[4]](#references)</sup>

यह interface data के लिए bidirectional **SWDIO** और clock के लिए **SWCLK** का उपयोग करता है। कई devices **Serial Wire/JTAG Debug Port (SWJ-DP)** implement करते हैं, जो shared pins पर SWD और JTAG के बीच selection की अनुमति देता है।<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 working group — JTAG और boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator documentation](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG pin enumeration](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Multi-device Systems के लिए Low Pin-count Debug Interfaces](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Debug और programming cable footprints](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
