# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG एक boundary scan करने की सुविधा देता है। Boundary scan कुछ circuitry का विश्लेषण करता है, जिसमें प्रत्येक pin के लिए embedded boundary-scan cells और registers शामिल होते हैं।

JTAG standard **boundary scans संचालित करने के लिए specific commands** परिभाषित करता है, जिनमें निम्नलिखित शामिल हैं:

- **BYPASS** आपको अन्य chips से होकर गुजरने के overhead के बिना किसी specific chip का परीक्षण करने देता है।
- **SAMPLE/PRELOAD** device के normal functioning mode में होने पर उसमें प्रवेश करने और उससे बाहर निकलने वाले data का sample लेता है।
- **EXTEST** pin states को set और read करता है।

यह अन्य commands को भी support कर सकता है, जैसे:

- किसी device की पहचान करने के लिए **IDCODE**
- device के internal testing के लिए **INTEST**

JTAGulator जैसे tool का उपयोग करने पर आपको इन instructions का सामना करना पड़ सकता है।

### The Test Access Port

Boundary scans में four-wire **Test Access Port (TAP)** के tests शामिल होते हैं। यह एक general-purpose port है, जो किसी component में built-in **JTAG test support** functions तक **access** प्रदान करता है। TAP निम्नलिखित five signals का उपयोग करता है:

- Test clock input (**TCK**) TCK वह **clock** है जो निर्धारित करता है कि TAP controller कितनी बार single action करेगा (दूसरे शब्दों में, state machine में next state पर jump करेगा)।
- Test mode select (**TMS**) input TMS **finite state machine** को control करता है। Clock के प्रत्येक beat पर, device का JTAG TAP controller TMS pin पर voltage को check करता है। यदि voltage एक निश्चित threshold से कम है, तो signal को low माना जाता है और 0 के रूप में interpret किया जाता है, जबकि यदि voltage एक निश्चित threshold से अधिक है, तो signal को high माना जाता है और 1 के रूप में interpret किया जाता है।
- Test data input (**TDI**) TDI वह pin है जो **scan cells के माध्यम से chip में data भेजता है**। प्रत्येक vendor इस pin पर communication protocol को define करने के लिए जिम्मेदार होता है, क्योंकि JTAG इसे define नहीं करता।
- Test data output (**TDO**) TDO वह pin है जो **chip से data बाहर भेजता है**।
- Test reset (**TRST**) input Optional TRST finite state machine को **known good state** पर reset करता है। वैकल्पिक रूप से, यदि TMS को लगातार five clock cycles तक 1 पर रखा जाता है, तो यह उसी प्रकार reset invoke करता है जैसे TRST pin करती, इसी कारण TRST optional है।

कभी-कभी आपको PCB पर इन pins के marked होने की जानकारी मिल सकती है। अन्य अवसरों पर आपको **उन्हें ढूंढना** पड़ सकता है।

### Identifying JTAG pins

JTAG ports को detect करने का fastest लेकिन सबसे महंगा तरीका **JTAGulator** का उपयोग करना है, जो विशेष रूप से इसी purpose के लिए बनाया गया device है (हालांकि यह **UART pinouts भी detect कर सकता है**)।

इसमें **24 channels** होते हैं, जिन्हें आप board के pins से connect कर सकते हैं। इसके बाद यह **सभी possible combinations पर BF attack** perform करता है और **IDCODE** तथा **BYPASS** boundary scan commands भेजता है। यदि इसे response मिलता है, तो यह प्रत्येक JTAG signal के corresponding channel को display करता है।

JTAG pinouts identify करने का एक सस्ता लेकिन बहुत धीमा तरीका Arduino-compatible microcontroller पर loaded [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) का उपयोग करना है।

**JTAGenum** का उपयोग करते समय, enumeration के लिए उपयोग किए जाने वाले **probing device के pins को पहले define** करना होगा। आपको device के pinout diagram का reference लेना होगा और फिर इन pins को अपने target device के test points से connect करना होगा।

JTAG pins identify करने का **third way** किसी pinout के लिए **PCB का inspection** करना है। कुछ मामलों में, PCBs सुविधाजनक रूप से **Tag-Connect interface** प्रदान कर सकते हैं, जो इस बात का स्पष्ट संकेत है कि board में JTAG connector भी है। आप देख सकते हैं कि वह interface [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) पर कैसा दिखता है। इसके अतिरिक्त, **PCB पर मौजूद chipsets की datasheets का inspection** करने पर ऐसे pinout diagrams मिल सकते हैं जो JTAG interfaces की ओर संकेत करते हैं।

## SDW

SWD debugging के लिए designed एक ARM-specific protocol है।

SWD interface के लिए **two pins** आवश्यक हैं: एक bidirectional **SWDIO** signal, जो JTAG के **TDI और TDO pins तथा clock** के equivalent है, और **SWCLK**, जो JTAG में **TCK** का equivalent है। कई devices **Serial Wire or JTAG Debug Port (SWJ-DP)** को support करते हैं, जो एक combined JTAG और SWD interface है और आपको target से SWD या JTAG probe में से किसी एक को connect करने में सक्षम बनाता है।

{{#include ../../banners/hacktricks-training.md}}
