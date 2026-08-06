# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) GNU/Linux और macOS के लिए एक free digital signal analyzer है, जिसे अज्ञात radio signals से information निकालने के लिए बनाया गया है। यह SoapySDR के माध्यम से विभिन्न SDR devices को support करता है और FSK, PSK तथा ASK signals का adjustable demodulation, analog video को decode करना, bursty signals का analysis और analog voice channels को सुनना (यह सब real time में) संभव बनाता है।<sup>[[1]](#references)</sup>

### Basic Config

इंस्टॉल करने के बाद कुछ चीजें हैं जिन्हें आप configure करने पर विचार कर सकते हैं।\
Settings में (दूसरे tab button में) आप **SDR device** चुन सकते हैं या पढ़ने के लिए **select a file** कर सकते हैं, साथ ही syntonise करने वाली frequency और Sample rate चुन सकते हैं (यदि आपका PC support करता है तो अधिकतम 2.56Msps तक recommended है)।

![SigDigger settings showing SDR device, input file, frequency and sample rate options](<../../images/image (245).png>)

GUI behaviour में, यदि आपका PC support करता है, तो कुछ चीजें enable करने की recommendation है:

![SigDigger - Basic Config: In the GUI behaviour it's recommended to enable a few things if your PC support it](<../../images/image (472).png>)

> [!TIP]
> यदि आपको लगता है कि आपका PC चीजें capture नहीं कर रहा है, तो OpenGL को disable करने और sample rate कम करने का प्रयास करें।

### Uses

- किसी signal को कुछ समय के लिए **capture और analyze करने** के लिए, "Push to capture" button को आवश्यक समय तक दबाए रखें।

![Basic Config - Uses: Just to capture some time of a signal and analyze it just maintain the button "Push to capture" as long as you need](<../../images/image (960).png>)

- SigDigger का **Tuner** **बेहतर signals capture करने** में सहायता करता है (लेकिन यह उन्हें degrade भी कर सकता है)। आदर्श रूप से 0 से शुरू करें और इसे **बढ़ाते रहें जब तक** कि आपको दिखाई न दे कि introduce किया गया **noise**, signal में आवश्यक **improvement** से **अधिक** हो गया है।

![SigDigger tuner control adjusted to improve the captured radio signal](<../../images/image (1099).png>)

### Synchronize with radio channel

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)के साथ जिस channel को सुनना चाहते हैं, उसके साथ synchronize करें, "Baseband audio preview" option configure करें, भेजी जा रही पूरी information प्राप्त करने के लिए bandwidth configure करें और फिर Tuner को उस level पर set करें जिसके बाद noise वास्तव में बढ़ना शुरू होता है:<sup>[[1]](#references)</sup>

![SigDigger synchronized radio channel with baseband audio preview and bandwidth configured](<../../images/image (585).png>)

## Interesting tricks

- जब कोई device information के bursts भेज रहा हो, तो आमतौर पर **पहला भाग preamble होता है**, इसलिए यदि आपको वहां **information न मिले** या **कुछ errors हों**, तो **चिंता करने की आवश्यकता नहीं** है।
- Information frames में आमतौर पर आपको **एक-दूसरे के साथ अच्छी तरह aligned अलग-अलग frames** मिलेंगे:

![Synchronize with radio channel - Interesting tricks: In frames of information you usually should find different frames well aligned between them](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: In frames of information you usually should find different frames well aligned between them](<../../images/image (597).png>)

- **Bits recover करने के बाद आपको उन्हें किसी तरीके से process करना पड़ सकता है**। उदाहरण के लिए, Manchester codification में up+down एक 1 या 0 होगा और down+up दूसरा होगा। इसलिए 1s और 0s के pairs (ups और downs) वास्तविक 1 या वास्तविक 0 होंगे।
- भले ही कोई signal Manchester codification का उपयोग कर रहा हो (जिसमें लगातार दो से अधिक 0s या 1s मिलना असंभव है), फिर भी आपको **preamble में लगातार कई 1s या 0s मिल सकते हैं**!

### Uncovering modulation type with IQ

Signals में information store करने के 3 तरीके हैं: **amplitude**, **frequency** या **phase** को modulate करना।\
यदि आप किसी signal को check कर रहे हैं, तो यह पता लगाने के अलग-अलग तरीके हैं कि information store करने के लिए इनमें से किसका उपयोग किया गया है (नीचे और तरीके दिए गए हैं), लेकिन एक अच्छा तरीका IQ graph को check करना है।

![SigDigger IQ graph used to identify whether a signal uses amplitude, frequency or phase modulation](<../../images/image (788).png>)

- **Detecting AM**: यदि IQ graph में, उदाहरण के लिए, **2 circles** दिखाई देते हैं (संभवतः एक 0 पर और दूसरा अलग amplitude पर), तो इसका अर्थ हो सकता है कि यह AM signal है। ऐसा इसलिए है क्योंकि IQ graph में 0 और circle के बीच की दूरी signal का amplitude होती है, इसलिए उपयोग किए गए अलग-अलग amplitudes को visualize करना आसान है।
- **Detecting PM**: पिछली image की तरह, यदि आपको आपस में संबंधित न होने वाले छोटे circles मिलते हैं, तो संभवतः phase modulation का उपयोग किया गया है। ऐसा इसलिए है क्योंकि IQ graph में point और 0,0 के बीच का angle signal का phase होता है, जिसका अर्थ है कि 4 अलग-अलग phases का उपयोग किया गया है।
- ध्यान दें कि यदि information इस तथ्य में छिपी है कि phase बदला गया है, न कि phase में स्वयं, तो आपको अलग-अलग phases स्पष्ट रूप से अलग दिखाई नहीं देंगे।
- **Detecting FM**: IQ में frequencies पहचानने के लिए कोई field नहीं होता (centre से दूरी amplitude और angle phase होता है)।\
इसलिए FM पहचानने के लिए इस graph में आपको **मूल रूप से केवल एक circle दिखाई देना चाहिए**।\
इसके अलावा, एक अलग frequency को IQ graph में **circle के across speed acceleration** के रूप में "represent" किया जाता है (इसलिए SysDigger में signal select करने पर IQ graph populate होता है; यदि बनाए गए circle में आपको acceleration या direction में बदलाव मिले, तो इसका अर्थ FM हो सकता है):

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)के साथ AM information check करते समय और केवल **envelop** को देखकर आप अलग-अलग स्पष्ट amplitude levels देख सकते हैं। उपयोग किया गया signal AM में pulses के रूप में information भेज रहा है; एक pulse इस तरह दिखाई देता है:<sup>[[1]](#references)</sup>

![SigDigger AM signal envelope with clear pulse amplitude levels](<../../images/image (590).png>)

और waveform के साथ symbol का एक भाग इस तरह दिखाई देता है:

![Uncovering AM - Checking the envelope: And this is how part of the symbol looks like with the waveform](<../../images/image (734).png>)

#### Checking the Histogram

आप information वाले **पूरे signal को select** कर सकते हैं, **Amplitude** mode और **Selection** select कर सकते हैं और **Histogram** पर click कर सकते हैं। आप देख सकते हैं कि केवल 2 स्पष्ट levels मिलते हैं।

![SigDigger amplitude histogram showing two clear levels for the selected AM signal](<../../images/image (264).png>)

उदाहरण के लिए, यदि आप इस AM signal में Amplitude के बजाय Frequency select करते हैं, तो आपको केवल 1 frequency मिलती है (frequency में modulate की गई information के लिए केवल 1 freq का उपयोग करने का कोई अर्थ नहीं है)।

![SigDigger frequency histogram for the AM signal showing one frequency](<../../images/image (732).png>)

यदि आपको बहुत सारी frequencies मिलती हैं, तो संभवतः यह FM नहीं होगा; channel के कारण signal frequency केवल modify हुई होगी।

#### With IQ

इस example में आप देख सकते हैं कि एक **बड़ा circle** है, लेकिन **centre में बहुत सारे points भी हैं**।

![Checking the Histogram - With IQ: In this example you can see how there is a big circle but also a lot of points in the centre](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

सबसे छोटा symbol select करें जो आपको मिल सके (ताकि आप निश्चित हों कि यह केवल 1 है) और "Selection freq" check करें। इस case में यह 1.013kHz (अर्थात 1kHz) होगा।

![Get Symbol Rate - With one symbol: Select the smallest symbol you can find (so you are sure it's just 1) and check the "Selection freq". I this case it would be 1.013kHz (so 1kHz)](<../../images/image (78).png>)

#### With a group of symbols

आप select किए जाने वाले symbols की संख्या भी indicate कर सकते हैं और SigDigger 1 symbol की frequency calculate करेगा (संभवतः जितने अधिक symbols select होंगे, result उतना बेहतर होगा)। इस scenario में मैंने 10 symbols select किए और "Selection freq" 1.004 Khz है:

![SigDigger symbol-rate calculation using a selected group of ten symbols](<../../images/image (1008).png>)

### Get Bits

यह पता चलने के बाद कि यह **AM modulated** signal है और इसका **symbol rate** क्या है (और यह जानने के बाद कि इस case में ऊपर जाना 1 और नीचे जाना 0 दर्शाता है), signal में encoded **bits प्राप्त करना** बहुत आसान है। इसलिए information वाले signal को select करें, sampling और decision configure करें और sample दबाएं (check करें कि **Amplitude** selected है, खोजा गया **Symbol rate** configure है और **Gadner clock recovery** selected है):

![SigDigger Get Bits panel configured for AM sampling, symbol rate and Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** का अर्थ है कि यदि आपने पहले symbol rate खोजने के लिए intervals select किए थे, तो वही symbol rate उपयोग किया जाएगा।
- **Manual** का अर्थ है कि indicate किया गया symbol rate उपयोग किया जाएगा।
- **Fixed interval selection** में आप select किए जाने वाले intervals की संख्या indicate करते हैं और यह उससे symbol rate calculate करता है।
- **Gadner clock recovery** आमतौर पर सबसे अच्छा option है, लेकिन फिर भी आपको कुछ approximate symbol rate indicate करना होगा।

Sample दबाने पर यह दिखाई देता है:

![With a group of symbols - Get Bits: Pressing sample this appears](<../../images/image (644).png>)

अब SigDigger को यह समझाने के लिए कि information ले जाने वाले level की **range कहां है**, आपको **lower level** पर click करना होगा और सबसे बड़े level तक click बनाए रखना होगा:

![SigDigger level-range selection from the lower amplitude level to the upper level](<../../images/image (439).png>)

यदि, उदाहरण के लिए, amplitude के **4 अलग-अलग levels** होते, तो आपको **Bits per symbol को 2** पर configure करना पड़ता और सबसे छोटे से सबसे बड़े level तक select करना पड़ता।

अंत में **Zoom बढ़ाकर** और **Row size बदलकर** आप bits देख सकते हैं (और सभी bits प्राप्त करने के लिए आप सबको select करके copy कर सकते हैं):

![With a group of symbols - Get Bits: Finally increasing the Zoom and changing the Row size you can see the bits (and you can select all and copy to get all the bits)](<../../images/image (276).png>)

यदि signal में प्रति symbol 1 से अधिक bit हैं (उदाहरण के लिए 2), तो SigDigger के पास यह जानने का कोई तरीका नहीं है कि कौन-सा symbol 00, 01, 10 या 11 है। इसलिए यह प्रत्येक symbol को दर्शाने के लिए अलग-अलग **grey scales** का उपयोग करेगा (और यदि आप bits copy करते हैं, तो यह 0 से 3 तक के **numbers** का उपयोग करेगा; आपको उन्हें process करना होगा)।

इसके अलावा **codifications** जैसे **Manchester** का उपयोग करें; **up+down** 1 या 0 हो सकता है और down+up 1 या 0 हो सकता है। उन cases में आपको प्राप्त ups (1) और downs (0) को process करके 01 या 10 के pairs को 0s या 1s से replace करना होगा।

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

FM में modulated information भेजने वाले signal का example:

![Uncovering FM - Checking the frequencies and waveform: Signal example sending information modulated in FM](<../../images/image (725).png>)

पिछली image में आप काफी अच्छी तरह देख सकते हैं कि **2 frequencies का उपयोग किया गया है**, लेकिन यदि आप **waveform observe** करें, तो हो सकता है कि आप **2 अलग-अलग frequencies को सही ढंग से पहचान न पाएं**:

![SigDigger FM waveform where the two frequencies are difficult to distinguish directly](<../../images/image (717).png>)

ऐसा इसलिए है क्योंकि मैंने signal को दोनों frequencies में capture किया; इसलिए एक लगभग दूसरी का negative है:

![SigDigger FM capture showing the two frequencies as approximate negatives of each other](<../../images/image (942).png>)

यदि synchronized frequency **एक frequency के अधिक करीब हो और दूसरी से दूर**, तो आप 2 अलग-अलग frequencies आसानी से देख सकते हैं:

![Uncovering FM - Checking the frequencies and waveform: If the synchronized frequency is closer to one frequency than to the other you can easily see the 2 different frequencies](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: If the synchronized frequency is closer to one frequency than to the other you can easily see the 2 different frequencies](<../../images/image (488).png>)

#### Checking the histogram

Information वाले signal का frequency histogram check करने पर आप 2 अलग-अलग signals आसानी से देख सकते हैं:

![Checking the frequencies and waveform - Checking the histogram: Checking the frequency histogram of the signal with information you can easily see 2 different signals](<../../images/image (871).png>)

इस case में यदि आप **Amplitude histogram** check करते हैं, तो आपको **केवल एक amplitude** मिलेगा, इसलिए यह **AM नहीं हो सकता** (यदि आपको बहुत सारे amplitudes मिलते हैं, तो ऐसा इसलिए हो सकता है क्योंकि channel के दौरान signal की power कम हो गई है):

![SigDigger amplitude histogram for FM signal showing a single amplitude level](<../../images/image (817).png>)

और यह phase histogram होगा (जो यह बहुत स्पष्ट करता है कि signal phase में modulated नहीं है):

![Checking the frequencies and waveform - Checking the histogram: And this is would be phase histogram (which makes very clear the signal is not modulated in phase)](<../../images/image (996).png>)

#### With IQ

IQ में frequencies पहचानने के लिए कोई field नहीं होता (centre से दूरी amplitude और angle phase होता है)।\
इसलिए FM पहचानने के लिए इस graph में आपको **मूल रूप से केवल एक circle दिखाई देना चाहिए**।\
इसके अलावा, एक अलग frequency को IQ graph में **circle के across speed acceleration** के रूप में "represent" किया जाता है (इसलिए SysDigger में signal select करने पर IQ graph populate होता है; यदि बनाए गए circle में आपको acceleration या direction में बदलाव मिले, तो इसका अर्थ FM हो सकता है):

![SigDigger IQ graph where FM appears as acceleration changes around the circle](<../../images/image (81).png>)

### Get Symbol Rate

Symbols ले जाने वाली frequencies खोज लेने के बाद symbol rate प्राप्त करने के लिए आप **AM example में उपयोग की गई same technique** का उपयोग कर सकते हैं।

### Get Bits

जब आप **यह पता लगा लें कि signal frequency में modulated है** और **symbol rate** भी मिल जाए, तो bits प्राप्त करने के लिए आप **AM example में उपयोग की गई same technique** का उपयोग कर सकते हैं।

## References

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
