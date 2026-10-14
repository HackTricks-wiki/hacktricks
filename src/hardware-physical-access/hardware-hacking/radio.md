# Radio

{{#include ../../banners/hacktricks-training.md}}

Signal की पहचान के बाद protocol-specific काम के लिए देखें [RFID/NFC, sub-GHz, infrared, BLE, and LoRaWAN testing](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) GNU/Linux और macOS के लिए एक मुफ़्त digital-signal analyzer है, जिसे अज्ञात radio signals से जानकारी निकालने के लिए बनाया गया है। यह SoapySDR के ज़रिए SDR devices को support करता है और FSK, PSK, ASK, analog video, bursty signals और analog voice channels के लिए real-time demodulation और analysis tools देता है।<sup>[[1]](#references)</sup>

### Basic Config

इंस्टॉल करने के बाद, कुछ settings configure करने पर विचार कर सकते हैं।\
Settings में (दूसरे tab button में), **SDR device** या input file, tune करने की frequency और sample rate चुनें। अगर host support करता है, तो 2.56 Msps तक की rate व्यावहारिक हो सकती है।

![SigDigger settings में SDR device, input file, frequency और sample rate के विकल्प दिखाए गए हैं](<../../images/image (245).png>)

GUI behaviour में, अगर आपका PC support करता है, तो कुछ चीज़ें enable करने की सलाह दी जाती है:

![SigDigger - Basic Config: GUI behaviour में, अगर आपका PC support करता है, तो कुछ चीज़ें enable करने की सलाह दी जाती है](<../../images/image (472).png>)

> [!TIP]
> अगर आपका PC चीज़ें capture नहीं कर रहा है, तो OpenGL disable करके sample rate कम करने की कोशिश करें।

### Uses

- किसी signal को कुछ समय तक **capture करके उसका analysis करने** के लिए, ज़रूरत के अनुसार "Push to capture" button को दबाए रखें।

![Basic Config - Uses: किसी signal को कुछ समय तक capture करके उसका analysis करने के लिए, ज़रूरत के अनुसार "Push to capture" button को दबाए रखें](<../../images/image (960).png>)

- SigDigger का **Tuner** बेहतर **signals capture करने** में मदद करता है (लेकिन यह उन्हें खराब भी कर सकता है)। आदर्श रूप से 0 से शुरू करें और इसे **बढ़ाते रहें, जब तक** कि आपको नज़र आए कि इससे आया **noise**, आपके ज़रूरी **signal में हुए सुधार** से **ज़्यादा** हो गया है।

![कैप्चर किए गए radio signal को बेहतर बनाने के लिए adjust किया गया SigDigger tuner control](<../../images/image (1099).png>)

### Synchronize with radio channel

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)से उस channel के साथ synchronize करें जिसे आप सुनना चाहते हैं। "Baseband audio preview" विकल्प configure करें, भेजी जा रही सारी जानकारी पाने के लिए bandwidth configure करें, फिर Tuner को उस level पर सेट करें जहाँ noise तेज़ी से बढ़ना शुरू होने से ठीक पहले हो:<sup>[[1]](#references)</sup>

![Baseband audio preview और configure किए गए bandwidth के साथ synchronized SigDigger radio channel](<../../images/image (585).png>)

## Interesting tricks

- जब कोई device जानकारी के bursts भेजता है, तो आम तौर पर **पहला हिस्सा preamble होता है**। इसलिए, अगर आपको वहाँ **जानकारी न मिले** या वहाँ **कुछ errors हों**, तो इसकी **चिंता करने की ज़रूरत नहीं** है।
- Information frames में आम तौर पर आपको **अलग-अलग frames एक-दूसरे के साथ अच्छी तरह aligned** दिखने चाहिए:

![Synchronize with radio channel - Interesting tricks: Information frames में आम तौर पर अलग-अलग frames एक-दूसरे के साथ अच्छी तरह aligned दिखने चाहिए](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: Information frames में आम तौर पर अलग-अलग frames एक-दूसरे के साथ अच्छी तरह aligned दिखने चाहिए](<../../images/image (597).png>)

- **Level transitions recover करने के बाद, आपको उन्हें decode करना पड़ सकता है।** Manchester encoding में, एक transition direction `0` और उसकी विपरीत direction `1` दर्शाती है; सटीक polarity इस्तेमाल किए गए convention पर निर्भर करती है।
- Payload में Manchester encoding इस्तेमाल होने पर भी preamble में sampled level लगातार एक जैसा हो सकता है, इसलिए decode करने से पहले frame boundary पहचानें।

### Uncovering modulation type with IQ

Signals में जानकारी store करने के 3 तरीके हैं: **amplitude**, **frequency** या **phase** को modulate करके।\
किसी signal की जाँच करते समय, यह पता लगाने के कई तरीके हैं कि जानकारी store करने के लिए इनमें से किसका इस्तेमाल हो रहा है (और तरीके नीचे दिए गए हैं), लेकिन एक अच्छा तरीका IQ graph देखना है।

![यह पहचानने के लिए इस्तेमाल किया गया SigDigger IQ graph कि signal amplitude, frequency या phase modulation इस्तेमाल करता है](<../../images/image (788).png>)

- **AM पहचानना**: अगर IQ graph में, उदाहरण के लिए, **2 circles** दिखें (शायद एक 0 पर और दूसरा किसी अलग amplitude पर), तो इसका मतलब AM signal हो सकता है। ऐसा इसलिए है क्योंकि IQ graph में 0 और circle के बीच की दूरी signal का amplitude होती है, जिससे अलग-अलग amplitudes का इस्तेमाल आसानी से दिखता है।
- **PM पहचानना**: पिछली image की तरह, अगर आपको ऐसे छोटे circles दिखें जो आपस में संबंधित न हों, तो संभवतः phase modulation इस्तेमाल हो रही है। ऐसा इसलिए है क्योंकि IQ graph में point और 0,0 के बीच का angle signal का phase होता है, यानी 4 अलग-अलग phases इस्तेमाल हो रहे हैं।
  - ध्यान दें कि अगर जानकारी इस बात में छिपी है कि phase बदला है, न कि phase की value में, तो आपको अलग-अलग phases साफ़ तौर पर अलग दिखेंगे नहीं।
- **FM पहचानना**: IQ में frequencies पहचानने के लिए कोई field नहीं होता (centre से दूरी amplitude होती है और angle phase)।\
  इसलिए, FM पहचानने के लिए इस graph में आपको **मूल रूप से सिर्फ़ एक circle** दिखना चाहिए।\
  इसके अलावा, frequency offset IQ circle के चारों ओर rotation rate बदल देता है। इसलिए SigDigger में rotation speed या direction का बदलना FM का संकेत हो सकता है।

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

[**SigDigger**](https://github.com/BatchDrake/SigDigger) से AM data की जाँच करते समय, signal का **envelope** अलग-अलग amplitude levels दिखा सकता है। इस sample signal में जानकारी amplitude-modulated pulses के रूप में भेजी जाती है; एक pulse कुछ इस तरह दिखता है:<sup>[[1]](#references)</sup>

![स्पष्ट pulse amplitude levels वाला SigDigger AM signal envelope](<../../images/image (590).png>)

और waveform के साथ symbol का एक हिस्सा कुछ इस तरह दिखता है:

![Uncovering AM - Checking the envelope: Waveform के साथ symbol का एक हिस्सा इस तरह दिखता है](<../../images/image (734).png>)

#### Checking the Histogram

आप जानकारी वाले **पूरे signal को select** कर सकते हैं, **Amplitude** mode और **Selection** चुनकर **Histogram** पर click कर सकते हैं। आप देख सकते हैं कि सिर्फ़ 2 स्पष्ट levels मौजूद हैं।

![चुने गए AM signal के लिए दो स्पष्ट levels दिखाता SigDigger amplitude histogram](<../../images/image (264).png>)

उदाहरण के लिए, अगर इस AM signal में Amplitude के बजाय Frequency चुनें, तो आपको सिर्फ़ 1 frequency मिलेगी (frequency में modulate की गई जानकारी सिर्फ़ 1 freq का इस्तेमाल नहीं कर सकती)।

![AM signal के लिए एक frequency दिखाता SigDigger frequency histogram](<../../images/image (732).png>)

अगर आपको बहुत सारी frequencies दिखें, तो संभवतः यह FM नहीं है; channel की वजह से signal frequency बदली होगी।

#### With IQ

इस उदाहरण में आप देख सकते हैं कि एक **बड़ा circle** है, लेकिन centre में **बहुत सारे points** भी हैं।

![Checking the Histogram - With IQ: इस उदाहरण में एक बड़ा circle और centre में बहुत सारे points दिखते हैं](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

सबसे छोटा ऐसा interval चुनें जिसमें स्पष्ट रूप से एक symbol हो और **Selection freq** देखें। इस उदाहरण में यह 1.013 kHz है, यानी लगभग 1 kHz।

![Get Symbol Rate - With one symbol: सबसे छोटा ऐसा interval चुनें जिसमें स्पष्ट रूप से एक symbol हो और "Selection freq" देखें। इस उदाहरण में यह 1.013 kHz (यानी 1 kHz) है।](<../../images/image (78).png>)

#### With a group of symbols

आप चुने जाने वाले symbols की संख्या भी तय कर सकते हैं और SigDigger एक symbol की frequency calculate कर देगा (आमतौर पर जितने ज़्यादा symbols चुने जाएँ, उतना बेहतर)। इस उदाहरण में मैंने 10 symbols चुने और "Selection freq" 1.004 Khz है:

![दस चुने गए symbols के group का उपयोग करके SigDigger द्वारा की गई symbol-rate calculation](<../../images/image (1008).png>)

### Get Bits

AM की पहचान करने और **symbol rate** का अनुमान लगाने के बाद, signal region चुनें, amplitude sampling और decision levels configure करें, **Gardner clock recovery** चुनें और **Sample** दबाएँ:

![AM sampling, symbol rate और Gardner clock recovery के लिए configure किया गया SigDigger Get Bits panel](<../../images/image (965).png>)

- **Sync to selection intervals** का मतलब है कि अगर आपने पहले symbol rate पता लगाने के लिए intervals चुने हैं, तो उसी symbol rate का इस्तेमाल होगा।
- **Manual** का मतलब है कि बताई गई symbol rate का इस्तेमाल होगा।
- **Fixed interval selection** में आप चुनने के लिए intervals की संख्या बताते हैं और इससे symbol rate calculate होती है।
- **Gardner clock recovery** एक उपयोगी default है, लेकिन इसके लिए symbol rate का अनुमानित मान फिर भी चाहिए।

Sample दबाने पर यह दिखाई देगा:

![With a group of symbols - Get Bits: Sample दबाने पर यह दिखाई देगा](<../../images/image (644).png>)

अब, SigDigger को यह समझाने के लिए कि जानकारी ले जाने वाले level की **range कहाँ है**, **lower level** पर click करें और दबाए रखते हुए सबसे ऊँचे level तक जाएँ:

![नीचे वाले amplitude level से ऊपर वाले level तक SigDigger level-range selection](<../../images/image (439).png>)

उदाहरण के लिए, अगर amplitude के **4 अलग-अलग levels** होते, तो आपको **Bits per symbol को 2** पर configure करके सबसे छोटे से सबसे बड़े level तक select करना होता।

आखिर में, **Zoom बढ़ाकर** और **Row size बदलकर**, आप bits देख सकते हैं (और सभी bits पाने के लिए उन्हें select करके copy कर सकते हैं):

![With a group of symbols - Get Bits: आखिर में Zoom बढ़ाकर और Row size बदलकर bits देखें; सभी bits पाने के लिए उन्हें select करके copy करें](<../../images/image (276).png>)

अगर signal में प्रति symbol 1 से ज़्यादा bit हो (उदाहरण के लिए 2), तो SigDigger को **पता नहीं होगा कि कौन-सा symbol** 00, 01, 10 या 11 है। इसलिए, हर symbol को दिखाने के लिए वह अलग-अलग **grey scales** इस्तेमाल करेगा (और bits copy करने पर 0 से 3 तक के **numbers** इस्तेमाल होंगे, जिन्हें आपको process करना होगा)।

**Manchester** जैसी line encodings के लिए, इस्तेमाल किए गए protocol convention के अनुसार हर valid transition pair (`01` या `10`) को एक data bit में बदलें।

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

FM में modulate की गई जानकारी भेजने वाले signal का उदाहरण:

![Uncovering FM - Checking the frequencies and waveform: FM में modulate की गई जानकारी भेजने वाले signal का उदाहरण](<../../images/image (725).png>)

Spectrum में **दो frequencies** साफ़ दिखाई देती हैं, हालाँकि time-domain waveform में उन्हें पहचानना मुश्किल हो सकता है:

![SigDigger FM waveform जिसमें दो frequencies को सीधे पहचानना मुश्किल है](<../../images/image (717).png>)

ऐसा इसलिए होता है क्योंकि capture दोनों frequencies के बीच में centered है, इसलिए उनके frequency offsets लगभग एक-दूसरे के विपरीत होते हैं:

![SigDigger FM capture जिसमें दो frequencies लगभग एक-दूसरे के विपरीत दिखती हैं](<../../images/image (942).png>)

अगर synchronized frequency एक frequency के **ज़्यादा करीब** हो और दूसरी से दूर हो, तो आप 2 अलग-अलग frequencies आसानी से देख सकते हैं:

![Uncovering FM - Checking the frequencies and waveform: अगर synchronized frequency एक frequency के ज़्यादा करीब हो और दूसरी से दूर हो, तो आप 2 अलग-अलग frequencies आसानी से देख सकते हैं](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: अगर synchronized frequency एक frequency के ज़्यादा करीब हो और दूसरी से दूर हो, तो आप 2 अलग-अलग frequencies आसानी से देख सकते हैं](<../../images/image (488).png>)

#### Checking the histogram

जानकारी वाले signal का frequency histogram देखने पर आपको 2 अलग-अलग signals आसानी से दिखेंगे:

![Checking the frequencies and waveform - Checking the histogram: जानकारी वाले signal का frequency histogram देखने पर आपको 2 अलग-अलग signals आसानी से दिखेंगे](<../../images/image (871).png>)

इस मामले में, अगर आप **Amplitude histogram** देखें, तो आपको **सिर्फ़ एक amplitude** मिलेगा, इसलिए यह **AM नहीं हो सकता** (अगर बहुत सारे amplitudes मिलें, तो ऐसा channel के दौरान signal की power घटने की वजह से हो सकता है):

![FM signal के लिए एक amplitude level दिखाता SigDigger amplitude histogram](<../../images/image (817).png>)

और यह phase histogram होगा (जिससे साफ़ पता चलता है कि signal phase में modulate नहीं है):

![Checking the frequencies and waveform - Checking the histogram: यह phase histogram है, जिससे साफ़ पता चलता है कि signal phase में modulate नहीं है](<../../images/image (996).png>)

#### With IQ

IQ में frequencies पहचानने के लिए कोई field नहीं होता (centre से दूरी amplitude होती है और angle phase)।\
इसलिए, FM पहचानने के लिए इस graph में आपको **मूल रूप से सिर्फ़ एक circle** दिखना चाहिए।\
इसके अलावा, frequency offset IQ circle के चारों ओर rotation rate बदल देता है। इसलिए SigDigger में rotation speed या direction का बदलना FM का संकेत हो सकता है:

![IQ circle के चारों ओर acceleration में बदलाव दिखाता SigDigger IQ graph, जो FM का संकेत है](<../../images/image (81).png>)

### Get Symbol Rate

Symbols ले जाने वाली frequencies मिल जाने के बाद, symbol rate निकालने के लिए आप **AM example में इस्तेमाल की गई वही technique** इस्तेमाल कर सकते हैं।

### Get Bits

Signal के **frequency में modulate होने** और **symbol rate** का पता चलने के बाद, bits पाने के लिए आप **AM example में इस्तेमाल की गई वही technique** इस्तेमाल कर सकते हैं।

## References

- [1] [SigDigger - GNU/Linux और macOS के लिए मुफ़्त digital signal analyzer](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
