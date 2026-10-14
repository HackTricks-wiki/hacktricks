# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) GNU/Linux और macOS के लिए एक मुफ़्त digital-signal analyzer है, जिसे अज्ञात radio signals से जानकारी निकालने के लिए बनाया गया है। यह SoapySDR के ज़रिए SDR devices को सपोर्ट करता है और FSK, PSK, ASK, analog video, bursty signals और analog voice channels के लिए real-time demodulation और analysis tools देता है।<sup>[[1]](#references)</sup>

### Basic Config

इंस्टॉल करने के बाद, कुछ चीज़ें कॉन्फ़िगर करने पर विचार कर सकते हैं।\
Settings में (दूसरे tab button पर), **SDR device** या input file, tune करने की frequency और sample rate चुनें। अगर host सपोर्ट करता है, तो 2.56 Msps तक की rate व्यावहारिक हो सकती है।

![SigDigger settings में SDR device, input file, frequency और sample rate के विकल्प दिखाए गए हैं](<../../images/image (245).png>)

GUI behaviour में, अगर आपका PC सपोर्ट करता है, तो कुछ विकल्प सक्षम करने की सलाह दी जाती है:

![SigDigger - Basic Config: GUI behaviour में, अगर आपका PC सपोर्ट करता है, तो कुछ विकल्प सक्षम करने की सलाह दी जाती है](<../../images/image (472).png>)

> [!TIP]
> अगर आपको लगे कि आपका PC चीज़ें capture नहीं कर रहा है, तो OpenGL को बंद करने और sample rate कम करने की कोशिश करें।

### Uses

- किसी signal को कुछ समय तक **capture करके उसका analysis** करने के लिए, ज़रूरत के अनुसार "Push to capture" button दबाकर रखें।

![Basic Config - Uses: किसी signal को capture करके उसका analysis करने के लिए, ज़रूरत के अनुसार "Push to capture" button दबाकर रखें](<../../images/image (960).png>)

- SigDigger का **Tuner** बेहतर signals **capture करने** में मदद करता है (लेकिन signal को खराब भी कर सकता है)। बेहतर होगा कि 0 से शुरू करें और इसे **तब तक बढ़ाते रहें जब तक** इससे आने वाला **noise**, आपको चाहिए उस **signal के improvement** से **ज़्यादा** न हो जाए।

![SigDigger tuner control को captured radio signal बेहतर करने के लिए समायोजित किया गया है](<../../images/image (1099).png>)

### Synchronize with radio channel

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) में जिस channel को सुनना चाहते हैं, उसके साथ synchronize करें। "Baseband audio preview" विकल्प कॉन्फ़िगर करें, भेजी जा रही सारी जानकारी पाने के लिए bandwidth सेट करें, और फिर Tuner को उस स्तर पर सेट करें जिसके बाद noise तेज़ी से बढ़ना शुरू होता है:<sup>[[1]](#references)</sup>

![SigDigger में synchronized radio channel, Baseband audio preview और bandwidth कॉन्फ़िगर किए गए हैं](<../../images/image (585).png>)

## Interesting tricks

- जब कोई device जानकारी के bursts भेजता है, तो आम तौर पर **पहला हिस्सा preamble होता है**। इसलिए, अगर आपको उसमें जानकारी **न मिले** या वहाँ कुछ errors हों, तो **चिंता करने की ज़रूरत नहीं** है।
- जानकारी वाले frames में, आम तौर पर **अलग-अलग frames एक-दूसरे के साथ अच्छी तरह aligned दिखने चाहिए**:

![Synchronize with radio channel - Interesting tricks: जानकारी वाले frames में, आम तौर पर अलग-अलग frames एक-दूसरे के साथ अच्छी तरह aligned दिखने चाहिए](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: जानकारी वाले frames में, आम तौर पर अलग-अलग frames एक-दूसरे के साथ अच्छी तरह aligned दिखने चाहिए](<../../images/image (597).png>)

- **Level transitions वापस पाने के बाद, आपको उन्हें decode करना पड़ सकता है।** Manchester encoding में, transition की एक दिशा `0` और विपरीत दिशा `1` दर्शाती है; सही polarity इस्तेमाल किए जा रहे convention पर निर्भर करती है।
- Payload में Manchester encoding इस्तेमाल होने के बावजूद, preamble में एक ही sampled level की लगातार run हो सकती है। इसलिए decoding से पहले frame boundary पहचानें।

### Uncovering modulation type with IQ

Signals में जानकारी store करने के 3 तरीके हैं: **amplitude**, **frequency** या **phase** को modulate करके।\
किसी signal की जाँच करते समय यह पता लगाने के अलग-अलग तरीके हैं कि जानकारी store करने के लिए इनमें से किसका इस्तेमाल हो रहा है (नीचे और तरीके दिए गए हैं), लेकिन IQ graph देखना एक अच्छा तरीका है।

![यह पहचानने के लिए इस्तेमाल किया गया SigDigger IQ graph कि signal में amplitude, frequency या phase modulation है](<../../images/image (788).png>)

- **AM पहचानना**: अगर IQ graph में, उदाहरण के लिए, **2 circles** दिखें (संभवतः एक 0 पर और दूसरा अलग amplitude पर), तो यह AM signal हो सकता है। ऐसा इसलिए है क्योंकि IQ graph में 0 और circle के बीच की दूरी signal का amplitude होती है, इसलिए अलग-अलग इस्तेमाल किए गए amplitudes को देखना आसान होता है।
- **PM पहचानना**: पिछली image की तरह, अगर आपको एक-दूसरे से असंबंधित छोटे circles दिखें, तो संभवतः phase modulation इस्तेमाल किया गया है। IQ graph में point और 0,0 के बीच का angle signal का phase होता है, जिसका मतलब है कि 4 अलग-अलग phases इस्तेमाल किए गए हैं।
  - ध्यान दें कि अगर जानकारी इस बात में छिपी है कि phase बदला है, न कि phase खुद क्या है, तो आपको अलग-अलग phases स्पष्ट रूप से अलग नहीं दिखेंगे।
- **FM पहचानना**: IQ में frequencies पहचानने के लिए कोई field नहीं होता (centre से दूरी amplitude है और angle phase)।\
  इसलिए, FM पहचानने के लिए इस graph में आपको **मूल रूप से सिर्फ़ एक circle दिखना चाहिए**।\
  इसके अलावा, frequency offset से IQ circle के चारों ओर rotation rate बदल जाता है। इसलिए SigDigger में rotation की speed या direction में बदलाव FM का संकेत हो सकता है।

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

[**SigDigger**](https://github.com/BatchDrake/SigDigger) से AM data की जाँच करते समय, signal का **envelope** amplitude के अलग-अलग स्तर दिखा सकता है। इस sample signal में जानकारी amplitude-modulated pulses के रूप में भेजी जाती है; एक pulse इस तरह दिखती है:<sup>[[1]](#references)</sup>

![SigDigger AM signal envelope में pulse के स्पष्ट amplitude levels दिखाए गए हैं](<../../images/image (590).png>)

और waveform के साथ symbol का एक हिस्सा इस तरह दिखता है:

![Uncovering AM - Checking the envelope: waveform के साथ symbol का एक हिस्सा इस तरह दिखता है](<../../images/image (734).png>)

#### Checking the Histogram

आप उस पूरे signal को **select** कर सकते हैं जिसमें जानकारी मौजूद है, **Amplitude** mode और **Selection** चुन सकते हैं, फिर **Histogram** पर click कर सकते हैं। आप देख सकते हैं कि सिर्फ़ 2 स्पष्ट levels मौजूद हैं।

![SigDigger amplitude histogram में चुने गए AM signal के लिए दो स्पष्ट levels दिखाए गए हैं](<../../images/image (264).png>)

उदाहरण के लिए, अगर इस AM signal में Amplitude की जगह Frequency चुनते हैं, तो आपको सिर्फ़ 1 frequency मिलेगी (frequency में modulate की गई जानकारी के लिए सिर्फ़ 1 freq का इस्तेमाल होना संभव नहीं है)।

![AM signal के लिए SigDigger frequency histogram में एक frequency दिख रही है](<../../images/image (732).png>)

अगर आपको बहुत सारी frequencies दिखें, तो संभवतः यह FM नहीं होगा; channel की वजह से ही signal frequency बदली होगी।

#### With IQ

इस उदाहरण में आप देख सकते हैं कि **एक बड़ा circle** है, लेकिन **centre में बहुत सारे points भी हैं**।

![Checking the Histogram - With IQ: इस उदाहरण में एक बड़ा circle और centre में बहुत सारे points दिखाए गए हैं](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

सबसे छोटा ऐसा interval चुनें जिसमें स्पष्ट रूप से एक symbol हो और **Selection freq** देखें। इस उदाहरण में यह 1.013 kHz है, यानी लगभग 1 kHz।

![Get Symbol Rate - With one symbol: सबसे छोटा ऐसा interval चुनें जिसमें स्पष्ट रूप से एक symbol हो और "Selection freq" देखें। इस उदाहरण में यह 1.013 kHz, यानी लगभग 1 kHz होगा।](<../../images/image (78).png>)

#### With a group of symbols

आप चुने जाने वाले symbols की संख्या भी बता सकते हैं; SigDigger 1 symbol की frequency calculate कर देगा (संभवतः जितने ज़्यादा symbols चुने जाएँगे, परिणाम उतना बेहतर होगा)। इस उदाहरण में मैंने 10 symbols चुने और "Selection freq" 1.004 Khz है:

![दस symbols के चुने हुए समूह का इस्तेमाल करके SigDigger द्वारा symbol-rate की गणना](<../../images/image (1008).png>)

### Get Bits

AM की पहचान करने और **symbol rate** का अनुमान लगाने के बाद, signal region चुनें, amplitude sampling और decision levels कॉन्फ़िगर करें, **Gardner clock recovery** चुनें और **Sample** दबाएँ:

![SigDigger Get Bits panel में AM sampling, symbol rate और Gardner clock recovery कॉन्फ़िगर किए गए हैं](<../../images/image (965).png>)

- **Sync to selection intervals** का मतलब है कि अगर आपने पहले symbol rate पता करने के लिए intervals चुने थे, तो वही symbol rate इस्तेमाल होगी।
- **Manual** का मतलब है कि बताई गई symbol rate इस्तेमाल की जाएगी।
- **Fixed interval selection** में आप चुने जाने वाले intervals की संख्या बताते हैं और इससे symbol rate calculate की जाती है।
- **Gardner clock recovery** एक उपयोगी default है, लेकिन इसके लिए भी लगभग सही symbol rate चाहिए।

Sample दबाने पर यह दिखाई देता है:

![With a group of symbols - Get Bits: Sample दबाने पर यह दिखाई देता है](<../../images/image (644).png>)

अब, SigDigger को यह समझाने के लिए कि जानकारी रखने वाले level की **range कहाँ है**, **lower level** पर click करें और click दबाए रखते हुए सबसे ऊँचे level तक जाएँ:

![SigDigger में lower amplitude level से upper level तक level-range चुनी जा रही है](<../../images/image (439).png>)

उदाहरण के लिए, अगर amplitude के **4 अलग-अलग levels** होते, तो आपको **Bits per symbol को 2** पर कॉन्फ़िगर करना पड़ता और सबसे छोटे से सबसे बड़े level तक select करना पड़ता।

अंत में, **Zoom बढ़ाकर** और **Row size बदलकर**, आप bits देख सकते हैं (सारे bits पाने के लिए आप सबको select करके copy कर सकते हैं):

![With a group of symbols - Get Bits: अंत में Zoom बढ़ाकर और Row size बदलकर bits देखे जा सकते हैं (सारे bits पाने के लिए सबको select करके copy कर सकते हैं)](<../../images/image (276).png>)

अगर signal में प्रति symbol 1 से ज़्यादा bit हो (उदाहरण के लिए 2), तो SigDigger को **यह पता नहीं चल सकता कि कौन-सा symbol** 00, 01, 10 या 11 है। इसलिए हर symbol दिखाने के लिए यह अलग-अलग **grey scales** इस्तेमाल करेगा (और bits copy करने पर यह **0 से 3 तक के numbers** इस्तेमाल करेगा, जिन्हें आपको खुद process करना होगा)।

**Manchester** जैसे line encodings के लिए, इस्तेमाल किए गए protocol convention के अनुसार हर मान्य transition pair (`01` या `10`) को data bit में बदलें।

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

FM में modulate की गई जानकारी भेजने वाले signal का उदाहरण:

![Uncovering FM - Checking the frequencies and waveform: FM में modulate की गई जानकारी भेजने वाले signal का उदाहरण](<../../images/image (725).png>)

Spectrum में **दो frequencies** स्पष्ट रूप से दिखती हैं, हालाँकि time-domain waveform में उन्हें अलग पहचानना मुश्किल हो सकता है:

![SigDigger FM waveform जिसमें दो frequencies को सीधे अलग पहचानना मुश्किल है](<../../images/image (717).png>)

ऐसा इसलिए होता है क्योंकि capture का centre दोनों frequencies के बीच में होता है, इसलिए उनके frequency offsets लगभग एक-दूसरे के विपरीत होते हैं:

![SigDigger FM capture में दो frequencies लगभग एक-दूसरे के विपरीत दिखाई गई हैं](<../../images/image (942).png>)

अगर synchronized frequency, एक frequency के **ज़्यादा करीब** हो और दूसरी के नहीं, तो आप 2 अलग-अलग frequencies को आसानी से देख सकते हैं:

![Uncovering FM - Checking the frequencies and waveform: अगर synchronized frequency एक frequency के ज़्यादा करीब हो और दूसरी के नहीं, तो आप 2 अलग-अलग frequencies को आसानी से देख सकते हैं](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: अगर synchronized frequency एक frequency के ज़्यादा करीब हो और दूसरी के नहीं, तो आप 2 अलग-अलग frequencies को आसानी से देख सकते हैं](<../../images/image (488).png>)

#### Checking the histogram

जानकारी वाले signal का frequency histogram देखने पर, आप आसानी से 2 अलग-अलग signals देख सकते हैं:

![Checking the frequencies and waveform - Checking the histogram: जानकारी वाले signal का frequency histogram देखने पर, आप आसानी से 2 अलग-अलग signals देख सकते हैं](<../../images/image (871).png>)

इस स्थिति में, अगर आप **Amplitude histogram** देखते हैं, तो आपको **सिर्फ़ एक amplitude** मिलेगा, इसलिए यह **AM नहीं हो सकता** (अगर आपको बहुत सारे amplitudes मिलें, तो हो सकता है कि channel से गुज़रते हुए signal की power कम हुई हो):

![FM signal के लिए SigDigger amplitude histogram में एक ही amplitude level दिखाया गया है](<../../images/image (817).png>)

और यह phase histogram होगा (जिससे स्पष्ट हो जाता है कि signal phase में modulate नहीं किया गया है):

![Checking the frequencies and waveform - Checking the histogram: यह phase histogram है, जिससे स्पष्ट हो जाता है कि signal phase में modulate नहीं किया गया है](<../../images/image (996).png>)

#### With IQ

IQ में frequencies पहचानने के लिए कोई field नहीं होता (centre से दूरी amplitude है और angle phase)।\
इसलिए, FM पहचानने के लिए इस graph में आपको **मूल रूप से सिर्फ़ एक circle दिखना चाहिए**।\
इसके अलावा, frequency offset से IQ circle के चारों ओर rotation rate बदल जाता है। इसलिए SigDigger में rotation की speed या direction में बदलाव FM का संकेत हो सकता है:

![SigDigger IQ graph में circle के चारों ओर acceleration में बदलाव को FM के रूप में दिखाया गया है](<../../images/image (81).png>)

### Get Symbol Rate

Symbols रखने वाली frequencies पता करने के बाद, symbol rate जानने के लिए आप **AM example में इस्तेमाल की गई वही technique** इस्तेमाल कर सकते हैं।

### Get Bits

जब आपको पता चल जाए कि **signal frequency में modulate किया गया है** और उसका **symbol rate** मिल जाए, तो bits पाने के लिए आप **AM example में इस्तेमाल की गई वही technique** इस्तेमाल कर सकते हैं।

## References

- [1] [SigDigger - GNU/Linux और macOS के लिए मुफ़्त digital signal analyzer](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
