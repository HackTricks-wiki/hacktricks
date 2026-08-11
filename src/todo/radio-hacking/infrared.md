# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Infrared कैसे काम करता है <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrared light मनुष्यों को दिखाई नहीं देती**। IR wavelength **0.7 से 1000 microns** तक होती है। घरेलू remotes data transmission के लिए IR signal का उपयोग करते हैं और 0.75..1.4 microns की wavelength range में काम करते हैं। Remote में मौजूद microcontroller एक infrared LED को specific frequency पर blink कराता है, जिससे digital signal IR signal में बदल जाता है।

IR signals प्राप्त करने के लिए **photoreceiver** का उपयोग किया जाता है। यह **IR light को voltage pulses में बदलता है**, जो पहले से ही **digital signals** होते हैं। आमतौर पर receiver के अंदर एक **dark light filter** होता है, जो **केवल desired wavelength को pass होने देता है** और noise को काट देता है।<sup>[[1]](#references)</sup>

### IR Protocols की विविधता <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols 3 factors में अलग होते हैं:<sup>[[1]](#references)</sup>

- bit encoding
- data structure
- carrier frequency — अक्सर 36..38 kHz range में

#### Bit encoding के तरीके <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits को pulses के बीच के space की duration को modulate करके encode किया जाता है। Pulse की width स्वयं constant रहती है।

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits को pulse की width को modulate करके encode किया जाता है। Pulse burst के बाद space की width constant रहती है।

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

इसे Manchester encoding के नाम से भी जाना जाता है। Logical value pulse burst और space के बीच transition की polarity से निर्धारित होती है। "Space to pulse burst" logic "0" को दर्शाता है, जबकि "pulse burst to space" logic "1" को दर्शाता है।

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. पिछले तरीकों और अन्य exotics का combination**

> [!TIP]
> ऐसे IR protocols मौजूद हैं जो कई प्रकार के devices के लिए **universal बनने का प्रयास कर रहे हैं**। सबसे प्रसिद्ध RC5 और NEC हैं। दुर्भाग्य से, सबसे प्रसिद्ध होने का **अर्थ सबसे common होना नहीं है**। मेरे environment में मुझे केवल दो NEC remotes मिले और कोई RC5 remote नहीं मिला।
>
> Manufacturers अपने स्वयं के unique IR protocols का उपयोग करना पसंद करते हैं, यहां तक कि devices की एक ही range (जैसे TV-boxes) के अंदर भी। इसलिए अलग-अलग companies के remotes और कभी-कभी एक ही company के अलग-अलग models के remotes, एक ही प्रकार के अन्य devices के साथ काम नहीं कर पाते।

### IR signal की जांच

Remote का IR signal कैसा दिखता है, यह देखने का सबसे reliable तरीका oscilloscope का उपयोग करना है। यह received signal को demodulate या invert नहीं करता, बल्कि उसे "as is" प्रदर्शित करता है। यह testing और debugging के लिए उपयोगी है। मैं NEC IR protocol के उदाहरण से expected signal दिखाऊंगा।<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

आमतौर पर encoded packet की शुरुआत में एक preamble होता है। इससे receiver gain level और background निर्धारित कर सकता है। कुछ protocols में preamble नहीं होता, जैसे Sharp।

इसके बाद data transmit किया जाता है। Structure, preamble और bit encoding method specific protocol द्वारा निर्धारित होते हैं।

**NEC IR protocol** में एक short command और एक repeat code होता है, जो button दबाए रखने के दौरान भेजा जाता है। Command और repeat code दोनों की शुरुआत में एक ही preamble होता है।

NEC **command**, preamble के अतिरिक्त, एक address byte और command-number byte से बना होता है, जिनसे device समझता है कि क्या perform करना है। Transmission की integrity जांचने के लिए address और command-number bytes को inverse values के साथ duplicate किया जाता है। Command के अंत में एक additional stop bit होता है।

**repeat code** में preamble के बाद एक "1" होता है, जो stop bit है।

**logic "0" और "1"** के लिए NEC Pulse Distance Encoding का उपयोग करता है: पहले एक pulse burst transmit किया जाता है, जिसके बाद एक pause होती है; उसकी length bit की value निर्धारित करती है।

### Air Conditioners

अन्य remotes के विपरीत, **air conditioners केवल दबाए गए button का code transmit नहीं करते**। Button दबाए जाने पर वे **सारी information भी transmit करते हैं**, ताकि **air conditioned machine और remote synchronised रहें**।\
इससे ऐसी स्थिति से बचा जाता है जिसमें एक remote से 20ºC पर set machine को 21ºC किया जाए, और फिर दूसरे remote से, जिसमें temperature अभी भी 20ºC हो, temperature को और बढ़ाया जाए; वह इसे 21ºC तक "बढ़ाएगा" (22ºC तक नहीं, क्योंकि वह समझता है कि temperature 21ºC है)।<sup>[[1]](#references)</sup>

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

आप Flipper Zero से Infrared पर attack कर सकते हैं:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

हाल के academic work (EvilScreen, 2022) ने प्रदर्शित किया कि **Infrared को Bluetooth या Wi-Fi के साथ combine करने वाले multi-channel remotes का उपयोग करके आधुनिक smart-TVs को पूरी तरह hijack किया जा सकता है**। यह attack high-privilege IR service codes को authenticated Bluetooth packets के साथ chain करता है, channel-isolation को bypass करता है और physical access के बिना arbitrary app launches, microphone activation या factory-reset की अनुमति देता है। अलग-अलग vendors के आठ mainstream TVs — जिनमें ISO/IEC 27001 compliance का दावा करने वाला एक Samsung model भी शामिल था — vulnerable पाए गए। Mitigation के लिए vendor firmware fixes या unused IR receivers को पूरी तरह disable करना आवश्यक है।<sup>[[2]](#references)</sup>

### IR LEDs के माध्यम से Air-Gapped Data Exfiltration (aIR-Jumper family)

Security cameras में आमतौर पर **night-vision IR LEDs** शामिल होती हैं। aIR-Jumper prototype ने दिखाया कि इन LEDs को नियंत्रित करने वाला malware **windows के माध्यम से secrets को external camera तक exfiltrate** कर सकता है, जिसकी speed **प्रत्येक surveillance camera के लिए 20 bit/s** और दूरी दसियों metres तक हो सकती है। Reverse direction में researchers ने सैकड़ों metres से kilometres की दूरी तक **100 bit/s से अधिक** की speed पर infiltration प्रदर्शित की।<sup>[[3]](#references)</sup> चूंकि यह light visible spectrum से बाहर होती है, operators को इसका पता नहीं चल सकता। Countermeasures में शामिल हैं:

* Sensitive areas में IR LEDs को physically shield या remove करें
* Camera LED duty-cycle और firmware integrity को monitor करें
* Windows और surveillance cameras पर IR-cut filters deploy करें

एक attacker strong IR projectors का उपयोग करके insecure cameras में data flash कर network में commands **infiltrate** कर सकता है।

### Flipper Zero 1.0 के साथ Long-Range Brute-Force और Extended Protocols

Firmware 1.0 (September 2024) ने universal-remotes library का विस्तार किया और microSD से infrared asset files की dynamic loading जोड़ी।<sup>[[4]](#references)</sup> इसके learning और universal-remote functions nearby TVs और air conditioners के विरुद्ध known commands को replay या try कर सकते हैं। Range emitter, optics, ambient light और receiver पर बहुत अधिक निर्भर करती है; external IR hardware इसे बढ़ा सकता है, लेकिन किसी fixed distance को assume नहीं करना चाहिए।

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay और dictionary-bruteforce modes वाला portable transceiver (ऊपर देखें)।
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – सस्ता DIY analyser/transmitter। इसे `Arduino-IRremote` library के साथ combine करें (v4.x >40 protocols को support करता है)।
* **Logic analysers** (Saleae/FX2) – protocol अज्ञात होने पर raw timings capture करने के लिए।
* **IR-blaster वाले smartphones** (जैसे Xiaomi) – quick field test के लिए, लेकिन limited range के साथ।

### Software

* **`Arduino-IRremote`** – actively maintained C++ library:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI decoders जो raw captures import करते हैं, protocol को auto-identify करते हैं और Pronto/Arduino code generate करते हैं।
* **LIRC / ir-keytable (Linux)** – command line से IR receive और inject करने के लिए:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Public spaces में deployed devices पर, आवश्यकता न होने पर IR receivers को disable या cover करें।
* Smart-TVs और remotes के बीच *pairing* या cryptographic checks लागू करें; privileged “service” codes को isolate करें।
* Classified areas के आसपास IR-cut filters या continuous-wave detectors deploy करें, ताकि optical covert channels बाधित हों।
* Controllable IR LEDs वाले cameras/IoT appliances की firmware integrity monitor करें।

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero Blog - Firmware 1.0 Released](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - usage and protocol documentation](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
