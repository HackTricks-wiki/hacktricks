# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Infrared कैसे काम करता है <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrared light मनुष्यों को दिखाई नहीं देती**। IR wavelength **0.7 से 1000 microns** तक होती है। घरेलू remotes data transmission के लिए IR signal का उपयोग करते हैं और 0.75..1.4 microns की wavelength range में काम करते हैं। Remote में मौजूद microcontroller एक infrared LED को एक विशिष्ट frequency पर blink कराता है, जिससे digital signal IR signal में बदल जाता है।

IR signals प्राप्त करने के लिए **photoreceiver** का उपयोग किया जाता है। यह **IR light को voltage pulses में बदलता है**, जो पहले से ही **digital signals** होते हैं। आमतौर पर receiver के अंदर **dark light filter** होता है, जो **केवल वांछित wavelength को गुजरने देता है** और noise को हटा देता है।<sup>[[1]](#references)</sup>

### IR Protocols की विविधता <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols 3 factors में अलग होते हैं:<sup>[[1]](#references)</sup>

- bit encoding
- data structure
- carrier frequency — अक्सर 36..38 kHz की range में

#### Bit encoding के तरीके <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits को pulses के बीच के space की duration को modulate करके encode किया जाता है। Pulse की width स्वयं constant रहती है।

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits को pulse की width को modulate करके encode किया जाता है। Pulse burst के बाद space की width constant रहती है।

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

इसे Manchester encoding के नाम से भी जाना जाता है। Logical value, pulse burst और space के बीच transition की polarity से निर्धारित होती है। "Space to pulse burst" logic "0" को दर्शाता है, जबकि "pulse burst to space" logic "1" को दर्शाता है।

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. पिछले तरीकों और अन्य exotics का combination**

> [!TIP]
> ऐसे IR protocols मौजूद हैं जो कई प्रकार के devices के लिए **universal बनने का प्रयास कर रहे हैं**। सबसे प्रसिद्ध RC5 और NEC हैं। दुर्भाग्य से, सबसे प्रसिद्ध होने का **अर्थ सबसे common होना नहीं है**। मेरे environment में मुझे केवल दो NEC remotes मिले और कोई RC5 remote नहीं मिला।
>
> Manufacturers अपने स्वयं के unique IR protocols का उपयोग करना पसंद करते हैं, यहाँ तक कि devices की एक ही range (उदाहरण के लिए, TV-boxes) के भीतर भी। इसलिए अलग-अलग companies के remotes और कभी-कभी एक ही company के अलग-अलग models के remotes, उसी प्रकार के अन्य devices के साथ काम नहीं कर पाते।

### IR signal की Exploring

Remote का IR signal कैसा दिखाई देता है, यह देखने का सबसे reliable तरीका oscilloscope का उपयोग करना है। यह प्राप्त signal को demodulate या invert नहीं करता, बल्कि उसे केवल "as is" प्रदर्शित करता है। यह testing और debugging के लिए उपयोगी है। मैं NEC IR protocol के example पर expected signal दिखाऊँगा।<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

आमतौर पर encoded packet की शुरुआत में एक preamble होता है। इससे receiver gain और background का level निर्धारित कर पाता है। कुछ protocols में preamble नहीं होता, उदाहरण के लिए, Sharp।

इसके बाद data transmit किया जाता है। Structure, preamble और bit encoding method specific protocol द्वारा निर्धारित होते हैं।

**NEC IR protocol** में एक short command और एक repeat code होता है, जो button दबाए रखने के दौरान भेजा जाता है। Command और repeat code, दोनों की शुरुआत में एक ही preamble होता है।

NEC **command**, preamble के अतिरिक्त, एक address byte और एक command-number byte से बना होता है, जिनके द्वारा device समझता है कि क्या perform करना है। Transmission की integrity जाँचने के लिए address और command-number bytes को inverse values के साथ duplicate किया जाता है। Command के अंत में एक additional stop bit होता है।

**repeat code** में preamble के बाद एक "1" होता है, जो stop bit है।

**logic "0" और "1"** के लिए NEC Pulse Distance Encoding का उपयोग करता है: पहले एक pulse burst transmit किया जाता है, जिसके बाद pause होता है; इसकी length bit की value निर्धारित करती है।

### Air Conditioners

अन्य remotes के विपरीत, **air conditioners केवल दबाए गए button का code transmit नहीं करते**। वे button दबाए जाने पर **सारी information भी transmit करते हैं**, ताकि **air conditioned machine और remote synchronised रहें**।\
इससे यह समस्या नहीं होगी कि एक remote से 20ºC पर set machine को 21ºC किया जाए और फिर दूसरे remote से, जिसमें temperature अभी भी 20ºC है, temperature बढ़ाया जाए तो वह इसे 21ºC "बढ़ा" दे (यह सोचकर कि temperature 21ºC है), न कि 22ºC।<sup>[[1]](#references)</sup>

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

आप Infrared पर Flipper Zero से attack कर सकते हैं:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

हाल के academic work (EvilScreen, 2022) ने प्रदर्शित किया कि **Infrared को Bluetooth या Wi-Fi के साथ combine करने वाले multi-channel remotes का उपयोग modern smart-TVs को पूरी तरह hijack करने के लिए किया जा सकता है**। यह attack high-privilege IR service codes को authenticated Bluetooth packets के साथ chain करता है, channel-isolation को bypass करता है और physical access के बिना arbitrary app launches, microphone activation या factory-reset की अनुमति देता है। अलग-अलग vendors के आठ mainstream TVs — जिसमें ISO/IEC 27001 compliance का दावा करने वाला एक Samsung model भी शामिल था — vulnerable पाए गए। Mitigation के लिए vendor firmware fixes या unused IR receivers को पूरी तरह disable करना आवश्यक है।<sup>[[2]](#references)</sup>

### IR LEDs के माध्यम से Air-Gapped Data Exfiltration (aIR-Jumper family)

Security cameras, routers या malicious USB sticks में अक्सर **night-vision IR LEDs** शामिल होते हैं। Research से पता चलता है कि malware इन LEDs को modulate करके (<10–20 kbit/s with simple OOK) **दीवारों और windows के पार secrets exfiltrate** कर सकता है, जहाँ external camera को कुछ tens of metres की दूरी पर रखा जाता है।<sup>[[3]](#references)</sup> चूँकि यह light visible spectrum से बाहर होती है, operators को इसका अक्सर पता नहीं चलता। Counter-measures:

* Sensitive areas में IR LEDs को physically shield या remove करें
* Camera LED duty-cycle और firmware integrity को monitor करें
* Windows और surveillance cameras पर IR-cut filters deploy करें

Attacker strong IR projectors का उपयोग करके insecure cameras में data flash कर, network में commands **infiltrate** भी कर सकता है।

### Flipper Zero 1.0 के साथ Long-Range Brute-Force & Extended Protocols

Firmware 1.0 (September 2024) में **dozens of extra IR protocols और optional external amplifier modules** जोड़े गए। Universal-remote brute-force mode के साथ मिलकर, Flipper high-power diode का उपयोग करके 30 m तक की दूरी से अधिकांश public TVs/ACs को disable या reconfigure कर सकता है।

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay और dictionary-bruteforce modes वाला portable transceiver (ऊपर देखें)।
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – सस्ता DIY analyser/transmitter। इसे `Arduino-IRremote` library के साथ combine करें (v4.x >40 protocols को support करता है)।
* **Logic analysers** (Saleae/FX2) – protocol unknown होने पर raw timings capture करने के लिए।
* **IR-blaster वाले Smartphones** (जैसे, Xiaomi) – quick field test के लिए, लेकिन range सीमित होती है।

### Software

* **`Arduino-IRremote`** – actively-maintained C++ library:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI decoders जो raw captures import करके protocol को auto-identify करते हैं और Pronto/Arduino code generate करते हैं।
* **LIRC / ir-keytable (Linux)** – command line से IR receive और inject करने के लिए:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* जब आवश्यकता न हो, public spaces में deployed devices के IR receivers को disable या cover करें।
* Smart-TVs और remotes के बीच *pairing* या cryptographic checks लागू करें; privileged “service” codes को isolate करें।
* Classified areas के आसपास IR-cut filters या continuous-wave detectors deploy करें, ताकि optical covert channels बाधित हो सकें।
* Controllable IR LEDs वाले cameras/IoT appliances की firmware integrity monitor करें।

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
