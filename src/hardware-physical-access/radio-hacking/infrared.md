# इन्फ्रारेड

{{#include ../../banners/hacktricks-training.md}}

## इन्फ्रारेड पोर्ट कैसे काम करता है <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**इन्फ्रारेड प्रकाश मनुष्यों को दिखाई नहीं देता**। IR की तरंगदैर्ध्य **0.7 से 1000 माइक्रॉन** तक होती है। घरेलू रिमोट डेटा ट्रांसमिशन के लिए IR सिग्नल का उपयोग करते हैं और 0.75..1.4 माइक्रॉन की तरंगदैर्ध्य सीमा में काम करते हैं। रिमोट का माइक्रोकंट्रोलर एक इन्फ्रारेड LED को विशिष्ट आवृत्ति पर चमकाता है, जिससे डिजिटल सिग्नल IR सिग्नल में बदल जाता है।

IR सिग्नल प्राप्त करने के लिए **photoreceiver** का उपयोग किया जाता है। यह **IR प्रकाश को वोल्टेज पल्स में बदलता है**, जो पहले से ही **डिजिटल सिग्नल** होते हैं। आमतौर पर, रिसीवर के अंदर **डार्क लाइट फ़िल्टर** होता है, जो **केवल वांछित तरंगदैर्ध्य को आने देता है** और शोर को रोकता है।<sup>[[1]](#references)</sup>

### IR प्रोटोकॉल के प्रकार <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR प्रोटोकॉल 3 कारकों में अलग-अलग होते हैं:<sup>[[1]](#references)</sup>

- बिट एन्कोडिंग
- डेटा संरचना
- कैरियर फ़्रीक्वेंसी — अक्सर 36..38 kHz की सीमा में

#### बिट एन्कोडिंग के तरीके <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

बिट्स को पल्स के बीच के अंतराल की अवधि में बदलाव करके एन्कोड किया जाता है। पल्स की चौड़ाई स्थिर रहती है।

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

बिट्स को पल्स की चौड़ाई में बदलाव करके एन्कोड किया जाता है। पल्स बर्स्ट के बाद आने वाले अंतराल की चौड़ाई स्थिर रहती है।

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

इसे Manchester encoding भी कहा जाता है। लॉजिकल मान पल्स बर्स्ट और अंतराल के बीच ट्रांज़िशन की ध्रुवता से तय होता है। "अंतराल से पल्स बर्स्ट" का मतलब लॉजिक "0" है, जबकि "पल्स बर्स्ट से अंतराल" का मतलब लॉजिक "1" है।

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. पिछले तरीकों के संयोजन और अन्य असामान्य तरीके**

> [!TIP]
> कुछ IR प्रोटोकॉल कई प्रकार के डिवाइसों के लिए **यूनिवर्सल बनने की कोशिश** करते हैं। सबसे प्रसिद्ध RC5 और NEC हैं। दुर्भाग्य से, सबसे प्रसिद्ध होने का **मतलब सबसे आम होना नहीं है**। मेरे अनुभव में, मुझे केवल दो NEC रिमोट मिले और कोई RC5 रिमोट नहीं मिला।
>
> निर्माता अपने अनूठे IR प्रोटोकॉल इस्तेमाल करना पसंद करते हैं, यहाँ तक कि एक ही श्रेणी के डिवाइसों (उदाहरण के लिए, TV-boxes) में भी। इसलिए, अलग-अलग कंपनियों के रिमोट और कभी-कभी एक ही कंपनी के अलग-अलग मॉडल के रिमोट, उसी प्रकार के अन्य डिवाइसों के साथ काम नहीं कर पाते।

### IR सिग्नल की जाँच

रिमोट का IR सिग्नल कैसा दिखता है, यह देखने का सबसे विश्वसनीय तरीका ऑसिलोस्कोप का उपयोग करना है। यह प्राप्त सिग्नल को demodulate या invert नहीं करता; इसे बस "जैसा है" वैसा ही दिखाता है। यह परीक्षण और debugging के लिए उपयोगी है। मैं NEC IR protocol के उदाहरण से अपेक्षित सिग्नल दिखाऊँगा।<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

आमतौर पर, एन्कोड किए गए पैकेट की शुरुआत में एक preamble होता है। इससे रिसीवर gain और background का स्तर निर्धारित कर पाता है। कुछ प्रोटोकॉल में preamble नहीं होता, जैसे Sharp।

इसके बाद डेटा ट्रांसमिट किया जाता है। संरचना, preamble और बिट एन्कोडिंग का तरीका विशिष्ट प्रोटोकॉल से तय होता है।

**NEC IR protocol** में एक छोटा command और एक repeat code होता है, जो बटन दबाए रहने के दौरान भेजा जाता है। command और repeat code, दोनों की शुरुआत में एक ही preamble होता है।

**NEC command** में preamble के अलावा, एक address byte और एक command-number byte होता है, जिससे डिवाइस समझता है कि क्या करना है। ट्रांसमिशन की अखंडता जाँचने के लिए address और command-number bytes को उलटे मानों के साथ दोहराया जाता है। command के अंत में एक अतिरिक्त stop bit होता है।

**Repeat code** में preamble के बाद "1" होता है, जो stop bit है।

**लॉजिक "0" और "1"** के लिए NEC, Pulse Distance Encoding का उपयोग करता है: पहले एक पल्स बर्स्ट ट्रांसमिट होता है, जिसके बाद एक विराम आता है। विराम की लंबाई बिट का मान निर्धारित करती है।

### एयर कंडीशनर

दूसरे रिमोट से अलग, **एयर कंडीशनर केवल दबाए गए बटन का code ट्रांसमिट नहीं करते**। बटन दबाए जाने पर वे **सारी जानकारी भी ट्रांसमिट करते हैं**, ताकि **एयर कंडीशनर और रिमोट सिंक्रोनाइज़ रहें**।\
इससे यह स्थिति नहीं होगी कि 20ºC पर सेट मशीन को एक रिमोट से 21ºC किया जाए और फिर दूसरे रिमोट का उपयोग करके, जिसमें तापमान अब भी 20ºC हो, तापमान और बढ़ाया जाए; ऐसे में तापमान 22ºC के बजाय "बढ़कर" 21ºC हो जाएगा, क्योंकि रिमोट उसे 21ºC मान रहा होगा।<sup>[[1]](#references)</sup>

---

## हमले और Offensive Research <a href="#attacks" id="attacks"></a>

आप Flipper Zero से Infrared पर हमला कर सकते हैं:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box पर कब्ज़ा (EvilScreen)

हाल के अकादमिक शोध (EvilScreen, 2022) ने दिखाया कि **Infrared को Bluetooth या Wi-Fi के साथ जोड़ने वाले multi-channel remotes का दुरुपयोग करके आधुनिक smart-TV को पूरी तरह hijack किया जा सकता है**। इस हमले में high-privilege IR service codes को authenticated Bluetooth packets के साथ जोड़ा जाता है, जिससे channel-isolation को bypass करके बिना physical access के मनमाने app लॉन्च किए जा सकते हैं, microphone सक्रिय किया जा सकता है या factory-reset किया जा सकता है। अलग-अलग vendors के आठ प्रमुख TV—जिनमें ISO/IEC 27001 compliance का दावा करने वाला एक Samsung मॉडल भी शामिल था—कमज़ोर पाए गए। इससे बचाव के लिए vendor firmware fixes या अप्रयुक्त IR receivers को पूरी तरह बंद करना आवश्यक है।<sup>[[2]](#references)</sup>

### IR LEDs के ज़रिए Air-Gapped Data Exfiltration (aIR-Jumper परिवार)

सुरक्षा कैमरों में आमतौर पर **night-vision IR LEDs** होते हैं। aIR-Jumper prototype ने दिखाया कि इन LEDs को नियंत्रित करने वाला malware, **खिड़कियों के पार बाहरी कैमरे तक secrets exfiltrate कर सकता है**—दसियों मीटर की दूरी पर प्रत्येक surveillance camera से **20 bit/s तक** की गति से। उलटी दिशा में, शोधकर्ताओं ने सैकड़ों मीटर से लेकर किलोमीटर तक की दूरी पर **100 bit/s से अधिक** की गति से infiltration भी प्रदर्शित की।<sup>[[3]](#references)</sup> चूँकि यह प्रकाश दृश्य स्पेक्ट्रम से बाहर होता है, इसलिए operators इसे शायद देख न पाएँ। बचाव के उपायों में शामिल हैं:

* संवेदनशील क्षेत्रों में IR LEDs को भौतिक रूप से ढकें या हटाएँ
* कैमरे के LED duty-cycle और firmware integrity पर नज़र रखें
* खिड़कियों और surveillance cameras पर IR-cut filters लगाएँ

हमलावर असुरक्षित कैमरों को डेटा वापस भेजकर नेटवर्क में commands **infiltrate** करने के लिए शक्तिशाली IR projectors का भी उपयोग कर सकता है। 

### Flipper Zero 1.0 के साथ Long-Range Brute-Force और Extended Protocols

Firmware 1.0 (सितंबर 2024) ने universal-remotes library का विस्तार किया और microSD से infrared asset files को dynamic रूप से लोड करने की सुविधा जोड़ी।<sup>[[4]](#references)</sup> इसके learning और universal-remote functions आसपास के TV और air conditioner पर ज्ञात commands को replay या आज़मा सकते हैं। रेंज emitter, optics, ambient light और receiver पर बहुत निर्भर करती है; external IR hardware से इसे बढ़ाया जा सकता है, लेकिन किसी निश्चित दूरी को मानकर नहीं चलना चाहिए।

---

## Tooling और व्यावहारिक उदाहरण <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay और dictionary-bruteforce modes वाला portable transceiver (ऊपर देखें)।
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – कम लागत वाला DIY analyser/transmitter। इसे `Arduino-IRremote` library के साथ इस्तेमाल करें (v4.x, 40 से अधिक protocols को support करता है)।
* **Logic analysers** (Saleae/FX2) – जब protocol अज्ञात हो, तब raw timings capture करें।
* **IR-blaster वाले smartphones** (जैसे, Xiaomi) – तुरंत field test करने के लिए उपयोगी, लेकिन इनकी रेंज सीमित होती है।

### Software

* **`Arduino-IRremote`** – सक्रिय रूप से maintain की जाने वाली C++ library:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – GUI decoders जो raw captures import करते हैं और protocol की auto-identification करके Pronto/Arduino code generate करते हैं।
* **LIRC / ir-keytable (Linux)** – command line से IR receive और inject करें:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* सार्वजनिक स्थानों पर लगाए गए उपकरणों के IR रिसीवर, आवश्यकता न होने पर बंद रखें या ढक दें।
* smart-TVs और रिमोट के बीच *pairing* या क्रिप्टोग्राफ़िक जाँच लागू करें; विशेषाधिकार प्राप्त “service” कोड अलग रखें।
* वर्गीकृत क्षेत्रों के आसपास IR-cut फ़िल्टर या continuous-wave डिटेक्टर लगाएँ, ताकि ऑप्टिकल covert channels बाधित हों।
* उन कैमरों/IoT उपकरणों की फ़र्मवेयर अखंडता की निगरानी करें जिनमें नियंत्रित किए जा सकने वाले IR LEDs हों।

## References

- [1] [Flipper Zero इन्फ्रारेड ब्लॉग पोस्ट](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: बहु-चैनल रिमोट कंट्रोल की नकल के ज़रिए Smart TV पर कब्ज़ा (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: सुरक्षा कैमरों और इन्फ्रारेड (IR) के ज़रिए covert Air-Gap Exfiltration/Infiltration (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero ब्लॉग - Firmware 1.0 जारी](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - उपयोग और प्रोटोकॉल दस्तावेज़](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
