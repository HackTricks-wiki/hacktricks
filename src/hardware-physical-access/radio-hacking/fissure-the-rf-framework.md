# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE एक open-source RF और reverse engineering framework है, जिसे सभी कौशल स्तरों के लोगों के लिए बनाया गया है। इसमें signal detection और classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation और AI/ML के लिए hooks शामिल हैं। यह framework software modules, radios, protocols, signal data, scripts, flow graphs, reference material और third-party tools के तेज़ी से एकीकरण को बढ़ावा देने के लिए बनाया गया था। FISSURE एक workflow enabler है, जो software को एक ही जगह रखता है और टीमों को एक ही सिद्ध baseline configuration साझा करते हुए, विशिष्ट Linux distributions पर आसानी से काम शुरू करने देता है।<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE के साथ शामिल framework और tools को RF energy का पता लगाने, signals का वर्णन करने, samples इकट्ठा करने और उनका विश्लेषण करने, transmission या injection techniques विकसित करने, तथा custom payloads या messages बनाने के लिए डिज़ाइन किया गया है। FISSURE पहचान, packet crafting और fuzzing के लिए protocol और signal की जानकारी भी देता है। साथ ही, इसमें traffic simulation और testing के लिए archives और playlists भी हैं।<sup>[[1]](#references)[[2]](#references)</sup>

Python codebase और graphical interface शुरुआती उपयोगकर्ताओं को RF और reverse-engineering tools सीखने में मदद करते हैं। शिक्षक इसमें शामिल lessons का उपयोग कर सकते हैं, जबकि developers और researchers अपने modules और workflows को एकीकृत कर सकते हैं। मौजूदा releases distributed sensor nodes, TAK integration, geolocation workflows और भूमिका-विशिष्ट Apptainer deployments को भी support करते हैं।<sup>[[1]](#references)[[3]](#references)</sup>

**अतिरिक्त जानकारी**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## शुरू करना

**समर्थित**

मौजूदा FISSURE में PyQt5 और GNU Radio 3.8 या 3.10 के साथ सक्रिय development के लिए **`Python3`** branch का उपयोग किया जाता है। पुरानी operating systems और GNU Radio 3.7 की आवश्यकता वाले third-party tools के लिए deprecated **`Python2_maint-3.7`** branch अभी भी उपलब्ध है। पहले इस्तेमाल किए जाने वाले `Python3_maint-3.8` और `Python3_maint-3.10` branch names अब ऐतिहासिक हैं; GNU Radio maintenance का चयन अब `Python3` branch से किया जाता है।<sup>[[1]](#references)[[3]](#references)</sup>

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | समर्थित Linux version का उपयोग करें | उससे मेल खाने वाले version का उपयोग करें |

**प्रगति में (beta)**

ये operating systems अभी beta स्थिति में हैं। इन पर development जारी है और इनमें कई features उपलब्ध नहीं हैं। Installer में शामिल कुछ items मौजूदा programs के साथ conflict कर सकते हैं या स्थिति हटाए जाने तक install होने में विफल हो सकते हैं।

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

कुछ third-party tools हर OS पर काम नहीं करते। Install करने से पहले मौजूदा [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) documentation देखें।<sup>[[3]](#references)</sup>

**Installation**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

submodule चरण FISSURE द्वारा उपयोग किए जाने वाले GNU Radio out-of-tree modules डाउनलोड करता है और उन modules को इंस्टॉल करते समय इसकी आवश्यकता होती है। Installer अपने installation GUIs लॉन्च करने के लिए आवश्यक अनुपलब्ध PyQt dependencies भी इंस्टॉल करेगा।<sup>[[3]](#references)</sup>

इसके बाद, वह विकल्प चुनें जो आपके operating system से सबसे अच्छा मेल खाता हो (यदि आपका OS किसी विकल्प से मेल खाता है, तो उसका अपने-आप पता चल जाना चाहिए)।

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

मौजूदा conflicts से बचने के लिए FISSURE को एक साफ operating system पर इंस्टॉल करने की अनुशंसा की जाती है। FISSURE के विभिन्न tools का उपयोग करते समय errors से बचने के लिए सभी अनुशंसित checkboxes चुनें (Default button)। इंस्टॉलेशन के दौरान कई prompts दिखाई देंगे, जिनमें से अधिकतर elevated permissions और user names के लिए होंगे। यदि किसी item के अंत में "Verify" section है, तो installer उसके बाद दिया गया command चलाएगा और command से errors मिलने या न मिलने के आधार पर checkbox item को हरे या लाल रंग में highlight करेगा। "Verify" section के बिना चुने गए items, इंस्टॉलेशन के बाद काले ही रहेंगे।

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**उपयोग**

एक terminal खोलें और दर्ज करें:

```
fissure
```

FISSURE के उपयोग के बारे में अधिक जानकारी के लिए Help मेनू देखें।

## विवरण

**घटक**

* डैशबोर्ड
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![घटक](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**क्षमताएँ**

| ![Signal Detector आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging आइकन](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**हार्डवेयर**

निम्नलिखित हार्डवेयर का FISSURE में एकीकरण अलग-अलग स्तरों पर है:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## पाठ

FISSURE में विभिन्न तकनीकों और विधियों से परिचित होने के लिए कई उपयोगी मार्गदर्शिकाएँ शामिल हैं। इनमें से कई में FISSURE के साथ एकीकृत विभिन्न टूल इस्तेमाल करने के चरण दिए गए हैं।

* [पाठ 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [पाठ 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [पाठ 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [पाठ 4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [पाठ 5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [पाठ 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [पाठ 7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [पाठ 8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [पाठ 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [पाठ 10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [पाठ 11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [पाठ 12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [पाठ 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [पाठ 14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## रोडमैप

* [ ] और अधिक हार्डवेयर प्रकार, RF प्रोटोकॉल, सिग्नल पैरामीटर और विश्लेषण टूल जोड़ें
* [ ] अधिक ऑपरेटिंग सिस्टम को समर्थन दें
* [ ] FISSURE के इर्द-गिर्द पाठ्यक्रम सामग्री विकसित करें (RF Attacks, Wi-Fi, GNU Radio, PyQt आदि)
* [ ] चुनी जा सकने वाली AI/ML तकनीकों के साथ सिग्नल कंडीशनर, फीचर एक्सट्रैक्टर और सिग्नल क्लासिफायर बनाएँ
* [ ] अज्ञात सिग्नलों से बिटस्ट्रीम बनाने के लिए रिकर्सिव डिमॉड्यूलेशन तंत्र लागू करें
* [ ] मुख्य FISSURE घटकों को सामान्य सेंसर नोड परिनियोजन योजना में बदलें

## योगदान

FISSURE को बेहतर बनाने के सुझावों का हार्दिक स्वागत है। यदि आपके पास नीचे दिए गए विषयों के बारे में कोई विचार हों, तो [Discussions](https://github.com/ainfosec/FISSURE/discussions) पेज या Discord Server पर टिप्पणी करें:

* नई सुविधाओं के सुझाव और डिज़ाइन में बदलाव
* इंस्टॉलेशन चरणों वाले सॉफ़्टवेयर टूल
* नए पाठ या मौजूदा पाठों के लिए अतिरिक्त सामग्री
* रुचि के RF प्रोटोकॉल
* एकीकरण के लिए अधिक हार्डवेयर और SDR प्रकार
* Python में IQ analysis scripts
* इंस्टॉलेशन से जुड़े सुधार और संशोधन

FISSURE को बेहतर बनाने में योगदान देना इसके विकास को तेज़ करने के लिए अत्यंत महत्वपूर्ण है। आपके सभी योगदानों की बहुत सराहना की जाती है। यदि आप कोड डेवलपमेंट के ज़रिए योगदान देना चाहते हैं, तो repo को fork करें और pull request बनाएँ:

1. प्रोजेक्ट को fork करें
2. अपनी feature branch बनाएँ (`git checkout -b feature/AmazingFeature`)
3. अपने बदलाव commit करें (`git commit -m 'Add some AmazingFeature'`)
4. branch पर push करें (`git push origin feature/AmazingFeature`)
5. pull request खोलें

बग की ओर ध्यान दिलाने के लिए [Issues](https://github.com/ainfosec/FISSURE/issues) बनाना भी स्वागत योग्य है।

## सहयोग

FISSURE के साथ सहयोग के अवसरों का प्रस्ताव रखने और उन्हें औपचारिक रूप देने के लिए Assured Information Security, Inc. (AIS) के Business Development विभाग से संपर्क करें—चाहे इसके लिए अपने सॉफ़्टवेयर को एकीकृत करने में समय देना हो, AIS के प्रतिभाशाली लोगों से अपनी तकनीकी चुनौतियों के समाधान विकसित करवाने हों, या FISSURE को अन्य प्लेटफ़ॉर्म/एप्लिकेशन में एकीकृत करना हो।

## लाइसेंस

GPL-3.0

लाइसेंस का विवरण देखने के लिए LICENSE फ़ाइल देखें।

## संपर्क

Discord Server से जुड़ें: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter पर फ़ॉलो करें: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## श्रेय

हम इन डेवलपर्स के प्रति आभार व्यक्त करते हैं:

[श्रेय](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## आभार

इस प्रोजेक्ट में योगदान के लिए Dr. Samuel Mantravadi और Joseph Reith का विशेष धन्यवाद।

## References

- [1] [FISSURE - RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE पेपर (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE दस्तावेज़ीकरण - इंस्टॉलेशन](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
