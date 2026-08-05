# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE एक open-source RF और reverse engineering framework है, जिसे सभी skill levels के लिए डिज़ाइन किया गया है। इसमें signal detection और classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation और AI/ML के लिए hooks शामिल हैं। यह framework software modules, radios, protocols, signal data, scripts, flow graphs, reference material और third-party tools के तेज़ integration को बढ़ावा देने के लिए बनाया गया था। FISSURE एक workflow enabler है, जो software को एक ही स्थान पर रखता है और teams को specific Linux distributions के लिए समान proven baseline configuration share करते हुए आसानी से up to speed होने देता है।<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE के साथ शामिल framework और tools को RF energy की उपस्थिति का पता लगाने, signal की characteristics को समझने, samples collect और analyze करने, transmit और/या injection techniques विकसित करने और custom payloads या messages तैयार करने के लिए डिज़ाइन किया गया है। FISSURE में protocol और signal information की लगातार बढ़ती library शामिल है, जो identification, packet crafting और fuzzing में सहायता करती है। Signals files download करने और traffic को simulate करने तथा systems का test करने के लिए playlists बनाने हेतु online archive capabilities भी उपलब्ध हैं।

Friendly Python codebase और user interface beginners को RF और reverse engineering से जुड़े popular tools और techniques के बारे में जल्दी सीखने की सुविधा देते हैं। Cybersecurity और engineering के educators built-in material का लाभ उठा सकते हैं या अपने real-world applications को demonstrate करने के लिए framework का उपयोग कर सकते हैं। Developers और researchers FISSURE का उपयोग अपने daily tasks के लिए या अपने cutting-edge solutions को व्यापक audience तक पहुँचाने के लिए कर सकते हैं। Community में FISSURE की awareness और usage बढ़ने के साथ-साथ इसकी capabilities का विस्तार और इसमें शामिल technology का दायरा भी बढ़ेगा।

**Additional Information**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Supported**

FISSURE में file navigation को आसान बनाने और code redundancy कम करने के लिए तीन branches हैं। Python2\_maint-3.7 branch में Python2, PyQt4 और GNU Radio 3.7 पर आधारित codebase है; Python3\_maint-3.8 branch Python3, PyQt5 और GNU Radio 3.8 पर आधारित है; और Python3\_maint-3.10 branch Python3, PyQt5 और GNU Radio 3.10 पर आधारित है।

|   Operating System   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In-Progress (beta)**

ये operating systems अभी भी beta status में हैं। इन पर development जारी है और कई features के missing होने की जानकारी है। Status हटाए जाने तक installer में मौजूद items existing programs के साथ conflict कर सकते हैं या install होने में fail हो सकते हैं।

|     Operating System     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Note: कुछ software tools हर OS पर काम नहीं करते। [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md) देखें।

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
यह PyQt software dependencies इंस्टॉल करेगा, जो installation GUIs लॉन्च करने के लिए आवश्यक हैं, यदि वे पहले से नहीं मिली हों।

इसके बाद, वह विकल्प चुनें जो आपके operating system से सबसे अच्छी तरह मेल खाता हो (यदि आपका OS किसी विकल्प से मेल खाता है, तो यह स्वतः detect हो जाना चाहिए)।

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

मौजूदा conflicts से बचने के लिए FISSURE को एक clean operating system पर इंस्टॉल करने की सलाह दी जाती है। FISSURE के भीतर विभिन्न tools को चलाते समय errors से बचने के लिए सभी recommended checkboxes (Default button) चुनें। Installation के दौरान कई prompts दिखाई देंगे, जिनमें अधिकांश elevated permissions और user names के बारे में पूछेंगे। यदि किसी item के अंत में "Verify" section है, तो installer उसके बाद दिया गया command चलाएगा और command से कोई errors उत्पन्न होने पर checkbox item को हरे या लाल रंग में highlight करेगा। "Verify" section के बिना checked items installation के बाद काले ही रहेंगे।

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Usage**

एक terminal खोलें और दर्ज करें:
```
fissure
```
अधिक जानकारी के लिए usage संबंधी FISSURE Help menu देखें।

## विवरण

**Components**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capabilities**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

निम्नलिखित विभिन्न स्तरों के integration वाले "supported" hardware की सूची है:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lessons

FISSURE में विभिन्न technologies और techniques से परिचित होने के लिए कई उपयोगी guides शामिल हैं। इनमें से कई में FISSURE में integrated विभिन्न tools का उपयोग करने के steps शामिल हैं।

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] अधिक hardware types, RF protocols, signal parameters और analysis tools जोड़ना
* [ ] अधिक operating systems को support करना
* [ ] FISSURE के आसपास class material विकसित करना (RF Attacks, Wi-Fi, GNU Radio, PyQt आदि)
* [ ] selectable AI/ML techniques के साथ signal conditioner, feature extractor और signal classifier बनाना
* [ ] unknown signals से bitstream बनाने के लिए recursive demodulation mechanisms लागू करना
* [ ] मुख्य FISSURE components को generic sensor node deployment scheme में बदलना

## Contributing

FISSURE में सुधार के suggestions का स्वागत है। यदि आपके पास निम्नलिखित के संबंध में कोई विचार है, तो [Discussions](https://github.com/ainfosec/FISSURE/discussions) page या Discord Server पर comment करें:

* New feature suggestions और design changes
* installation steps वाले software tools
* Existing lessons के लिए new lessons या additional material
* रुचि के RF protocols
* integration के लिए अधिक hardware और SDR types
* Python में IQ analysis scripts
* Installation corrections और improvements

FISSURE को बेहतर बनाने में contributions इसके development को तेज करने के लिए महत्वपूर्ण हैं। आपके द्वारा दिया गया कोई भी contribution बहुत सराहनीय है। यदि आप code development के माध्यम से contribute करना चाहते हैं, तो repo को fork करके pull request बनाएं:

1. Project को fork करें
2. अपना feature branch बनाएं (`git checkout -b feature/AmazingFeature`)
3. अपने changes commit करें (`git commit -m 'Add some AmazingFeature'`)
4. Branch पर push करें (`git push origin feature/AmazingFeature`)
5. Pull request खोलें

Bugs पर ध्यान आकर्षित करने के लिए [Issues](https://github.com/ainfosec/FISSURE/issues) बनाना भी स्वागतयोग्य है।

## Collaborating

किसी भी FISSURE collaboration opportunity का प्रस्ताव देने और उसे formalize करने के लिए Assured Information Security, Inc. (AIS) Business Development से संपर्क करें - चाहे वह आपके software को integrate करने के लिए समय समर्पित करने, AIS के talented लोगों से आपकी technical challenges के लिए solutions विकसित करवाने, या FISSURE को अन्य platforms/applications में integrate करने के माध्यम से हो।

## License

GPL-3.0

License details के लिए LICENSE file देखें।

## Contact

Discord Server से जुड़ें: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter पर follow करें: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

हम इन developers के प्रति आभार व्यक्त करते हैं:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

इस project में contributions के लिए Dr. Samuel Mantravadi और Joseph Reith को विशेष धन्यवाद।

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
