# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE एक open-source RF और reverse engineering framework है, जिसे सभी skill levels के लिए डिज़ाइन किया गया है। इसमें signal detection और classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation और AI/ML के लिए hooks शामिल हैं। यह framework software modules, radios, protocols, signal data, scripts, flow graphs, reference material और third-party tools के तेज़ी से integration को बढ़ावा देने के लिए बनाया गया था। FISSURE एक workflow enabler है, जो software को एक ही स्थान पर रखता है और teams को एक ही proven baseline configuration साझा करते हुए specific Linux distributions पर आसानी से up to speed होने देता है।<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE के साथ शामिल framework और tools RF energy का detection, signals का characterization, samples का collection और analysis, transmit या injection techniques का development, तथा custom payloads या messages तैयार करने के लिए डिज़ाइन किए गए हैं। FISSURE identification, packet crafting और fuzzing के लिए protocol और signal information भी प्रदान करता है, साथ ही traffic simulation और testing के लिए archives और playlists भी उपलब्ध कराता है।<sup>[[1]](#references)[[2]](#references)</sup>

Python codebase और graphical interface beginners को RF और reverse-engineering tools सीखने में सहायता करते हैं। Educators built-in lessons का उपयोग कर सकते हैं, जबकि developers और researchers अपने modules और workflows को integrate कर सकते हैं। Current releases distributed sensor nodes, TAK integration, geolocation workflows और role-specific Apptainer deployments को भी support करते हैं।<sup>[[1]](#references)[[3]](#references)</sup>

**अतिरिक्त जानकारी**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Supported**

Current FISSURE active development के लिए **`Python3`** branch का उपयोग करता है, जिसमें PyQt5 और GNU Radio 3.8 या 3.10 शामिल हैं। Deprecated **`Python2_maint-3.7`** branch पुराने operating systems और उन third-party tools के लिए उपलब्ध है जिन्हें GNU Radio 3.7 की आवश्यकता होती है। पहले के `Python3_maint-3.8` और `Python3_maint-3.10` branch names historical हैं; GNU Radio maintenance selection अब `Python3` branch से handle किया जाता है।<sup>[[1]](#references)[[3]](#references)</sup>

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | supported Linux version का उपयोग करें | matching version का उपयोग करें |

**In-Progress (beta)**

ये operating systems अभी भी beta status में हैं। इन पर development जारी है और कई features के missing होने की जानकारी है। Status हटाए जाने तक installer में मौजूद items existing programs के साथ conflict कर सकते हैं या install होने में fail हो सकते हैं।

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

कुछ third-party tools प्रत्येक OS पर काम नहीं करते। Install करने से पहले वर्तमान [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) documentation देखें।<sup>[[3]](#references)</sup>

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
submodule step FISSURE द्वारा उपयोग किए जाने वाले GNU Radio out-of-tree modules को download करता है और उन modules को install करते समय आवश्यक होता है। Installer उन missing PyQt dependencies को भी install करेगा, जो इसकी installation GUIs launch करने के लिए आवश्यक हैं।<sup>[[3]](#references)</sup>

इसके बाद, वह option चुनें जो आपके operating system से सबसे अच्छी तरह मेल खाता हो (यदि आपका OS किसी option से मेल खाता है, तो इसका स्वतः detect हो जाना चाहिए)।

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

मौजूदा conflicts से बचने के लिए FISSURE को clean operating system पर install करने की recommended है। FISSURE के भीतर विभिन्न tools को operate करते समय errors से बचने के लिए सभी recommended checkboxes (Default button) select करें। Installation के दौरान कई prompts दिखाई देंगे, जिनमें अधिकतर elevated permissions और user names मांगे जाएंगे। यदि किसी item के अंत में "Verify" section है, तो installer उसके बाद वाली command run करेगा और command से कोई error उत्पन्न होने या न होने के आधार पर checkbox item को green या red highlight करेगा। "Verify" section के बिना checked items installation के बाद black ही रहेंगे।

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**उपयोग**

एक terminal खोलें और दर्ज करें:
```
fissure
```
अधिक जानकारी के लिए उपयोग संबंधी FISSURE Help menu देखें।

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

निम्नलिखित hardware का FISSURE में integration के विभिन्न स्तरों पर समर्थन है:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lessons

FISSURE में विभिन्न technologies और techniques से परिचित होने के लिए कई उपयोगी guides शामिल हैं। इनमें से कई में FISSURE में integrated विभिन्न tools के उपयोग के steps शामिल हैं।

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
* [Lesson12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lesson13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lesson14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Roadmap

* [ ] अधिक hardware types, RF protocols, signal parameters और analysis tools जोड़ना
* [ ] अधिक operating systems का support
* [ ] FISSURE के आसपास class material विकसित करना (RF Attacks, Wi-Fi, GNU Radio, PyQt आदि)
* [ ] selectable AI/ML techniques के साथ signal conditioner, feature extractor और signal classifier बनाना
* [ ] unknown signals से bitstream बनाने के लिए recursive demodulation mechanisms लागू करना
* [ ] मुख्य FISSURE components को generic sensor node deployment scheme में स्थानांतरित करना

## Contributing

FISSURE को बेहतर बनाने के लिए suggestions का दृढ़ता से स्वागत है। यदि आपके पास निम्नलिखित के संबंध में कोई विचार है, तो [Discussions](https://github.com/ainfosec/FISSURE/discussions) page या Discord Server में comment करें:

* नए feature suggestions और design changes
* installation steps वाले software tools
* existing lessons के लिए नई lessons या additional material
* रुचि के RF protocols
* integration के लिए अधिक hardware और SDR types
* Python में IQ analysis scripts
* installation corrections और improvements

FISSURE को बेहतर बनाने में contributions इसके development को तेज करने के लिए महत्वपूर्ण हैं। आपके द्वारा किया गया कोई भी contribution अत्यंत सराहनीय है। यदि आप code development के माध्यम से contribute करना चाहते हैं, तो repo को fork करें और pull request बनाएँ:

1. Project को fork करें
2. अपनी feature branch बनाएँ (`git checkout -b feature/AmazingFeature`)
3. अपने changes commit करें (`git commit -m 'Add some AmazingFeature'`)
4. Branch पर push करें (`git push origin feature/AmazingFeature`)
5. Pull request खोलें

Bugs पर ध्यान आकर्षित करने के लिए [Issues](https://github.com/ainfosec/FISSURE/issues) बनाना भी स्वागतयोग्य है।

## Collaborating

Assured Information Security, Inc. (AIS) Business Development से संपर्क करके FISSURE collaboration opportunities का प्रस्ताव दें और उन्हें formalize करें–चाहे वह आपके software को integrate करने के लिए समय समर्पित करने, AIS के talented लोगों से आपकी technical challenges के लिए solutions विकसित कराने, या FISSURE को अन्य platforms/applications में integrate करने के माध्यम से हो।

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

इस project में योगदान के लिए Dr. Samuel Mantravadi और Joseph Reith को विशेष धन्यवाद।

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
