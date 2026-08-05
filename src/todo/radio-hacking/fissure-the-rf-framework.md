# FISSURE - Mfumo wa RF

{{#include ../../banners/hacktricks-training.md}}

**Uelewaji na Reverse Engineering ya Signal kwa kutumia SDR isiyotegemea Frequency**

FISSURE ni framework ya RF na reverse engineering ya open-source iliyoundwa kwa viwango vyote vya ujuzi, ikiwa na hooks za signal detection na classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation, na AI/ML. Framework hii iliundwa kuwezesha integration ya haraka ya software modules, radios, protocols, signal data, scripts, flow graphs, reference material, na third-party tools. FISSURE ni workflow enabler inayoweka software yote katika location moja na kuruhusu teams kuanza kazi kwa urahisi huku zikishiriki baseline configuration ileile iliyothibitishwa kwa Linux distributions maalum.<sup>[[1]](#references)[[2]](#references)</sup>

Framework na tools zilizojumuishwa katika FISSURE zimeundwa kutambua uwepo wa RF energy, kuelewa sifa za signal, kukusanya na kuchanganua samples, kuunda transmit na/au injection techniques, na kutengeneza custom payloads au messages. FISSURE ina library inayokua ya protocol na signal information kusaidia katika identification, packet crafting, na fuzzing. Online archive capabilities zinapatikana kwa kupakua signal files na kuunda playlists za kuiga traffic na kujaribu systems.

Python codebase na user interface yake rafiki huruhusu beginners kujifunza haraka kuhusu tools na techniques maarufu zinazohusisha RF na reverse engineering. Educators katika cybersecurity na engineering wanaweza kutumia material iliyojengwa ndani au kutumia framework kuonyesha matumizi yao ya real-world. Developers na researchers wanaweza kutumia FISSURE kwa kazi zao za kila siku au kuonyesha solutions zao za cutting-edge kwa audience pana zaidi. Awareness na matumizi ya FISSURE yanapoongezeka katika community, ndivyo capabilities zake na upana wa technology inayohusisha utakavyoongezeka.

**Taarifa za Ziada**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Kuanza

**Zinazotumika**

Kuna branches tatu ndani ya FISSURE ili kurahisisha navigation ya files na kupunguza code redundancy. Branch ya Python2\_maint-3.7 ina codebase iliyojengwa kwa kutumia Python2, PyQt4, na GNU Radio 3.7; Python3\_maint-3.8 imejengwa kwa kutumia Python3, PyQt5, na GNU Radio 3.8; na Python3\_maint-3.10 imejengwa kwa kutumia Python3, PyQt5, na GNU Radio 3.10.

|   Operating System   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Ziko Kwenye Maendeleo (beta)**

Operating systems hizi bado ziko katika hali ya beta. Ziko kwenye development na features kadhaa zinajulikana kuwa hazipo. Items zilizo katika installer zinaweza kugongana na programs zilizopo au kushindwa ku-install hadi status hiyo iondolewe.

|     Operating System     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Kumbuka: Baadhi ya software tools hazifanyi kazi katika kila OS. Tazama [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Hii itaweka dependencies za software ya PyQt zinazohitajika kuzindua installation GUIs ikiwa hazijapatikana.

Kisha, chagua option inayolingana zaidi na operating system yako (inapaswa kutambuliwa automatically ikiwa OS yako inalingana na option fulani).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Inapendekezwa kusakinisha FISSURE kwenye operating system safi ili kuepuka conflicts zilizopo. Chagua checkboxes zote zinazopendekezwa (Default button) ili kuepuka errors unapotumia tools mbalimbali ndani ya FISSURE. Kutakuwa na prompts nyingi wakati wa installation, ambazo mara nyingi zitaomba elevated permissions na user names. Ikiwa kipengee kina sehemu ya "Verify" mwishoni, installer itaendesha command inayofuata na kuonyesha checkbox hiyo ikiwa ya kijani au nyekundu kulingana na kama command hiyo imetoa errors. Vipengee vilivyochaguliwa bila sehemu ya "Verify" vitaendelea kuwa vyeusi baada ya installation.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Matumizi**

Fungua terminal na uandike:
```
fissure
```
Rejelea menyu ya FISSURE Help kwa maelezo zaidi kuhusu matumizi.

## Maelezo

**Vipengele**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Uwezo**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Kigunduzi cha Mawimbi**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Udanganyaji wa IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Utafutaji wa Mawimbi**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Utambuzi wa Miundo**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Mashambulizi**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Orodha za Kuchezesha Mawimbi**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Mkusanyiko wa Picha**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Uundaji wa Pakiti**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Ujumuishaji wa Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Kikokotoo cha CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Uwekaji wa Kumbukumbu**_            |

**Vifaa**

Ifuatayo ni orodha ya vifaa "vinavyoungwa mkono" kwa viwango tofauti vya ujumuishaji:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adapta za 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Masomo

FISSURE inakuja na miongozo kadhaa yenye manufaa ya kufahamu teknolojia na mbinu mbalimbali. Mingi yake ina hatua za kutumia tools mbalimbali zilizounganishwa kwenye FISSURE.

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

## Mpango wa Maendeleo

* [ ] Ongeza aina zaidi za vifaa, RF protocols, vigezo vya mawimbi na tools za uchanganuzi
* [ ] Saidia operating systems zaidi
* [ ] Tengeneza nyenzo za masomo kuhusu FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, n.k.)
* [ ] Tengeneza signal conditioner, feature extractor na signal classifier yenye mbinu za AI/ML zinazoweza kuchaguliwa
* [ ] Tekeleza mbinu za recursive demodulation za kuzalisha bitstream kutoka kwa mawimbi yasiyojulikana
* [ ] Hamisha vipengele vikuu vya FISSURE kwenda kwenye mpango wa jumla wa deployment ya sensor nodes

## Kuchangia

Mapendekezo ya kuboresha FISSURE yanahimizwa sana. Acha maoni kwenye ukurasa wa [Discussions](https://github.com/ainfosec/FISSURE/discussions) au kwenye Discord Server ikiwa una mawazo kuhusu yafuatayo:

* Mapendekezo ya vipengele vipya na mabadiliko ya muundo
* Software tools pamoja na hatua za usakinishaji
* Masomo mapya au nyenzo za ziada kwa masomo yaliyopo
* RF protocols zinazovutia
* Aina zaidi za vifaa na SDR kwa ajili ya ujumuishaji
* IQ analysis scripts katika Python
* Marekebisho na maboresho ya usakinishaji

Michango ya kuboresha FISSURE ni muhimu katika kuharakisha maendeleo yake. Tunathamini sana mchango wowote utakaotoa. Ikiwa ungependa kuchangia kupitia code development, fork repo na uunde pull request:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

Kuunda [Issues](https://github.com/ainfosec/FISSURE/issues) ili kuarifu kuhusu bugs pia kunakaribishwa.

## Kushirikiana

Wasiliana na Business Development ya Assured Information Security, Inc. (AIS) ili kupendekeza na kurasimisha fursa zozote za ushirikiano wa FISSURE - iwe ni kupitia kutenga muda wa kuunganisha software yako, kuwa na wataalamu wenye vipaji wa AIS watengeneze solutions kwa changamoto zako za kiufundi, au kuunganisha FISSURE kwenye platforms/applications nyingine.

## Leseni

GPL-3.0

Kwa maelezo ya leseni, tazama faili la LICENSE.

## Mawasiliano

Jiunge na Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Follow on Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Waandaaji

Tunawashukuru na kutambua waandaaji hawa:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Shukrani

Shukrani za pekee kwa Dr. Samuel Mantravadi na Joseph Reith kwa michango yao kwenye mradi huu.

## Marejeo

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
