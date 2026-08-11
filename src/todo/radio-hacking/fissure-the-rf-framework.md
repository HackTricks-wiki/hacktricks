# FISSURE - Mfumo wa RF

{{#include ../../banners/hacktricks-training.md}}

**Uelewa na Reverse Engineering ya Signals kwa kutumia SDR Isiyotegemea Frequency**

FISSURE ni framework ya RF na reverse engineering ya open-source iliyoundwa kwa ajili ya viwango vyote vya ujuzi, ikiwa na hooks za utambuzi na uainishaji wa signal, ugunduzi wa protocol, utekelezaji wa attack, uchezaji wa IQ, uchambuzi wa vulnerability, automation, na AI/ML. Framework hii iliundwa kuwezesha ujumuishaji wa haraka wa software modules, radios, protocols, signal data, scripts, flow graphs, reference material, na third-party tools. FISSURE ni workflow enabler inayoweka software katika eneo moja na kuruhusu teams kuanza kufanya kazi kwa urahisi huku zikishiriki baseline configuration ileile iliyothibitishwa kwa Linux distributions mahususi.<sup>[[1]](#references)[[2]](#references)</sup>

Framework na tools zilizo pamoja na FISSURE zimeundwa kutambua RF energy, kubainisha signals, kukusanya na kuchanganua samples, kutengeneza transmit au injection techniques, na kuunda payloads au messages maalum. FISSURE pia hutoa taarifa za protocols na signals kwa ajili ya identification, packet crafting, na fuzzing, pamoja na archives na playlists za traffic simulation na testing.<sup>[[1]](#references)[[2]](#references)</sup>

Python codebase na graphical interface husaidia beginners kujifunza RF na reverse-engineering tools. Educators wanaweza kutumia lessons zilizojengewa ndani, huku developers na researchers wakiunganisha modules na workflows zao wenyewe. Releases za sasa pia zinaunga mkono distributed sensor nodes, TAK integration, geolocation workflows, na role-specific Apptainer deployments.<sup>[[1]](#references)[[3]](#references)</sup>

**Taarifa Zaidi**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Kuanza

**Zinazoungwa Mkono**

FISSURE ya sasa hutumia branch ya **`Python3`** kwa active development pamoja na PyQt5 na GNU Radio 3.8 au 3.10. Branch ya zamani **`Python2_maint-3.7`**, ambayo imepitwa na wakati, bado inapatikana kwa operating systems za zamani na third-party tools zinazohitaji GNU Radio 3.7. Majina ya zamani ya branches `Python3_maint-3.8` na `Python3_maint-3.10` ni ya kihistoria; uteuzi wa GNU Radio maintenance sasa unashughulikiwa kutoka branch ya `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | tumia Linux version inayoungwa mkono | tumia version inayolingana |

**Zinaendelea (beta)**

Operating systems hizi bado ziko katika hali ya beta. Zinaendelea kutengenezwa na inajulikana kuwa features kadhaa hazipo. Vitu vilivyo kwenye installer vinaweza kuleta conflict na programs zilizopo au kushindwa ku-install hadi hali hii iondolewe.

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Baadhi ya third-party tools hazifanyi kazi kwenye kila OS. Kagua nyaraka za sasa za [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) kabla ya ku-install.<sup>[[3]](#references)</sup>

**Usakinishaji**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
Hatua ya submodule hupakua GNU Radio out-of-tree modules zinazotumiwa na FISSURE na inahitajika wakati wa kusakinisha modules hizo. Installer pia itasakinisha PyQt dependencies zinazokosekana zinazohitajika kuanzisha installation GUIs zake.<sup>[[3]](#references)</sup>

Kisha, chagua option inayolingana zaidi na operating system yako (inapaswa kutambuliwa automatically ikiwa OS yako inalingana na option fulani).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Inapendekezwa kusakinisha FISSURE kwenye operating system safi ili kuepuka conflicts zilizopo. Chagua checkboxes zote zinazopendekezwa (Default button) ili kuepuka errors wakati wa kutumia tools mbalimbali ndani ya FISSURE. Kutakuwa na prompts nyingi wakati wa installation, ambazo nyingi zitaomba elevated permissions na user names. Ikiwa item ina sehemu ya "Verify" mwishoni, installer itaendesha command inayofuata na kuangazia checkbox item kwa rangi ya kijani au nyekundu kulingana na ikiwa command hiyo itazalisha errors. Items zilizochaguliwa zisizo na sehemu ya "Verify" zitasalia nyeusi baada ya installation.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Matumizi**

Fungua terminal na uweke:
```
fissure
```
Rejelea menyu ya Help ya FISSURE kwa maelezo zaidi kuhusu matumizi.

## Maelezo

**Vipengele**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Uwezo**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

Hardware ifuatayo ina viwango tofauti vya integration katika FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Masomo

FISSURE inakuja na miongozo kadhaa yenye msaada ili kufahamiana na technologies na techniques mbalimbali. Mingi kati yake ina hatua za kutumia tools mbalimbali zilizounganishwa katika FISSURE.

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

## Mpango wa Maendeleo

* [ ] Ongeza aina zaidi za hardware, RF protocols, signal parameters na analysis tools
* [ ] Saidia operating systems zaidi
* [ ] Tengeneza class material kuhusu FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, n.k.)
* [ ] Unda signal conditioner, feature extractor na signal classifier yenye techniques za AI/ML zinazoweza kuchaguliwa
* [ ] Tekeleza mechanisms za recursive demodulation kwa ajili ya kuzalisha bitstream kutoka kwa signals zisizojulikana
* [ ] Hamisha components kuu za FISSURE kwenda kwenye generic sensor node deployment scheme

## Kuchangia

Mapendekezo ya kuboresha FISSURE yanakaribishwa sana. Acha maoni katika ukurasa wa [Discussions](https://github.com/ainfosec/FISSURE/discussions) au katika Discord Server ikiwa una mawazo kuhusu yafuatayo:

* Mapendekezo ya features mpya na mabadiliko ya design
* Software tools pamoja na hatua za installation
* Masomo mapya au nyenzo za ziada kwa masomo yaliyopo
* RF protocols zinazovutia
* Aina zaidi za hardware na SDR kwa ajili ya integration
* IQ analysis scripts katika Python
* Marekebisho na maboresho ya installation

Michango ya kuboresha FISSURE ni muhimu katika kuharakisha maendeleo yake. Mchango wowote unaotoa unathaminiwa sana. Ikiwa ungependa kuchangia kupitia code development, fork repo na uunde pull request:

1. Fork project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

Kuunda [Issues](https://github.com/ainfosec/FISSURE/issues) ili kuleta bugs kwenye uangalizi pia kunakaribishwa.

## Kushirikiana

Wasiliana na Business Development ya Assured Information Security, Inc. (AIS) ili kupendekeza na kurasimisha fursa zozote za collaboration kuhusu FISSURE–iwe ni kwa kutenga muda wa ku-integrate software yako, kuwaacha wataalamu wenye uwezo wa AIS watengeneze solutions kwa changamoto zako za kiufundi, au ku-integrate FISSURE katika platforms/applications nyingine.

## Leseni

GPL-3.0

Kwa maelezo ya leseni, angalia faili ya LICENSE.

## Mawasiliano

Jiunge na Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Tufuate kwenye Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Shukrani

Tunawatambua na kuwashukuru developers hawa:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Shukrani za Pekee

Shukrani za pekee kwa Dr. Samuel Mantravadi na Joseph Reith kwa michango yao katika project hii.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
