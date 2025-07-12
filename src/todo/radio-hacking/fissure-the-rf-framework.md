# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Kuelewa na Uhandisi wa Nyuma wa Ishara za SDR zisizo na Kiwango**

FISSURE ni mfumo wa RF na uhandisi wa nyuma wa chanzo wazi ulioandaliwa kwa viwango vyote vya ujuzi ukiwa na viunganishi vya kugundua na kuainisha ishara, kugundua protokali, kutekeleza mashambulizi, kudhibiti IQ, kuchambua udhaifu, automatisering, na AI/ML. Mfumo huu ulijengwa ili kuhamasisha uunganishaji wa haraka wa moduli za programu, redio, protokali, data za ishara, skripti, grafu za mtiririko, vifaa vya rejea, na zana za wahusika wengine. FISSURE ni mwezeshaji wa mtiririko wa kazi ambao unashikilia programu katika eneo moja na unaruhusu timu kujiweka sawa kwa urahisi huku wakishiriki usanidi wa msingi uliojaribiwa kwa usahihi kwa usambazaji maalum wa Linux.

Mfumo na zana zilizo pamoja na FISSURE zimeundwa kugundua uwepo wa nishati ya RF, kuelewa sifa za ishara, kukusanya na kuchambua sampuli, kuendeleza mbinu za kutuma na/au sindano, na kuunda mizigo au ujumbe maalum. FISSURE ina maktaba inayokua ya taarifa za protokali na ishara kusaidia katika utambuzi, uundaji wa pakiti, na fuzzing. Uwezo wa kuhifadhi mtandaoni upo ili kupakua faili za ishara na kujenga orodha za nyimbo kuiga trafiki na kujaribu mifumo.

Msingi wa msimbo wa Python na kiolesura cha mtumiaji kinawaruhusu wanaanza kujifunza haraka kuhusu zana na mbinu maarufu zinazohusiana na RF na uhandisi wa nyuma. Walimu katika usalama wa mtandao na uhandisi wanaweza kutumia vifaa vilivyomo au kutumia mfumo huu kuonyesha maombi yao halisi. Wataalamu na watafiti wanaweza kutumia FISSURE kwa kazi zao za kila siku au kufichua suluhisho zao za kisasa kwa hadhira pana. Kadri ufahamu na matumizi ya FISSURE yanavyokua katika jamii, ndivyo uwezo wake na wigo wa teknolojia inayojumuisha itakavyoongezeka.

**Taarifa Zaidi**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Kuanzisha

**Inayoungwa Mkono**

Kuna matawi matatu ndani ya FISSURE ili kufanya urambazaji wa faili kuwa rahisi na kupunguza kurudiwa kwa msimbo. Tawi la Python2\_maint-3.7 lina msingi wa msimbo uliojengwa kuzunguka Python2, PyQt4, na GNU Radio 3.7; tawi la Python3\_maint-3.8 limejengwa kuzunguka Python3, PyQt5, na GNU Radio 3.8; na tawi la Python3\_maint-3.10 limejengwa kuzunguka Python3, PyQt5, na GNU Radio 3.10.

|   Mfumo wa Uendeshaji   |   Tawi la FISSURE   |
| :----------------------: | :-----------------: |
|  Ubuntu 18.04 (x64)     | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64)    | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64)    | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64)    | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64)    | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64)    | Python3\_maint-3.8 |

**Katika Mchakato (beta)**

Mifumo hii ya uendeshaji bado iko katika hali ya beta. Ziko katika maendeleo na vipengele kadhaa vinajulikana kukosekana. Vitu katika installer vinaweza kuingiliana na programu zilizopo au kushindwa kufunga hadi hali hiyo itakapondolewa.

|     Mfumo wa Uendeshaji     |    Tawi la FISSURE   |
| :--------------------------: | :------------------: |
| DragonOS Focal (x86\_64)    |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)       | Python3\_maint-3.10 |

Kumbuka: Zana fulani za programu hazifanyi kazi kwa kila OS. Angalia [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Usanidi**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Hii itasakinisha utegemezi wa programu za PyQt zinazohitajika kuanzisha GUI za usakinishaji ikiwa hazipatikani.

Ifuatayo, chagua chaguo linalofaa zaidi kwa mfumo wako wa uendeshaji (linapaswa kugundulika kiotomatiki ikiwa OS yako inalingana na chaguo).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Inapendekezwa kusakinisha FISSURE kwenye mfumo safi wa uendeshaji ili kuepuka migongano iliyopo. Chagua masanduku yote yanayopendekezwa (Kitufe cha Kawaida) ili kuepuka makosa wakati wa kutumia zana mbalimbali ndani ya FISSURE. Kutakuwa na maonyesho mengi wakati wa usakinishaji, hasa yanayouliza ruhusa za juu na majina ya watumiaji. Ikiwa kipengee kina sehemu ya "Thibitisha" mwishoni, msakinishaji atatekeleza amri inayofuata na kuangazia kipengee cha sanduku kuwa kijani au nyekundu kulingana na ikiwa kuna makosa yoyote yanayotokana na amri hiyo. Vitu vilivyokaguliwa bila sehemu ya "Thibitisha" vitabaki kuwa nyeusi baada ya usakinishaji.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Matumizi**

Fungua terminal na ingiza:
```
fissure
```
Refer to the FISSURE Help menu for more details on usage.

## Details

**Components**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capabilities**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

Orodha ifuatayo ni ya vifaa "vilivyosaidiwa" vyenye viwango tofauti vya uunganisho:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lessons

FISSURE inakuja na miongozo kadhaa ya kusaidia kufahamiana na teknolojia na mbinu tofauti. Mingi ina hatua za kutumia zana mbalimbali ambazo zimeunganishwa ndani ya FISSURE.

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

* [ ] Ongeza aina zaidi za vifaa, protokali za RF, vigezo vya ishara, zana za uchambuzi
* [ ] Saidia mifumo zaidi ya uendeshaji
* [ ] Tengeneza vifaa vya darasa kuhusiana na FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, nk.)
* [ ] Unda kondishina ya ishara, mtoa sifa, na mchanganuzi wa ishara kwa mbinu za AI/ML zinazoweza kuchaguliwa
* [ ] Tekeleza mitambo ya demodulation ya kurudi kwa ajili ya kuzalisha bitstream kutoka kwa ishara zisizojulikana
* [ ] Hamasisha vipengele vya msingi vya FISSURE kwa mpango wa uanzishaji wa node ya sensor ya jumla

## Contributing

Mapendekezo ya kuboresha FISSURE yanahimizwa sana. Acha maoni kwenye ukurasa wa [Discussions](https://github.com/ainfosec/FISSURE/discussions) au kwenye Discord Server ikiwa una mawazo yoyote kuhusu yafuatayo:

* Mapendekezo ya vipengele vipya na mabadiliko ya muundo
* Zana za programu zenye hatua za usakinishaji
* Masomo mapya au nyenzo za ziada kwa masomo yaliyopo
* Protokali za RF zinazovutia
* Vifaa zaidi na aina za SDR kwa uunganisho
* Skripti za uchambuzi wa IQ katika Python
* Marekebisho na maboresho ya usakinishaji

Michango ya kuboresha FISSURE ni muhimu ili kuharakisha maendeleo yake. Michango yoyote unayofanya inathaminiwa sana. Ikiwa unataka kuchangia kupitia maendeleo ya msimbo, tafadhali fork repo na uunde ombi la kuvuta:

1. Fork mradi
2. Unda tawi lako la kipengele (`git checkout -b feature/AmazingFeature`)
3. Fanya commit mabadiliko yako (`git commit -m 'Add some AmazingFeature'`)
4. Push kwenye tawi (`git push origin feature/AmazingFeature`)
5. Fungua ombi la kuvuta

Kuunda [Issues](https://github.com/ainfosec/FISSURE/issues) ili kuleta umakini kwa makosa pia kunakaribishwa.

## Collaborating

Wasiliana na Assured Information Security, Inc. (AIS) Business Development ili kupendekeza na kuimarisha fursa zozote za ushirikiano wa FISSURE–iwe ni kwa kujitolea muda wa kuunganisha programu yako, kuwa na watu wenye talanta katika AIS kuunda suluhisho kwa changamoto zako za kiufundi, au kuunganisha FISSURE katika majukwaa/aplikes nyingine.

## License

GPL-3.0

Kwa maelezo ya leseni, angalia faili ya LICENSE.

## Contact

Join the Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Follow on Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

Tunaelewa na tunashukuru kwa hawa wabunifu:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

Shukrani maalum kwa Dr. Samuel Mantravadi na Joseph Reith kwa michango yao katika mradi huu.

{{#include ../../banners/hacktricks-training.md}}
