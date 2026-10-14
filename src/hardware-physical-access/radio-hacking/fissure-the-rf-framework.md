# FISSURE - Mfumo wa RF

{{#include ../../banners/hacktricks-training.md}}

**Uelewa wa Mawimbi na Reverse Engineering kwa kutumia SDR usiotegemea Masafa**

FISSURE ni framework ya RF na reverse engineering ya chanzo huria, iliyoundwa kwa ajili ya viwango vyote vya ujuzi na yenye hooks za kutambua na kuainisha mawimbi, kugundua protocols, kutekeleza mashambulizi, kudhibiti IQ, kuchanganua udhaifu, kuendesha otomatiki, na kutumia AI/ML. Framework hii ilijengwa ili kuwezesha uunganishaji wa haraka wa modules za software, radios, protocols, data za mawimbi, scripts, flow graphs, nyenzo za marejeleo, na zana za wahusika wengine. FISSURE huwezesha mtiririko wa kazi kwa kuweka software zote mahali pamoja na kuziwezesha timu kuanza kufanya kazi kwa urahisi huku zikishiriki usanidi wa msingi uliothibitishwa kwa distributions mahususi za Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Framework na zana zilizo kwenye FISSURE zimeundwa kugundua nishati ya RF, kubainisha sifa za mawimbi, kukusanya na kuchanganua sampuli, kutengeneza mbinu za kutuma au kuingiza mawimbi, na kuunda payloads au messages maalum. FISSURE pia hutoa maelezo ya protocols na mawimbi kwa ajili ya utambuzi, uundaji wa packets, na fuzzing, pamoja na archives na playlists za kuiga na kujaribu trafiki.<sup>[[1]](#references)[[2]](#references)</sup>

Codebase ya Python na kiolesura cha picha huwasaidia wanaoanza kujifunza RF na zana za reverse engineering. Waelimishaji wanaweza kutumia masomo yaliyojengewa ndani, huku developers na watafiti wakiweza kuunganisha modules na workflows zao. Matoleo ya sasa pia yanaunga mkono distributed sensor nodes, muunganisho wa TAK, workflows za geolocation, na deployments za Apptainer zinazotegemea majukumu.<sup>[[1]](#references)[[3]](#references)</sup>

**Maelezo ya Ziada**

* [Ukurasa wa AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slides za GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Makala ya GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Video ya GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Nakala ya Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Kuanza

**Zinazoungwa Mkono**

FISSURE ya sasa hutumia tawi la **`Python3`** kwa ajili ya maendeleo yanayoendelea na PyQt5 na GNU Radio 3.8 au 3.10. Tawi lililoacha kutumika la **`Python2_maint-3.7`** bado linapatikana kwa mifumo ya uendeshaji ya zamani na zana za wahusika wengine zinazohitaji GNU Radio 3.7. Majina ya zamani ya matawi `Python3_maint-3.8` na `Python3_maint-3.10` ni ya kihistoria; uteuzi wa toleo la matengenezo la GNU Radio sasa hufanywa kutoka kwenye tawi la `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Mfumo wa Uendeshaji | Tawi la FISSURE | Tawi Chaguomsingi la GNU Radio |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | tumia toleo la Linux linaloungwa mkono | tumia toleo linalolingana |

**Zinazoendelea Kutengenezwa (beta)**

Mifumo hii ya uendeshaji bado iko katika hali ya beta. Inaendelea kutengenezwa na inajulikana kuwa baadhi ya vipengele havipo. Vipengee vilivyo kwenye installer vinaweza kuleta migogoro na programu zilizopo au kushindwa kusakinishwa hadi hali ya beta iondolewe.

| Mfumo wa Uendeshaji | Tawi la FISSURE | Tawi Chaguomsingi la GNU Radio |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Baadhi ya zana za wahusika wengine hazifanyi kazi kwenye kila OS. Angalia nyaraka za sasa za [Migogoro Inayojulikana na Software ya Wahusika Wengine](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) kabla ya kusakinisha.<sup>[[3]](#references)</sup>

**Usakinishaji**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

Hatua ya submodule hupakua modules za GNU Radio out-of-tree zinazotumiwa na FISSURE na inahitajika wakati wa kusakinisha modules hizo. Pia, kisakinishi kitasakinisha dependencies za PyQt zinazokosekana ambazo zinahitajika ili kufungua GUI za usakinishaji.<sup>[[3]](#references)</sup>

Kisha, chagua chaguo linalolingana zaidi na mfumo wako wa uendeshaji (linapaswa kutambuliwa kiotomatiki ikiwa OS yako inalingana na chaguo fulani).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Inapendekezwa kusakinisha FISSURE kwenye mfumo safi wa uendeshaji ili kuepuka migongano iliyopo. Chagua visanduku vyote vya kuteua vinavyopendekezwa (kitufe cha Default) ili kuepuka hitilafu unapotumia zana mbalimbali ndani ya FISSURE. Kutakuwa na vidokezo kadhaa wakati wa usakinishaji, vingi vikiomba ruhusa zilizoinuliwa na majina ya watumiaji. Ikiwa kipengee kina sehemu ya "Verify" mwishoni, kisakinishi kitaendesha amri inayofuata na kuangazia kisanduku cha kuteua cha kipengee kwa kijani au nyekundu kulingana na kama amri hiyo imetoa hitilafu zozote. Vipengee vilivyowekwa alama ya kuteuliwa ambavyo havina sehemu ya "Verify" vitabaki vyeusi baada ya usakinishaji.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Matumizi**

Fungua terminal na uandike:

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

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Udhibiti wa IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Utafutaji wa mawimbi**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Utambuzi wa ruwaza**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Mashambulizi**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Orodha za kucheza mawimbi**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Matunzio ya picha**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Uundaji wa pakiti**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Muunganisho wa Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Kikokotoo cha CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Uwekaji kumbukumbu**_            |

**Vifaa**

Vifaa vifuatavyo vimeunganishwa na FISSURE kwa viwango tofauti:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Adapta za 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Masomo

FISSURE ina miongozo kadhaa yenye manufaa ya kukusaidia kufahamu teknolojia na mbinu mbalimbali. Mingi ina hatua za kutumia zana mbalimbali zilizounganishwa na FISSURE.

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

## Ramani ya maendeleo

* [ ] Ongeza aina zaidi za vifaa, itifaki za RF, vigezo vya mawimbi na zana za uchanganuzi
* [ ] Saidia mifumo zaidi ya uendeshaji
* [ ] Tengeneza nyenzo za masomo kuhusu FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, n.k.)
* [ ] Unda kifaa cha kurekebisha mawimbi, kichimbaji vipengele na kiainishaji mawimbi kinachotumia mbinu za AI/ML zinazoweza kuchaguliwa
* [ ] Tekeleza mbinu za demodulation za kujirudia ili kutoa bitstream kutoka kwa mawimbi yasiyojulikana
* [ ] Hamishia vipengele vikuu vya FISSURE kwenye mfumo wa jumla wa usambazaji wa nodi za vihisi

## Kuchangia

Mapendekezo ya kuboresha FISSURE yanakaribishwa sana. Acha maoni kwenye ukurasa wa [Discussions](https://github.com/ainfosec/FISSURE/discussions) au kwenye Discord Server ikiwa una mawazo kuhusu yafuatayo:

* Mapendekezo ya vipengele vipya na mabadiliko ya muundo
* Zana za programu pamoja na hatua za usakinishaji
* Masomo mapya au nyenzo za ziada za masomo yaliyopo
* Itifaki za RF zinazokuvutia
* Aina zaidi za vifaa na SDR za kuunganisha
* Hati za uchanganuzi wa IQ katika Python
* Marekebisho na maboresho ya usakinishaji

Michango ya kuboresha FISSURE ni muhimu ili kuharakisha maendeleo yake. Tunathamini sana mchango wowote unaotoa. Ikiwa ungependa kuchangia kwa kutengeneza code, tafadhali fanya fork ya repo na uunde pull request:

1. Fanya fork ya mradi
2. Unda tawi lako la kipengele (`git checkout -b feature/AmazingFeature`)
3. Fanya commit ya mabadiliko yako (`git commit -m 'Add some AmazingFeature'`)
4. Sukuma mabadiliko kwenye tawi (`git push origin feature/AmazingFeature`)
5. Fungua pull request

Pia unakaribishwa kuunda [Issues](https://github.com/ainfosec/FISSURE/issues) ili kuangazia bugs.

## Ushirikiano

Wasiliana na kitengo cha Business Development cha Assured Information Security, Inc. (AIS) ili kupendekeza na kurasimisha fursa zozote za ushirikiano wa FISSURE—iwe ni kwa kutenga muda wa kuunganisha programu yako, kuwaomba wataalamu wenye vipaji wa AIS watengeneze suluhu za changamoto zako za kiufundi, au kuunganisha FISSURE kwenye majukwaa/programu nyingine.

## Leseni

GPL-3.0

Kwa maelezo kuhusu leseni, angalia faili la LICENSE.

## Mawasiliano

Jiunge na Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Tufuate kwenye Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Shukrani

Tunawashukuru na kuwathamini watengenezaji hawa:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Shukrani za pekee

Shukrani za pekee kwa Dkt. Samuel Mantravadi na Joseph Reith kwa michango yao katika mradi huu.

## References

- [1] [FISSURE - Mfumo wa RF (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Makala ya FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Nyaraka za FISSURE - Usakinishaji](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
