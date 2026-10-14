# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

Kwa kifaa unachoweza kukifikia moja kwa moja, anza na kiolesura kinachopatikana kwenye ubao au ishara zake: [UART serial consoles](uart.md), [JTAG/SWD debug access](jtag.md), mabasi ya [I²C](i2c.md) na [SPI flash](spi.md). [Side-channel analysis](side_channel_analysis.md) na [fault injection](fault_injection_attacks.md) hushughulikia kazi tofauti za upimaji na kuingiza hitilafu kwa glitching; [radio signal analysis](radio.md) huchunguza sehemu ya kuingilia kupitia mawimbi ya hewani. Kwa taratibu za RFID/NFC, sub-GHz, infrared, BLE, LoRaWAN na iButton zinazolenga kifaa husika, tumia [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Kagua viwango vya umeme vya kifaa na vikwazo vilivyoelezwa katika sura husika kabla ya kuunganisha zana.

## JTAG

JTAG (IEEE 1149.1) husaidia kufanya majaribio ya boundary-scan kupitia seli zilizowekwa kuzunguka pini za I/O za kifaa. Vichakataji vingi pia hutoa vitendaji vya debug vya mtengenezaji kupitia Test Access Port (TAP) hiyo hiyo; boundary scan na CPU debugging ni matumizi yanayohusiana ya JTAG, lakini si maneno yenye maana sawa.<sup>[[1]](#references)</sup>

Kiwango cha JTAG kinafafanua **amri mahususi za kufanya boundary scans**, zikiwemo zifuatazo:

- **BYPASS** huchagua rejista ya bypass ya biti moja ili vifaa vingine katika mnyororo wa scan viweze kufikiwa kwa gharama ndogo zaidi.
- **SAMPLE/PRELOAD** hunasa thamani za pini wakati wa utendakazi wa kawaida na inaweza kupakia mapema rejista ya boundary-scan kabla ya kutumia maagizo mengine.
- **EXTEST** huweka na kusoma hali za pini.

Pia inaweza kusaidia amri nyingine kama vile:

- **IDCODE** ya kutambua kifaa
- **INTEST** ya kufanya majaribio ya ndani ya kifaa

Unaweza kukutana na maagizo haya unapotumia zana kama JTAGulator.

### The Test Access Port

**Test Access Port (TAP)** hutoa ufikiaji wa mantiki ya majaribio ya JTAG ya kipengele. Ishara nne zinahitajika, na `TRST` ni ya hiari:<sup>[[1]](#references)</sup>

- Ingizo la saa ya majaribio (**TCK**) TCK ni **saa** inayobainisha mara ngapi kidhibiti cha TAP kitachukua hatua moja (kwa maneno mengine, kuhamia hali inayofuata katika mashine ya hali).
- Ingizo la kuchagua modi ya majaribio (**TMS**) TMS hudhibiti **finite state machine**. Katika kila mpigo wa saa, kidhibiti cha JTAG TAP cha kifaa hukagua volteji kwenye pini ya TMS. Ikiwa volteji iko chini ya kiwango fulani, ishara huchukuliwa kuwa ya chini na kutafsiriwa kama 0; ikiwa volteji iko juu ya kiwango fulani, ishara huchukuliwa kuwa ya juu na kutafsiriwa kama 1.
- Ingizo la data ya majaribio (**TDI**) huingiza maagizo au data ya majaribio kwa mfululizo kwenye rejista iliyochaguliwa ya TAP. IEEE 1149.1 hufafanua tabia ya uhamishaji ya TAP, huku watengenezaji wakifafanua maagizo ya hiari na rejista za debug.
- Tokeo la data ya majaribio (**TDO**) TDO ni pini inayotuma **data kutoka kwenye chip**.
- Ingizo la reset ya majaribio (**TRST**) TRST ya hiari huweka upya finite state machine **kwenye hali salama inayojulikana**. Vinginevyo, ikiwa TMS itawekwa kwenye 1 kwa mizunguko mitano ya saa mfululizo, hufanya reset, kama vile pini ya TRST; ndiyo maana TRST ni ya hiari.

Wakati mwingine unaweza kupata pini hizo zikiwa zimewekewa alama kwenye PCB. Nyakati nyingine huenda ukahitaji **kuzitafuta**.

### Identifying JTAG pins

Chaguo la haraka, lililotengenezwa mahsusi kwa kazi hii—lakini lenye gharama kubwa kiasi—la kutambua milango ya JTAG ni **JTAGulator**, ambayo pia inaweza kutambua mpangilio wa pini za UART.<sup>[[2]](#references)</sup>

Ina **chaneli 24** zinazoweza kuunganishwa kwenye test points za ubao. Hujaribu mchanganyiko wa pini zinazowezekana kwa kutumia scans za **IDCODE** na **BYPASS**, kisha kuripoti chaneli zinazolingana na ishara za JTAG zilizotambuliwa.

Njia ya bei nafuu lakini ya polepole zaidi ya kutambua mpangilio wa pini za JTAG ni kutumia [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) iliyopakiwa kwenye microcontroller inayooana na Arduino.

Ukitumia **JTAGenum**, kwanza bainisha pini za microcontroller ya uchunguzi zitakazotumika katika utambuzi. Rejelea mpangilio wake wa pini, kisha unganisha pini hizo kwenye test points zinazowezekana kwenye ubao lengwa.<sup>[[3]](#references)</sup>

**Njia ya tatu** ya kutambua pini za JTAG ni **kukagua PCB** ili kutafuta footprint inayojulikana. Baadhi ya mbao zina footprint ya **Tag-Connect**, ingawa Tag-Connect ni mfumo wa kiunganishi unaoweza kubeba JTAG, SWD, UART au kiolesura kingine—hivyo, uwepo wake pekee hauthibitishi kuwa pini hizo ni za JTAG. Datasheet za vipengele na vipimo vya continuity vinaweza kusaidia kutambua ishara halisi.<sup>[[5]](#references)</sup>

## SDW

SWD ni kiolesura cha Arm cha debug chenye pini mbili na kinachotumia pakiti.<sup>[[4]](#references)</sup>

Kiolesura hiki hutumia **SWDIO** ya mawasiliano ya pande mbili kwa data na **SWCLK** kwa saa. Vifaa vingi hutumia **Serial Wire/JTAG Debug Port (SWJ-DP)** inayoruhusu kuchagua kati ya SWD na JTAG kwenye pini zinazoshirikishwa.<sup>[[4]](#references)</sup>

## References

- [1] [Kikundi kazi cha IEEE 1149.1 — JTAG na boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Nyaraka za JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Utambuzi wa pini za JTAG kwa Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Miingiliano ya Debug yenye Pini Chache kwa Mifumo ya Vifaa Vingi](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints za nyaya za debug na programming](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
