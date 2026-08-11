# Udukuzi wa Vifaa

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) huwezesha upimaji wa boundary-scan kupitia seli zilizowekwa kuzunguka pini za I/O za kifaa. Vichakataji vingi pia hufichua kazi za utatuzi maalum za mtengenezaji kupitia Test Access Port (TAP) hiyo hiyo; boundary scan na utatuzi wa CPU ni matumizi yanayohusiana ya JTAG, si visawe.<sup>[[1]](#references)</sup>

Kiwango cha JTAG hufafanua **amri mahususi za kufanya boundary scans**, zikiwemo zifuatazo:

- **BYPASS** huchagua rejista ya bypass yenye biti moja ili vifaa vingine katika scan chain vifikiwe kwa overhead ndogo.
- **SAMPLE/PRELOAD** hunasa thamani za pini wakati wa utendaji wa kawaida na inaweza kupakia rejista ya boundary-scan kabla ya instruksheni nyingine.
- **EXTEST** huweka na kusoma hali za pini.

Pia inaweza kusaidia amri nyingine kama:

- **IDCODE** ya kutambua kifaa
- **INTEST** ya kufanya majaribio ya ndani ya kifaa

Huenda ukakutana na instruksheni hizi unapotumia tool kama JTAGulator.

### Test Access Port

**Test Access Port (TAP)** hutoa ufikiaji wa mantiki ya majaribio ya JTAG ya sehemu. Ishara nne zinahitajika, na `TRST` ni ya hiari:<sup>[[1]](#references)</sup>

- Ingizo la saa ya majaribio (**TCK**) TCK ni **saa** inayobainisha mara ngapi kidhibiti cha TAP kitafanya kitendo kimoja (kwa maneno mengine, kurukia hali inayofuata katika state machine).
- Ingizo la kuchagua hali ya majaribio (**TMS**) TMS hudhibiti **finite state machine**. Katika kila mpigo wa saa, kidhibiti cha JTAG TAP cha kifaa hukagua voltage kwenye pini ya TMS. Ikiwa voltage iko chini ya kiwango fulani, ishara huchukuliwa kuwa ya chini na kutafsiriwa kama 0; ikiwa voltage iko juu ya kiwango fulani, ishara huchukuliwa kuwa ya juu na kutafsiriwa kama 1.
- Ingizo la data ya majaribio (**TDI**) husogeza instruksheni ya mfululizo au data ya majaribio ndani ya rejista iliyochaguliwa ya TAP. IEEE 1149.1 hufafanua tabia ya uhamishaji wa TAP, huku watengenezaji wakifafanua instruksheni za hiari na rejista za utatuzi.
- Tokeo la data ya majaribio (**TDO**) TDO ni pini inayotuma **data nje ya chip**.
- Ingizo la reset ya majaribio (**TRST**) TRST ya hiari huweka upya finite state machine **kwenye hali salama inayojulikana**. Vinginevyo, TMS ikishikiliwa kwenye 1 kwa mizunguko mitano ya saa mfululizo, huanzisha reset, kwa njia ileile ambayo pini ya TRST ingefanya; ndiyo sababu TRST ni ya hiari.

Wakati mwingine utaweza kupata pini hizo zikiwa zimewekwa alama kwenye PCB. Katika hali nyingine huenda ukahitaji **kuzitafuta**.

### Kutambua pini za JTAG

Chaguo la haraka, lililoundwa mahsusi—lakini ghali kwa kulinganisha—la kutambua port za JTAG ni **JTAGulator**, ambayo pia inaweza kutambua mpangilio wa pini za UART.<sup>[[2]](#references)</sup>

Ina **channels 24** zinazoweza kuunganishwa kwenye test points za board. Huhesabu michanganyiko ya pini zinazowezekana kwa kutumia scans za **IDCODE** na **BYPASS**, kisha huripoti channels zinazolingana na ishara za JTAG zilizotambuliwa.

Njia ya bei nafuu lakini ya polepole zaidi ya kutambua mpangilio wa pini za JTAG ni kutumia [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) iliyopakiwa kwenye microcontroller inayooana na Arduino.

Ukitumia **JTAGenum**, kwanza fafanua pini za microcontroller ya uchunguzi zitakazotumika kwa enumeration. Angalia pinout yake, kisha unganisha pini hizo kwenye test points zinazowezekana kwenye board lengwa.<sup>[[3]](#references)</sup>

**Njia ya tatu** ya kutambua pini za JTAG ni **kukagua PCB** ili kupata footprint inayojulikana. Baadhi ya boards hufichua **Tag-Connect** footprint, ingawa Tag-Connect ni mfumo wa connector unaoweza kubeba JTAG, SWD, UART au interface nyingine—si uthibitisho wa pekee kwamba pini hizo ni za JTAG. Datasheet za components na vipimo vya continuity vinaweza kisha kutambua ishara halisi.<sup>[[5]](#references)</sup>

## SDW

SWD ni interface ya utatuzi ya Arm yenye pini mbili na inayotumia packets.<sup>[[4]](#references)</sup>

Interface hii hutumia **SWDIO** ya mwelekeo-mbili kwa data na **SWCLK** kwa saa. Vifaa vingi hutekeleza **Serial Wire/JTAG Debug Port (SWJ-DP)** inayoruhusu kuchagua kati ya SWD na JTAG kwenye pini zinazoshirikiwa.<sup>[[4]](#references)</sup>

## References

- [1] [Kikundi kazi cha IEEE 1149.1 — JTAG na boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Nyaraka za JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Enumeration ya pini za Arduino JTAG](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces za utatuzi zenye pini chache kwa mifumo yenye vifaa vingi](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints za nyaya za utatuzi na programming](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
