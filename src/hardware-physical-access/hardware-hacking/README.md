# Udukuzi wa Vifaa

{{#include ../../banners/hacktricks-training.md}}

Kwa kifaa unachoweza kukifikia kimwili, anza na kiolesura kinachopatikana kupitia ubao au ishara zake: [konsoli za serial za UART](uart.md), [ufikiaji wa utatuzi wa JTAG/SWD](jtag.md), [ufuatiliaji wa maelekezo wa CoreSight](arm-coresight-instruction-tracing.md), mabasi ya [I²C](i2c.md) na [SPI flash](spi.md). [Uchambuzi wa side-channel](side_channel_analysis.md) na [uingizaji wa hitilafu](fault_injection_attacks.md) hushughulikia kazi tofauti za upimaji na glitching; [uchambuzi wa ishara za redio](radio.md) unahusu njia ya kuingilia kupitia mawimbi ya hewani. Kwa taratibu za RFID/NFC, sub-GHz, infrared, BLE, LoRaWAN na iButton zinazolenga kifaa mahususi, tumia [Udukuzi wa Redio na Violesura vya Ukaribu](../radio-hacking/README.md). Angalia viwango vya umeme vya kifaa lengwa na vikwazo vilivyoelezwa katika sura husika kabla ya kuunganisha zana.

## JTAG

JTAG (IEEE 1149.1) huwezesha upimaji wa boundary-scan kupitia seli zilizowekwa kuzunguka pini za I/O za kifaa. Prosesa nyingi pia hutoa vipengele vya utatuzi vinavyotegemea mtengenezaji kupitia Test Access Port (TAP) hiyo hiyo; boundary scan na utatuzi wa CPU ni matumizi yanayohusiana ya JTAG, lakini si visawe.<sup>[[1]](#references)</sup>

Kiwango cha JTAG kinafafanua **amri mahususi za kufanya boundary scans**, zikiwemo zifuatazo:

- **BYPASS** huchagua rejista ya bypass ya biti moja ili vifaa vingine katika mnyororo wa scan viweze kufikiwa kwa gharama ndogo ya ziada.
- **SAMPLE/PRELOAD** hunasa thamani za pini wakati wa utendaji wa kawaida na inaweza kupakia mapema rejista ya boundary-scan kabla ya kutumia instruction nyingine.
- **EXTEST** huweka na kusoma hali za pini.

Pia inaweza kutumia amri nyingine kama vile:

- **IDCODE** ya kutambua kifaa
- **INTEST** ya kufanya majaribio ya ndani ya kifaa

Unaweza kukutana na instructions hizi unapotumia zana kama JTAGulator.

### Test Access Port

**Test Access Port (TAP)** hutoa ufikiaji wa mantiki ya majaribio ya JTAG ya kipengele. Ishara nne zinahitajika, na `TRST` ni ya hiari:<sup>[[1]](#references)</sup>

- Ingizo la saa ya majaribio (**TCK**) TCK ni **saa** inayobainisha mara ngapi kidhibiti cha TAP kitafanya kitendo kimoja (kwa maneno mengine, kuhamia hali inayofuata katika state machine).
- Ingizo la kuchagua hali ya majaribio (**TMS**) TMS hudhibiti **finite state machine**. Katika kila mpigo wa saa, kidhibiti cha JTAG TAP cha kifaa hukagua volti kwenye pini ya TMS. Ikiwa volti iko chini ya kiwango fulani, ishara huhesabiwa kuwa ya chini na kutafsiriwa kama 0; ikiwa iko juu ya kiwango hicho, ishara huhesabiwa kuwa ya juu na kutafsiriwa kama 1.
- Ingizo la data ya majaribio (**TDI**) huhamisha kwa mfululizo instruction au data ya majaribio kwenda kwenye rejista iliyochaguliwa ya TAP. IEEE 1149.1 hufafanua jinsi uhamishaji wa TAP unavyofanyika, huku watengenezaji wakifafanua instructions za hiari na rejista za utatuzi.
- Tokeo la data ya majaribio (**TDO**) TDO ni pini inayotuma **data kutoka kwenye chip**.
- Ingizo la kuweka upya majaribio (**TRST**) TRST ya hiari huweka upya finite state machine **kwenye hali salama inayojulikana**. Vinginevyo, TMS ikishikiliwa kwenye 1 kwa mizunguko mitano ya saa mfululizo, huanzisha uwekaji upya kama ule wa pini ya TRST; ndiyo sababu TRST ni ya hiari.

Wakati mwingine utaweza kupata pini hizo zikiwa zimewekewa alama kwenye PCB. Katika hali nyingine, huenda ukahitaji **kuzitafuta**.

### Kutambua pini za JTAG

Chaguo la haraka, lililoundwa mahususi—lakini lenye gharama kubwa zaidi—la kugundua milango ya JTAG ni **JTAGulator**, ambayo pia inaweza kutambua mipangilio ya pini za UART.<sup>[[2]](#references)</sup>

Ina **chaneli 24** zinazoweza kuunganishwa kwenye sehemu za majaribio za ubao. Hujaribu michanganyiko ya pini zinazowezekana kwa kutumia scans za **IDCODE** na **BYPASS**, kisha huripoti chaneli zinazolingana na ishara za JTAG zilizotambuliwa.

Njia ya bei nafuu lakini ya polepole zaidi ya kutambua mipangilio ya pini za JTAG ni kutumia [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) iliyopakiwa kwenye microcontroller inayooana na Arduino.

Kwa **JTAGenum**, kwanza bainisha pini za microcontroller ya uchunguzi zitakazotumika kwa enumeration. Angalia mpangilio wake wa pini, kisha unganisha pini hizo kwenye sehemu za majaribio zinazowezekana kwenye ubao lengwa.<sup>[[3]](#references)</sup>

**Njia ya tatu** ya kutambua pini za JTAG ni **kukagua PCB** ili kutafuta footprint inayojulikana. Baadhi ya mbao zina footprint ya **Tag-Connect**, ingawa Tag-Connect ni mfumo wa kiunganishi unaoweza kubeba JTAG, SWD, UART au kiolesura kingine—uwepo wake pekee hauthibitishi kuwa pini hizo ni za JTAG. Datasheet za vipengele na vipimo vya mwendelezo wa umeme vinaweza kusaidia kutambua ishara halisi.<sup>[[5]](#references)</sup>

## SDW

SWD ni kiolesura cha utatuzi cha Arm chenye pini mbili na kinachotumia pakiti.<sup>[[4]](#references)</sup>

Kiolesura hiki hutumia **SWDIO** inayoweza kutuma na kupokea data, pamoja na **SWCLK** kwa saa. Vifaa vingi hutumia **Serial Wire/JTAG Debug Port (SWJ-DP)** inayoruhusu kuchagua kati ya SWD na JTAG kwenye pini zinazotumiwa kwa pamoja.<sup>[[4]](#references)</sup>

## References

- [1] [Kikundi kazi cha IEEE 1149.1 — JTAG na boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Nyaraka za JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Enumeration ya pini za JTAG za Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Violesura vya utatuzi vyenye pini chache kwa mifumo ya vifaa vingi](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprint za kebo za utatuzi na programu](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
