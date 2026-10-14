# Udukuzi wa Vifaa

{{#include ../../banners/hacktricks-training.md}}

Kwa kifaa unachoweza kukifikia kimwili, anza na kiolesura kinachopatikana kupitia ubao wake au ishara zake: [konsoli za serial za UART](uart.md), [ufikiaji wa utatuzi kupitia JTAG/SWD](jtag.md), mabasi ya [I²C](i2c.md) na [SPI flash](spi.md). [Uchambuzi wa side-channel](side_channel_analysis.md) na [uingizaji wa hitilafu](fault_injection_attacks.md) hutumika kwa kazi tofauti za upimaji na kusababisha hitilafu za muda mfupi; [uchambuzi wa ishara za redio](radio.md) hushughulikia njia ya kuingia kupitia mawasiliano ya hewani. Kagua viwango vya umeme vya kifaa lengwa na vikwazo vilivyoelezwa katika sura husika kabla ya kuunganisha zana.

## JTAG

JTAG (IEEE 1149.1) huruhusu upimaji wa boundary-scan kupitia seli zilizowekwa kuzunguka pini za I/O za kifaa. Vichakataji vingi pia hutoa utendaji wa utatuzi mahususi wa mtengenezaji kupitia Test Access Port (TAP) hiyo hiyo; boundary scan na utatuzi wa CPU ni matumizi yanayohusiana ya JTAG, lakini si maneno yanayomaanisha kitu kimoja.<sup>[[1]](#references)</sup>

Kiwango cha JTAG kinafafanua **amri mahususi za kufanya boundary scan**, zikiwemo zifuatazo:

- **BYPASS** huchagua rejista ya bypass ya biti moja ili vifaa vingine katika mnyororo wa scan viweze kufikiwa kwa gharama ndogo zaidi.
- **SAMPLE/PRELOAD** hunasa thamani za pini wakati wa utendaji wa kawaida na inaweza kupakia awali rejista ya boundary-scan kabla ya kutumia amri nyingine.
- **EXTEST** huweka na kusoma hali za pini.

Pia inaweza kutumia amri nyingine kama vile:

- **IDCODE** ya kutambua kifaa
- **INTEST** ya kufanya majaribio ya ndani ya kifaa

Unaweza kukutana na maagizo haya unapotumia zana kama JTAGulator.

### Test Access Port

**Test Access Port (TAP)** hutoa ufikiaji kwa mantiki ya majaribio ya JTAG ya kijenzi. Ishara nne zinahitajika na `TRST` ni ya hiari:<sup>[[1]](#references)</sup>

- Ingizo la saa ya jaribio (**TCK**) TCK ni **saa** inayobainisha mara ngapi kidhibiti cha TAP kitafanya kitendo kimoja (kwa maneno mengine, kuhamia hali inayofuata katika mashine ya hali).
- Ingizo la kuchagua hali ya jaribio (**TMS**) TMS hudhibiti **mashine ya hali zenye kikomo**. Katika kila mpigo wa saa, kidhibiti cha JTAG TAP cha kifaa hukagua volti kwenye pini ya TMS. Ikiwa volti iko chini ya kiwango fulani, ishara huchukuliwa kuwa ya chini na kutafsiriwa kama 0; ikiwa volti iko juu ya kiwango hicho, ishara huchukuliwa kuwa ya juu na kutafsiriwa kama 1.
- Ingizo la data ya jaribio (**TDI**) huhamisha maagizo ya serial au data ya majaribio hadi kwenye rejista ya TAP iliyochaguliwa. IEEE 1149.1 hufafanua jinsi uhamishaji wa TAP unavyofanyika, ilhali watengenezaji hufafanua maagizo ya hiari na rejista za utatuzi.
- Tokeo la data ya jaribio (**TDO**) TDO ni pini inayotuma **data kutoka kwenye chip**.
- Ingizo la kuweka upya jaribio (**TRST**) TRST ya hiari huweka upya mashine ya hali **kwenye hali salama inayojulikana**. Vinginevyo, TMS ikishikiliwa kwenye 1 kwa mizunguko mitano ya saa mfululizo, huanzisha uwekaji upya sawa na ule wa pini ya TRST; ndiyo maana TRST ni ya hiari.

Wakati mwingine utaweza kupata pini hizo zikiwa zimeandikwa kwenye PCB. Nyakati nyingine huenda ukahitaji **kuzitafuta**.

### Kutambua pini za JTAG

Chaguo la haraka, lililotengenezwa mahsusi kwa kazi hii—lakini ghali kiasi—la kugundua milango ya JTAG ni **JTAGulator**, ambayo pia inaweza kutambua mpangilio wa pini za UART.<sup>[[2]](#references)</sup>

Ina **chaneli 24** zinazoweza kuunganishwa kwenye sehemu za majaribio za ubao. Hukagua michanganyiko ya pini inayowezekana kwa kutumia scan za **IDCODE** na **BYPASS**, kisha huripoti chaneli zinazolingana na ishara za JTAG zilizogunduliwa.

Njia nafuu zaidi, lakini ya polepole sana, ya kutambua mpangilio wa pini za JTAG ni kutumia [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) iliyopakiwa kwenye kidhibiti kidogo kinachooana na Arduino.

Ukitumia **JTAGenum**, kwanza fafanua pini za kidhibiti kidogo cha uchunguzi zitakazotumika katika utafutaji. Angalia mpangilio wa pini zake, kisha unganisha pini hizo kwenye sehemu za majaribio zinazowezekana kwenye ubao lengwa.<sup>[[3]](#references)</sup>

**Njia ya tatu** ya kutambua pini za JTAG ni **kukagua PCB** ili kutafuta alama ya muunganisho inayojulikana. Baadhi ya mbao zina alama ya **Tag-Connect**, ingawa Tag-Connect ni mfumo wa kiunganishi unaoweza kubeba JTAG, SWD, UART au kiolesura kingine—uwepo wake pekee hauthibitishi kuwa pini hizo ni za JTAG. Datasheet za vijenzi na vipimo vya mwendelezo vinaweza kusaidia kutambua ishara halisi.<sup>[[5]](#references)</sup>

## SDW

SWD ni kiolesura cha utatuzi cha Arm kinachotumia pini mbili na pakiti za data.<sup>[[4]](#references)</sup>

Kiolesura hiki hutumia **SWDIO** ya pande mbili kwa data na **SWCLK** kwa saa. Vifaa vingi hutekeleza **Serial Wire/JTAG Debug Port (SWJ-DP)** inayowezesha kuchagua kati ya SWD na JTAG kwenye pini zinazotumiwa kwa pamoja.<sup>[[4]](#references)</sup>

## References

- [1] [Kikundi kazi cha IEEE 1149.1 — JTAG na boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Nyaraka za JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Utafutaji wa pini za JTAG kwa Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Violesura vya utatuzi vinavyotumia pini chache kwa mifumo ya vifaa vingi](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Alama za viunganishi vya utatuzi na upangaji programu](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
