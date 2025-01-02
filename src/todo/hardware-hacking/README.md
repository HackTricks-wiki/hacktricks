# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG inaruhusu kufanya uchambuzi wa mipaka. Uchambuzi wa mipaka unachambua mzunguko fulani, ikiwa ni pamoja na seli za mipaka zilizojumuishwa na register kwa kila pini.

Standards ya JTAG inaelezea **amri maalum za kufanya uchambuzi wa mipaka**, ikiwa ni pamoja na yafuatayo:

- **BYPASS** inakuwezesha kupima chip maalum bila mzigo wa kupita kupitia chips nyingine.
- **SAMPLE/PRELOAD** inachukua sampuli ya data inayingia na kutoka kwenye kifaa wakati kiko katika hali yake ya kawaida ya kufanya kazi.
- **EXTEST** inaweka na kusoma hali za pini.

Inaweza pia kusaidia amri nyingine kama:

- **IDCODE** kwa kutambua kifaa
- **INTEST** kwa mtihani wa ndani wa kifaa

Unaweza kukutana na maelekezo haya unapokuwa ukitumia chombo kama JTAGulator.

### The Test Access Port

Uchambuzi wa mipaka unajumuisha majaribio ya **Test Access Port (TAP)** ya nyaya nne, bandari ya matumizi ya jumla inayotoa **ufikiaji wa kazi za msaada wa mtihani wa JTAG** zilizojengwa ndani ya kipengee. TAP inatumia ishara tano zifuatazo:

- Ingizo la saa ya mtihani (**TCK**) TCK ni **saa** inayofafanua mara ngapi kidhibiti cha TAP kitachukua hatua moja (kwa maneno mengine, kuruka hadi hali inayofuata katika mashine ya hali).
- Ingizo la kuchagua hali ya mtihani (**TMS**) TMS inasimamia **mashine ya hali ya mwisho**. Kila kipigo cha saa, kidhibiti cha JTAG TAP cha kifaa kinachunguza voltage kwenye pini ya TMS. Ikiwa voltage iko chini ya kigezo fulani, ishara inachukuliwa kuwa ya chini na kutafsiriwa kama 0, wakati voltage ikiwa juu ya kigezo fulani, ishara inachukuliwa kuwa ya juu na kutafsiriwa kama 1.
- Ingizo la data ya mtihani (**TDI**) TDI ni pini inayotuma **data ndani ya chip kupitia seli za uchambuzi**. Kila muuzaji anawajibika kufafanua itifaki ya mawasiliano kupitia pini hii, kwa sababu JTAG haifafanui hii.
- Kutoka kwa data ya mtihani (**TDO**) TDO ni pini inayotuma **data kutoka kwenye chip**.
- Ingizo la kurekebisha mtihani (**TRST**) TRST ya hiari inarejesha mashine ya hali ya mwisho **katika hali nzuri inayojulikana**. Vinginevyo, ikiwa TMS inashikiliwa kwenye 1 kwa mizunguko mitano mfululizo ya saa, inasababisha kurekebisha, kama vile pini ya TRST ingefanya, ndiyo maana TRST ni ya hiari.

Wakati mwingine utaweza kupata pini hizo zimeandikwa kwenye PCB. Katika matukio mengine unaweza kuhitaji **kuzipata**.

### Identifying JTAG pins

Njia ya haraka lakini ya gharama kubwa kugundua bandari za JTAG ni kwa kutumia **JTAGulator**, kifaa kilichoundwa mahsusi kwa ajili ya kusudi hili (ingawa pia kinaweza **gundua pinouts za UART**).

Ina **channels 24** ambazo unaweza kuunganisha na pini za bodi. Kisha inafanya **shambulio la BF** la mchanganyiko wote wanaowezekana ikituma amri za uchambuzi wa mipaka **IDCODE** na **BYPASS**. Ikiwa inapokea jibu, inaonyesha channel inayolingana na kila ishara ya JTAG.

Njia ya bei nafuu lakini ya polepole zaidi ya kutambua pinouts za JTAG ni kwa kutumia [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) iliyopakuliwa kwenye microcontroller inayofaa na Arduino.

Kwa kutumia **JTAGenum**, kwanza ungetakiwa **kufafanua pini za kifaa cha uchunguzi** ambacho utatumia kwa ajili ya uhesabu. Ungehitaji kurejelea mchoro wa pinout wa kifaa, kisha kuunganisha hizi pini na maeneo ya mtihani kwenye kifaa chako cha lengo.

Njia **ya tatu** ya kutambua pini za JTAG ni kwa **kuangalia PCB** kwa moja ya pinouts. Katika baadhi ya matukio, PCB zinaweza kwa urahisi kutoa **kiunganishi cha Tag-Connect**, ambacho ni dalili wazi kwamba bodi ina kiunganishi cha JTAG, pia. Unaweza kuona jinsi kiunganishi hicho kinavyoonekana kwenye [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Zaidi ya hayo, kuangalia **karatasi za data za chipsets kwenye PCB** kunaweza kufichua michoro ya pinout inayotaja viunganishi vya JTAG.

## SDW

SWD ni itifaki maalum ya ARM iliyoundwa kwa ajili ya ufuatiliaji.

Kiunganishi cha SWD kinahitaji **pini mbili**: ishara ya **SWDIO** inayoweza kuelekezwa, ambayo ni sawa na pini za **TDI na TDO za JTAG** na saa, na **SWCLK**, ambayo ni sawa na **TCK** katika JTAG. Vifaa vingi vinasaidia **Bandari ya Ufuatiliaji wa Nyaya au JTAG (SWJ-DP)**, kiunganishi kilichounganisha cha JTAG na SWD ambacho kinakuruhusu kuunganisha probe ya SWD au JTAG kwa lengo.

{{#include ../../banners/hacktricks-training.md}}
