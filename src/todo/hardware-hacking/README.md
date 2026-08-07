# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG huruhusu kufanya boundary scan. Boundary scan huchanganua circuitry fulani, ikiwemo boundary-scan cells na registers zilizopachikwa kwa kila pin.

JTAG standard hufafanua **specific commands za kufanya boundary scans**, zikiwemo:

- **BYPASS** hukuruhusu ku-test chip maalum bila gharama ya ziada ya kupitia chips nyingine.
- **SAMPLE/PRELOAD** huchukua sample ya data inayoingia na kutoka kwenye device ikiwa katika hali yake ya kawaida ya kufanya kazi.
- **EXTEST** huweka na kusoma hali za pins.

Pia inaweza ku-support commands nyingine kama:

- **IDCODE** kwa ajili ya kutambua device
- **INTEST** kwa ajili ya internal testing ya device

Unaweza kukutana na instructions hizi unapotumia tool kama JTAGulator.

### The Test Access Port

Boundary scans hujumuisha tests za **Test Access Port (TAP)** yenye waya nne, port ya matumizi ya jumla inayotoa **access kwa JTAG test support** functions zilizojengwa ndani ya component. TAP hutumia signals tano zifuatazo:

- Test clock input (**TCK**) TCK ni **clock** inayobainisha mara ngapi TAP controller itachukua action moja (kwa maneno mengine, kuruka kwenda state inayofuata kwenye state machine).
- Test mode select (**TMS**) input TMS hudhibiti **finite state machine**. Kwa kila beat ya clock, JTAG TAP controller ya device hukagua voltage kwenye TMS pin. Ikiwa voltage iko chini ya threshold fulani, signal huchukuliwa kuwa low na kutafsiriwa kama 0, ilhali ikiwa voltage iko juu ya threshold fulani, signal huchukuliwa kuwa high na kutafsiriwa kama 1.
- Test data input (**TDI**) TDI ni pin inayotuma **data ndani ya chip kupitia scan cells**. Kila vendor anawajibika kufafanua communication protocol kupitia pin hii, kwa sababu JTAG haifafanui hilo.
- Test data output (**TDO**) TDO ni pin inayotuma **data kutoka kwenye chip**.
- Test reset (**TRST**) input TRST ya hiari hu-reset finite state machine **kwenda kwenye known good state**. Vinginevyo, TMS ikishikiliwa kwenye 1 kwa clock cycles tano mfululizo, huanzisha reset, kwa njia ileile ambayo TRST pin ingefanya, ndiyo maana TRST ni ya hiari.

Wakati mwingine utaweza kupata pins hizo zikiwa zimewekewa alama kwenye PCB. Katika hali nyingine unaweza kuhitaji **kuzipata**.

### Identifying JTAG pins

Njia ya haraka zaidi lakini yenye gharama kubwa zaidi ya kutambua JTAG ports ni kutumia **JTAGulator**, device iliyoundwa mahsusi kwa madhumuni haya (ingawa inaweza **pia kutambua UART pinouts**).

Ina **channels 24** unazoweza kuunganisha kwenye pins za board. Kisha hufanya **BF attack** ya combinations zote zinazowezekana kwa kutuma **IDCODE** na **BYPASS** boundary scan commands. Ikiwa inapokea response, huonyesha channel inayolingana na kila JTAG signal

Njia ya bei nafuu lakini ya polepole zaidi ya kutambua JTAG pinouts ni kutumia [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) iliyopakiwa kwenye Arduino-compatible microcontroller.

Kwa kutumia **JTAGenum**, kwanza uta-**define pins za probing** device utakayotumia kwa enumeration.Utalazimika kurejelea pinout diagram ya device, kisha uunganishe pins hizo na test points kwenye target device yako.

**Njia ya tatu** ya kutambua JTAG pins ni **kukagua PCB** ili kutafuta mojawapo ya pinouts. Katika baadhi ya hali, PCBs zinaweza kutoa kwa urahisi **Tag-Connect interface**, ambayo ni ishara wazi kwamba board pia ina JTAG connector. Unaweza kuona jinsi interface hiyo inavyoonekana kwenye [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Zaidi ya hayo, kukagua **datasheets za chipsets zilizo kwenye PCB** kunaweza kufichua pinout diagrams zinazoelekeza kwenye JTAG interfaces.

## SDW

SWD ni protocol maalum ya ARM iliyoundwa kwa ajili ya debugging.

SWD interface inahitaji **pins mbili**: signal ya bidirectional **SWDIO**, ambayo ni sawa na **TDI na TDO pins za JTAG pamoja na clock**, na **SWCLK**, ambayo ni sawa na **TCK** katika JTAG. Devices nyingi hu-support **Serial Wire or JTAG Debug Port (SWJ-DP)**, interface iliyounganisha JTAG na SWD inayokuwezesha kuunganisha SWD au JTAG probe kwenye target.

{{#include ../../banners/hacktricks-training.md}}
