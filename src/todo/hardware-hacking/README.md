# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) ondersteun grensskanderingstoetsing deur selle wat rondom 'n toestel se I/O-penne geplaas is. Baie verwerkers stel ook verskafferspesifieke debug-funksies deur dieselfde Test Access Port (TAP) beskikbaar; grensskandering en CPU-debugging is verwante gebruike van JTAG, nie sinonieme nie.<sup>[[1]](#references)</sup>

Die JTAG-standaard definieer **spesifieke opdragte vir die uitvoer van grensskanderings**, insluitend die volgende:

- **BYPASS** kies 'n eenbis-omleidingsregister sodat ander toestelle in 'n skanderingsketting met minimale oorhoofse koste bereik kan word.
- **SAMPLE/PRELOAD** vang penwaardes tydens normale werking vas en kan die grensskanderingsregister vooraf laai voordat 'n ander instruksie uitgevoer word.
- **EXTEST** stel penstatusse in en lees dit.

Dit kan ook ander opdragte ondersteun, soos:

- **IDCODE** vir die identifisering van 'n toestel
- **INTEST** vir die interne toetsing van die toestel

Jy kan hierdie instruksies teëkom wanneer jy 'n instrument soos die JTAGulator gebruik.

### Die Test Access Port

Die **Test Access Port (TAP)** bied toegang tot 'n komponent se JTAG-toetslogika. Vier seine word vereis, en `TRST` is opsioneel:<sup>[[1]](#references)</sup>

- Toetsklokinvoer (**TCK**) Die TCK is die **klok** wat bepaal hoe dikwels die TAP-beheerder 'n enkele aksie uitvoer (met ander woorde, na die volgende toestand in die toestandsmasjien spring).
- Toetsmodusseleksie- (**TMS**) invoer TMS beheer die **eindige toestandsmasjien**. Op elke kloksiklus kontroleer die toestel se JTAG TAP-beheerder die spanning op die TMS-pen. As die spanning onder 'n sekere drempel is, word die sein as laag beskou en as 0 geïnterpreteer, terwyl die sein as hoog beskou en as 1 geïnterpreteer word as die spanning bo 'n sekere drempel is.
- Toetsdata-invoer (**TDI**) skuif seriele instruksie- of toetsdata in die geselekteerde TAP-register in. IEEE 1149.1 definieer die TAP-oordraggedrag, terwyl verskaffers opsionele instruksies en debug-registers definieer.
- Toetsdata-uitvoer (**TDO**) TDO is die pen wat **data uit die chip stuur**.
- Toetsreset- (**TRST**) invoer Die opsionele TRST stel die eindige toestandsmasjien **na 'n bekende, goeie toestand** terug. Alternatiewelik, as TMS vir vyf opeenvolgende kloksiklusse op 1 gehou word, aktiveer dit 'n reset op dieselfde manier as die TRST-pen; daarom is TRST opsioneel.

Soms sal jy hierdie penne gemerk op die PCB kan vind. In ander gevalle sal jy hulle moet **vind**.

### Identifisering van JTAG-penne

'n Vinnige, doelgeboude—maar betreklik duur—opsie vir die opsporing van JTAG-poorte is die **JTAGulator**, wat ook UART-penuitlegte kan identifiseer.<sup>[[2]](#references)</sup>

Dit het **24 kanale** wat aan bordtoetspunte gekoppel kan word. Dit som kandidate vir penkombinasies met behulp van **IDCODE**- en **BYPASS**-skanderings op en rapporteer die kanale wat met die opgespoorde JTAG-seine ooreenstem.

'n Goedkoper maar baie stadiger manier om JTAG-penuitlegte te identifiseer, is om [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) te gebruik wat op 'n Arduino-versoenbare mikrobeheerder gelaai is.

Met **JTAGenum** definieer jy eers die penne van die ondersoekmikrobeheerder wat vir enumerasie gebruik word. Raadpleeg die penuitleg daarvan en koppel dan hierdie penne aan kandidaat-toetspunte op die teikenbord.<sup>[[3]](#references)</sup>

'n **Derde manier** om JTAG-penne te identifiseer, is om die **PCB** vir 'n bekende voetspoor te **inspekteer**. Sommige borde stel 'n **Tag-Connect**-voetspoor beskikbaar, hoewel Tag-Connect 'n konnektorstelsel is wat JTAG, SWD, UART of 'n ander koppelvlak kan dra—dit is op sigself nie bewys dat die penne JTAG is nie. Komponentdatablaaie en kontinuïteitsmetings kan dan die werklike seine identifiseer.<sup>[[5]](#references)</sup>

## SDW

SWD is Arm se tweepen-, pakkეტgebaseerde debug-koppelvlak.<sup>[[4]](#references)</sup>

Die koppelvlak gebruik die tweerigting-**SWDIO** vir data en **SWCLK** vir die klok. Baie toestelle implementeer 'n **Serial Wire/JTAG Debug Port (SWJ-DP)** wat die keuse tussen SWD en JTAG op gedeelde penne moontlik maak.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1-werkgroep — JTAG en grensskandering](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator-dokumentasie](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG-penenumerasie](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug-koppelvlakke met min penne vir multi-toestelstelsels](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Voetspore vir debug- en programmeringskabels](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
