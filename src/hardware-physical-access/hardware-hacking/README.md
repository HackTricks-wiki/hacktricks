# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

Vir ’n toestel waartoe jy fisiese toegang het, begin met die koppelvlak wat deur sy bord of seine blootgestel word: [UART-reekskonsoles](uart.md), [JTAG/SWD-ontfoutingstoegang](jtag.md), [I²C](i2c.md)- en [SPI-flits](spi.md)-busse. [Sy-kanaal-analise](side_channel_analysis.md) en [foutinspuiting](fault_injection_attacks.md) hanteer verskillende meet- en glitching-take; [radioseinanalise](radio.md) dek ’n toegangspunt oor die lug. Gaan die teiken se elektriese vlakke en die beperkings in die toepaslike hoofstuk na voordat jy gereedskap koppel.

## JTAG

JTAG (IEEE 1149.1) ondersteun grensskanderingstoetse deur selle wat rondom ’n toestel se I/O-penne geplaas is. Baie verwerkers stel ook verskafferspesifieke ontfoutingsfunksies deur dieselfde Test Access Port (TAP) beskikbaar; grensskandering en SVE-ontfouting is verwante gebruike van JTAG, nie sinonieme nie.<sup>[[1]](#references)</sup>

Die JTAG-standaard definieer **spesifieke opdragte vir grensskanderings**, insluitend die volgende:

- **BYPASS** kies ’n eenbis-omleidingsregister sodat ander toestelle in ’n skanderingsketting met minimale oorhoofse koste bereik kan word.
- **SAMPLE/PRELOAD** neem penwaardes tydens normale werking vas en kan die grensskanderingsregister vooraf laai voordat ’n ander instruksie uitgevoer word.
- **EXTEST** stel penstate in en lees dit.

Dit kan ook ander opdragte ondersteun, soos:

- **IDCODE** om ’n toestel te identifiseer
- **INTEST** om die toestel intern te toets

Jy kan hierdie instruksies teëkom wanneer jy ’n instrument soos die JTAGulator gebruik.

### Die Test Access Port

Die **Test Access Port (TAP)** bied toegang tot ’n komponent se JTAG-toetslogika. Vier seine word benodig, en `TRST` is opsioneel:<sup>[[1]](#references)</sup>

- Toetsklokinvoer (**TCK**) Die TCK is die **klok** wat bepaal hoe gereeld die TAP-beheerder ’n enkele aksie uitvoer (met ander woorde, na die volgende toestand in die toestandsmasjien oorgaan).
- Toetsmodusseleksie-invoer (**TMS**) TMS beheer die **eindige toestandsmasjien**. By elke klokpuls kontroleer die toestel se JTAG TAP-beheerder die spanning op die TMS-pen. As die spanning onder ’n sekere drempel is, word die sein as laag beskou en as 0 geïnterpreteer; as die spanning bo ’n sekere drempel is, word die sein as hoog beskou en as 1 geïnterpreteer.
- Toetsdatainvoer (**TDI**) skuif seriële instruksies of toetsdata na die gekose TAP-register. IEEE 1149.1 definieer die TAP-oordraggedrag, terwyl verskaffers opsionele instruksies en ontfoutingsregisters definieer.
- Toetsdata-uitvoer (**TDO**) TDO is die pen wat **data uit die skyfie stuur**.
- Toetsherstelinvoer (**TRST**) Die opsionele TRST herstel die eindige toestandsmasjien **na ’n bekende, werkende toestand**. Alternatiewelik kan TMS vir vyf opeenvolgende klokiklusse op 1 gehou word om ’n herstel uit te voer, net soos met die TRST-pen; daarom is TRST opsioneel.

Soms sal jy hierdie penne op die PCB gemerk sien. Ander kere sal jy dit moet **vind**.

### Identifisering van JTAG-penne

’n Vinnige, doelgemaakte, maar betreklik duur opsie om JTAG-poorte op te spoor, is die **JTAGulator**, wat ook UART-penindelings kan identifiseer.<sup>[[2]](#references)</sup>

Dit het **24 kanale** wat aan bordtoetspunte gekoppel kan word. Dit lys moontlike penkombinasies met **IDCODE**- en **BYPASS**-skanderings en rapporteer die kanale wat ooreenstem met die bespeurde JTAG-seine.

’n Goedkoper maar baie stadiger manier om JTAG-penindelings te identifiseer, is om [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) op ’n Arduino-versoenbare mikrobeheerder te laai.

Met **JTAGenum** definieer jy eers die penne van die ondersoekende mikrobeheerder wat vir die enumerasie gebruik word. Raadpleeg sy penindeling en koppel dan daardie penne aan moontlike toetspunte op die teikenbord.<sup>[[3]](#references)</sup>

’n **Derde manier** om JTAG-penne te identifiseer, is om die **PCB te inspekteer** vir ’n bekende voetspoor. Sommige borde het ’n **Tag-Connect**-voetspoor, hoewel Tag-Connect ’n koppelaarstelsel is wat JTAG, SWD, UART of ’n ander koppelvlak kan dra—dit bewys nie op sigself dat die penne JTAG is nie. Komponentdatablaaie en kontinuïteitsmetings kan dan die werklike seine identifiseer.<sup>[[5]](#references)</sup>

## SDW

SWD is Arm se tweepen-, pakkiegebaseerde ontfoutingskoppelvlak.<sup>[[4]](#references)</sup>

Die koppelvlak gebruik tweerigting-**SWDIO** vir data en **SWCLK** vir die klok. Baie toestelle implementeer ’n **Serial Wire/JTAG Debug Port (SWJ-DP)** waarmee daar tussen SWD en JTAG op gedeelde penne gekies kan word.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1-werkgroep — JTAG en grensskandering](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator-dokumentasie](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG-penenumerasie](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Ontfoutingskoppelvlakke met min penne vir stelsels met veelvuldige toestelle](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Voetspore vir ontfoutings- en programmeringskabels](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
