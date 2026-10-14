# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

Vir ’n toestel waartoe jy fisiese toegang het, begin by die koppelvlak wat deur die bord of seine blootgestel word: [UART-seriale konsoles](uart.md), [JTAG/SWD-ontfoutingstoegang](jtag.md), [I²C](i2c.md) en [SPI-flits](spi.md)-busse. [Sy-kanaal-ontleding](side_channel_analysis.md) en [foutinspuiting](fault_injection_attacks.md) behels ander meet- en glitching-take; [radioseinontleding](radio.md) dek ’n toegangspunt oor die lug. Vir teikenspesifieke RFID/NFC-, sub-GHz-, infrarooi-, BLE-, LoRaWAN- en iButton-prosedures, gebruik [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Gaan die teiken se elektriese vlakke en die beperkings in die toepaslike hoofstuk na voordat jy gereedskap aansluit.

## JTAG

JTAG (IEEE 1149.1) ondersteun grensskanderingstoetse deur selle wat om ’n toestel se I/O-penne geplaas is. Baie verwerkers stel ook verskafferspesifieke ontfoutingsfunksies deur dieselfde Test Access Port (TAP) beskikbaar; grensskandering en CPU-ontfouting is verwante gebruike van JTAG, nie sinonieme nie.<sup>[[1]](#references)</sup>

Die JTAG-standaard definieer **spesifieke opdragte vir die uitvoer van grensskanderings**, waaronder:

- **BYPASS** kies ’n eenbis-omseilregister sodat ander toestelle in ’n skanderingsketting met minimale oorhoofse koste bereik kan word.
- **SAMPLE/PRELOAD** neem penwaardes tydens normale werking vas en kan die grensskanderingregister vooraf laai voordat ’n ander instruksie uitgevoer word.
- **EXTEST** stel penstatusse in en lees dit.

Dit kan ook ander opdragte ondersteun, soos:

- **IDCODE** om ’n toestel te identifiseer
- **INTEST** vir interne toetsing van die toestel

Jy kan hierdie instruksies teëkom wanneer jy ’n instrument soos die JTAGulator gebruik.

### Die Test Access Port

Die **Test Access Port (TAP)** bied toegang tot ’n komponent se JTAG-toetslogika. Vier seine word vereis en `TRST` is opsioneel:<sup>[[1]](#references)</sup>

- Toetsklokinvoer (**TCK**) Die TCK is die **klok** wat bepaal hoe gereeld die TAP-beheerder ’n enkele aksie uitvoer (met ander woorde, na die volgende toestand in die toestandsmasjien spring).
- Toetsmodus-seleksie-invoer (**TMS**) TMS beheer die **eindige toestandsmasjien**. Met elke klokpuls kontroleer die toestel se JTAG TAP-beheerder die spanning op die TMS-pen. As die spanning onder ’n sekere drempel is, word die sein as laag beskou en as 0 geïnterpreteer; as die spanning bo ’n sekere drempel is, word die sein as hoog beskou en as 1 geïnterpreteer.
- Toetsdata-invoer (**TDI**) skuif seriële instruksie- of toetsdata na die geselekteerde TAP-register. IEEE 1149.1 definieer die TAP-oordraggedrag, terwyl verskaffers opsionele instruksies en ontfoutingsregisters definieer.
- Toetsdata-uitvoer (**TDO**) TDO is die pen wat **data uit die skyfie stuur**.
- Toetsterugstel-invoer (**TRST**) Die opsionele TRST stel die eindige toestandsmasjien **na ’n bekende, geldige toestand terug**. Alternatiewelik veroorsaak dit ’n terugstelling as TMS vir vyf opeenvolgende klok siklusse op 1 gehou word, net soos die TRST-pen; daarom is TRST opsioneel.

Soms kan jy hierdie penne op die PCB gemerk vind. Ander kere moet jy hulle dalk **opspoor**.

### Identifisering van JTAG-penne

’n Vinnige, doelgemaakte, maar betreklik duur opsie om JTAG-poorte op te spoor, is die **JTAGulator**, wat ook UART-penkonfigurasies kan identifiseer.<sup>[[2]](#references)</sup>

Dit het **24 kanale** wat aan toetspunte op die bord gekoppel kan word. Dit lys kandidaat-penkombinasies met **IDCODE**- en **BYPASS**-skanderings en rapporteer die kanale wat met die bespeurde JTAG-seine ooreenstem.

’n Goedkoper, maar baie stadiger manier om JTAG-penkonfigurasies te identifiseer, is om [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) te gebruik wat op ’n Arduino-versoenbare mikrobeheerder gelaai is.

Met **JTAGenum** definieer jy eers die penne op die ondersoekende mikrobeheerder wat vir die opsporing gebruik word. Raadpleeg die penkonfigurasie en koppel dan hierdie penne aan kandidaat-toetspunte op die teikenbord.<sup>[[3]](#references)</sup>

’n **Derde manier** om JTAG-penne te identifiseer, is om die **PCB te inspekteer** vir ’n bekende voetspoor. Sommige borde het ’n **Tag-Connect**-voetspoor, hoewel Tag-Connect ’n koppela stelsel is wat JTAG, SWD, UART of ’n ander koppelvlak kan dra—dit bewys nie op sigself dat die penne JTAG is nie. Komponentdatablaaie en kontinuïteitsmetings kan daarna die werklike seine identifiseer.<sup>[[5]](#references)</sup>

## SDW

SWD is Arm se tweepen-, pakkiegebaseerde ontfoutingskoppelvlak.<sup>[[4]](#references)</sup>

Die koppelvlak gebruik die tweerigting-**SWDIO** vir data en **SWCLK** vir die klok. Baie toestelle implementeer ’n **Serial Wire/JTAG Debug Port (SWJ-DP)** wat keuse tussen SWD en JTAG op gedeelde penne moontlik maak.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1-werkgroep — JTAG en grensskandering](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator-dokumentasie](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG-penopsporing](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Ontfoutingskoppelvlakke met min penne vir stelsels met veelvuldige toestelle](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Voetspore vir ontfoutings- en programmeringskabels](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
