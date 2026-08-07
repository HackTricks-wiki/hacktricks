# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG maak dit moontlik om ’n boundary scan uit te voer. Die boundary scan ontleed sekere stroombane, insluitend ingebedde boundary-scan-selle en registers vir elke pen.

Die JTAG-standaard definieer **spesifieke opdragte vir die uitvoer van boundary scans**, insluitend die volgende:

- **BYPASS** laat jou toe om ’n spesifieke chip te toets sonder die ekstra las daarvan om deur ander chips te gaan.
- **SAMPLE/PRELOAD** neem ’n monster van die data wat die toestel binnegaan en verlaat wanneer dit in sy normale werkingsmodus is.
- **EXTEST** stel pen-toestande en lees dit.

Dit kan ook ander opdragte ondersteun, soos:

- **IDCODE** om ’n toestel te identifiseer
- **INTEST** vir interne toetsing van die toestel

Jy kan hierdie instruksies teëkom wanneer jy ’n tool soos die JTAGulator gebruik.

### Die Test Access Port

Boundary scans sluit toetse van die vier-draad **Test Access Port (TAP)** in, ’n algemene doelpoort wat **toegang tot die JTAG-toetsondersteunings**-funksies bied wat in ’n komponent ingebou is. TAP gebruik die volgende vyf seine:

- Test clock input (**TCK**) Die TCK is die **klok** wat bepaal hoe gereeld die TAP-beheerder ’n enkele aksie sal uitvoer (met ander woorde, na die volgende toestand in die toestandsmasjien sal spring).
- Test mode select (**TMS**) input TMS beheer die **finite state machine**. Op elke klokslag kontroleer die toestel se JTAG TAP-beheerder die spanning op die TMS-pen. As die spanning onder ’n sekere drempel is, word die sein as laag beskou en as 0 geïnterpreteer, terwyl die sein as hoog beskou en as 1 geïnterpreteer word as die spanning bo ’n sekere drempel is.
- Test data input (**TDI**) TDI is die pen wat **data deur die scan cells die chip instuur**. Elke vendor is verantwoordelik vir die definiëring van die kommunikasieprotokol oor hierdie pen, omdat JTAG dit nie definieer nie.
- Test data output (**TDO**) TDO is die pen wat **data uit die chip stuur**.
- Test reset (**TRST**) input Die opsionele TRST stel die finite state machine **na ’n bekende goeie toestand** terug. Alternatiewelik, as die TMS vir vyf opeenvolgende kloksiklusse op 1 gehou word, voer dit ’n reset uit, op dieselfde manier as wat die TRST-pen sou doen; daarom is TRST opsioneel.

Soms sal jy hierdie penne gemerk op die PCB kan vind. In ander gevalle sal jy hulle dalk moet **vind**.

### Identifisering van JTAG-penne

Die vinnigste maar duurste manier om JTAG-poorte op te spoor, is deur die **JTAGulator** te gebruik, ’n toestel wat spesifiek vir hierdie doel geskep is (hoewel dit **ook UART-pinouts kan opspoor**).

Dit het **24 kanale** wat jy aan die borde se penne kan koppel. Daarna voer dit ’n **BF attack** van al die moontlike kombinasies uit deur **IDCODE**- en **BYPASS**-boundary-scan-opdragte te stuur. As dit ’n antwoord ontvang, vertoon dit die kanaal wat met elke JTAG-sein ooreenstem.

’n Goedkoper maar baie stadiger manier om JTAG-pinouts te identifiseer, is om [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) te gebruik wat op ’n Arduino-versoenbare mikrobeheerder gelaai is.

Met **JTAGenum** sal jy eers die **penne van die probing**-toestel definieer wat jy vir die enumerasie sal gebruik. Jy sal na die toestel se pinout-diagram moet verwys en dan hierdie penne met die toetspunte op jou teikentoestel verbind.

’n **Derde manier** om JTAG-penne te identifiseer, is om die **PCB** vir een van die pinouts te **inspekteer**. In sommige gevalle kan PCBs gerieflik die **Tag-Connect interface** verskaf, wat ’n duidelike aanduiding is dat die bord ook ’n JTAG-connector het. Jy kan sien hoe daardie koppelvlak lyk by [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Daarbenewens kan die inspeksie van die **datasheets van die chipsets op die PCB** pinout-diagramme onthul wat na JTAG-koppelvlakke wys.

## SDW

SWD is ’n ARM-spesifieke protokol wat vir debugging ontwerp is.

Die SWD-koppelvlak vereis **twee penne**: ’n tweerigting-**SWDIO**-sein, wat die ekwivalent van JTAG se **TDI- en TDO-penne en ’n klok** is, en **SWCLK**, wat die ekwivalent van **TCK** in JTAG is. Baie toestelle ondersteun die **Serial Wire or JTAG Debug Port (SWJ-DP)**, ’n gekombineerde JTAG- en SWD-koppelvlak waarmee jy óf ’n SWD- óf JTAG-probe aan die teiken kan koppel.

{{#include ../../banners/hacktricks-training.md}}
