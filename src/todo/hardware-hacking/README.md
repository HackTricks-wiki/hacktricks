# Hardeware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG laat 'n grensskandering toe. Die grensskandering analiseer sekere stroombane, insluitend ingebedde grensskandeercelle en registers vir elke pen.

Die JTAG-standaard definieer **spesifieke opdragte vir die uitvoering van grensskanderings**, insluitend die volgende:

- **BYPASS** laat jou toe om 'n spesifieke skyf te toets sonder die oorhoofse koste van die deurgee van ander skywe.
- **SAMPLE/PRELOAD** neem 'n monster van die data wat die toestel binnekom en verlaat wanneer dit in sy normale funksioneringsmodus is.
- **EXTEST** stel en lees penstate.

Dit kan ook ander opdragte ondersteun soos:

- **IDCODE** vir die identifisering van 'n toestel
- **INTEST** vir die interne toetsing van die toestel

Jy mag hierdie instruksies teëkom wanneer jy 'n hulpmiddel soos die JTAGulator gebruik.

### Die Toets Toegang Poort

Grensskanderings sluit toetse van die vier-draad **Toets Toegang Poort (TAP)** in, 'n algemene poort wat **toegang tot die JTAG toetsondersteuning** funksies wat in 'n komponent ingebou is, bied. TAP gebruik die volgende vyf seine:

- Toets klok invoer (**TCK**) Die TCK is die **klok** wat definieer hoe gereeld die TAP-beheerder 'n enkele aksie sal neem (met ander woorde, na die volgende toestand in die toestandmasjien spring).
- Toets modus seleksie (**TMS**) invoer TMS beheer die **eindige toestandmasjien**. Op elke klop van die klok, kontroleer die toestel se JTAG TAP-beheerder die spanning op die TMS-pen. As die spanning onder 'n sekere drempel is, word die sein as laag beskou en as 0 geïnterpreteer, terwyl, as die spanning bo 'n sekere drempel is, die sein as hoog beskou word en as 1 geïnterpreteer word.
- Toets data invoer (**TDI**) TDI is die pen wat **data in die skyf deur die skandeercelle** stuur. Elke verskaffer is verantwoordelik vir die definisie van die kommunikasieprotokol oor hierdie pen, omdat JTAG dit nie definieer nie.
- Toets data uitvoer (**TDO**) TDO is die pen wat **data uit die skyf** stuur.
- Toets reset (**TRST**) invoer Die opsionele TRST reset die eindige toestandmasjien **na 'n bekende goeie toestand**. Alternatiewelik, as die TMS op 1 gehou word vir vyf agtereenvolgende klok siklusse, roep dit 'n reset op, op dieselfde manier as wat die TRST-pen sou doen, wat die rede is waarom TRST opsioneel is.

Soms sal jy in staat wees om daardie penne op die PCB gemerk te vind. In ander gevalle mag jy moet **hulle vind**.

### Identifisering van JTAG penne

Die vinnigste maar duurste manier om JTAG-poorte te detecteer, is deur die gebruik van die **JTAGulator**, 'n toestel wat spesifiek vir hierdie doel geskep is (alhoewel dit **ook UART pinouts kan opspoor**).

Dit het **24 kanale** wat jy aan die bord se penne kan koppel. Dan voer dit 'n **BF-aanval** van al die moontlike kombinasies uit deur **IDCODE** en **BYPASS** grensskandeeropdragte te stuur. As dit 'n antwoord ontvang, vertoon dit die kanaal wat ooreenstem met elke JTAG sein.

'n Goedkoper maar baie stadiger manier om JTAG pinouts te identifiseer, is deur die [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) wat op 'n Arduino-ondersteunde mikrobeheerder gelaai is.

Met **JTAGenum**, sal jy eers die **penne van die proef toestel** wat jy vir die enumerasie gaan gebruik, moet **definieer**. Jy sal die toestel se penuitdiagram moet verwys, en dan hierdie penne met die toetspunte op jou teiken toestel verbind.

'n **Derde manier** om JTAG penne te identifiseer, is deur die **PCB te inspekteer** vir een van die pinouts. In sommige gevalle mag PCB's gerieflik die **Tag-Connect interface** bied, wat 'n duidelike aanduiding is dat die bord ook 'n JTAG-connector het. Jy kan sien hoe daardie interface lyk by [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Boonop mag die inspeksie van die **datasheets van die chipsets op die PCB** pinuitdiagramme onthul wat na JTAG interfaces dui.

## SDW

SWD is 'n ARM-spesifieke protokol wat ontwerp is vir foutopsporing.

Die SWD-interface vereis **twee penne**: 'n bidireksionele **SWDIO** sein, wat die ekwivalent is van JTAG se **TDI en TDO penne en 'n klok**, en **SWCLK**, wat die ekwivalent is van **TCK** in JTAG. Baie toestelle ondersteun die **Serial Wire of JTAG Debug Port (SWJ-DP)**, 'n gekombineerde JTAG en SWD-interface wat jou in staat stel om óf 'n SWD óf JTAG-sonde aan die teiken te koppel.

{{#include ../../banners/hacktricks-training.md}}
