# Die Modbus-protokol

{{#include ../../banners/hacktricks-training.md}}

## Inleiding tot die Modbus-protokol

Die Modbus-protokol is 'n wyd gebruikte protokol in Industrial Automation and Control Systems. Modbus maak kommunikasie tussen verskeie toestelle moontlik, soos programmable logic controllers (PLCs), sensors, aktueerders en ander industriële toestelle. Dit is noodsaaklik om die Modbus-protokol te verstaan, aangesien dit die mees gebruikte kommunikasieprotokol in die ICS is en baie potensiële attack surface bied vir sniffing en selfs die injection van opdragte in PLCs.

Hier word konsepte puntsgewys uiteengesit om konteks oor die protokol en die aard van die werking daarvan te verskaf. Die grootste uitdaging in ICS-sekuriteit is die koste van implementering en opgradering. Hierdie protokolle en standaarde is in die vroeë 80's en 90's ontwerp en word steeds wyd gebruik. Aangesien 'n industrie baie toestelle en verbindings het, is die opgradering van toestelle baie moeilik, wat hackers 'n voordeel bied wanneer hulle met verouderde protokolle werk. Attacks op Modbus is feitlik onvermydelik, aangesien dit sonder opgradering gebruik sal word indien die werking daarvan krities vir die industrie is.

## Die Client-Server-argitektuur

Die Modbus-protokol word tipies in 'n Client Server Architecture gebruik, waar 'n master-toestel (client) kommunikasie met een of meer slave-toestelle (servers) begin. Daar word ook hierna verwys as Master-Slave-argitektuur, wat wyd in elektronika en IoT met SPI, I2C, ensovoorts gebruik word.

## Serial- en Etherent-weergawes

Die Modbus-protokol is ontwerp vir beide Serial Communication sowel as Ethernet Communications. Serial Communication word wyd in legacy-stelsels gebruik, terwyl moderne toestelle Ethernet ondersteun, wat hoë datatempo's bied en meer geskik is vir moderne industriële netwerke.

## Datarepresentasie

Data word in die Modbus-protokol as ASCII of Binary oorgedra, hoewel die binêre formaat gebruik word weens die kompaktheid daarvan met ouer toestelle.

## Funksiekodes

Die ModBus-protokol werk met die oordrag van spesifieke funksiekodes wat gebruik word om PLCs en verskeie beheertoestelle te bedryf. Hierdie gedeelte is belangrik om te verstaan, aangesien replay attacks uitgevoer kan word deur funksiekodes weer oor te dra. Legacy-toestelle ondersteun geen encryption vir data-oordrag nie en het gewoonlik lang drade wat hulle verbind, wat tot tampering met hierdie drade en die vaslegging/injection van data lei.

## Adressering van Modbus

Elke toestel in die netwerk het 'n unieke adres wat noodsaaklik is vir kommunikasie tussen toestelle. Protokolle soos Modbus RTU, Modbus TCP, ensovoorts word gebruik om adressering te implementeer en dien as 'n transport layer vir die data-oordrag. Die data wat oorgedra word, is in die Modbus-protokolformaat en bevat die boodskap.

Verder implementeer Modbus ook foutkontroles om die integriteit van die oorgedraagde data te verseker. Maar die belangrikste is dat Modbus 'n Open Standard is en enigiemand dit in hul toestelle kan implementeer. Dit het daartoe gelei dat hierdie protokol 'n wêreldwye standaard geword het en wyd in die industriële outomatiseringsbedryf gebruik word.

Weens die grootskaalse gebruik daarvan en die gebrek aan opgraderings, bied attacking van Modbus 'n beduidende voordeel met sy attack surface. ICS is sterk afhanklik van kommunikasie tussen toestelle, en enige attacks daarop kan gevaarlik wees vir die werking van industriële stelsels. Attacks soos replay, data injection, data sniffing en leaking, Denial of Service, data forgery, ensovoorts, kan uitgevoer word indien die transmissiemedium deur die aanvaller geïdentifiseer word.

{{#include ../../banners/hacktricks-training.md}}
