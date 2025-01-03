# Die Modbus Protokol

## Inleiding tot die Modbus Protokol

Die Modbus-protokol is 'n wyd gebruikte protokol in Industriële Outomatisering en Beheerstelsels. Modbus stel kommunikasie tussen verskeie toestelle soos programmeerbare logika-beheerders (PLC's), sensors, actuators en ander industriële toestelle moontlik. Om die Modbus-protokol te verstaan, is noodsaaklik, aangesien dit die mees gebruikte kommunikasieprotokol in die ICS is en 'n groot potensiële aanvalsvlak het vir sniffing en selfs die inspuiting van opdragte in PLC's.

Hier word konsepte puntgewys uiteengesit om die konteks van die protokol en sy werking te verskaf. Die grootste uitdaging in ICS-stelselsekuriteit is die koste van implementering en opgradering. Hierdie protokolle en standaarde is in die vroeë 80's en 90's ontwerp en word steeds wyd gebruik. Aangesien 'n industrie baie toestelle en verbindings het, is dit baie moeilik om toestelle op te gradeer, wat hackers 'n voordeel gee om met verouderde protokolle te werk. Aanvalle op Modbus is prakties onontkombaar, aangesien dit gebruik gaan word sonder opgradering, en sy werking is krities vir die industrie.

## Die Kliënt-Server Argitektuur

Modbus-protokol word tipies gebruik in 'n Kliënt-Server Argitektuur waar 'n meester toestel (kliënt) kommunikasie met een of meer slaaf toestelle (bedieners) begin. Dit word ook as Meester-Slaaf argitektuur verwys, wat wyd in elektronika en IoT met SPI, I2C, ens. gebruik word.

## Serial en Ethernet Weergawes

Modbus-protokol is ontwerp vir beide, Seriële Kommunikasie sowel as Ethernet Kommunikasies. Die Seriële Kommunikasie word wyd in erfenisstelsels gebruik, terwyl moderne toestelle Ethernet ondersteun wat hoë datarates bied en meer geskik is vir moderne industriële netwerke.

## Data Verteenwoordiging

Data word in die Modbus-protokol as ASCII of Binêr oorgedra, alhoewel die binêre formaat gebruik word weens sy kompakteerbaarheid met ouer toestelle.

## Funksiekodes

ModBus-protokol werk met die oordrag van spesifieke funksiekodes wat gebruik word om die PLC's en verskeie beheertoestelle te bedryf. Hierdie gedeelte is belangrik om te verstaan, aangesien herhalingsaanvalle gedoen kan word deur funksiekodes weer te stuur. Erfenistoestelle ondersteun nie enige versleuteling vir datatransmissie nie en het gewoonlik lang drade wat hulle verbind, wat lei tot die manipulasie van hierdie drade en die vang/inspuiting van data.

## Adressering van Modbus

Elke toestel in die netwerk het 'n unieke adres wat noodsaaklik is vir kommunikasie tussen toestelle. Protokolle soos Modbus RTU, Modbus TCP, ens. word gebruik om adressering te implementeer en dien as 'n vervoervlak vir die datatransmissie. Die data wat oorgedra word, is in die Modbus-protokol formaat wat die boodskap bevat.

Boonop implementeer Modbus ook foutkontroles om die integriteit van die oorgedrade data te verseker. Maar die meeste van alles, Modbus is 'n Open Standard en enige iemand kan dit in hul toestelle implementeer. Dit het hierdie protokol 'n globale standaard gemaak en dit is wydverspreid in die industriële outomatiseringsbedryf.

As gevolg van sy groot skaal gebruik en gebrek aan opgraderings, bied die aanval op Modbus 'n beduidende voordeel met sy aanvalsvlak. ICS is hoogs afhanklik van kommunikasie tussen toestelle en enige aanvalle wat daarop gemaak word, kan gevaarlik wees vir die werking van die industriële stelsels. Aanvalle soos herhaling, datainspuiting, datasniffing en lek, Denial of Service, data vervalsing, ens. kan uitgevoer word as die medium van transmissie deur die aanvaller geïdentifiseer word.
