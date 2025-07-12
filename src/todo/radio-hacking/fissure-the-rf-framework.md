# FISSURE - Die RF Raamwerk

{{#include ../../banners/hacktricks-training.md}}

**Frekwensie Onafhanklike SDR-gebaseerde Seinbegrip en Omgekeerde Ingenieurswese**

FISSURE is 'n oopbron RF en omgekeerde ingenieurswese raamwerk wat ontwerp is vir alle vaardigheidsvlakke met haakplekke vir sein-detektering en klassifikasie, protokolontdekking, aanvalsuitvoering, IQ-manipulasie, kwesbaarheidanalise, outomatisering, en KI/ML. Die raamwerk is gebou om die vinnige integrasie van sagtewaremodules, radio's, protokolle, seindata, skripte, vloediagramme, verwysingsmateriaal, en derdeparty gereedskap te bevorder. FISSURE is 'n werksvloei-enabler wat sagteware op een plek hou en spanne in staat stel om moeiteloos op hoogte te kom terwyl hulle dieselfde bewese basis konfigurasie vir spesifieke Linux verspreidings deel.

Die raamwerk en gereedskap wat saam met FISSURE ingesluit is, is ontwerp om die teenwoordigheid van RF-energie te detecteer, die eienskappe van 'n sein te verstaan, monsters te versamel en te analiseer, oordrag- en/of inspuittegnieke te ontwikkel, en pasgemaakte payloads of boodskappe te skep. FISSURE bevat 'n groeiende biblioteek van protokol- en seininligting om te help met identifikasie, pakketvorming, en fuzzing. Aanlyn argief vermoëns bestaan om seinlêers af te laai en afspeellys te bou om verkeer te simuleer en stelsels te toets.

Die vriendelike Python-kodebasis en gebruikerskoppelvlak laat beginners toe om vinnig te leer oor gewilde gereedskap en tegnieke wat RF en omgekeerde ingenieurswese betrek. Onderwysers in kuberveiligheid en ingenieurswese kan voordeel trek uit die ingeboude materiaal of die raamwerk gebruik om hul eie werklike toepassings te demonstreer. Ontwikkelaars en navorsers kan FISSURE gebruik vir hul daaglikse take of om hul baanbrekende oplossings aan 'n breër gehoor bloot te stel. Soos bewustheid en gebruik van FISSURE in die gemeenskap groei, sal die omvang van sy vermoëns en die breedte van die tegnologie wat dit insluit ook groei.

**Addisionele Inligting**

* [AIS Bladsy](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Papier](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transkripsie](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Begin

**Gesteunde**

Daar is drie takke binne FISSURE om lêer navigasie makliker te maak en kode redundans te verminder. Die Python2\_maint-3.7 tak bevat 'n kodebasis gebou rondom Python2, PyQt4, en GNU Radio 3.7; die Python3\_maint-3.8 tak is gebou rondom Python3, PyQt5, en GNU Radio 3.8; en die Python3\_maint-3.10 tak is gebou rondom Python3, PyQt5, en GNU Radio 3.10.

|   Bedryfstelsel   |   FISSURE Tak   |
| :----------------: | :------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In-Voortgang (beta)**

Hierdie bedryfstelsels is steeds in beta-status. Hulle is in ontwikkeling en verskeie funksies is bekend om te ontbreek. Items in die installeerder mag met bestaande programme konflik en mag nie installeer totdat die status verwyder is nie.

|     Bedryfstelsel     |    FISSURE Tak   |
| :--------------------: | :--------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Nota: Sekere sagteware gereedskap werk nie vir elke OS nie. Verwys na [Sagteware En Konflikte](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installasie**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Dit sal PyQt-sagteware-afhanklikhede installeer wat benodig word om die installasie-GUI's te begin as hulle nie gevind word nie.

Kies volgende die opsie wat die beste by jou bedryfstelsel pas (moet outomaties gedetecteer word as jou OS by 'n opsie pas).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Dit word aanbeveel om FISSURE op 'n skoon bedryfstelsel te installeer om bestaande konflikte te vermy. Kies al die aanbevole keuselys (Standaardknoppie) om foute te vermy terwyl jy die verskillende gereedskap binne FISSURE gebruik. Daar sal verskeie vrae tydens die installasie wees, meestal wat om verhoogde toestemmings en gebruikersname vra. As 'n item 'n "Verifieer" afdeling aan die einde bevat, sal die installeerder die opdrag wat volg uitvoer en die keuselysitem groen of rooi uitlig, afhangende van of daar enige foute deur die opdrag geproduseer word. Gekontroleerde items sonder 'n "Verifieer" afdeling sal swart bly na die installasie.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Gebruik**

Maak 'n terminal oop en voer in:
```
fissure
```
Verwys na die FISSURE Help-menu vir meer besonderhede oor gebruik.

## Besonderhede

**Komponente**

* Dashboard
* Sentraal Hub (HIPRFISR)
* Teiken Sein Identifikasie (TSI)
* Protokol Ontdekking (PD)
* Stroomgrafiek & Skrip Uitvoerder (FGE)

![komponente](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Vermoe**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Sein Detektor**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulasie**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Sein Soektog**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Patroon Herkenning**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Aanvalle**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Sein Speellys**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Beeld Galery**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Pakket Ontwerp**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integrasie**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Rekenkamer**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Teken**_            |

**Hardeware**

Die volgende is 'n lys van "ondersteunde" hardeware met verskillende vlakke van integrasie:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 mikro
* Open Sniffer
* PlutoSDR

## Lesse

FISSURE kom met verskeie nuttige gidse om bekend te raak met verskillende tegnologieë en tegnieke. Baie sluit stappe in vir die gebruik van verskillende gereedskap wat in FISSURE geïntegreer is.

* [Les1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Les2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Les3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Les4: ESP Borde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Les5: Radiosonde Opsporing](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Les6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Les7: Data Tipes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Les8: Aangepaste GNU Radio Blokke](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Les9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Les10: Ham Radio Eksamens](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Les11: Wi-Fi Gereedskap](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Padkaart

* [ ] Voeg meer hardeware tipes, RF protokolle, sein parameters, analise gereedskap by
* [ ] Ondersteun meer bedryfstelsels
* [ ] Ontwikkel klas materiaal rondom FISSURE (RF Aanvalle, Wi-Fi, GNU Radio, PyQt, ens.)
* [ ] Skep 'n sein voorverwerker, kenmerk ekstrakteerder, en sein klassifiseerder met selekteerbare AI/ML tegnieke
* [ ] Implementeer rekursiewe demodulasie meganismes om 'n bitstroom van onbekende seine te produseer
* [ ] Oorgang van die hoof FISSURE komponente na 'n generiese sensor node ontplooiing skema

## Bydrae

Voorstelle om FISSURE te verbeter word sterk aangemoedig. Laat 'n opmerking in die [Besprekings](https://github.com/ainfosec/FISSURE/discussions) bladsy of in die Discord Bediening as jy enige gedagtes het oor die volgende:

* Nuwe kenmerk voorstelle en ontwerp veranderinge
* Sagteware gereedskap met installasie stappe
* Nuwe lesse of addisionele materiaal vir bestaande lesse
* RF protokolle van belang
* Meer hardeware en SDR tipes vir integrasie
* IQ analise skripte in Python
* Installasie regstellings en verbeterings

Bydraes om FISSURE te verbeter is van kardinale belang om sy ontwikkeling te versnel. Enige bydraes wat jy maak word baie waardeer. As jy wil bydra deur kode ontwikkeling, fork asseblief die repo en skep 'n pull request:

1. Fork die projek
2. Skep jou kenmerk tak (`git checkout -b feature/AmazingFeature`)
3. Commit jou veranderinge (`git commit -m 'Voeg 'n paar AmazingFeature' by`)
4. Push na die tak (`git push origin feature/AmazingFeature`)
5. Maak 'n pull request oop

Om [Probleme](https://github.com/ainfosec/FISSURE/issues) te skep om aandag aan foute te bring word ook verwelkom.

## Samewerking

Kontak Assured Information Security, Inc. (AIS) Besigheidsontwikkeling om enige FISSURE samewerkingsgeleenthede voor te stel en te formaliseer – of dit nou is deur tyd te wy aan die integrasie van jou sagteware, dat die talentvolle mense by AIS oplossings vir jou tegniese uitdagings ontwikkel, of om FISSURE in ander platforms/toepassings te integreer.

## Lisensie

GPL-3.0

Vir lisensie besonderhede, sien LICENSE lêer.

## Kontak

Sluit aan by die Discord Bediening: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Volg op Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Besigheidsontwikkeling - Assured Information Security, Inc. - bd@ainfosec.com

## Krediete

Ons erken en is dankbaar teenoor hierdie ontwikkelaars:

[Krediete](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Erkennings

Spesiale dank aan Dr. Samuel Mantravadi en Joseph Reith vir hul bydraes tot hierdie projek.

{{#include ../../banners/hacktricks-training.md}}
