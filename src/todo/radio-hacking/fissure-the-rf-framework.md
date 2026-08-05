# FISSURE - Die RF-raamwerk

{{#include ../../banners/hacktricks-training.md}}

**Frekwensie-onafhanklike SDR-gebaseerde seinbegrip en reverse engineering**

FISSURE is 'n open-source RF- en reverse engineering-raamwerk wat vir alle vaardigheidsvlakke ontwerp is, met hooks vir seindetectie en -klassifikasie, protokolontdekking, aanvaluitvoering, IQ-manipulasie, kwesbaarheidsontleding, outomatisering en AI/ML. Die raamwerk is gebou om die vinnige integrasie van sagtewaremodules, radio's, protokolle, seindata, scripts, vloeigrafieke, verwysingsmateriaal en derdeparty-nutsgoed te bevorder. FISSURE is 'n werksvloei-fasiliteerder wat sagteware op een plek hou en spanne in staat stel om moeiteloos op hoogte te kom terwyl hulle dieselfde bewese basislynkonfigurasie vir spesifieke Linux-distribusies deel.<sup>[[1]](#references)[[2]](#references)</sup>

Die raamwerk en nutsgoed wat by FISSURE ingesluit is, is ontwerp om die teenwoordigheid van RF-energie te detecteer, die eienskappe van 'n sein te verstaan, samples te versamel en te ontleed, transmit- en/of injection-tegnieke te ontwikkel, en pasgemaakte payloads of boodskappe te skep. FISSURE bevat 'n groeiende biblioteek van protokol- en seininligting om met identifikasie, packet crafting en fuzzing te help. Aanlynargieffunksionaliteit is beskikbaar om seëlêers af te laai en playlists te bou om verkeer te simuleer en stelsels te toets.

Die gebruikersvriendelike Python-kodebasis en gebruikerskoppelvlak stel beginners in staat om vinnig van gewilde nutsgoed en tegnieke rakende RF en reverse engineering te leer. Opvoeders in kuberveiligheid en ingenieurswese kan die ingeboude materiaal benut of die raamwerk gebruik om hul eie werklike toepassings te demonstreer. Ontwikkelaars en navorsers kan FISSURE vir hul daaglikse take gebruik of dit aanwend om hul voorpuntoplossings aan 'n wyer gehoor bloot te stel. Namate bewustheid en gebruik van FISSURE in die gemeenskap groei, sal die omvang van sy vermoëns en die breedte van die tegnologie wat dit omvat ook toeneem.

**Bykomende inligting**

* [AIS-bladsy](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22-skyfies](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22-artikel](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22-video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat-transkripsie](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Aan die gang kom

**Ondersteun**

Daar is drie branches binne FISSURE om lêernavigasie makliker te maak en koderedundansie te verminder. Die Python2\_maint-3.7 branch bevat 'n kodebasis wat rondom Python2, PyQt4 en GNU Radio 3.7 gebou is; die Python3\_maint-3.8 branch is rondom Python3, PyQt5 en GNU Radio 3.8 gebou; en die Python3\_maint-3.10 branch is rondom Python3, PyQt5 en GNU Radio 3.10 gebou.

|   Bedryfstelsel   |   FISSURE-branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In ontwikkeling (beta)**

Hierdie bedryfstelsels is steeds in beta-status. Hulle is onder ontwikkeling en dit is bekend dat verskeie funksies ontbreek. Items in die installer kan met bestaande programme bots of nie installeer nie totdat die status verwyder word.

|     Bedryfstelsel     |    FISSURE-branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Nota: Sekere sagteware-nutsgoed werk nie op elke bedryfstelsel nie. Verwys na [Sagteware en konflikte](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installasie**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Dit sal die PyQt-sagtewareafhanklikhede installeer wat nodig is om die installasie-GUI's te begin indien hulle nie gevind word nie.

Kies vervolgens die opsie wat die beste by jou bedryfstelsel pas (dit behoort outomaties bespeur te word indien jou bedryfstelsel met 'n opsie ooreenstem).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Dit word aanbeveel om FISSURE op 'n skoon bedryfstelsel te installeer om bestaande konflikte te vermy. Kies al die aanbevole merkblokkies (Default-knoppie) om foute te vermy wanneer die verskillende nutsgoed binne FISSURE gebruik word. Daar sal verskeie versoeke tydens die installasie verskyn, meestal om verhoogde toestemmings en gebruikersname te vra. Indien 'n item 'n "Verify"-afdeling aan die einde bevat, sal die installeerder die daaropvolgende opdrag uitvoer en die merkblokkie-item groen of rooi uitlig, afhangend daarvan of die opdrag enige foute lewer. Gemerkte items sonder 'n "Verify"-afdeling sal ná die installasie swart bly.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Gebruik**

Maak 'n terminaal oop en voer in:
```
fissure
```
Verwys na die FISSURE Help-menu vir meer besonderhede oor gebruik.

## Besonderhede

**Komponente**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Vermoëns**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardeware**

Die volgende is ’n lys van “ondersteunde” hardeware met wisselende vlakke van integrasie:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lesse

FISSURE bevat verskeie nuttige gidse om vertroud te raak met verskillende tegnologieë en tegnieke. Baie daarvan bevat stappe vir die gebruik van verskeie tools wat in FISSURE geïntegreer is.

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Padkaart

* [ ] Voeg meer hardewaretipes, RF-protokolle, seinparameters en analise-tools by
* [ ] Ondersteun meer bedryfstelsels
* [ ] Ontwikkel klasmateriaal rondom FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, ens.)
* [ ] Skep ’n seinconditioner, feature extractor en seinclassifier met kiesbare AI/ML-tegnieke
* [ ] Implementeer rekursiewe demodulation-meganismes om ’n bitstream uit onbekende seine te produseer
* [ ] Skakel die hoof-FISSURE-komponente oor na ’n generiese sensor node-ontplooiingskema

## Bydraes

Voorstelle om FISSURE te verbeter, word sterk aangemoedig. Laat ’n opmerking op die [Discussions](https://github.com/ainfosec/FISSURE/discussions)-bladsy of in die Discord Server indien jy enige gedagtes oor die volgende het:

* Voorstelle vir nuwe features en ontwerpwysigings
* Software tools met installasiestappe
* Nuwe lesse of bykomende materiaal vir bestaande lesse
* RF-protokolle van belang
* Meer hardeware- en SDR-tipes vir integrasie
* IQ-analise-skripte in Python
* Regstellings en verbeterings aan die installasie

Bydraes om FISSURE te verbeter, is noodsaaklik om die ontwikkeling daarvan te versnel. Enige bydraes wat jy maak, word opreg waardeer. Indien jy deur kode-ontwikkeling wil bydra, fork die repo en skep ’n pull request:

1. Fork die projek
2. Skep jou feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit jou veranderinge (`git commit -m 'Add some AmazingFeature'`)
4. Push na die branch (`git push origin feature/AmazingFeature`)
5. Open ’n pull request

Die skep van [Issues](https://github.com/ainfosec/FISSURE/issues) om aandag op bugs te vestig, word ook verwelkom.

## Samewerking

Kontak Assured Information Security, Inc. (AIS) se Business Development-afdeling om enige FISSURE-samewerkingsgeleenthede voor te stel en te formaliseer – hetsy deur tyd daaraan te wy om jou software te integreer, die talentvolle mense by AIS oplossings vir jou tegniese uitdagings te laat ontwikkel, of FISSURE in ander platforms/applications te integreer.

## Lisensie

GPL-3.0

Vir lisensiebesonderhede, sien die LICENSE-lêer.

## Kontak

Sluit by die Discord Server aan: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Volg op Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Krediete

Ons erken en waardeer hierdie developers:

[Krediete](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Erkennings

Spesiale dank aan Dr. Samuel Mantravadi en Joseph Reith vir hul bydraes tot hierdie projek.

## Verwysings

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
