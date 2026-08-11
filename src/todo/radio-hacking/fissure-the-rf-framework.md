# FISSURE - Die RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE is 'n open-source RF- en reverse-engineering-framework wat vir alle vaardigheidsvlakke ontwerp is, met hooks vir seinbespeuring en -klassifikasie, protokolontdekking, aanvaluitvoering, IQ-manipulasie, kwesbaarheidsanalise, outomatisering en AI/ML. Die framework is gebou om die vinnige integrasie van sagtewaremodules, radio's, protokolle, seindata, scripts, flow graphs, verwysingsmateriaal en derdepartytools te bevorder. FISSURE is 'n workflow-enabler wat sagteware op een plek hou en spanne in staat stel om moeiteloos op hoogte te kom terwyl hulle dieselfde bewese basislynkonfigurasie vir spesifieke Linux-distributions deel.<sup>[[1]](#references)[[2]](#references)</sup>

Die framework en tools wat by FISSURE ingesluit is, is ontwerp om RF-energie te bespeur, seine te karakteriseer, samples te versamel en te analiseer, transmit- of injection-tegnieke te ontwikkel, en custom payloads of boodskappe saam te stel. FISSURE verskaf ook protokol- en seininligting vir identifikasie, packet crafting en fuzzing, plus archives en playlists vir traffic-simulasie en -testing.<sup>[[1]](#references)[[2]](#references)</sup>

Die Python-codebase en grafiese interface help beginners om RF- en reverse-engineering-tools aan te leer. Educators kan die ingeboude lessons gebruik, terwyl developers en researchers hul eie modules en workflows kan integreer. Huidige releases ondersteun ook distributed sensor nodes, TAK-integrasie, geolocation-workflows en role-specific Apptainer-deployments.<sup>[[1]](#references)[[3]](#references)</sup>

**Bykomende Inligting**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Aan die gang kom

**Ondersteun**

Huidige FISSURE gebruik die **`Python3`**-branch vir aktiewe ontwikkeling met PyQt5 en GNU Radio 3.8 of 3.10. Die deprecated **`Python2_maint-3.7`**-branch bly beskikbaar vir ouer operating systems en third-party tools wat GNU Radio 3.7 vereis. Die voormalige `Python3_maint-3.8`- en `Python3_maint-3.10`-branchnames is histories; GNU Radio-maintenance selection word nou vanaf die `Python3`-branch hanteer.<sup>[[1]](#references)[[3]](#references)</sup>

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | use a supported Linux version | use the matching version |

**In-ontwikkeling (beta)**

Hierdie operating systems is steeds in beta-status. Hulle is onder ontwikkeling en daar is bekend dat verskeie features ontbreek. Items in die installer kan met bestaande programme konflik of dalk nie installeer nie totdat die status verwyder word.

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Sekere third-party tools werk nie op elke OS nie. Gaan die huidige [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts)-documentation na voordat jy installeer.<sup>[[3]](#references)</sup>

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
Die submodule-stap laai die GNU Radio out-of-tree modules af wat deur FISSURE gebruik word en is nodig wanneer daardie modules geïnstalleer word. Die installer sal ook ontbrekende PyQt-dependencies installeer wat nodig is om die installasie-GUI's te begin.<sup>[[3]](#references)</sup>

Kies vervolgens die opsie wat die beste by jou bedryfstelsel pas (dit behoort outomaties opgespoor te word indien jou bedryfstelsel met ’n opsie ooreenstem).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Dit word aanbeveel om FISSURE op ’n skoon bedryfstelsel te installeer om bestaande konflik te vermy. Kies al die aanbevole merkblokkies (Default-knoppie) om foute te vermy wanneer die verskillende tools binne FISSURE gebruik word. Daar sal tydens die installasie verskeie versoeke verskyn, meestal vir verhoogde toestemmings en gebruikersname. Indien ’n item ’n "Verify"-afdeling aan die einde bevat, sal die installer die daaropvolgende command uitvoer en die merkblokkie-item groen of rooi uitlig, afhangend van of die command enige foute oplewer. Gemerkte items sonder ’n "Verify"-afdeling sal ná die installasie swart bly.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Gebruik**

Maak ’n terminal oop en voer in:
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

![komponente](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Vermoëns**

| ![Seindetektor-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Seindetektor**_ | ![IQ-manipulasie-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ-manipulasie**_      | ![Seinopsoek-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Seinopsoek**_          | ![Patroonherkenning-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Patroonherkenning**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Aanval-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Aanvalle**_           | ![Fuzzing-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Seinsnitlys-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Seinsnitlyste**_       | ![Beeldgalery-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Beeldgalery**_  |
| ![Pakketskepping-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Pakketskepping**_   | ![Scapy-integrasie-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy-integrasie**_ | ![CRC-sakrekenaar-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC-sakrekenaar**_ | ![Aantekening-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Aantekening**_            |

**Hardeware**

Die volgende hardeware het verskillende vlakke van integrasie in FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lesse

FISSURE bevat verskeie nuttige gidse om met verskillende tegnologieë en tegnieke vertroud te raak. Baie daarvan sluit stappe in vir die gebruik van verskeie nutsmiddels wat in FISSURE geïntegreer is.

* [Les1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Les2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Les3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Les4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Les5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Les6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Les7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Les8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Les9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Les10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Les11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Les12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Les13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Les14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Padkaart

* [ ] Voeg meer hardewaretipes, RF-protokolle, seinparameters en analisernutsmiddels by
* [ ] Ondersteun meer bedryfstelsels
* [ ] Ontwikkel klasmateriaal rondom FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, ens.)
* [ ] Skep ’n seinversorger, kenmerkonttrekker en seinklassifiseerder met kiesbare AI/ML-tegnieke
* [ ] Implementeer rekursiewe demodulasiemeganismes om ’n bitstroom uit onbekende seine te produseer
* [ ] Skakel die hoofkomponente van FISSURE oor na ’n generiese sensor-node-ontplooiingskema

## Bydraes

Voorstelle om FISSURE te verbeter word sterk aangemoedig. Laat ’n opmerking op die [Discussions](https://github.com/ainfosec/FISSURE/discussions)-bladsy of in die Discord Server indien jy enige idees oor die volgende het:

* Voorstelle vir nuwe kenmerke en ontwerpveranderings
* Software tools met installasiestappe
* Nuwe lesse of bykomende materiaal vir bestaande lesse
* RF-protokolle van belang
* Meer hardeware- en SDR-tipes vir integrasie
* IQ-ontledingskripte in Python
* Installasieregstellings en -verbeterings

Bydraes om FISSURE te verbeter is noodsaaklik om die ontwikkeling daarvan te versnel. Enige bydraes wat jy maak, word grootliks waardeer. Indien jy deur kode-ontwikkeling wil bydra, forking die repo en skep ’n pull request:

1. Fork die projek
2. Skep jou feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit jou veranderinge (`git commit -m 'Add some AmazingFeature'`)
4. Push na die branch (`git push origin feature/AmazingFeature`)
5. Open ’n pull request

Dit word ook verwelkom om [Issues](https://github.com/ainfosec/FISSURE/issues) te skep om aandag op bugs te vestig.

## Samewerking

Kontak Assured Information Security, Inc. (AIS) se Business Development-afdeling om enige FISSURE-samewerkingsgeleenthede voor te stel en te formaliseer–hetsy deur tyd daaraan te wy om jou software te integreer, deur die talentvolle mense by AIS oplossings vir jou tegniese uitdagings te laat ontwikkel, of deur FISSURE in ander platforms/toepassings te integreer.

## Lisensie

GPL-3.0

Vir lisensiebesonderhede, sien die LICENSE-lêer.

## Kontak

Sluit by die Discord Server aan: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Volg op Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Erkennings

Ons erken en waardeer hierdie ontwikkelaars:

[Erkennings](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Bedankings

Spesiale dank aan Dr. Samuel Mantravadi en Joseph Reith vir hul bydraes tot hierdie projek.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
