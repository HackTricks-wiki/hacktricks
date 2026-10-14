# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE is ’n oopbron-RF- en reverse engineering-framework wat vir alle vaardigheidsvlakke ontwerp is, met hooks vir seinopsporing en -klassifikasie, protokolontdekking, aanvaluitvoering, IQ-manipulasie, kwesbaarheidsontleding, outomatisering en AI/ML. Die framework is gebou om die vinnige integrasie van sagtewaremodules, radio’s, protokolle, seindata, skripte, vloeigrafieke, verwysingsmateriaal en derdeparty-nutsmiddels te bevorder. FISSURE maak werkvloeie moontlik deur sagteware op een plek te hou en spanne in staat te stel om vinnig aan die gang te kom terwyl hulle dieselfde beproefde basisopstelling vir spesifieke Linux-verspreidings deel.<sup>[[1]](#references)[[2]](#references)</sup>

Die framework en nutsmiddels wat by FISSURE ingesluit is, is ontwerp om RF-energie op te spoor, seine te karakteriseer, monsters in te samel en te ontleed, tegnieke vir uitsending of inspuiting te ontwikkel, en pasgemaakte payloads of boodskappe te skep. FISSURE verskaf ook protokol- en seininligting vir identifikasie, pakketskepping en fuzzing, plus argiewe en snitlyste vir verkeersimulasie en toetsing.<sup>[[1]](#references)[[2]](#references)</sup>

Die Python-kodebasis en grafiese koppelvlak help beginners om RF- en reverse-engineering-nutsmiddels te leer. Opvoeders kan die ingeboude lesse gebruik, terwyl ontwikkelaars en navorsers hul eie modules en werkvloeie kan integreer. Huidige vrystellings ondersteun ook verspreide sensornodusse, TAK-integrasie, geoligging-werkvloeie en rolspesifieke Apptainer-ontplooiings.<sup>[[1]](#references)[[3]](#references)</sup>

**Bykomende inligting**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Aan die gang

**Ondersteun**

Huidige FISSURE gebruik die **`Python3`**-tak vir aktiewe ontwikkeling met PyQt5 en GNU Radio 3.8 of 3.10. Die verouderde **`Python2_maint-3.7`**-tak bly beskikbaar vir ouer bedryfstelsels en derdeparty-nutsmiddels wat GNU Radio 3.7 vereis. Die voormalige takname `Python3_maint-3.8` en `Python3_maint-3.10` is histories; die keuse van GNU Radio-onderhoudstak word nou vanuit die `Python3`-tak hanteer.<sup>[[1]](#references)[[3]](#references)</sup>

| Bedryfstelsel | FISSURE-tak | Verstek GNU Radio-tak |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | gebruik ’n ondersteunde Linux-weergawe | gebruik die ooreenstemmende weergawe |

**In ontwikkeling (beta)**

Hierdie bedryfstelsels is steeds in beta-status. Hulle is onder ontwikkeling en daar is bekend dat verskeie kenmerke ontbreek. Items in die installeerder kan met bestaande programme bots of dalk nie installeer voordat die status verwyder word nie.

| Bedryfstelsel | FISSURE-tak | Verstek GNU Radio-tak |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Sekere derdeparty-nutsmiddels werk nie op elke bedryfstelsel nie. Gaan die huidige dokumentasie oor [bekende konflikte en derdeparty-sagteware](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) na voordat jy installeer.<sup>[[3]](#references)</sup>

**Installasie**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

Die submodule-stap laai die GNU Radio out-of-tree-modules af wat deur FISSURE gebruik word, en is nodig wanneer daardie modules geïnstalleer word. Die installeerder sal ook ontbrekende PyQt-afhanklikhede installeer wat nodig is om die installasie-GUI's te begin.<sup>[[3]](#references)</sup>

Kies vervolgens die opsie wat die beste by jou bedryfstelsel pas (dit behoort outomaties opgespoor te word as jou bedryfstelsel by een van die opsies pas).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Dit word aanbeveel om FISSURE op 'n skoon bedryfstelsel te installeer om bestaande konflikte te vermy. Kies al die aanbevole merkblokkies (Default-knoppie) om foute te voorkom wanneer jy die verskillende nutsmiddels binne FISSURE gebruik. Tydens die installasie sal daar verskeie aanwysings verskyn, meestal versoeke om verhoogde regte en gebruikersname. As 'n item 'n "Verify"-afdeling aan die einde bevat, sal die installeerder die daaropvolgende opdrag uitvoer en die merkblokkie groen of rooi uitlig, afhangend van of die opdrag foute oplewer. Gemerkte items sonder 'n "Verify"-afdeling sal ná die installasie swart bly.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Gebruik**

Maak 'n terminaal oop en voer in:

```
fissure
```

Raadpleeg die FISSURE Help-kieslys vir meer besonderhede oor die gebruik.

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
| ![Pakketvervaardiging-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Pakketvervaardiging**_   | ![Scapy-integrasie-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy-integrasie**_ | ![CRC-sakrekenaar-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC-sakrekenaar**_ | ![Logboekhouding-ikoon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logboekhouding**_            |

**Hardeware**

Die volgende hardeware het verskillende vlakke van integrasie in FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11-adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lesse

FISSURE bevat verskeie nuttige gidse om vertroud te raak met verskillende tegnologieë en tegnieke. Baie daarvan bevat stappe vir die gebruik van verskeie nutsmiddels wat in FISSURE geïntegreer is.

* [Les1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Les2: Lua-dissektors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Les3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Les4: ESP-borde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Les5: Radiosonde-opsporing](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Les6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Les7: Datatipes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Les8: Pasgemaakte GNU Radio-blokke](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Les9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Les10: Hamradio-eksamens](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Les11: Wi-Fi-nutsmiddels](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Les12: Skep van selflaaibare USB's](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Les13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Les14: Plafonwaaiers](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Padkaart

* [ ] Voeg meer hardewaretipes, RF-protokolle, seinparameters en ontledingsnutsmiddels by
* [ ] Ondersteun meer bedryfstelsels
* [ ] Ontwikkel klasmateriaal oor FISSURE (RF-aanvalle, Wi-Fi, GNU Radio, PyQt, ens.)
* [ ] Skep 'n seintoestandingsmodule, kenmerkonttrekker en seinklassifiseerder met kiesbare AI/ML-tegnieke
* [ ] Implementeer rekursiewe demodulasiemeganismes om 'n bitstroom uit onbekende seine te produseer
* [ ] Skakel die hoofkomponente van FISSURE oor na 'n generiese sensorskema vir ontplooiing

## Bydrae lewer

Voorstelle om FISSURE te verbeter, word sterk aangemoedig. Laat 'n opmerking op die [Besprekings](https://github.com/ainfosec/FISSURE/discussions)-bladsy of in die Discord-bediener as jy enige idees oor die volgende het:

* Voorstelle vir nuwe kenmerke en ontwerpveranderinge
* Sagtewarenutsmiddels met installasiestappe
* Nuwe lesse of bykomende materiaal vir bestaande lesse
* RF-protokolle van belang
* Meer hardeware- en SDR-tipes vir integrasie
* IQ-ontledingskripte in Python
* Regstellings en verbeterings vir installasie

Bydraes om FISSURE te verbeter, is noodsaaklik om die ontwikkeling daarvan te bespoedig. Enige bydraes wat jy maak, word opreg waardeer. As jy deur kode-ontwikkeling wil bydra, fork die repo en skep 'n pull request:

1. Fork die projek
2. Skep jou feature-tak (`git checkout -b feature/AmazingFeature`)
3. Commit jou veranderinge (`git commit -m 'Add some AmazingFeature'`)
4. Push na die tak (`git push origin feature/AmazingFeature`)
5. Open 'n pull request

Dit word ook verwelkom dat jy [Issues](https://github.com/ainfosec/FISSURE/issues) skep om aandag op foute te vestig.

## Samewerking

Kontak Assured Information Security, Inc. (AIS) se Besigheidsontwikkeling-afdeling om enige samewerkingsgeleenthede met FISSURE voor te stel en te formaliseer—hetsy deur tyd af te staan om jou sagteware te integreer, die bekwame mense by AIS oplossings vir jou tegniese uitdagings te laat ontwikkel, of FISSURE in ander platforms/toepassings te integreer.

## Lisensie

GPL-3.0

Vir lisensiebesonderhede, sien die LICENSE-lêer.

## Kontak

Sluit by die Discord-bediener aan: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Volg op Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Besigheidsontwikkeling - Assured Information Security, Inc. - bd@ainfosec.com

## Erkennings

Ons erken en bedank hierdie ontwikkelaars:

[Erkennings](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Dankbetuigings

Spesiale dank aan Dr. Samuel Mantravadi en Joseph Reith vir hul bydraes tot hierdie projek.

## References

- [1] [FISSURE - Die RF-raamwerk (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE-artikel (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE-dokumentasie - Installasie](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
