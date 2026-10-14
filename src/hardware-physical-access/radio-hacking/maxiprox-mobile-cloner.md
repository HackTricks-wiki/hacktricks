# Bou van ’n draagbare HID MaxiProx 125 kHz mobiele kloner

{{#include ../../banners/hacktricks-training.md}}

## Doel
Verander ’n netaangedrewe HID MaxiProx 5375-langafstandleser van 125 kHz in ’n veldontplooibare, battery-aangedrewe kentekenkloner wat nabyheidskaarte ongemerk insamel tydens fisiese-sekuriteitsassesserings.

Die omskakeling hier is gebaseer op TrustedSec se navorsingsreeks “Kom ons kloon ’n kloner – Deel 3: Sit alles bymekaar” en kombineer meganiese, elektriese en RF-oorwegings sodat die finale toestel in ’n rugsak gepak en onmiddellik op die perseel gebruik kan word.<sup>[[1]](#references)</sup>

> [!warning]
> Werk aan netaangedrewe toerusting en litiumioon-kragbanke kan gevaarlik wees. Verifieer elke verbinding **voordat** jy die stroombaan van krag voorsien, en hou die antennas, koaksiale kabels en grondvlakke presies soos in die fabrieksontwerp om te voorkom dat die leser se afstemming verander.

## Materiaallys (BOM)

* HID MaxiProx 5375-leser (of enige 12 V HID Prox®-langafstandleser)
* ESP RFID Tool v2.2 (Wiegand-snuffelaar/-logboekhouer gebaseer op ESP32)
* USB-PD (Power-Delivery)-snellermodule wat 12 V @ ≥3 A kan onderhandel
* 100 W USB-C-kragbank (lewer 12 V PD-profiel)
* 26 AWG-silikoongeïsoleerde verbindingsdraad – rooi/wit
* SPST-wisselskakelaar vir paneelmontering (vir die gonser-afskakelskakelaar)
* NKK AT4072-skakelaarbeskermer / ongelukvaste dop
* Soldeerbout, soldeerlont en desoldeerpomp
* ABS-geskikte handgereedskap: figuursaag, nutsmes, plat- en halfronde lêers
* Boorpunte 1/16″ (1.5 mm) en 1/8″ (3 mm)
* 3 M VHB-dubbelzijdige kleefband en kabelbinders

## 1. Krag-substelsel

1. Desoldeer en verwyder die fabrieks-buck converter-dogterbord wat gebruik word om 5 V vir die logikaplaat te lewer.
2. Monteer ’n USB-PD-sneller langs die ESP RFID Tool en lei die USB-C-aansluiting van die sneller na die buitekant van die omhulsel.
3. Die PD-sneller onderhandel 12 V vanaf die kragbank en voer dit direk na die MaxiProx (die leser verwag van nature 10–14 V). ’n Sekondêre 5 V-rail word vanaf die ESP-bord geneem om enige bykomstighede van krag te voorsien.
4. Die 100 W-batterypak word gelyk met die interne afstandhouer geplaas, sodat daar **geen** kragkabels oor die ferrietantenna hang nie en RF-werkverrigting behoue bly.

## 2. Gonserskakelaar – Stil werking

1. Vind die twee luidspreker-kontakblokkies op die MaxiProx-logikaplaat.
2. Verwyder die soldeersel van *albei* kontakblokkies, en soldeer dan net die **negatiewe** kontakblokkie weer vas.
3. Soldeer 26 AWG-drade (wit = negatief, rooi = positief) aan die gonserkontakblokkies en lei hulle deur ’n nuutgesnyde gleuf na ’n SPST-skakelaar vir paneelmontering.
4. Wanneer die skakelaar oop is, word die gonserstroombaan onderbreek en werk die leser heeltemal stil – ideaal vir die ongemerkte insameling van kentekens.
5. Pas ’n veerbelaaide NKK AT4072-veiligheidsdop oor die skakelaar. Vergroot die opening versigtig met ’n figuursaag/lêer totdat dit oor die skakelaarbehuizing vasklik. Die beskermer voorkom dat die skakelaar per ongeluk binne ’n rugsak geaktiveer word.

## 3. Omhulsel en meganiese werk

• Gebruik ’n spoelsnyer en daarna ’n mes en lêer om die interne ABS-“uitbulting” te *verwyder*, sodat die groot USB-C-battery plat op die afstandhouer kan sit.
• Sny twee parallelle kanale in die omhulselwand vir die USB-C-kabel; dit sluit die battery vas en voorkom beweging/vibrasie.
• Maak ’n reghoekige opening vir die battery se **krag**-knoppie:
  1. Plak ’n papiersjabloon oor die plek vas.
  2. Boor 1/16″-loodsgate in al vier hoeke.
  3. Vergroot dit met ’n 1/8″-boorpunt.
  4. Verbind die gate met ’n figuursaag; werk die kante met ’n lêer af.  
  ✱ ’n Roterende Dremel is *vermy* – die hoëspoedpunt smelt dik ABS en laat ’n onooglike rand.

## 4. Finale montering

1. Plaas die MaxiProx-logikaplaat terug en soldeer die SMA-pigtail weer aan die PCB-grondkontak van die leser.
2. Monteer die ESP RFID Tool en USB-PD-sneller met 3 M VHB.
3. Rangskik al die bedrading met kabelbinders en hou die kragdrade **ver** van die antennalus.
4. Draai die omhulsel se skroewe vas totdat die battery liggies saamgepers is; die interne wrywing voorkom dat die pak verskuif wanneer die toestel terugspring ná elke kaartlesing.

## 5. Reikafstand- en afskermingstoetse

* Met ’n 125 kHz-**Pupa**-toetskaart het die draagbare kloner konsekwent op **≈ 8 cm** in vrye lug gelees – dieselfde as met netaangedrewe werking.<sup>[[1]](#references)</sup>
* Deur die leser in ’n dunwandige metaalkassie te plaas (om ’n bankvoorportaaltoonbank na te boots), is die reikafstand tot ≤ 2 cm verminder, wat bevestig dat groot metaalomhulsels as doeltreffende RF-afskermings dien.<sup>[[1]](#references)</sup>

## Gebruikstappe

1. Laai die USB-C-battery, koppel dit aan en skakel die hoofkragskakelaar aan.
2. (Opsioneel) Maak die gonserbeskermer oop en aktiveer hoorbare terugvoer wanneer jy op die werkbank toets; sluit dit voordat jy dit ongemerk in die veld gebruik.
3. Loop verby die teiken se kentekendraer – die MaxiProx aktiveer die kaart en die ESP RFID Tool vang die Wiegand-stroom op.
4. Stort die vasgevangde geloofsbriewe oor Wi-Fi of USB-UART uit en speel dit weer af/kloon dit soos nodig.

## Foutopsporing

| Simptoom | Waarskynlike oorsaak | Oplossing |
|---------|--------------|------|
| Leser herbegin wanneer ’n kaart aangebied word | PD-sneller het 9 V in plaas van 12 V onderhandel | Verifieer die sneller se jumpers / probeer ’n USB-C-kabel met hoër kraggradering |
| Geen leesreikafstand nie | Battery of bedrading lê *bo-op* die antenna | Lei kabels anders en hou 2 cm speling rondom die ferrietlus |
| Gonser tjirp steeds | Skakelaar is op die positiewe draad in plaas van die negatiewe bedraad | Skuif die afskakelskakelaar sodat dit die **negatiewe** luidsprekerspoor onderbreek |

## References

- [1] [Kom ons kloon ’n kloner – Deel 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)
{{#include ../../banners/hacktricks-training.md}}