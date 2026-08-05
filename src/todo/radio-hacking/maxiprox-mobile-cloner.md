# Bou van 'n Draagbare HID MaxiProx 125 kHz Mobile Cloner

{{#include ../../banners/hacktricks-training.md}}

## Doel
Verander 'n netstroom-aangedrewe HID MaxiProx 5375-langafstand-125 kHz-leser in 'n veldtoepasbare, battery-aangedrewe badge cloner wat proximity-kaarte stilweg tydens fisiese-sekuriteitsassesserings insamel.

Die omskakeling wat hier behandel word, is gebaseer op TrustedSec se navorsingsreeks “Let’s Clone a Cloner – Part 3: Putting It All Together” en kombineer meganiese, elektriese en RF-oorwegings sodat die finale toestel in 'n rugsak gesit en onmiddellik op die terrein gebruik kan word.<sup>[[1]](#references)</sup>

> [!warning]
> Manipulering van netstroom-aangedrewe toerusting en Lithium-ion-kragbanke kan gevaarlik wees.  Verifieer elke verbinding **voordat** jy die stroombaan aktiveer, en hou die antennas, koaks en grondvlakke presies soos in die fabrieksontwerp om te voorkom dat die leser se afstemming verander.

## Materiaallys (BOM)

* HID MaxiProx 5375-leser (of enige 12 V HID Prox®-langafstandleser)
* ESP RFID Tool v2.2 (ESP32-gebaseerde Wiegand-snuffelaar/logger)
* USB-PD (Power-Delivery)-trigger-module wat 12 V teen ≥3 A kan onderhandel
* 100 W USB-C-kragbank (lewer 12 V PD-profiel)
* 26 AWG silikoon-geïsoleerde verbindingsdraad – rooi/wit
* Paneelgemonteerde SPST-wipskakelaar (vir beeper kill-switch)
* NKK AT4072-skakelaarbeskermer / ongelukvaste kap
* Soldeerbout, soldeerlont en desoldeerpomp
* ABS-geskikte handgereedskap: figuursaag, nutsmes, plat- en halfsirkelvyle
* Boorpunte 1/16″ (1,5 mm) en 1/8″ (3 mm)
* 3 M VHB-dubbelzijdige kleefband en Zip-ties

## 1. Kragsubstelsel

1. Desoldeer en verwyder die fabrieks-buck-converter-dogterbord wat gebruik word om 5 V vir die logika-PCB te genereer.
2. Monteer 'n USB-PD-trigger langs die ESP RFID Tool en lei die trigger se USB-C-aansluiting na die buitekant van die omhulsel.
3. Die PD-trigger onderhandel 12 V vanaf die kragbank en voer dit direk na die MaxiProx (die leser verwag van nature 10–14 V).  'n Sekondêre 5 V-rail word van die ESP-bord af geneem om enige bykomstighede van krag te voorsien.
4. Die 100 W-battery word gelyk met die interne afstandstuk geplaas sodat daar **geen** kragkabels oor die ferrietantenna hang nie, wat RF-werkverrigting behou.

## 2. Beeper Kill-Switch – Stil werking

1. Vind die twee luidsprekerkussings op die MaxiProx-logikabord.
2. Verwyder die soldeersel van *albei* kussings, en soldeer dan slegs die **negatiewe** kussing weer.
3. Soldeer 26 AWG-drade (wit = negatief, rooi = positief) aan die beeper-kussings en lei hulle deur 'n nuutgesnyde gleuf na 'n paneelgemonteerde SPST-skakelaar.
4. Wanneer die skakelaar oop is, is die beeperstroombaan onderbreek en werk die leser heeltemal stil – ideaal vir die heimlike insameling van badges.
5. Plaas 'n NKK AT4072-veergelaaide veiligheidskap oor die wipskakelaar.  Vergroot die boring versigtig met 'n figuursaag / vyl totdat dit oor die skakelaarliggaam vasklik.  Die beskermer voorkom toevallige aktivering binne-in 'n rugsak.

## 3. Omhulsel- en meganiese werk

• Gebruik 'n platkniptang en daarna 'n mes en vyl om die interne ABS-“uitbulting” te *verwyder* sodat die groot USB-C-battery plat op die afstandstuk sit.
• Sny twee parallelle kanale in die omhulselwand vir die USB-C-kabel; dit sluit die battery in plek en verwyder beweging/vibrasie.
• Skep 'n reghoekige opening vir die battery se **krag**-knoppie:
1. Plak 'n papierstensil oor die ligging.
2. Boor 1/16″-loodsgate in al vier hoeke.
3. Vergroot dit met 'n 1/8″-boorpunt.
4. Verbind die gate met 'n figuursaag; werk die rande met 'n vyl af.
✱  'n Roterende Dremel is *vermy* – die hoëspoedpunt smelt dik ABS en laat 'n onooglike rand.

## 4. Finale samestelling

1. Installeer die MaxiProx-logikabord weer en soldeer die SMA-pigtail weer aan die leser se PCB-grondkussing.
2. Monteer die ESP RFID Tool en USB-PD-trigger met 3 M VHB.
3. Rangskik alle bedrading met Zip-ties en hou kragdrade **ver** van die antennalus.
4. Draai die omhulselskroewe vas totdat die battery liggies saamgepers is; die interne wrywing voorkom dat die battery skuif wanneer die toestel ná elke kaartlesing terugspring.

## 5. Reikwydte- en afskermingstoetse

* Met 'n 125 kHz **Pupa**-toetskaart het die draagbare cloner konsekwente lesings op **≈ 8 cm** in vrye lug behaal – identies aan netstroomwerking.<sup>[[1]](#references)</sup>
* Deur die leser in 'n dunwandige metaalkas te plaas (om 'n bankportaaltoonbank te simuleer), is die reikwydte tot ≤ 2 cm verminder, wat bevestig dat aansienlike metaalomhulsels as effektiewe RF-skerms optree.<sup>[[1]](#references)</sup>

## Gebruiksproses

1. Laai die USB-C-battery, koppel dit, en skakel die hoofkragskakelaar aan.
2. (Opsioneel) Maak die beeperbeskermer oop en aktiveer hoorbare terugvoer tydens banktoetse; sluit dit vas voordat jy dit heimlik in die veld gebruik.
3. Loop verby die teiken se badge-houer – die MaxiProx sal die kaart aktiveer en die ESP RFID Tool vang die Wiegand-stroom vas.
4. Stort die vasgevange credentials oor Wi-Fi of USB-UART uit en speel dit weer af / clone dit soos vereis.

## Probleemoplossing

| Simptoom | Waarskynlike oorsaak | Oplossing |
|---------|--------------|------|
| Leser herbegin wanneer kaart aangebied word | PD-trigger het 9 V in plaas van 12 V onderhandel | Verifieer trigger-jumpers / probeer 'n USB-C-kabel met hoër kragvermoë |
| Geen leesreikwydte nie | Battery of bedrading lê *bo-op* die antenna | Herlei kabels en hou 2 cm speling rondom die ferrietlus |
| Beeper tjirp steeds | Skakelaar is op die positiewe leiding bedraad in plaas van die negatiewe | Verskuif die kill-switch sodat dit die **negatiewe** luidsprekerspoor onderbreek |

## Verwysings

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
