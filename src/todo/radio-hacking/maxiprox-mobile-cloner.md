# Bou 'n Draagbare HID MaxiProx 125 kHz Mobiele Kloner

{{#include ../../banners/hacktricks-training.md}}

## Doel
Turn 'n mains-powered HID MaxiProx 5375 langafstand 125 kHz leser in 'n veld-ontplooiable, battery-aangedrewe badge kloner wat stilweg proximiteitskaarte oes tydens fisiese-sekuriteitsassesseringe.

Die omskakeling wat hier behandel word, is gebaseer op TrustedSec se “Let’s Clone a Cloner – Part 3: Putting It All Together” navorsingsreeks en kombineer meganiese, elektriese en RF oorwegings sodat die finale toestel in 'n rugsak gegooi kan word en onmiddellik op die terrein gebruik kan word.

> [!warning]
> Manipuleer van mains-powered toerusting en Lithium-ion kragbanke kan gevaarlik wees.  Verifieer elke verbinding **voor** jy die stroombaan aktiveer en hou die antennas, coax en grondvlak presies soos hulle in die fabriek ontwerp is om te voorkom dat die leser gedetuneer word.

## Materiaallys (BOM)

* HID MaxiProx 5375 leser (of enige 12 V HID Prox® langafstand leser)
* ESP RFID Tool v2.2 (ESP32-gebaseerde Wiegand sniffer/logger)
* USB-PD (Power-Delivery) trigger module wat in staat is om 12 V @ ≥3 A te onderhandel
* 100 W USB-C kragbank (gee 12 V PD profiel)
* 26 AWG silikoon-geïsoleerde aansluitdraad – rooi/blank
* Paneel-mount SPST skakelaar (vir beeper kill-switch)
* NKK AT4072 skakel-guard / ongeluk-bestande dop
* Soldering iron, solder wick & desolder pump
* ABS-gegradeerde handgereedskap: coping-saw, nut-knife, plat & half-rond vyle
* Boorgate 1/16″ (1.5 mm) en 1/8″ (3 mm)
* 3 M VHB dubbelzijdige band & Zip-ties

## 1. Krag Substelsel

1. Verwyder die fabriek buck-converter dogterbord wat gebruik word om 5 V vir die logika PCB te genereer.
2. Monteer 'n USB-PD trigger langs die ESP RFID Tool en lei die trigger se USB-C aansluiting na die buitekant van die behuising.
3. Die PD trigger onderhandel 12 V van die kragbank en voer dit direk aan die MaxiProx (die leser verwag van nature 10–14 V).  'n Sekondêre 5 V spoor word van die ESP bord geneem om enige bykomstighede van krag te voorsien.
4. Die 100 W batterypakket is vlak teen die interne standoff geplaas sodat daar **geen** kragdraad oor die ferrietantenna hang nie, wat RF prestasie behou.

## 2. Beeper Kill-Switch – Stille Bedryf

1. Vind die twee luidspreker pads op die MaxiProx logika bord.
2. Wick *albei* pads skoon, dan her-solder net die **negatiewe** pad.
3. Solder 26 AWG drade (blank = negatief, rooi = positief) aan die beeper pads en lei hulle deur 'n nuut gesnyde gleuf na 'n paneel-mount SPST skakelaar.
4. Wanneer die skakelaar oop is, is die beeper stroombaan gebroke en die leser werk in volledige stilte – ideaal vir geheime badge oes.
5. Plaas 'n NKK AT4072 veer-gelaaide veiligheidsdop oor die skakelaar.  Vergrend die boring versigtig met 'n coping-saw / file totdat dit oor die skakelaar liggaam klik.  Die guard voorkom toevallige aktivering binne 'n rugsak.

## 3. Behuizing & Meganiese Werk

• Gebruik vlak snellers en dan 'n mes & file om die interne ABS “bump-out” te *verwyder* sodat die groot USB-C battery plat op die standoff sit.
• Snit twee parallelle kanale in die behuising muur vir die USB-C kabel; dit vergrendel die battery in plek en elimineer beweging/vibrasie.
• Skep 'n reghoekige opening vir die battery se **krag** knoppie:
1. Plak 'n papier sjabloon oor die plek.
2. Boor 1/16″ pilootgate in al vier hoeke.
3. Vergroot met 'n 1/8″ boor.
4. Verbind die gate met 'n coping saw; voltooi die kante met 'n file.
✱  'n Rotary Dremel is *vermy* – die hoë spoed boor smelt dik ABS en laat 'n lelike rand.

## 4. Finale Samestelling

1. Her-installeer die MaxiProx logika bord en her-solder die SMA pigtail aan die leser se PCB grond pad.
2. Monteer die ESP RFID Tool en USB-PD trigger met 3 M VHB.
3. Kleed al die bedrading met zip-ties, hou kragleidings **ver** van die antenna lus.
4. Trek die behuising skroewe styf totdat die battery liggies saamgepers is; die interne wrywing voorkom dat die pakket skuif wanneer die toestel terugskiet na elke kaart lees.

## 5. Bereik & Skilding Toetse

* Met 'n 125 kHz **Pupa** toetskaart het die draagbare kloner konsekwente lees by **≈ 8 cm** in vrye lug – identies aan mains-powered werking.
* Om die leser binne 'n dunwandige metaal kontantkas te plaas (om 'n banklobby lessenaar na te boots) het die bereik tot ≤ 2 cm verminder, wat bevestig dat substansiële metaal behuisings as effektiewe RF skilde optree.

## Gebruik Werkvloei

1. Laai die USB-C battery, verbind dit, en draai die hoof krag skakelaar om.
2. (Opsioneel) Maak die beeper guard oop en stel hoorbare terugvoer in wanneer jy op die bank toets; sluit dit af voor geheime veldgebruik.
3. Loop verby die teiken badge houer – die MaxiProx sal die kaart aktiveer en die ESP RFID Tool vang die Wiegand stroom.
4. Dump gevangenis geloofsbriewe oor Wi-Fi of USB-UART en herhaal/klon as nodig.

## Probleemoplossing

| Simptoom | Waarskynlike Oorsaak | Regstelling |
|---------|--------------|------|
| Leser herbegin wanneer kaart aangebied word | PD trigger het 9 V onderhandel, nie 12 V nie | Verifieer trigger jumpers / probeer 'n hoër-krag USB-C kabel |
| Geen leesbereik | Battery of bedrading sit *op top* van die antenna | Herlei kabels & hou 2 cm vryheid rondom die ferriet lus |
| Beeper piep steeds | Skakelaar is op die positiewe leiding in plaas van negatief | Verander kill-switch om die **negatiewe** luidspreker spoor te breek |

## Verwysings

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
