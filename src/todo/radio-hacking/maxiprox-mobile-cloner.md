# Izrada prenosivog HID MaxiProx 125 kHz mobilnog klonera

{{#include ../../banners/hacktricks-training.md}}

## Cilj
Pretvoriti mrežno napajani HID MaxiProx 5375 long-range 125 kHz čitač u terenski, baterijski napajan cloner kartica koji nečujno prikuplja proximity kartice tokom procena fizičke bezbednosti.

Ovde opisana konverzija zasniva se na TrustedSec istraživačkoj seriji „Let’s Clone a Cloner – Part 3: Putting It All Together“ i objedinjuje mehaničke, električne i RF aspekte, tako da se finalni uređaj može ubaciti u ranac i odmah koristiti na lokaciji.<sup>[[1]](#references)</sup>

> [!warning]
> Manipulacija opremom napajanom iz električne mreže i Lithium-ion power-bank uređajima može biti opasna. Proverite svaku vezu **pre** uključivanja kola i držite antene, koaksijalne kablove i ground plane-ove tačno onako kako su postavljeni u fabričkom dizajnu da biste izbegli detuning čitača.

## Spisak materijala (BOM)

* HID MaxiProx 5375 reader (ili bilo koji 12 V HID Prox® long-range reader)
* ESP RFID Tool v2.2 (Wiegand sniffer/logger zasnovan na ESP32)
* USB-PD (Power-Delivery) trigger module koji može da pregovara 12 V @ ≥3 A
* 100 W USB-C power-bank (daje 12 V PD profile)
* 26 AWG silicone-insulated hook-up wire – crvena/bela
* Panel-mount SPST toggle switch (za beeper kill-switch)
* NKK AT4072 switch-guard / accident-proof cap
* Lemilica, solder wick i desolder pump
* ABS-rated hand tools: coping-saw, utility-knife, flat & half-round files
* Burgije 1/16″ (1,5 mm) i 1/8″ (3 mm)
* 3 M VHB double-sided tape i Zip-ties

## 1. Power Sub-System

1. Odlemite i uklonite fabričku buck-converter daughter-board koja se koristi za generisanje 5 V za logic PCB.
2. Postavite USB-PD trigger pored ESP RFID Tool-a i sprovedite USB-C receptacle triggera do spoljašnje strane kućišta.
3. PD trigger pregovara 12 V iz power-bank uređaja i dovodi ga direktno do MaxiProx-a (čitač nativno očekuje 10–14 V). Sekundarna 5 V rail grana uzima se sa ESP ploče za napajanje dodatne opreme.
4. Baterijski paket od 100 W postavite ravno uz unutrašnji standoff, tako da **nema** power kablova položenih preko feritne antene, čime se očuvaju RF performanse.

## 2. Beeper Kill-Switch – nečujan rad

1. Pronađite dva speaker pada na MaxiProx logic board-u.
2. Očistite *oba* pada pomoću solder wick-a, zatim ponovo zalemite samo **negativni** pad.
3. Zalemite 26 AWG žice (bela = negativna, crvena = pozitivna) na beeper padove i sprovedite ih kroz novoissečeni otvor do panel-mount SPST switch-a.
4. Kada je switch otvoren, beeper circuit je prekinut i reader radi potpuno nečujno – idealno za covert prikupljanje badge kartica.
5. Postavite NKK AT4072 spring-loaded safety cap preko toggle-a. Pažljivo proširite otvor pomoću coping-saw-a / file dok ne nalegne preko tela switch-a. Guard sprečava slučajno aktiviranje unutar ranca.

## 3. Enclosure & Mechanical Work

• Upotrebite flush cutters, zatim knife & file, da *uklonite* unutrašnji ABS „bump-out“ kako bi velika USB-C baterija ravno nalegla na standoff.
• Isecite dva paralelna kanala u zidu kućišta za USB-C kabl; to fiksira bateriju i uklanja pomeranje/vibracije.
• Napravite pravougaoni otvor za **power** dugme baterije:
1. Zalepite papirni stencil preko predviđenog mesta.
2. Izbušite pilot rupe burgijom 1/16″ u sva četiri ugla.
3. Proširite ih burgijom 1/8″.
4. Spojite rupe coping saw-om; završno obradite ivice file-om.
✱  Rotary Dremel je *izbegnut* – bit velike brzine topi debeli ABS i ostavlja neurednu ivicu.

## 4. Final Assembly

1. Ponovo postavite MaxiProx logic board i zalemite SMA pigtail na ground pad reader PCB-a.
2. Pričvrstite ESP RFID Tool i USB-PD trigger pomoću 3 M VHB trake.
3. Sredite sve kablove pomoću zip-ties, držeći power vodove **daleko** od antenna loop-a.
4. Zategnite šrafove kućišta dok baterija ne bude blago pritisnuta; unutrašnje trenje sprečava pomeranje paketa kada se uređaj trzne nakon svakog očitavanja kartice.

## 5. Range & Shielding Tests

* Korišćenjem 125 kHz **Pupa** test kartice, portable cloner je postizao stabilna očitavanja na **≈ 8 cm** na otvorenom – identično radu sa mrežnim napajanjem.<sup>[[1]](#references)</sup>
* Postavljanje reader-a u tankozidnu metalnu kasu (kao simulacija pulta u predvorju banke) smanjilo je domet na ≤ 2 cm, potvrđujući da kućišta sa znatnom količinom metala deluju kao efikasni RF shield-ovi.<sup>[[1]](#references)</sup>

## Usage Workflow

1. Napunite USB-C bateriju, povežite je i uključite glavni power switch.
2. (Opcionalno) Otvorite beeper guard i uključite zvučne povratne informacije tokom bench-testiranja; zaključajte ga pre covert upotrebe na terenu.
3. Prođite pored ciljanog korisnika badge kartice – MaxiProx će energizovati karticu, a ESP RFID Tool će uhvatiti Wiegand stream.
4. Izvezite prikupljene credentials preko Wi-Fi-ja ili USB-UART-a i po potrebi ih replay/clone-ujte.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|------|
| Reader se restartuje kada se kartica prinese | PD trigger je pregovarao 9 V umesto 12 V | Proverite trigger jumpers / pokušajte sa USB-C kablom veće snage |
| Nema read range-a | Baterija ili kablovi se nalaze *na vrhu* antene | Preusmerite kablove i održavajte razmak od 2 cm oko feritne loop antene |
| Beeper i dalje pišti | Switch je povezan na pozitivni vod umesto na negativni | Premestite kill-switch tako da prekida **negativnu** speaker trace |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
