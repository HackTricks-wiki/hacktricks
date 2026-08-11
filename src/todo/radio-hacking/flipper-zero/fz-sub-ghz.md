# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#introduction" id="introduction"></a>

Flipper Zero može **da prima i emituje radio-frekvencije u opsegu od 300 do 928 MHz** pomoću ugrađenog modula, uz ograničenja frekvencija za konfigurisani region. Može da čita, čuva i emulira kompatibilne daljinske upravljače koji se koriste za kapije, rampe, radio brave, prekidače, bežična zvona, pametna svetla i druge uređaje.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardver <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero ima ugrađeni sub-1 GHz modul zasnovan na CC1101 primopredajniku i radio-anteni. Stvarni domet zavisi od frekvencije, antene, okruženja i predajnika; Flipper navodi domet do približno 50 metara u povoljnim uslovima. Hardver pokriva opsege 300-348 MHz, 387-464 MHz i 779-928 MHz, dok firmware i regionalna pravila dodatno ograničavaju emitovanje.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Radnje

### Frequency Analyser

> [!TIP]
> Kako pronaći frekvenciju koju daljinski upravljač koristi

Tokom analize, Flipper Zero skenira jačinu signala (RSSI) na svim frekvencijama dostupnim u konfiguraciji frekvencija. Flipper Zero prikazuje frekvenciju sa najvišom RSSI vrednošću, sa jačinom signala većom od -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Da biste utvrdili frekvenciju daljinskog upravljača, uradite sledeće:

1. Postavite daljinski upravljač veoma blizu leve strane uređaja Flipper Zero.
2. Idite na **Main Menu** **→ Sub-GHz**.
3. Izaberite **Frequency Analyzer**, zatim pritisnite i držite dugme na daljinskom upravljaču koji želite da analizirate.
4. Pogledajte vrednost frekvencije na ekranu.

### Read

> [!TIP]
> Pronađite informacije o korišćenoj frekvenciji (ovo je takođe način da pronađete koja se frekvencija koristi)

Opcija **Read** osluškuje konfigurisanu frekvenciju i modulaciju (433.92 MHz AM podrazumevano). Kada prepozna podržani signal, ekran prikazuje informacije koje se kasnije mogu sačuvati i ponovo reprodukovati.<sup>[[1]](#references)</sup>

Dok se koristi Read, moguće je pritisnuti **levo dugme** i **konfigurisati ga**.\
Trenutno ima **4 modulacije** (AM270, AM650, FM328 i FM476), kao i **nekoliko relevantnih frekvencija**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Možete izabrati bilo koju dozvoljenu frekvenciju. Ako niste sigurni koju frekvenciju daljinski upravljač koristi, podesite **Hopping na ON** (podrazumevano je isključen), a zatim nekoliko puta pritisnite dugme na daljinskom upravljaču dok Flipper ne uhvati signal i prijavi frekvenciju.

> [!CAUTION]
> Prebacivanje između frekvencija traje određeno vreme, pa signali emitovani tokom prebacivanja mogu biti propušteni. Za bolji prijem signala podesite fiksnu frekvenciju utvrđenu pomoću Frequency Analyzer-a.

### **Read Raw**

> [!TIP]
> Preuzmite (i ponovo reprodukujte) signal na konfigurisanoj frekvenciji

Opcija **Read Raw** snima signale poslate na izabranoj frekvenciji. Ovo se može koristiti za hvatanje i ponovno reprodukovanje signala tokom autorizovanog testiranja.<sup>[[1]](#references)</sup>

Podrazumevano, **Read Raw takođe koristi 433.92 MHz sa AM650**. Ako je opcija Read pronašla signal na drugoj frekvenciji ili modulaciji, pritisnite Left unutar opcije Read Raw da biste promenili ta podešavanja.

### Brute-Force

Ako znate protokol koji uređaj koristi, kao što su garažna vrata, možda je moguće **generisati kandidate kodova i emitovati ih pomoću uređaja Flipper Zero**. Projekat `flipperzero-bruteforce` podržava nekoliko uobičajenih protokola sa statičkim kodovima.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Dodajte signale sa konfigurisane liste protokola

#### Lista podržanih protokola <a href="#id-3iglu" id="id-3iglu"></a>

Meni Add Manually prikazuje unapred podešene protokole dokumentovane za Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (radi sa većinom sistema sa statičkim kodom) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Podržani Sub-GHz proizvođači

Pogledajte listu podržanih proizvođača za Flipper Zero.<sup>[[5]](#references)</sup>

### Podržane frekvencije po regionima

Pre emitovanja proverite zvaničnu listu regionalnih frekvencija.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Dobijte dBm vrednosti sačuvanih frekvencija

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
