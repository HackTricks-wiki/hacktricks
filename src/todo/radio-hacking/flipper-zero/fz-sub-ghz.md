# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero može da **prima i emituje radio-frekvencije u opsegu od 300 do 928 MHz** pomoću ugrađenog modula, koji može da čita, čuva i emulira daljinske upravljače. Ovi upravljači se koriste za interakciju sa kapijama, rampama, radio-bravama, prekidačima na daljinsko upravljanje, bežičnim zvoncima, pametnim svetlima i drugim uređajima. Flipper Zero može da vam pomogne da utvrdite da li je vaša bezbednost ugrožena.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardver <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ima ugrađeni sub-1 GHz modul zasnovan na [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 čipu](https://www.ti.com/lit/ds/symlink/cc1101.pdf) i radio-antenu (maksimalni domet je 50 metara). I CC1101 čip i antena projektovani su za rad na frekvencijama u opsezima 300–348 MHz, 387–464 MHz i 779–928 MHz.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Radnje

### Frequency Analyser

> [!TIP]
> Kako pronaći frekvenciju koju daljinski upravljač koristi

Tokom analize, Flipper Zero skenira jačinu signala (RSSI) na svim frekvencijama dostupnim u konfiguraciji frekvencije. Flipper Zero prikazuje frekvenciju sa najvišom vrednošću RSSI, čija je jačina signala veća od -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Da biste utvrdili frekvenciju daljinskog upravljača, uradite sledeće:

1. Postavite daljinski upravljač veoma blizu leve strane uređaja Flipper Zero.
2. Idite na **Main Menu** **→ Sub-GHz**.
3. Izaberite **Frequency Analyzer**, zatim pritisnite i držite dugme na daljinskom upravljaču koji želite da analizirate.
4. Proverite vrednost frekvencije na ekranu.

### Read

> [!TIP]
> Pronađite informacije o korišćenoj frekvenciji (ovo je još jedan način da pronađete koja se frekvencija koristi)

Opcija **Read** **osluškuje podešenu frekvenciju** na navedenoj modulaciji: podrazumevano 433.92 AM. Ako se tokom čitanja **nešto pronađe**, na ekranu se prikazuju **informacije**. Ove informacije mogu da se koriste za kasniju reprodukciju signala.<sup>[[1]](#references)</sup>

Dok je opcija Read aktivna, moguće je pritisnuti **levo dugme** i **konfigurisati je**.\
Trenutno ima **4 modulacije** (AM270, AM650, FM328 i FM476), kao i **nekoliko relevantnih sačuvanih frekvencija**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Možete podesiti **bilo koju frekvenciju koja vas zanima**, ali ako **niste sigurni koja frekvencija** se koristi na vašem daljinskom upravljaču, **podesite Hopping na ON** (podrazumevano je isključen) i pritisnite dugme nekoliko puta dok je Flipper ne uhvati i prikaže potrebne informacije za podešavanje frekvencije.

> [!CAUTION]
> Prebacivanje između frekvencija traje određeno vreme, zbog čega signali emitovani u trenutku prebacivanja mogu biti propušteni. Za bolji prijem signala podesite fiksnu frekvenciju utvrđenu pomoću opcije Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Preuzmite (i ponovite) signal na podešenoj frekvenciji

Opcija **Read Raw** **snima signale** koji se šalju na frekvenciji koja se osluškuje. Ovo se može koristiti za **preuzimanje** signala i njegovo **ponavljanje**.<sup>[[1]](#references)</sup>

Podrazumevano, **Read Raw** je takođe podešen na 433.92 u AM650, ali ako ste pomoću opcije Read pronašli da se signal koji vas zanima nalazi na **drugoj frekvenciji/modulaciji, možete i to izmeniti** pritiskom na levo dugme (dok ste unutar opcije Read Raw).

### Brute-Force

Ako poznajete protokol koji, na primer, koristi garažna vrata, moguće je **generisati sve kodove i poslati ih pomoću uređaja Flipper Zero.** Ovo je primer koji podržava uobičajene tipove garažnih vrata: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Dodavanje ručno

> [!TIP]
> Dodajte signale sa konfigurisanog spiska protokola

#### Spisak [podržanih protokola](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (radi sa većinom sistema sa statičkim kodom) | 433.92 | Static  |
| ---------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                         | 433.92 | Static  |
| Nice Flo 24bit_433                                         | 433.92 | Static  |
| CAME 12bit_433                                             | 433.92 | Static  |
| CAME 24bit_433                                             | 433.92 | Static  |
| Linear_300                                                 | 300.00 | Static  |
| CAME TWEE                                                  | 433.92 | Static  |
| Gate TX_433                                                | 433.92 | Static  |
| DoorHan_315                                                | 315.00 | Dynamic |
| DoorHan_433                                                | 433.92 | Dynamic |
| LiftMaster_315                                             | 315.00 | Dynamic |
| LiftMaster_390                                             | 390.00 | Dynamic |
| Security+2.0_310                                           | 310.00 | Dynamic |
| Security+2.0_315                                           | 315.00 | Dynamic |
| Security+2.0_390                                           | 390.00 | Dynamic |

### Podržani Sub-GHz vendors

Pogledajte spisak na [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Podržane frekvencije po regionu

Pogledajte spisak na [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Testiranje

> [!TIP]
> Dobijte dBm vrednosti sačuvanih frekvencija

## Reference

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
