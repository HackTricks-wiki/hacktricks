# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero može **primati i emitovati radio-frekvencije u opsegu od 300 do 928 MHz** pomoću ugrađenog modula, koji može da čita, čuva i emulira daljinske upravljače. Ovi upravljači se koriste za interakciju sa kapijama, rampama, radio-bravama, prekidačima sa daljinskim upravljanjem, bežičnim zvoncima, pametnim svetlima i drugim uređajima. Flipper Zero može da vam pomogne da saznate da li je vaša bezbednost ugrožena.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardver <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ima ugrađeni sub-1 GHz modul zasnovan na [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 čipu](https://www.ti.com/lit/ds/symlink/cc1101.pdf) i radio-antenu (maksimalni domet je 50 metara). I CC1101 čip i antena projektovani su za rad na frekvencijama u opsezima 300–348 MHz, 387–464 MHz i 779–928 MHz.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Radnje

### Frequency Analyser

> [!TIP]
> Kako pronaći frekvenciju koju koristi daljinski upravljač

Tokom analize, Flipper Zero skenira jačinu signala (RSSI) na svim frekvencijama dostupnim u konfiguraciji frekvencije. Flipper Zero prikazuje frekvenciju sa najvišom RSSI vrednošću, čija je jačina signala veća od -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Da biste odredili frekvenciju daljinskog upravljača, uradite sledeće:

1. Postavite daljinski upravljač veoma blizu leve strane uređaja Flipper Zero.
2. Idite na **Main Menu** **→ Sub-GHz**.
3. Izaberite **Frequency Analyzer**, zatim pritisnite i držite dugme na daljinskom upravljaču koji želite da analizirate.
4. Proverite vrednost frekvencije na ekranu.

### Read

> [!TIP]
> Pronađite informacije o korišćenoj frekvenciji (takođe još jedan način da pronađete koja se frekvencija koristi)

Opcija **Read** **osluškuje podešenu frekvenciju** na naznačenoj modulaciji: podrazumevano 433.92 AM. Ako se **nešto pronađe** tokom čitanja, **informacije se prikazuju** na ekranu. Ove informacije mogu da se koriste za reprodukovanje signala u budućnosti.<sup>[[1]](#references)</sup>

Dok se koristi Read, moguće je pritisnuti **levo dugme** i **konfigurisati ga**.\
Trenutno ima **4 modulacije** (AM270, AM650, FM328 i FM476), kao i **nekoliko relevantnih sačuvanih frekvencija**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Možete podesiti **bilo koju koja vas zanima**, međutim, ako **niste sigurni koja bi frekvencija** mogla biti ona koju koristi vaš daljinski upravljač, **podesite Hopping na ON** (podrazumevano je isključeno) i pritisnite dugme nekoliko puta dok je Flipper ne uhvati i pruži vam informacije potrebne za podešavanje frekvencije.

> [!CAUTION]
> Prebacivanje između frekvencija traje određeno vreme, zbog čega signali emitovani u trenutku prebacivanja mogu biti propušteni. Za bolji prijem signala podesite fiksnu frekvenciju određenu pomoću opcije Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Ukradite (i ponovite) signal na podešenoj frekvenciji

Opcija **Read Raw** **snima signale** poslate na frekvenciji koja se osluškuje. Ovo se može koristiti za **krađu** signala i njegovo **ponavljanje**.

Podrazumevano, **Read Raw je takođe podešen na 433.92 u AM650**, ali ako ste pomoću opcije Read pronašli da je signal koji vas zanima na **drugoj frekvenciji/modulaciji, to takođe možete izmeniti** pritiskom nalevo (dok ste unutar opcije Read Raw).

### Brute-Force

Ako poznajete protokol koji koristi, na primer, garažna vrata, moguće je **generisati sve kodove i poslati ih pomoću uređaja Flipper Zero.** Ovo je primer koji podržava opšte uobičajene tipove garaža: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Dodajte signale sa konfigurisane liste protokola

#### Lista [podržanih protokola](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (radi sa većinom sistema sa statičkim kodom) | 433.92 | Statički  |
| ---------------------------------------------------------- | ------ | --------- |
| Nice Flo 12bit_433                                          | 433.92 | Statički  |
| Nice Flo 24bit_433                                          | 433.92 | Statički  |
| CAME 12bit_433                                              | 433.92 | Statički  |
| CAME 24bit_433                                              | 433.92 | Statički  |
| Linear_300                                                  | 300.00 | Statički  |
| CAME TWEE                                                   | 433.92 | Statički  |
| Gate TX_433                                                 | 433.92 | Statički  |
| DoorHan_315                                                 | 315.00 | Dinamički |
| DoorHan_433                                                 | 433.92 | Dinamički |
| LiftMaster_315                                              | 315.00 | Dinamički |
| LiftMaster_390                                              | 390.00 | Dinamički |
| Security+2.0_310                                            | 310.00 | Dinamički |
| Security+2.0_315                                            | 315.00 | Dinamički |
| Security+2.0_390                                            | 390.00 | Dinamički |

### Podržani Sub-GHz proizvođači

Pogledajte listu na [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Podržane frekvencije po regionima

Pogledajte listu na [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> Dobijte dBm vrednosti sačuvanih frekvencija

## Reference

- [1] [Flipper Zero Sub-GHz dokumentacija](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
