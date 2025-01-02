# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero može **prijemati i prenositi radio frekvencije u opsegu od 300-928 MHz** sa svojim ugrađenim modulom, koji može čitati, čuvati i emulirati daljinske upravljače. Ovi upravljači se koriste za interakciju sa kapijama, barijerama, radio bravama, daljinskim prekidačima, bežičnim zvonima, pametnim svetlima i još mnogo toga. Flipper Zero može vam pomoći da saznate da li je vaša sigurnost ugrožena.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardver <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ima ugrađeni sub-1 GHz modul zasnovan na [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 čipu](https://www.ti.com/lit/ds/symlink/cc1101.pdf) i radio antenu (maksimalni domet je 50 metara). I CC1101 čip i antena su dizajnirani da rade na frekvencijama u opsezima 300-348 MHz, 387-464 MHz i 779-928 MHz.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Akcije

### Analizator frekvencije

> [!NOTE]
> Kako pronaći koja frekvencija se koristi za daljinski upravljač

Kada analizira, Flipper Zero skenira jačinu signala (RSSI) na svim frekvencijama dostupnim u konfiguraciji frekvencije. Flipper Zero prikazuje frekvenciju sa najvišom vrednošću RSSI, sa jačinom signala višom od -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Da biste odredili frekvenciju daljinskog upravljača, uradite sledeće:

1. Postavite daljinski upravljač vrlo blizu levo od Flipper Zero.
2. Idite na **Glavni meni** **→ Sub-GHz**.
3. Izaberite **Analizator frekvencije**, zatim pritisnite i držite dugme na daljinskom upravljaču koje želite da analizirate.
4. Pregledajte vrednost frekvencije na ekranu.

### Čitanje

> [!NOTE]
> Pronađite informacije o korišćenoj frekvenciji (takođe drugi način da saznate koja frekvencija se koristi)

Opcija **Čitanje** **sluša na konfigurisanom frekvenciji** na naznačenoj modulaciji: 433.92 AM po defaultu. Ako **se nešto pronađe** prilikom čitanja, **informacije se daju** na ekranu. Ove informacije mogu se koristiti za repliciranje signala u budućnosti.

Dok je Čitanje u upotrebi, moguće je pritisnuti **levo dugme** i **konfigurisati ga**.\
U ovom trenutku ima **4 modulacije** (AM270, AM650, FM328 i FM476), i **several relevant frequencies** pohranjene:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Možete postaviti **bilo koju koja vas zanima**, međutim, ako niste **sigurni koja frekvencija** bi mogla biti ona koju koristi vaš daljinski upravljač, **postavite Hopping na ON** (Isključeno po defaultu), i pritisnite dugme nekoliko puta dok Flipper ne uhvati i ne pruži vam informacije koje su vam potrebne za postavljanje frekvencije.

> [!CAUTION]
> Prebacivanje između frekvencija traje neko vreme, stoga se signali koji se prenose u trenutku prebacivanja mogu propustiti. Za bolju prijem signala, postavite fiksnu frekvenciju određenu od strane Analizatora frekvencije.

### **Čitaj sirovo**

> [!NOTE]
> Ukrao (i ponovo emitovao) signal na konfigurisanom frekvenciji

Opcija **Čitaj sirovo** **snima signale** koji se šalju na slušanoj frekvenciji. Ovo se može koristiti za **krađu** signala i **ponavljanje** istog.

Po defaultu **Čitaj sirovo je takođe na 433.92 u AM650**, ali ako ste sa opcijom Čitanje otkrili da je signal koji vas zanima na **drugoj frekvenciji/modulaciji, možete to takođe izmeniti** pritiskom levo (dok ste unutar opcije Čitaj sirovo).

### Brute-Force

Ako znate protokol koji koristi, na primer, garažna vrata, moguće je **generisati sve kodove i poslati ih sa Flipper Zero.** Ovo je primer koji podržava opšte uobičajene tipove garaža: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Dodaj ručno

> [!NOTE]
> Dodajte signale iz konfigurisane liste protokola

#### Lista [podržanih protokola](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (radi sa većinom sistema sa statičkim kodovima) | 433.92 | Statički  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Statički  |
| Nice Flo 24bit_433                                             | 433.92 | Statički  |
| CAME 12bit_433                                                 | 433.92 | Statički  |
| CAME 24bit_433                                                 | 433.92 | Statički  |
| Linear_300                                                     | 300.00 | Statički  |
| CAME TWEE                                                      | 433.92 | Statički  |
| Gate TX_433                                                    | 433.92 | Statički  |
| DoorHan_315                                                    | 315.00 | Dinamički |
| DoorHan_433                                                    | 433.92 | Dinamički |
| LiftMaster_315                                                 | 315.00 | Dinamički |
| LiftMaster_390                                                 | 390.00 | Dinamički |
| Security+2.0_310                                               | 310.00 | Dinamički |
| Security+2.0_315                                               | 315.00 | Dinamički |
| Security+2.0_390                                               | 390.00 | Dinamički |

### Podržani Sub-GHz dobavljači

Proverite listu na [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Podržane frekvencije po regionu

Proverite listu na [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!NOTE]
> Dobijte dBms sa sačuvanih frekvencija

## Reference

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
