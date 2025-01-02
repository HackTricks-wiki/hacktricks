# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero può **ricevere e trasmettere frequenze radio nella gamma di 300-928 MHz** con il suo modulo integrato, che può leggere, salvare ed emulare telecomandi. Questi telecomandi sono utilizzati per interagire con cancelli, barriere, serrature radio, interruttori a distanza, campanelli wireless, luci intelligenti e altro ancora. Flipper Zero può aiutarti a scoprire se la tua sicurezza è compromessa.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ha un modulo sub-1 GHz integrato basato su un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) e un'antenna radio (la portata massima è di 50 metri). Sia il chip CC1101 che l'antenna sono progettati per operare a frequenze nelle bande 300-348 MHz, 387-464 MHz e 779-928 MHz.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Azioni

### Analizzatore di Frequenza

> [!NOTE]
> Come trovare quale frequenza sta usando il telecomando

Quando si analizza, Flipper Zero sta scansionando la forza dei segnali (RSSI) a tutte le frequenze disponibili nella configurazione di frequenza. Flipper Zero visualizza la frequenza con il valore RSSI più alto, con una forza del segnale superiore a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Per determinare la frequenza del telecomando, procedi come segue:

1. Posiziona il telecomando molto vicino a sinistra di Flipper Zero.
2. Vai a **Menu Principale** **→ Sub-GHz**.
3. Seleziona **Analizzatore di Frequenza**, quindi premi e tieni premuto il pulsante sul telecomando che desideri analizzare.
4. Controlla il valore della frequenza sullo schermo.

### Leggi

> [!NOTE]
> Trova informazioni sulla frequenza utilizzata (anche un altro modo per trovare quale frequenza è utilizzata)

L'opzione **Leggi** **ascolta sulla frequenza configurata** sulla modulazione indicata: 433.92 AM per impostazione predefinita. Se **viene trovato qualcosa** durante la lettura, **le informazioni vengono fornite** sullo schermo. Queste informazioni potrebbero essere utilizzate per replicare il segnale in futuro.

Mentre Leggi è in uso, è possibile premere il **pulsante sinistro** e **configurarlo**.\
In questo momento ha **4 modulazioni** (AM270, AM650, FM328 e FM476), e **diverse frequenze rilevanti** memorizzate:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Puoi impostare **quella che ti interessa**, tuttavia, se **non sei sicuro di quale frequenza** potrebbe essere quella utilizzata dal telecomando che hai, **imposta Hopping su ON** (Off per impostazione predefinita), e premi il pulsante più volte finché Flipper non la cattura e ti fornisce le informazioni necessarie per impostare la frequenza.

> [!CAUTION]
> Passare tra le frequenze richiede del tempo, quindi i segnali trasmessi al momento del passaggio possono essere persi. Per una migliore ricezione del segnale, imposta una frequenza fissa determinata dall'Analizzatore di Frequenza.

### **Leggi Raw**

> [!NOTE]
> Ruba (e ripeti) un segnale nella frequenza configurata

L'opzione **Leggi Raw** **registra i segnali** inviati nella frequenza di ascolto. Questo può essere utilizzato per **rubare** un segnale e **ripeterlo**.

Per impostazione predefinita, **Leggi Raw è anche a 433.92 in AM650**, ma se con l'opzione Leggi hai scoperto che il segnale che ti interessa è in una **frequenza/modulazione diversa, puoi anche modificarlo** premendo a sinistra (mentre sei all'interno dell'opzione Leggi Raw).

### Brute-Force

Se conosci il protocollo utilizzato ad esempio dal cancello del garage, è possibile **generare tutti i codici e inviarli con il Flipper Zero.** Questo è un esempio che supporta i tipi comuni di garage: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Aggiungi Manualmente

> [!NOTE]
> Aggiungi segnali da un elenco configurato di protocolli

#### Elenco dei [protocolli supportati](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (funziona con la maggior parte dei sistemi a codice statico) | 433.92 | Statico  |
| -------------------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                                        | 433.92 | Statico  |
| Nice Flo 24bit_433                                                        | 433.92 | Statico  |
| CAME 12bit_433                                                            | 433.92 | Statico  |
| CAME 24bit_433                                                            | 433.92 | Statico  |
| Linear_300                                                                | 300.00 | Statico  |
| CAME TWEE                                                                 | 433.92 | Statico  |
| Gate TX_433                                                               | 433.92 | Statico  |
| DoorHan_315                                                               | 315.00 | Dinamico |
| DoorHan_433                                                               | 433.92 | Dinamico |
| LiftMaster_315                                                            | 315.00 | Dinamico |
| LiftMaster_390                                                            | 390.00 | Dinamico |
| Security+2.0_310                                                          | 310.00 | Dinamico |
| Security+2.0_315                                                          | 315.00 | Dinamico |
| Security+2.0_390                                                          | 390.00 | Dinamico |

### Fornitori Sub-GHz supportati

Controlla l'elenco in [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frequenze supportate per regione

Controlla l'elenco in [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!NOTE]
> Ottieni dBms delle frequenze salvate

## Riferimento

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
